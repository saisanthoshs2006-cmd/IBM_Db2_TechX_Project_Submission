"""Run an approved query, only as a verified restricted Db2 user and only with audit available.

Security boundary: Db2 authorization. The execution connection must belong to a dedicated user
that holds no authority except CONNECT, no write privilege on any table, and SELECT only on
allowed data-source schemas. SQL_ATTR_ACCESS_MODE=READ_ONLY is a hint, not enforcement, and the
rollback after each query is hygiene, not protection; neither is relied on.

Phase 2A: no restricted user exists and audit is disabled, so execute_approved always refuses.
Creating the user and its GRANTs is a separate, approved step.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence

from db2intel.db.connection import DbError
from db2intel.guard.analysis import BLOCKED, ERROR, GuardDecision, object_allowed
from db2intel.guard.audit import AuditSink, AuditUnavailable, make_record
from db2intel.guard.context import GuardContext

SUCCESS = "SUCCESS"
TIMEOUT_SQLSTATE = "57014"  # statement cancelled (query timeout)

# Verified against Db2 12.1.5 in Phase 2B before first use.
SESSION_USER_SQL = "SELECT SESSION_USER FROM SYSIBM.SYSDUMMY1"
AUTHORITIES_SQL = (
    "SELECT RTRIM(AUTHORITY), D_USER, D_GROUP, D_PUBLIC, ROLE_USER, ROLE_GROUP, ROLE_PUBLIC, D_ROLE "
    "FROM TABLE(SYSPROC.AUTH_LIST_AUTHORITIES_FOR_AUTHID(?, 'U')) AS T"
)
GROUPS_SQL = "SELECT * FROM TABLE(SYSPROC.AUTH_LIST_GROUPS_FOR_AUTHID(?)) AS T"
ROLES_SQL = "SELECT RTRIM(ROLENAME) FROM TABLE(SYSPROC.AUTH_LIST_ROLES_FOR_AUTHID(?, 'U')) AS T"
TABAUTH_SQL = (
    "SELECT RTRIM(TABSCHEMA), RTRIM(TABNAME), RTRIM(GRANTEE), GRANTEETYPE, CONTROLAUTH, ALTERAUTH, "
    "DELETEAUTH, INDEXAUTH, INSERTAUTH, REFAUTH, SELECTAUTH, UPDATEAUTH FROM SYSCAT.TABAUTH WHERE "
)
ALLOWED_AUTHORITIES = frozenset({"CONNECT"})


class PrincipalError(PermissionError):
    """The execution connection is not a verified restricted user."""


class ExecutionSession(Protocol):
    def query(self, sql: str, params: Sequence[Any] = ()) -> list[tuple]: ...
    def execute_capped(self, sql: str, max_rows: int, timeout_seconds: int) -> "QueryResult": ...
    def rollback(self) -> None: ...


@dataclass(frozen=True)
class QueryResult:
    columns: tuple[str, ...]
    rows: tuple[tuple, ...]
    truncated: bool


@dataclass(frozen=True)
class ExecutionOutcome:
    request_id: str
    status: str
    code: str
    reason: str
    columns: tuple[str, ...] = ()
    rows: tuple[tuple, ...] = field(default=())
    truncated: bool = False
    execution_ms: int | None = None
    sqlstate: str | None = None


def _granted(flag) -> bool:
    return str(flag or "").strip().upper() in ("Y", "G")


def verify_restricted_principal(session: ExecutionSession, admin_users: Sequence[str],
                                allowed_schemas: frozenset[str]) -> str:
    """Return the session user if it is a restricted reader; raise PrincipalError otherwise."""
    rows = session.query(SESSION_USER_SQL)
    if len(rows) != 1:
        raise PrincipalError("cannot determine the execution user")
    user = str(rows[0][0]).strip().upper()
    admins = {a.strip().upper() for a in admin_users} | {"DB2INST1"}
    if not user or user in admins:
        raise PrincipalError(f"execution must use a dedicated restricted user, not {user or 'an unknown user'}")

    authorities = session.query(AUTHORITIES_SQL, (user,))
    if not authorities:
        raise PrincipalError("cannot list the execution user's authorities")
    extra = sorted(
        str(name).strip().upper() for name, *flags in authorities
        if str(name).strip().upper() not in ALLOWED_AUTHORITIES and any(_granted(f) for f in flags)
    )
    if extra:
        raise PrincipalError(f"execution user holds authorities beyond CONNECT: {', '.join(extra)}")

    groups = [str(r[0]).strip().upper() for r in session.query(GROUPS_SQL, (user,))]
    roles = [str(r[0]).strip().upper() for r in session.query(ROLES_SQL, (user,))]
    grantees = [("U", user), ("G", "PUBLIC")] + [("G", g) for g in groups] + [("R", r) for r in roles]
    where = " OR ".join("(GRANTEETYPE = ? AND GRANTEE = ?)" for _ in grantees)
    params = tuple(v for pair in grantees for v in pair)
    for (schema, table, grantee, _gtype, control, alter, delete, index, insert, ref, select, update) in session.query(
        TABAUTH_SQL + where, params
    ):
        schema, table = str(schema).strip().upper(), str(table).strip().upper()
        writes = [n for n, f in (("CONTROL", control), ("ALTER", alter), ("DELETE", delete), ("INDEX", index),
                                 ("INSERT", insert), ("REFERENCES", ref), ("UPDATE", update)) if _granted(f)]
        if writes:
            raise PrincipalError(f"{grantee.strip()} holds {', '.join(writes)} on {schema}.{table}")
        if _granted(select) and not object_allowed(schema, table, allowed_schemas):
            if str(grantee).strip().upper() == "PUBLIC" and schema.startswith("SYS"):
                continue  # default catalog access granted to PUBLIC; SYS* is denied by the parser and EXPLAIN check
            raise PrincipalError(f"{grantee.strip()} can SELECT {schema}.{table}, outside the allowed schemas")
    return user


def execute_approved(decision: GuardDecision, session: ExecutionSession, audit: AuditSink, ctx: GuardContext,
                     question: str, admin_users: Sequence[str]) -> ExecutionOutcome:
    rid = decision.request_id
    if not decision.approved or not decision.sql:
        return ExecutionOutcome(rid, BLOCKED, "not_approved", "only an APPROVED decision can be executed")
    try:
        audit_ready = audit.ready()
    except Exception:
        audit_ready = False
    if not audit_ready:
        return ExecutionOutcome(rid, BLOCKED, "audit_unavailable", "audit persistence is not available; refusing to execute")
    try:
        verify_restricted_principal(session, admin_users, ctx.allowed_schemas)
    except PrincipalError as exc:
        return ExecutionOutcome(rid, BLOCKED, "principal_not_restricted", str(exc))
    except DbError as exc:
        return ExecutionOutcome(rid, BLOCKED, "principal_unverified", f"cannot verify the execution user: {exc}", sqlstate=exc.sqlstate)

    started = time.monotonic()
    try:
        result = session.execute_capped(decision.sql, ctx.limits.max_rows, ctx.limits.timeout_seconds)
        outcome = ExecutionOutcome(rid, SUCCESS, "ok", "query executed", result.columns, result.rows,
                                   result.truncated, int((time.monotonic() - started) * 1000))
    except DbError as exc:
        elapsed = int((time.monotonic() - started) * 1000)
        if exc.sqlstate == TIMEOUT_SQLSTATE:
            outcome = ExecutionOutcome(rid, ERROR, "timeout", f"query exceeded {ctx.limits.timeout_seconds} s and was cancelled",
                                       execution_ms=elapsed, sqlstate=exc.sqlstate)
        else:
            outcome = ExecutionOutcome(rid, ERROR, "execution_failed", str(exc), execution_ms=elapsed, sqlstate=exc.sqlstate)
    finally:
        try:
            session.rollback()
        except DbError:
            pass  # hygiene only: the restricted user cannot have written anything

    record = make_record(
        request_id=rid, question=question, generated_sql=decision.sql, status=outcome.status,
        reason=None if outcome.status == SUCCESS else outcome.reason, estimated_cost=decision.estimated_cost,
        row_count=len(outcome.rows) if outcome.status == SUCCESS else None, execution_ms=outcome.execution_ms,
        sqlstate=outcome.sqlstate, error_message=outcome.reason if outcome.status == ERROR else None,
    )
    try:
        audit.write(record)
    except Exception as exc:
        reason = str(exc) if isinstance(exc, AuditUnavailable) else type(exc).__name__
        return ExecutionOutcome(rid, ERROR, "audit_failed", f"audit write failed; result withheld ({reason})")
    return outcome
