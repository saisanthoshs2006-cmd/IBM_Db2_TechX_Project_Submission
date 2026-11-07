"""Decide whether a query may run, without running it.

Steps, all on one analysis connection that never commits:
  1. static guard (parser.guard_sql): one read-only SELECT over allowed schemas, row cap added
  2. PREPARE only (deferred prepare off): Db2 compiles the statement; nothing is executed
  3. package cache: exactly one entry carrying this request's marker, with exactly the prepared
     text, never executed; its QUERY_COST_ESTIMATE must be within the limit
  4. SYSPROC.EXPLAIN_FROM_SECTION on that entry. Its rows are located through the request
     marker in EXPLAIN_STATEMENT.STATEMENT_TEXT (exactly one original-level row), not through
     the OUT timestamp, which ibm_db does not return (Phase 2B probe, 2026-11-06). Requester,
     source name/schema/version must equal the OUT values, a returned timestamp must equal the
     row's, exactly one EXPLAIN_INSTANCE row must exist, and every statement, object and
     operator row read must belong to that instance and statement.
     The section-level cost must be within the limit and every table and index the plan
     touches must belong to an allowed schema.
  5. the cache entry is checked again (still unique, still never executed)
  6. ROLLBACK on every path, then reads prove the explain rows are gone: EXPLAIN_STATEMENT by
     the request marker; EXPLAIN_INSTANCE, EXPLAIN_OBJECT and EXPLAIN_OPERATOR by the resolved
     explain key, or (if the key was never resolved) by a count of the whole table. Any row left,
     or any failure of these checks, makes the result ERROR cleanup_failed, overriding all others.

A missing, expired, ambiguous or unexpected result at any step is BLOCKED. Only a decision
whose status is APPROVED may be passed to execution.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence

from db2intel.db.connection import DbError
from db2intel.guard import rules
from db2intel.guard.context import GuardContext
from db2intel.guard.lexer import GuardViolation
from db2intel.guard.parser import _schema_denied, guard_sql

APPROVED, BLOCKED, COST_REJECTED, ERROR = "APPROVED", "BLOCKED", "COST_REJECTED", "ERROR"

CACHE_LOOKUP_SQL = (
    "SELECT HEX(EXECUTABLE_ID), QUERY_COST_ESTIMATE, NUM_EXECUTIONS, STMT_TEXT "
    "FROM TABLE(MON_GET_PKG_CACHE_STMT('D', NULL, NULL, -2)) AS T "
    "WHERE STMT_TEXT LIKE ? ESCAPE '!'"
)
_KEY_WHERE = (
    "WHERE EXPLAIN_REQUESTER = ? AND EXPLAIN_TIME = ? AND SOURCE_NAME = ? "
    "AND SOURCE_SCHEMA = ? AND SOURCE_VERSION = ?"
)
# Locate this request's explain rows by its unique marker (original-level statement text).
EXPLAIN_LOCATE_SQL = (
    "SELECT RTRIM(EXPLAIN_REQUESTER), VARCHAR(EXPLAIN_TIME), RTRIM(SOURCE_NAME), RTRIM(SOURCE_SCHEMA), "
    "RTRIM(SOURCE_VERSION), STMTNO, SECTNO FROM DB2INTEL.EXPLAIN_STATEMENT "
    "WHERE EXPLAIN_LEVEL = 'O' AND STATEMENT_TEXT LIKE ? ESCAPE '!'"
)
EXPLAIN_INSTANCE_SQL = f"SELECT COUNT(*) FROM DB2INTEL.EXPLAIN_INSTANCE {_KEY_WHERE}"
EXPLAIN_STATEMENT_SQL = (
    "SELECT EXPLAIN_LEVEL, STMTNO, SECTNO, TOTAL_COST, STATEMENT_TEXT "
    f"FROM DB2INTEL.EXPLAIN_STATEMENT {_KEY_WHERE}"
)
EXPLAIN_OBJECT_SQL = (
    "SELECT RTRIM(OBJECT_SCHEMA), RTRIM(OBJECT_NAME), RTRIM(OBJECT_TYPE), EXPLAIN_LEVEL, STMTNO, SECTNO "
    f"FROM DB2INTEL.EXPLAIN_OBJECT {_KEY_WHERE}"
)
EXPLAIN_OPERATOR_SQL = (
    "SELECT OPERATOR_ID, RTRIM(OPERATOR_TYPE), TOTAL_COST, EXPLAIN_LEVEL, STMTNO, SECTNO "
    f"FROM DB2INTEL.EXPLAIN_OPERATOR {_KEY_WHERE} ORDER BY OPERATOR_ID"
)
# After rollback: no statement row may still carry the marker ...
EXPLAIN_LEFTOVER_SQL = "SELECT COUNT(*) FROM DB2INTEL.EXPLAIN_STATEMENT WHERE STATEMENT_TEXT LIKE ? ESCAPE '!'"
# ... and no instance, object or operator row may remain, checked directly (not via ON DELETE
# CASCADE): by the resolved key, or, when the key is unknown, across the whole table. Nothing
# ever commits explain rows, so any committed row in these tables is a cleanup failure.
LEFTOVER_TABLES = ("EXPLAIN_INSTANCE", "EXPLAIN_OBJECT", "EXPLAIN_OPERATOR")
LEFTOVER_BY_KEY_SQL = {t: f"SELECT COUNT(*) FROM DB2INTEL.{t} {_KEY_WHERE}" for t in LEFTOVER_TABLES}
LEFTOVER_ANY_SQL = {t: f"SELECT COUNT(*) FROM DB2INTEL.{t}" for t in LEFTOVER_TABLES}
INDEX_TABLE_SQL = "SELECT RTRIM(TABSCHEMA), RTRIM(TABNAME) FROM SYSCAT.INDEXES WHERE INDSCHEMA = ? AND INDNAME = ?"

_HEX_ID_RE = re.compile(r"^(?:[0-9A-F]{2}){1,64}$")


@dataclass(frozen=True)
class ExplainKey:
    """Identifies an explain instance. From the driver's OUT parameters `time` may be empty
    (ibm_db returns None for the TIMESTAMP OUT); the resolved key always carries the row's time."""

    explain_schema: str
    requester: str
    time: str
    source_name: str
    source_schema: str
    source_version: str

    def params(self) -> tuple[str, ...]:
        return (self.requester, self.time, self.source_name, self.source_schema, self.source_version)


class AnalysisSession(Protocol):
    """Analysis connection: can prepare and read, never executes user SQL and never commits."""

    def prepare_only(self, sql: str) -> int: ...
    def query(self, sql: str, params: Sequence[Any] = ()) -> list[tuple]: ...
    def explain_from_section(self, executable_id_hex: str, explain_schema: str) -> ExplainKey: ...
    def rollback(self) -> None: ...


@dataclass(frozen=True)
class PlanOperator:
    operator_id: int
    operator_type: str
    total_cost: float


@dataclass(frozen=True)
class GuardDecision:
    request_id: str
    status: str
    code: str
    reason: str
    sql: str | None = None  # the guarded SQL that may be executed (no marker)
    prepared_text: str | None = None  # what was prepared (with marker)
    estimated_cost: float | None = None  # package cache QUERY_COST_ESTIMATE
    explain_cost: float | None = None  # EXPLAIN_STATEMENT section-level TOTAL_COST
    objects: tuple[tuple[str, str, str], ...] = ()
    plan: tuple[PlanOperator, ...] = ()
    sqlstate: str | None = None
    tables: tuple[tuple[str, str], ...] = field(default=())

    @property
    def approved(self) -> bool:
        return self.status == APPROVED


def new_request_id() -> str:
    return str(uuid.uuid4())


def marker_for(request_id: str) -> str:
    return rules.MARKER_PREFIX + uuid.UUID(request_id).hex.upper()


def with_marker(sql: str, marker: str) -> str:
    # The marker is added after parsing (user SQL may not contain comments or markers).
    # Whether Db2 keeps it in STMT_TEXT is verified in Phase 2B; if not, every lookup is BLOCKED.
    return f"/* {marker} */ {sql}"


def like_pattern(marker: str) -> str:
    escaped = marker.replace("!", "!!").replace("%", "!%").replace("_", "!_")
    return f"%{escaped}%"


def object_allowed(schema: str, name: str, allowed: frozenset[str]) -> bool:
    if (schema, name) in rules.READABLE_SYSTEM_OBJECTS:
        return True
    return not _schema_denied(schema) and schema in allowed


class _Stop(Exception):
    def __init__(self, status: str, code: str, reason: str, sqlstate: str | None = None):
        super().__init__(reason)
        self.status, self.code, self.reason, self.sqlstate = status, code, reason, sqlstate


def _number(value, what: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise _Stop(BLOCKED, "cost_unknown", f"{what} is missing or not a number") from None
    if number != number or number < 0 or number == float("inf"):
        raise _Stop(BLOCKED, "cost_unknown", f"{what} is not a valid cost")
    return number


def _cache_entry(session: AnalysisSession, marker: str, prepared: str) -> tuple[str, float]:
    rows = session.query(CACHE_LOOKUP_SQL, (like_pattern(marker),))
    if not rows:
        raise _Stop(BLOCKED, "cache_missing", "the prepared statement is not in the package cache (missing or expired)")
    if len(rows) != 1:
        raise _Stop(BLOCKED, "cache_ambiguous", f"{len(rows)} package cache entries carry this request marker")
    hexid, cost, executions, text = rows[0]
    hexid = str(hexid or "").strip().upper()
    if not _HEX_ID_RE.match(hexid):
        raise _Stop(BLOCKED, "cache_unexpected", "package cache entry has no valid executable id")
    if text != prepared:
        raise _Stop(BLOCKED, "cache_text_mismatch", "package cache text differs from the prepared statement")
    if executions != 0:
        raise _Stop(BLOCKED, "already_executed", "package cache shows the statement was executed")
    return hexid, _number(cost, "package cache cost estimate")


def _check_key(key: ExplainKey, explain_schema: str) -> None:
    """Validate the OUT parameters. The timestamp may be empty; everything else is required."""
    if not isinstance(key, ExplainKey) or str(key.explain_schema).strip() != explain_schema:
        raise _Stop(BLOCKED, "explain_unexpected", "EXPLAIN_FROM_SECTION wrote to an unexpected explain schema")
    if not all(isinstance(v, str) and v.strip() for v in (key.requester, key.source_name, key.source_schema)):
        raise _Stop(BLOCKED, "explain_unexpected", "EXPLAIN_FROM_SECTION did not return its identifying keys")
    if not isinstance(key.source_version, str) or not isinstance(key.time, str):
        raise _Stop(BLOCKED, "explain_unexpected", "EXPLAIN_FROM_SECTION did not return its identifying keys")


def _explain(session: AnalysisSession, hexid: str, ctx: GuardContext) -> ExplainKey:
    try:
        key = session.explain_from_section(hexid, ctx.explain_schema)
    except DbError as exc:
        raise _Stop(BLOCKED, "explain_failed", f"EXPLAIN_FROM_SECTION failed: {exc}", exc.sqlstate) from None
    _check_key(key, ctx.explain_schema)
    return key


def _timestamp_digits(value) -> str | None:
    """'2026-11-06-15.30.00.123456', '2026-11-06 15:30:00.1234' or a datetime -> 26 digits
    (date and time plus a fraction padded to Db2's maximum of 12 digits)."""
    if hasattr(value, "strftime"):
        return value.strftime("%Y%m%d%H%M%S%f").ljust(26, "0")
    digits = re.sub(r"\D", "", str(value or ""))
    if not 14 <= len(digits) <= 26:
        return None
    return digits.ljust(26, "0")


def _locate(session: AnalysisSession, marker: str, out: ExplainKey) -> tuple[ExplainKey, tuple]:
    """Find this request's explain instance through the marker and cross-check it."""
    rows = session.query(EXPLAIN_LOCATE_SQL, (like_pattern(marker),))
    if not rows:
        raise _Stop(BLOCKED, "explain_rows_missing", "no explain statement row carries this request marker")
    if len(rows) != 1:
        raise _Stop(BLOCKED, "explain_ambiguous", f"{len(rows)} explain statement rows carry this request marker")
    requester, etime, source_name, source_schema, source_version, stmtno, sectno = rows[0]
    found = {
        "requester": str(requester or "").strip(), "source name": str(source_name or "").strip(),
        "source schema": str(source_schema or "").strip(), "source version": str(source_version or "").strip(),
    }
    expected = {
        "requester": out.requester.strip(), "source name": out.source_name.strip(),
        "source schema": out.source_schema.strip(), "source version": out.source_version.strip(),
    }
    differ = [name for name in found if found[name] != expected[name]]
    row_time = _timestamp_digits(etime)
    if row_time is None:
        differ.append("explain time (missing in row)")
    elif out.time.strip() and _timestamp_digits(out.time) != row_time:
        differ.append("explain time")
    if differ:
        raise _Stop(BLOCKED, "explain_key_mismatch",
                    f"explain row does not match EXPLAIN_FROM_SECTION output: {', '.join(differ)}")
    key = ExplainKey(out.explain_schema, found["requester"], str(etime).strip(), found["source name"],
                     found["source schema"], found["source version"])
    instances = session.query(EXPLAIN_INSTANCE_SQL, key.params())
    if not instances or instances[0][0] != 1:
        count = instances[0][0] if instances else 0
        raise _Stop(BLOCKED, "explain_instance_mismatch", f"expected exactly one explain instance, found {count}")
    return key, (stmtno, sectno)


def _same_statement(rows, statement_ids: set, what: str) -> None:
    for row in rows:
        level, stmtno, sectno = row[-3:]
        if (str(level).strip(), stmtno, sectno) not in statement_ids:
            raise _Stop(BLOCKED, "explain_instance_mismatch",
                        f"{what} row belongs to statement {(str(level).strip(), stmtno, sectno)}, not to this request")


def _read_plan(session: AnalysisSession, key: ExplainKey, stmt_id: tuple, prepared: str, ctx: GuardContext):
    statements = session.query(EXPLAIN_STATEMENT_SQL, key.params())
    levels = [str(row[0]).strip() for row in statements]
    if sorted(levels) != ["O", "S"]:
        raise _Stop(BLOCKED, "explain_unexpected", f"expected one original and one section explain row, got {levels}")
    if any((row[1], row[2]) != stmt_id for row in statements):
        raise _Stop(BLOCKED, "explain_instance_mismatch", "explain statement rows belong to different statements")
    by_level = {str(row[0]).strip(): (row[3], row[4]) for row in statements}
    if by_level["O"][1] != prepared:
        raise _Stop(BLOCKED, "explain_text_mismatch", "explained statement text differs from the prepared statement")
    explain_cost = _number(by_level["S"][0], "explain total cost")
    statement_ids = {(level, stmt_id[0], stmt_id[1]) for level in levels}

    object_rows = session.query(EXPLAIN_OBJECT_SQL, key.params())
    if not object_rows:
        raise _Stop(BLOCKED, "explain_rows_missing", "the plan lists no objects")
    _same_statement(object_rows, statement_ids, "explain object")
    objects = []
    for schema, name, obj_type, *_ in object_rows:
        schema, name, obj_type = str(schema).strip(), str(name).strip(), str(obj_type).strip()
        if obj_type == "TA":
            if not object_allowed(schema, name, ctx.allowed_schemas):
                raise _Stop(BLOCKED, "forbidden_object", f"the plan reads table {schema}.{name}, which is not allowed")
        elif obj_type == "IX":
            owners = session.query(INDEX_TABLE_SQL, (schema, name))
            if len(owners) != 1:
                raise _Stop(BLOCKED, "forbidden_object", f"cannot resolve the table of index {schema}.{name}")
            tschema, tname = (str(v).strip() for v in owners[0])
            if not object_allowed(tschema, tname, ctx.allowed_schemas):
                raise _Stop(BLOCKED, "forbidden_object", f"the plan uses index {schema}.{name} on {tschema}.{tname}, which is not allowed")
        else:
            raise _Stop(BLOCKED, "forbidden_object", f"the plan uses object {schema}.{name} of unsupported type {obj_type!r}")
        objects.append((schema, name, obj_type))
    if not any(t == "TA" for _, _, t in objects):
        raise _Stop(BLOCKED, "explain_unexpected", "the plan lists no tables")

    operator_rows = session.query(EXPLAIN_OPERATOR_SQL, key.params())
    if not operator_rows:
        raise _Stop(BLOCKED, "explain_rows_missing", "the plan has no operators")
    _same_statement(operator_rows, statement_ids, "explain operator")
    plan = tuple(PlanOperator(int(op_id), str(op_type).strip(), float(cost or 0))
                 for op_id, op_type, cost, *_ in operator_rows)
    return explain_cost, tuple(objects), plan


def analyze(sql: str, session: AnalysisSession, ctx: GuardContext, request_id: str | None = None) -> GuardDecision:
    request_id = request_id or new_request_id()
    try:
        guarded = guard_sql(sql, ctx.allowed_schemas, ctx.limits.max_rows)
    except GuardViolation as exc:
        return GuardDecision(request_id, BLOCKED, exc.code, str(exc))

    marker = marker_for(request_id)
    prepared = with_marker(guarded.text, marker)
    base = dict(sql=guarded.text, prepared_text=prepared, tables=guarded.tables)
    result: dict = {}
    explained = False  # set before the call: a failed call may still have written rows
    key: ExplainKey | None = None  # resolved key, once located
    stop: _Stop | None = None
    try:
        try:
            columns = session.prepare_only(prepared)
        except DbError as exc:
            raise _Stop(ERROR, "prepare_failed", f"Db2 could not prepare the query: {exc}", exc.sqlstate) from None
        if not isinstance(columns, int) or columns < 1:
            raise _Stop(BLOCKED, "no_result_set", "the statement does not describe a result set")

        hexid, cache_cost = _cache_entry(session, marker, prepared)
        result["estimated_cost"] = cache_cost
        if cache_cost > ctx.limits.max_estimated_cost:
            raise _Stop(COST_REJECTED, "cost_too_high",
                        f"estimated cost {cache_cost:,.0f} timerons exceeds the limit {ctx.limits.max_estimated_cost:,.0f}")

        explained = True
        out = _explain(session, hexid, ctx)
        key, stmt_id = _locate(session, marker, out)
        explain_cost, objects, plan = _read_plan(session, key, stmt_id, prepared, ctx)
        result.update(explain_cost=explain_cost, objects=objects, plan=plan)
        if explain_cost > ctx.limits.max_estimated_cost:
            raise _Stop(COST_REJECTED, "cost_too_high",
                        f"explained cost {explain_cost:,.0f} timerons exceeds the limit {ctx.limits.max_estimated_cost:,.0f}")

        hexid_again, _ = _cache_entry(session, marker, prepared)
        if hexid_again != hexid:
            raise _Stop(BLOCKED, "cache_unexpected", "package cache entry changed during analysis")
    except _Stop as exc:
        stop = exc
    except DbError as exc:
        stop = _Stop(ERROR, "db_error", f"Db2 error during analysis: {exc}", exc.sqlstate)
    except Exception as exc:  # malformed driver data or a bug: never approve, never skip cleanup
        stop = _Stop(ERROR, "internal_error", f"unexpected {type(exc).__name__} during analysis")
    finally:
        cleanup_error = _rollback_and_verify(session, marker, explained, key)

    if cleanup_error:
        return GuardDecision(request_id, ERROR, "cleanup_failed", cleanup_error, **base, **result)
    if stop:
        return GuardDecision(request_id, stop.status, stop.code, stop.reason, sqlstate=stop.sqlstate, **base, **result)
    return GuardDecision(request_id, APPROVED, "approved", "all checks passed", **base, **result)


def _leftover_checks(marker: str, key: ExplainKey | None) -> list[tuple[str, str, tuple]]:
    checks = [("EXPLAIN_STATEMENT", EXPLAIN_LEFTOVER_SQL, (like_pattern(marker),))]
    for table in LEFTOVER_TABLES:
        if key is not None:
            checks.append((table, LEFTOVER_BY_KEY_SQL[table], key.params()))
        else:
            checks.append((table, LEFTOVER_ANY_SQL[table], ()))
    return checks


def _rollback_and_verify(session: AnalysisSession, marker: str, explained: bool,
                         key: ExplainKey | None) -> str | None:
    """Roll back (removing explain rows) and, if EXPLAIN was attempted, prove its rows are gone."""
    try:
        session.rollback()
        if explained:
            remaining = []
            for table, sql, params in _leftover_checks(marker, key):
                rows = session.query(sql, params)
                count = rows[0][0] if len(rows) == 1 and len(rows[0]) == 1 else None
                if type(count) is not int or count < 0:  # COUNT(*) is an INTEGER; anything else is unreadable
                    remaining.append(f"{table}=unknown")
                elif count:
                    remaining.append(f"{table}={count}")
            session.rollback()
            if remaining:
                return f"explain rows are still present after rollback: {', '.join(remaining)}"
    except Exception as exc:
        try:
            session.rollback()
        except Exception:
            pass
        return f"rollback after analysis failed: {exc}"
    return None
