"""Decide whether a query may run, without running it.

Steps, all on one analysis connection that never commits:
  1. static guard (parser.guard_sql): one read-only SELECT over allowed schemas, row cap added
  2. PREPARE only (deferred prepare off): Db2 compiles the statement; nothing is executed
  3. package cache, dynamic statements only (MON_GET_PKG_CACHE_STMT('D', ...)): exactly one
     entry carrying this request's marker, with exactly the prepared text and a valid executable
     id, never executed; its QUERY_COST_ESTIMATE must be within the limit. Its package metadata
     (PACKAGE_SCHEMA, PACKAGE_NAME, PACKAGE_VERSION_ID, SECTION_NUMBER) is accepted in exactly
     two shapes: all four NULL, as Db2 reports for dynamic SQL (seen on Db2 12.1.5 in G2.4), or
     complete (schema and name non-empty, version NULL or text, section a non-negative integer).
     Any partial or malformed shape is BLOCKED. No explain row may carry the marker yet.
  4. SYSPROC.EXPLAIN_FROM_SECTION on that entry, as a prepared CALL whose statement timeout is
     the configured query.timeout_seconds and is read back from the statement handle before it
     runs (G2.3: callproc cannot take a statement timeout, a connection default does not reach
     it, and a prepared CALL returns no OUT values through ibm_db 3.3.0). Its rows are located
     through the request marker in EXPLAIN_STATEMENT.STATEMENT_TEXT: exactly one original-level
     row, whose text must equal the prepared text, whose requester must be the session user,
     whose source schema and name must be non-empty, whose source version must be NULL or text,
     and whose section number and EXPLAIN_TIME must be readable. When the cache entry carried
     package metadata, the row's source schema/name/version and section number must also equal
     it; with all-NULL dynamic metadata, the row's identity rests on the unique marker (absent
     before EXPLAIN), the exact text, the session user and the single row and instance.
     Exactly one EXPLAIN_INSTANCE row must exist for the resolved key, and every statement,
     object and operator row read must belong to that instance and statement.
     The section-level cost must be within the limit and every table and index the plan
     touches must belong to an allowed schema.
  5. the cache entry is checked again: same executable id and the same package metadata
     (all-NULL stays all-NULL), still unique, exact text, never executed
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
    "SELECT HEX(EXECUTABLE_ID), QUERY_COST_ESTIMATE, NUM_EXECUTIONS, STMT_TEXT, "
    "RTRIM(PACKAGE_SCHEMA), RTRIM(PACKAGE_NAME), RTRIM(PACKAGE_VERSION_ID), SECTION_NUMBER "
    "FROM TABLE(MON_GET_PKG_CACHE_STMT('D', NULL, NULL, -2)) AS T "
    "WHERE STMT_TEXT LIKE ? ESCAPE '!'"
)
# The only CALL the guard sends. Run as a prepared statement so it can carry a query timeout.
EXPLAIN_CALL_SQL = "CALL SYSPROC.EXPLAIN_FROM_SECTION(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
QUERY_TIMEOUT_SQLSTATE = "57014"  # SQL0952N: processing was cancelled (query timeout)
_KEY_WHERE = (
    "WHERE EXPLAIN_REQUESTER = ? AND EXPLAIN_TIME = ? AND SOURCE_NAME = ? "
    "AND SOURCE_SCHEMA = ? AND SOURCE_VERSION = ?"
)
# Locate this request's explain rows by its unique marker (original-level statement text).
EXPLAIN_LOCATE_SQL = (
    "SELECT RTRIM(EXPLAIN_REQUESTER), VARCHAR(EXPLAIN_TIME), RTRIM(SOURCE_NAME), RTRIM(SOURCE_SCHEMA), "
    "RTRIM(SOURCE_VERSION), STMTNO, SECTNO, STATEMENT_TEXT FROM DB2INTEL.EXPLAIN_STATEMENT "
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


class ExplainTimeoutUnconfirmed(DbError):
    """The EXPLAIN statement's query timeout could not be set and read back; it is not run."""


@dataclass(frozen=True)
class ExplainKey:
    """Identifies an explain instance (the key columns of every explain table). The guard builds
    it from the marker-located EXPLAIN_STATEMENT row after cross-checking that row."""

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
    def explain_section(self, executable_id_hex: str, explain_schema: str, timeout_seconds: int) -> None: ...
    def rollback(self) -> None: ...


@dataclass(frozen=True)
class CacheEntry:
    """The unique dynamic SQL package-cache entry for a prepared statement.

    Db2 reports package schema/name/version and section number as NULL for dynamic SQL. When
    those fields are present, retain them for cross-checking; otherwise the exact executable ID,
    marker, statement text, requester and EXPLAIN row association provide the identity checks.
    """

    hexid: str
    cost: float
    package_schema: str | None
    package_name: str | None
    package_version: str | None
    section: int | None


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


def _section_number(value) -> int | None:
    """SECTNO / SECTION_NUMBER as a non-negative int, or None if it is not one."""
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    if number < 0 or (not isinstance(value, int) and str(value).strip() != str(number)):
        return None
    return number


def _cache_entry(session: AnalysisSession, marker: str, prepared: str) -> CacheEntry:
    rows = session.query(CACHE_LOOKUP_SQL, (like_pattern(marker),))
    if not rows:
        raise _Stop(BLOCKED, "cache_missing", "the prepared statement is not in the package cache (missing or expired)")
    if len(rows) != 1:
        raise _Stop(BLOCKED, "cache_ambiguous", f"{len(rows)} package cache entries carry this request marker")
    if len(rows[0]) != 8:
        raise _Stop(BLOCKED, "cache_unexpected", "package cache entry has an unexpected shape")
    hexid, cost, executions, text, pkg_schema, pkg_name, pkg_version, section = rows[0]
    hexid = str(hexid or "").strip().upper()
    if not _HEX_ID_RE.match(hexid):
        raise _Stop(BLOCKED, "cache_unexpected", "package cache entry has no valid executable id")
    if text != prepared:
        raise _Stop(BLOCKED, "cache_text_mismatch", "package cache text differs from the prepared statement")
    if executions != 0:
        raise _Stop(BLOCKED, "already_executed", "package cache shows the statement was executed")
    # This function is explicitly restricted to dynamic SQL by MON_GET_PKG_CACHE_STMT('D', ...).
    # Db2 documents PACKAGE_SCHEMA, PACKAGE_NAME, PACKAGE_VERSION_ID and SECTION_NUMBER as NULL
    # for dynamic statements. Accept that all-NULL shape only; reject partial or malformed
    # metadata so a future query change cannot silently broaden this exception.
    metadata = (pkg_schema, pkg_name, pkg_version, section)
    if all(value is None for value in metadata):
        identity = (None, None, None, None)
    else:
        if not (isinstance(pkg_schema, str) and pkg_schema.strip()
                and isinstance(pkg_name, str) and pkg_name.strip()
                and (pkg_version is None or isinstance(pkg_version, str))):
            raise _Stop(BLOCKED, "cache_unexpected", "package cache metadata is partial or malformed")
        section_number = _section_number(section)
        if section_number is None:
            raise _Stop(BLOCKED, "cache_unexpected", "package cache entry has no valid section number")
        identity = (pkg_schema.strip(), pkg_name.strip(),
                    (pkg_version or "").strip(), section_number)
    return CacheEntry(hexid, _number(cost, "package cache cost estimate"), *identity)


def _check_no_marked_rows(session: AnalysisSession, marker: str) -> None:
    """Before EXPLAIN: no explain row may carry this request's marker, so the row found after
    EXPLAIN can only have been written by this request's own EXPLAIN."""
    rows = session.query(EXPLAIN_LEFTOVER_SQL, (like_pattern(marker),))
    count = rows[0][0] if len(rows) == 1 and len(rows[0]) == 1 else None
    if type(count) is not int or count < 0:
        raise _Stop(BLOCKED, "explain_unexpected", "could not confirm that no explain row carries this request marker")
    if count:
        raise _Stop(BLOCKED, "explain_preexisting", f"{count} explain rows already carry this request marker")


def _explain(session: AnalysisSession, entry: CacheEntry, ctx: GuardContext) -> None:
    try:
        session.explain_section(entry.hexid, ctx.explain_schema, ctx.limits.timeout_seconds)
    except ExplainTimeoutUnconfirmed as exc:
        raise _Stop(BLOCKED, "explain_timeout_unconfirmed", f"EXPLAIN_FROM_SECTION not run: {exc}", exc.sqlstate) from None
    except DbError as exc:
        if exc.sqlstate == QUERY_TIMEOUT_SQLSTATE:
            raise _Stop(BLOCKED, "explain_timeout",
                        f"EXPLAIN_FROM_SECTION exceeded the {ctx.limits.timeout_seconds} s query timeout",
                        exc.sqlstate) from None
        raise _Stop(BLOCKED, "explain_failed", f"EXPLAIN_FROM_SECTION failed: {exc}", exc.sqlstate) from None


def _timestamp_digits(value) -> str | None:
    """'2026-11-06-15.30.00.123456', '2026-11-06 15:30:00.1234' or a datetime -> 26 digits
    (date and time plus a fraction padded to Db2's maximum of 12 digits)."""
    if hasattr(value, "strftime"):
        return value.strftime("%Y%m%d%H%M%S%f").ljust(26, "0")
    digits = re.sub(r"\D", "", str(value or ""))
    if not 14 <= len(digits) <= 26:
        return None
    return digits.ljust(26, "0")


def _locate(session: AnalysisSession, marker: str, prepared: str, entry: CacheEntry,
            ctx: GuardContext) -> tuple[ExplainKey, tuple]:
    """Find this request's explain instance through the marker and cross-check it against the
    prepared text, the session user and the package cache entry that was explained."""
    rows = session.query(EXPLAIN_LOCATE_SQL, (like_pattern(marker),))
    if not rows:
        raise _Stop(BLOCKED, "explain_rows_missing", "no explain statement row carries this request marker")
    if len(rows) != 1:
        raise _Stop(BLOCKED, "explain_ambiguous", f"{len(rows)} explain statement rows carry this request marker")
    if len(rows[0]) != 8:
        raise _Stop(BLOCKED, "explain_unexpected", "explain statement row has an unexpected shape")
    requester, etime, source_name, source_schema, source_version, stmtno, sectno, text = rows[0]
    if text != prepared:
        raise _Stop(BLOCKED, "explain_text_mismatch", "the marked explain row's text differs from the prepared statement")
    differ = []
    if not isinstance(requester, str) or requester.strip() != ctx.session_user.strip():
        differ.append("requester")
    if not isinstance(source_name, str) or not source_name.strip():
        differ.append("source name (empty)")
    if not isinstance(source_schema, str) or not source_schema.strip():
        differ.append("source schema (empty)")
    if source_version is not None and not isinstance(source_version, str):
        differ.append("source version (unreadable)")
    if entry.package_schema is not None:
        if not isinstance(source_schema, str) or source_schema.strip() != entry.package_schema:
            differ.append("source schema")
        if not isinstance(source_name, str) or source_name.strip() != entry.package_name:
            differ.append("source name")
        found_version = source_version.strip() if isinstance(source_version, str) else ""
        if found_version != entry.package_version:
            differ.append("source version")
    section_number = _section_number(sectno)
    if section_number is None:
        differ.append("section number")
    elif entry.section is not None and section_number != entry.section:
        differ.append("section number")
    if not (isinstance(requester, str) and requester.strip()):
        differ.append("requester (empty)")
    row_time = _timestamp_digits(etime)
    if row_time is None:
        differ.append("explain time (missing in row)")
    if differ:
        raise _Stop(BLOCKED, "explain_key_mismatch",
                    f"explain row does not match the explained package cache entry: {', '.join(differ)}")
    key = ExplainKey(ctx.explain_schema, requester.strip(), str(etime).strip(), source_name.strip(),
                     source_schema.strip(), "" if source_version is None else source_version.strip())
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

        entry = _cache_entry(session, marker, prepared)
        result["estimated_cost"] = entry.cost
        if entry.cost > ctx.limits.max_estimated_cost:
            raise _Stop(COST_REJECTED, "cost_too_high",
                        f"estimated cost {entry.cost:,.0f} timerons exceeds the limit {ctx.limits.max_estimated_cost:,.0f}")
        _check_no_marked_rows(session, marker)

        explained = True
        _explain(session, entry, ctx)
        key, stmt_id = _locate(session, marker, prepared, entry, ctx)
        explain_cost, objects, plan = _read_plan(session, key, stmt_id, prepared, ctx)
        result.update(explain_cost=explain_cost, objects=objects, plan=plan)
        if explain_cost > ctx.limits.max_estimated_cost:
            raise _Stop(COST_REJECTED, "cost_too_high",
                        f"explained cost {explain_cost:,.0f} timerons exceeds the limit {ctx.limits.max_estimated_cost:,.0f}")

        entry_again = _cache_entry(session, marker, prepared)
        if (entry_again.hexid, entry_again.package_schema, entry_again.package_name, entry_again.package_version,
                entry_again.section) != (entry.hexid, entry.package_schema, entry.package_name,
                                         entry.package_version, entry.section):
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
