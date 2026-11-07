"""Guard limits and the database preflight that loads them. Every check fails closed.

Preflight runs read-only SELECTs on the analysis connection:
  * the connection is to an allowed database (never SAMPLE)
  * the statement concentrator (STMT_CONC) is OFF, so the package cache keeps the exact text
    that was prepared, including the request marker
  * the 11 explain tables exist in DB2INTEL
  * query limits in DB2INTEL.APP_SETTING are present and in range
  * the readable schemas come from enabled READ_ONLY rows in DB2INTEL.DATA_SOURCE
  * no user-defined function shadows an allow-listed built-in function name
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Protocol, Sequence

from db2intel.guard import rules
from db2intel.guard.parser import check_allowed_schemas

EXPLAIN_SCHEMA = "DB2INTEL"
EXPLAIN_TABLES = frozenset({
    "EXPLAIN_INSTANCE", "EXPLAIN_STATEMENT", "EXPLAIN_ARGUMENT", "EXPLAIN_OBJECT", "EXPLAIN_OPERATOR",
    "EXPLAIN_PREDICATE", "EXPLAIN_STREAM", "EXPLAIN_DIAGNOSTIC", "EXPLAIN_DIAGNOSTIC_DATA",
    "OBJECT_METRICS", "EXPLAIN_ACTUALS",
})

LIMIT_RANGES = {
    "query.max_rows": ("INTEGER", 1, 10_000),
    "query.max_estimated_cost": ("DECIMAL", 1, 1_000_000_000),
    "query.timeout_seconds": ("INTEGER", 1, 300),
}

SERVER_SQL = "SELECT CURRENT SERVER, SESSION_USER FROM SYSIBM.SYSDUMMY1"
STMT_CONC_SQL = "SELECT RTRIM(VALUE) FROM SYSIBMADM.DBCFG WHERE NAME = 'stmt_conc'"
EXPLAIN_TABLES_SQL = "SELECT RTRIM(TABNAME) FROM SYSCAT.TABLES WHERE TABSCHEMA = ? AND TYPE = 'T'"
LIMITS_SQL = "SELECT SETTING_KEY, SETTING_VALUE, VALUE_TYPE FROM DB2INTEL.APP_SETTING WHERE SETTING_KEY LIKE 'query.%'"
SOURCES_SQL = (
    "SELECT RTRIM(SCHEMA_NAME) FROM DB2INTEL.DATA_SOURCE "
    "WHERE IS_ENABLED = 1 AND ACCESS_MODE = 'READ_ONLY' AND DATABASE_NAME = ?"
)


def udf_shadow_sql(count: int) -> str:
    marks = ", ".join("?" for _ in range(count))
    return (
        "SELECT RTRIM(ROUTINESCHEMA), RTRIM(ROUTINENAME) FROM SYSCAT.ROUTINES "
        f"WHERE ROUTINETYPE = 'F' AND ROUTINESCHEMA NOT LIKE 'SYS%' AND ROUTINENAME IN ({marks})"
    )


class PreflightError(RuntimeError):
    """The guard cannot prove its preconditions, so it refuses to run."""


class ExplainTablesNotEmpty(PreflightError):
    """Explain rows exist although every check rolls back; someone must inspect them manually."""


class Queryable(Protocol):
    def query(self, sql: str, params: Sequence[Any] = ()) -> list[tuple]: ...


@dataclass(frozen=True)
class GuardLimits:
    max_rows: int
    max_estimated_cost: float
    timeout_seconds: int


@dataclass(frozen=True)
class GuardContext:
    database: str
    session_user: str
    allowed_schemas: frozenset[str]
    limits: GuardLimits
    explain_schema: str = EXPLAIN_SCHEMA


def parse_limits(rows: Sequence[tuple]) -> GuardLimits:
    found: dict[str, tuple[str, str]] = {}
    for key, value, value_type in rows:
        key = str(key).strip()
        if key in found:
            raise PreflightError(f"setting {key} appears more than once")
        found[key] = (str(value).strip(), str(value_type).strip())
    values = {}
    for key, (expected_type, low, high) in LIMIT_RANGES.items():
        if key not in found:
            raise PreflightError(f"required setting {key} is missing from DB2INTEL.APP_SETTING")
        raw, value_type = found[key]
        if value_type != expected_type:
            raise PreflightError(f"setting {key} has type {value_type}, expected {expected_type}")
        try:
            number = Decimal(raw)
        except InvalidOperation:
            raise PreflightError(f"setting {key} is not a number: {raw!r}") from None
        if not number.is_finite() or (expected_type == "INTEGER" and number != number.to_integral_value()):
            raise PreflightError(f"setting {key} is not a valid {expected_type}: {raw!r}")
        if not low <= number <= high:
            raise PreflightError(f"setting {key}={raw} is outside the allowed range {low}..{high}")
        values[key] = number
    return GuardLimits(
        max_rows=int(values["query.max_rows"]),
        max_estimated_cost=float(values["query.max_estimated_cost"]),
        timeout_seconds=int(values["query.timeout_seconds"]),
    )


def load_guard_context(db: Queryable, allowed_databases: Sequence[str]) -> GuardContext:
    rows = db.query(SERVER_SQL)
    if len(rows) != 1:
        raise PreflightError("could not identify the connected database")
    server, user = (str(v).strip().upper() for v in rows[0])
    allowed_dbs = {d.strip().upper() for d in allowed_databases}
    if server == "SAMPLE" or server not in allowed_dbs:
        raise PreflightError(f"the SQL guard may not run against database {server}")

    conc = [str(r[0]).strip().upper() for r in db.query(STMT_CONC_SQL)]
    if not conc or any(v != "OFF" for v in conc):
        raise PreflightError(
            f"statement concentrator must be OFF (stmt_conc = {conc or 'unknown'}); "
            "with it on, cached statement text cannot be matched to the prepared text"
        )

    present = {str(r[0]).strip() for r in db.query(EXPLAIN_TABLES_SQL, (EXPLAIN_SCHEMA,))}
    missing = sorted(EXPLAIN_TABLES - present)
    if missing:
        raise PreflightError(f"explain tables missing in {EXPLAIN_SCHEMA}: {', '.join(missing)} (apply migration 003)")

    limits = parse_limits(db.query(LIMITS_SQL))

    schemas = [str(r[0]).strip().upper() for r in db.query(SOURCES_SQL, (server,))]
    if not schemas:
        raise PreflightError(f"no enabled READ_ONLY data source for database {server}")
    try:
        allowed = check_allowed_schemas(schemas)
    except ValueError as exc:
        raise PreflightError(f"DATA_SOURCE is misconfigured: {exc}") from None

    names = sorted(rules.ALLOWED_FUNCTIONS)
    shadows = db.query(udf_shadow_sql(len(names)), tuple(names))
    if shadows:
        listed = ", ".join(f"{s}.{n}" for s, n in shadows)
        raise PreflightError(f"user-defined functions shadow allow-listed built-ins: {listed}")

    return GuardContext(database=server, session_user=user, allowed_schemas=allowed, limits=limits)


# One fixed read-only statement per explain table (names are constants, never user input).
EXPLAIN_COUNT_SQL = {table: f"SELECT COUNT(*) FROM {EXPLAIN_SCHEMA}.{table}" for table in sorted(EXPLAIN_TABLES)}


def check_explain_tables_empty(db: Queryable) -> None:
    """Refuse to start unless all 11 explain tables are empty. Reads only; never deletes.

    Every guard check rolls back its EXPLAIN_FROM_SECTION rows, so rows that are already there
    were committed by something else, or a check's cleanup failed in a way the latch did not see.
    The guard does not try to clean them up.
    """
    found = []
    for table, sql in EXPLAIN_COUNT_SQL.items():
        rows = db.query(sql)
        if len(rows) != 1 or len(rows[0]) != 1:
            raise PreflightError(f"could not count rows in {EXPLAIN_SCHEMA}.{table}")
        try:
            count = int(rows[0][0])
        except (TypeError, ValueError):
            raise PreflightError(f"could not count rows in {EXPLAIN_SCHEMA}.{table}") from None
        if count != 0:
            found.append(f"{table}={count}")
    if found:
        raise ExplainTablesNotEmpty(
            f"explain tables in {EXPLAIN_SCHEMA} are not empty ({', '.join(found)}); "
            "inspect them manually, nothing is cleaned up automatically"
        )
