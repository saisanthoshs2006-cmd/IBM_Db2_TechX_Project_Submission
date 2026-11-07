"""Guard preflight with fake catalog responses. Offline."""
import re
from pathlib import Path

import pytest

from db2intel.guard import context as C
from db2intel.guard import rules
from db2intel.guard.context import PreflightError, load_guard_context, parse_limits
from guard_fakes import no_db_driver  # noqa: F401

SQL_DIR = Path(__file__).resolve().parents[1] / "sql"
SEEDED_LIMITS = [("query.max_rows", "500", "INTEGER"), ("query.max_estimated_cost", "50000", "DECIMAL"),
                 ("query.timeout_seconds", "30", "INTEGER")]


class FakeCatalog:
    def __init__(self, **over):
        self.responses = {
            C.SERVER_SQL: [("TESTDB  ", "DB2INST1")],
            C.STMT_CONC_SQL: [("OFF",)],
            C.EXPLAIN_TABLES_SQL: [(t,) for t in C.EXPLAIN_TABLES] + [("SCHEMA_MIGRATION",)],
            C.LIMITS_SQL: list(SEEDED_LIMITS),
            C.SOURCES_SQL: [("DB2INTEL_DEMO",)],
            "UDF": [],
        }
        self.responses.update(over)
        self.calls = []

    def query(self, sql, params=()):
        self.calls.append((sql, tuple(params)))
        if sql.startswith("SELECT RTRIM(ROUTINESCHEMA)"):
            assert params == tuple(sorted(rules.ALLOWED_FUNCTIONS)) and sql.count("?") == len(params)
            return self.responses["UDF"]
        return self.responses[sql]


def test_happy_path_loads_context():
    db = FakeCatalog()
    ctx = load_guard_context(db, ("TESTDB",))
    assert ctx.database == "TESTDB" and ctx.session_user == "DB2INST1"
    assert ctx.allowed_schemas == frozenset({"DB2INTEL_DEMO"}) and ctx.explain_schema == "DB2INTEL"
    assert (ctx.limits.max_rows, ctx.limits.max_estimated_cost, ctx.limits.timeout_seconds) == (500, 50000.0, 30)
    assert (C.SOURCES_SQL, ("TESTDB",)) in db.calls


def test_preflight_only_reads():
    db = FakeCatalog()
    load_guard_context(db, ("TESTDB",))
    for sql, _ in db.calls:
        assert sql.lstrip().upper().startswith("SELECT ")


@pytest.mark.parametrize("server,allowed", [("SAMPLE", ("SAMPLE", "TESTDB")), ("PRODDB", ("TESTDB",))])
def test_wrong_database_is_refused(server, allowed):
    with pytest.raises(PreflightError, match="may not run against"):
        load_guard_context(FakeCatalog(**{C.SERVER_SQL: [(server, "DB2INST1")]}), allowed)


@pytest.mark.parametrize("rows", [[("ON",)], [("COMMENTS",)], [], [("OFF",), ("ON",)], [("",)]])
def test_statement_concentrator_must_be_off(rows):
    with pytest.raises(PreflightError, match="statement concentrator"):
        load_guard_context(FakeCatalog(**{C.STMT_CONC_SQL: rows}), ("TESTDB",))


def test_statement_concentrator_off_on_every_member_is_accepted():
    load_guard_context(FakeCatalog(**{C.STMT_CONC_SQL: [("OFF",), ("off ",)]}), ("TESTDB",))


def test_missing_explain_tables_are_refused():
    tables = [(t,) for t in C.EXPLAIN_TABLES if t != "EXPLAIN_OBJECT"]
    with pytest.raises(PreflightError, match="EXPLAIN_OBJECT"):
        load_guard_context(FakeCatalog(**{C.EXPLAIN_TABLES_SQL: tables}), ("TESTDB",))


@pytest.mark.parametrize("rows,match", [
    (SEEDED_LIMITS[:2], "query.timeout_seconds is missing"),
    ([("query.max_rows", "0", "INTEGER")] + SEEDED_LIMITS[1:], "outside the allowed range"),
    ([("query.max_rows", "20000", "INTEGER")] + SEEDED_LIMITS[1:], "outside the allowed range"),
    ([("query.max_rows", "12.5", "INTEGER")] + SEEDED_LIMITS[1:], "not a valid INTEGER"),
    ([("query.max_rows", "abc", "INTEGER")] + SEEDED_LIMITS[1:], "not a number"),
    ([("query.max_rows", "NaN", "INTEGER")] + SEEDED_LIMITS[1:], "not a valid"),
    ([("query.max_rows", "500", "STRING")] + SEEDED_LIMITS[1:], "has type STRING"),
    (SEEDED_LIMITS[:1] + [("query.max_estimated_cost", "-1", "DECIMAL")] + SEEDED_LIMITS[2:], "outside"),
    (SEEDED_LIMITS[:2] + [("query.timeout_seconds", "3600", "INTEGER")], "outside"),
    (SEEDED_LIMITS + [("query.max_rows", "10", "INTEGER")], "more than once"),
])
def test_bad_limits_are_refused(rows, match):
    with pytest.raises(PreflightError, match=match):
        parse_limits(rows)


def test_seeded_settings_in_migration_001_pass_the_limit_checks():
    text = (SQL_DIR / "001_schema_meta.sql").read_text()
    rows = re.findall(r"\('(query\.[a-z_]+)',\s*'([^']*)',\s*'([A-Z]+)'", text)
    limits = parse_limits(rows)
    assert (limits.max_rows, limits.max_estimated_cost, limits.timeout_seconds) == (500, 50000.0, 30)


@pytest.mark.parametrize("sources,match", [
    ([], "no enabled READ_ONLY data source"),
    ([("DB2INST1",)], "misconfigured"),
    ([("DB2INTEL",)], "misconfigured"),
    ([("DB2INTEL_DEMO",), ("SYSCAT",)], "misconfigured"),
])
def test_bad_data_sources_are_refused(sources, match):
    with pytest.raises(PreflightError, match=match):
        load_guard_context(FakeCatalog(**{C.SOURCES_SQL: sources}), ("TESTDB",))


def test_data_source_query_only_takes_enabled_read_only_rows_for_this_database():
    assert "IS_ENABLED = 1" in C.SOURCES_SQL and "ACCESS_MODE = 'READ_ONLY'" in C.SOURCES_SQL
    assert "DATABASE_NAME = ?" in C.SOURCES_SQL


def test_user_defined_function_shadowing_a_builtin_is_refused():
    with pytest.raises(PreflightError, match="DB2INST1.ROUND"):
        load_guard_context(FakeCatalog(UDF=[("DB2INST1", "ROUND")]), ("TESTDB",))
