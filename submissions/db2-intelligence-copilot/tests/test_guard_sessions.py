"""ibm_db session adapters with stub drivers, the guard CLI, and consistency with the applied DDL.

No real driver, no database: every driver here is a recording stub.
"""
import re
import sys
from pathlib import Path

import pytest

from db2intel.db.connection import DbError
from db2intel.guard import __main__ as cli
from db2intel.guard import analysis as A
from db2intel.guard import context as C
from db2intel.guard import execution as E
from db2intel.guard.audit import AUDIT_STATUSES
from db2intel.guard.sessions import Db2AnalysisSession, Db2ExecutionSession
from db2intel.db.sql_script import load_script
from test_explain_tables import split_top_level
from guard_fakes import CTX, HEXID, FakeAnalysis, StubConnection, StubDriver, no_db_driver  # noqa: F401

SQL_DIR = Path(__file__).resolve().parents[1] / "sql"


# ---- analysis session ----------------------------------------------------------------------
def test_prepare_only_disables_deferred_prepare_and_never_executes():
    drv = StubDriver(num_fields=3)
    s = Db2AnalysisSession(StubConnection(drv))
    assert s.prepare_only("SELECT 1 FROM SYSIBM.SYSDUMMY1") == 3
    assert drv.calls == [("prepare", "SELECT 1 FROM SYSIBM.SYSDUMMY1", {1277: 0})]
    assert not any(c[0] == "execute" for c in drv.calls)


def test_prepare_failure_is_a_dberror_with_sqlstate():
    drv = StubDriver(fail={"prepare": "[IBM][CLI Driver][DB2/LINUXX8664] SQL0204N undefined SQLSTATE=42704"})
    with pytest.raises(DbError) as info:
        Db2AnalysisSession(StubConnection(drv)).prepare_only("SELECT X FROM Y.Z")
    assert info.value.sqlstate == "42704"


def test_prepared_statements_are_held_until_rollback_then_freed():
    drv = StubDriver()
    conn = StubConnection(drv)
    s = Db2AnalysisSession(conn)
    s.prepare_only("SELECT 1 FROM SYSIBM.SYSDUMMY1")
    assert not any(c[0] == "free_stmt" for c in drv.calls)
    s.rollback()
    assert conn.rollbacks == 1 and drv.calls[-1] == ("free_stmt", "stmt1")


def test_statements_are_freed_even_if_rollback_fails():
    drv = StubDriver()
    s = Db2AnalysisSession(StubConnection(drv, rollback_error=DbError("gone")))
    s.prepare_only("SELECT 1 FROM SYSIBM.SYSDUMMY1")
    with pytest.raises(DbError):
        s.rollback()
    assert drv.calls[-1] == ("free_stmt", "stmt1")


# ---- bounded EXPLAIN: prepared CALL with a confirmed statement timeout (production since G2.4) ----
def explain(drv, hexid=HEXID, timeout=30):
    return Db2AnalysisSession(StubConnection(drv)).explain_section(hexid, "DB2INTEL", timeout)


def test_explain_section_prepares_the_call_with_the_timeout_and_reads_it_back_first():
    drv = StubDriver()
    assert explain(drv, HEXID.lower()) is None
    kinds = [c[0] for c in drv.calls]
    assert kinds == ["prepare", "get_option"] + ["bind_param"] * 10 + ["execute", "free_stmt"]
    assert drv.calls[0] == ("prepare", A.EXPLAIN_CALL_SQL, {StubDriver.SQL_ATTR_QUERY_TIMEOUT: 30})
    assert drv.calls[1] == ("get_option", "stmt1", StubDriver.SQL_ATTR_QUERY_TIMEOUT, 0)
    binds = [c[2:] for c in drv.calls if c[0] == "bind_param"]
    assert binds[:5] == [(1, bytes.fromhex(HEXID), 1), (2, "M", 1), (3, None, 1), (4, -1, 1), (5, "DB2INTEL", 2)]
    assert [b[0] for b in binds[5:]] == [6, 7, 8, 9, 10] and all(b[2] == 4 for b in binds[5:])
    assert not any(c[0] == "callproc" for c in drv.calls)


def test_explain_call_sql_is_the_only_call_and_matches_the_procedure_signature():
    assert A.EXPLAIN_CALL_SQL == "CALL SYSPROC.EXPLAIN_FROM_SECTION(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"


@pytest.mark.parametrize("readback", [False, None, 0, 29, 31, True, "30", 30.0])
def test_unconfirmed_timeout_is_refused_and_the_call_never_runs(readback):
    drv = StubDriver(timeout_readback=readback)
    with pytest.raises(A.ExplainTimeoutUnconfirmed):
        explain(drv)
    kinds = [c[0] for c in drv.calls]
    assert kinds == ["prepare", "get_option", "free_stmt"]


def test_boolean_read_back_never_confirms_a_one_second_timeout():
    """True == 1 in Python; a boolean read-back is not a timeout, whatever the requested value."""
    drv = StubDriver(timeout_readback=True)
    with pytest.raises(A.ExplainTimeoutUnconfirmed):
        explain(drv, timeout=1)
    assert [c[0] for c in drv.calls] == ["prepare", "get_option", "free_stmt"]
    assert explain(StubDriver(timeout_readback=1), timeout=1) is None


@pytest.mark.parametrize("timeout", [0, 301, -1, True, "30", 30.0, None])
def test_invalid_timeout_never_reaches_the_driver(timeout):
    drv = StubDriver()
    with pytest.raises(A.ExplainTimeoutUnconfirmed):
        explain(drv, timeout=timeout)
    assert drv.calls == []


def test_driver_without_query_timeout_is_refused():
    class NoTimeout(StubDriver):
        def __getattribute__(self, name):
            if name == "SQL_ATTR_QUERY_TIMEOUT":
                raise AttributeError(name)
            return super().__getattribute__(name)
    drv = NoTimeout()
    with pytest.raises(A.ExplainTimeoutUnconfirmed):
        explain(drv)
    assert drv.calls == []


@pytest.mark.parametrize("hexid", ["", "XYZ", "ABC", "'; DROP TABLE X --"])
def test_invalid_executable_id_never_reaches_the_driver_on_the_bounded_path(hexid):
    drv = StubDriver()
    with pytest.raises(DbError):
        explain(drv, hexid=hexid)
    assert drv.calls == []


@pytest.mark.parametrize("step", ["prepare", "get_option", "bind_param", "execute"])
def test_driver_failure_at_any_step_is_a_dberror_and_the_statement_is_freed(step):
    drv = StubDriver(fail={step: "[IBM][CLI Driver] SQL0952N cancelled  SQLSTATE=57014"})
    with pytest.raises(DbError) as info:
        explain(drv)
    assert info.value.sqlstate == "57014" and not isinstance(info.value, A.ExplainTimeoutUnconfirmed)
    if step != "prepare":
        assert drv.calls[-1] == ("free_stmt", "stmt1")


def test_execute_returning_false_is_an_error():
    class FalseExecute(StubDriver):
        def execute(self, stmt, params=None):
            self.calls.append(("execute", stmt))
            return False
    drv = FalseExecute()
    with pytest.raises(DbError):
        explain(drv)
    assert drv.calls[-1] == ("free_stmt", "stmt1")


def test_explain_from_section_binds_executable_id_and_reads_out_keys():
    out = ("stmt", bytes.fromhex(HEXID), "M", None, -1, "DB2INTEL  ", "DB2INST1", "2026-11-06-15.30.00.000000",
           "SYSSH200", "NULLID", "")
    drv = StubDriver(callproc_result=out)
    key = Db2AnalysisSession(StubConnection(drv)).explain_from_section(HEXID.lower(), "DB2INTEL")
    (_, name, params), free = drv.calls
    assert name == "SYSPROC.EXPLAIN_FROM_SECTION"
    assert params[:5] == (bytes.fromhex(HEXID), "M", None, -1, "DB2INTEL")
    assert free == ("free_stmt", "stmt")
    assert key == A.ExplainKey("DB2INTEL", "DB2INST1", "2026-11-06-15.30.00.000000", "SYSSH200", "NULLID", "")


def test_null_out_timestamp_as_observed_on_db2_12_1_5_becomes_empty():
    """Phase 2B probe: callproc returned None for EXPLAIN_TIME and 'NULLID  ' padded."""
    out = ("stmt", bytes.fromhex(HEXID), "M", None, -1, "DB2INTEL", "DB2INST1", None, "SYSSH200", "NULLID  ", "")
    key = Db2AnalysisSession(StubConnection(StubDriver(callproc_result=out))).explain_from_section(HEXID, "DB2INTEL")
    assert key == A.ExplainKey("DB2INTEL", "DB2INST1", "", "SYSSH200", "NULLID", "")


@pytest.mark.parametrize("hexid", ["", "XYZ", "ABC", "'; DROP TABLE X --"])
def test_invalid_executable_id_never_reaches_the_driver(hexid):
    drv = StubDriver()
    with pytest.raises(DbError):
        Db2AnalysisSession(StubConnection(drv)).explain_from_section(hexid, "DB2INTEL")
    assert drv.calls == []


@pytest.mark.parametrize("result", [None, False, ("stmt",), ("stmt",) * 5])
def test_unexpected_callproc_result_is_an_error(result):
    with pytest.raises(DbError):
        Db2AnalysisSession(StubConnection(StubDriver(callproc_result=result))).explain_from_section(HEXID, "DB2INTEL")


def test_sessions_have_no_commit():
    for cls in (Db2AnalysisSession, Db2ExecutionSession):
        assert not hasattr(cls, "commit")


# ---- execution session ---------------------------------------------------------------------
def test_execute_sets_timeout_and_caps_fetch():
    drv = StubDriver(rows=[(i, i) for i in range(10)])
    res = Db2ExecutionSession(StubConnection(drv)).execute_capped("SELECT A, B FROM T", 3, 30)
    assert drv.calls[0] == ("prepare", "SELECT A, B FROM T", {0: 30})
    assert res.rows == ((0, 0), (1, 1), (2, 2)) and res.truncated and res.columns == ("C0", "C1")
    assert drv.calls[-1][0] == "free_stmt"


def test_execute_without_driver_timeout_support_refuses():
    drv = StubDriver()
    del StubDriver.SQL_ATTR_QUERY_TIMEOUT
    try:
        with pytest.raises(DbError, match="statement timeouts"):
            Db2ExecutionSession(StubConnection(drv)).execute_capped("SELECT 1 FROM SYSIBM.SYSDUMMY1", 5, 30)
    finally:
        StubDriver.SQL_ATTR_QUERY_TIMEOUT = 0
    assert drv.calls == []


def test_execute_timeout_error_keeps_sqlstate_and_frees_statement():
    drv = StubDriver(fail={"execute": "SQL0952N Processing was cancelled due to an interrupt. SQLSTATE=57014"})
    with pytest.raises(DbError) as info:
        Db2ExecutionSession(StubConnection(drv)).execute_capped("SELECT 1 FROM SYSIBM.SYSDUMMY1", 5, 30)
    assert info.value.sqlstate == "57014" and drv.calls[-1][0] == "free_stmt"


@pytest.mark.parametrize("rows,timeout", [(0, 30), (5, 0), (5, 301)])
def test_execute_rejects_invalid_limits(rows, timeout):
    with pytest.raises(DbError):
        Db2ExecutionSession(StubConnection(StubDriver())).execute_capped("SELECT 1 FROM SYSIBM.SYSDUMMY1", rows, timeout)


# ---- CLI -----------------------------------------------------------------------------------
def test_cli_lint_is_offline(capsys):
    assert cli.main(["lint", "select * from db2intel_demo.customer"]) == 0
    out = capsys.readouterr().out
    assert "SELECT * FROM DB2INTEL_DEMO.CUSTOMER FETCH FIRST 500 ROWS ONLY" in out


def test_cli_lint_blocks(capsys):
    assert cli.main(["lint", "SELECT * FROM DB2INST1.EMPLOYEE_INFO"]) == 1
    assert capsys.readouterr().err.startswith("BLOCKED [forbidden_schema]")


def test_cli_lint_reads_stdin(monkeypatch, capsys):
    import io
    monkeypatch.setattr(sys, "stdin", io.StringIO("SELECT 1 FROM SYSIBM.SYSDUMMY1"))
    assert cli.main(["lint", "-", "--max-rows", "5"]) == 0
    assert "FETCH FIRST 5 ROWS ONLY" in capsys.readouterr().out


def test_cli_has_no_execute_command():
    with pytest.raises(SystemExit):
        cli.main(["run", "SELECT 1 FROM SYSIBM.SYSDUMMY1"])


def test_cli_check_uses_preflight_then_analysis_and_closes(monkeypatch, capsys):
    fake = FakeAnalysis()
    closed = []

    class Conn:
        def close(self):
            closed.append(True)

    monkeypatch.setattr(cli, "_open_analysis", lambda: (Conn(), fake, ("TESTDB",)))
    monkeypatch.setattr(C, "load_guard_context", lambda db, dbs: CTX)
    assert cli.main(["check", "SELECT * FROM DB2INTEL_DEMO.CUSTOMER"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("APPROVED") and "reads TA DB2INTEL_DEMO.CUSTOMER" in out and closed == [True]


def test_cli_check_reports_preflight_failure(monkeypatch, capsys):
    class Conn:
        def close(self):
            pass

    def boom(db, dbs):
        raise C.PreflightError("statement concentrator must be OFF")

    monkeypatch.setattr(cli, "_open_analysis", lambda: (Conn(), FakeAnalysis(), ("TESTDB",)))
    monkeypatch.setattr(C, "load_guard_context", boom)
    assert cli.main(["check", "SELECT * FROM DB2INTEL_DEMO.CUSTOMER"]) == 1
    assert "statement concentrator" in capsys.readouterr().err


# ---- consistency with the applied DDL (migrations 001 and 003) -------------------------------
def _columns(script: str, table: str) -> set[str]:
    """Column names of DB2INTEL.<table> as created by the reviewed migration script."""
    for stmt in load_script(SQL_DIR / script).statements:
        canon = " ".join(stmt.split())
        if canon.upper().startswith(f"CREATE TABLE DB2INTEL.{table} ("):
            body = canon[canon.index("(") + 1: canon.rindex(")")]
            return {part.split()[0].upper() for part in split_top_level(body)
                    if not part.upper().startswith(("PRIMARY KEY", "FOREIGN KEY", "CONSTRAINT"))}
    raise AssertionError(f"{table} not created by {script}")


GUARD_COLUMNS = {
    ("003_explain_tables.sql", "EXPLAIN_STATEMENT"): (A.EXPLAIN_STATEMENT_SQL,
        ["EXPLAIN_LEVEL", "STMTNO", "SECTNO", "TOTAL_COST", "STATEMENT_TEXT", "EXPLAIN_REQUESTER", "EXPLAIN_TIME", "SOURCE_NAME", "SOURCE_SCHEMA", "SOURCE_VERSION"]),
    ("003_explain_tables.sql", "EXPLAIN_STATEMENT "): (A.EXPLAIN_LOCATE_SQL,
        ["EXPLAIN_LEVEL", "STMTNO", "SECTNO", "STATEMENT_TEXT", "EXPLAIN_REQUESTER", "EXPLAIN_TIME", "SOURCE_NAME", "SOURCE_SCHEMA", "SOURCE_VERSION"]),
    ("003_explain_tables.sql", "EXPLAIN_INSTANCE"): (A.EXPLAIN_INSTANCE_SQL,
        ["EXPLAIN_REQUESTER", "EXPLAIN_TIME", "SOURCE_NAME", "SOURCE_SCHEMA", "SOURCE_VERSION"]),
    ("003_explain_tables.sql", "EXPLAIN_OBJECT"): (A.EXPLAIN_OBJECT_SQL,
        ["OBJECT_SCHEMA", "OBJECT_NAME", "OBJECT_TYPE", "EXPLAIN_LEVEL", "STMTNO", "SECTNO", "EXPLAIN_REQUESTER", "EXPLAIN_TIME", "SOURCE_NAME", "SOURCE_SCHEMA", "SOURCE_VERSION"]),
    ("003_explain_tables.sql", "EXPLAIN_OPERATOR"): (A.EXPLAIN_OPERATOR_SQL,
        ["OPERATOR_ID", "OPERATOR_TYPE", "TOTAL_COST", "EXPLAIN_LEVEL", "STMTNO", "SECTNO", "EXPLAIN_REQUESTER", "EXPLAIN_TIME", "SOURCE_NAME", "SOURCE_SCHEMA", "SOURCE_VERSION"]),
    **{("003_explain_tables.sql", f"{t}  "): (A.LEFTOVER_BY_KEY_SQL[t],
         ["EXPLAIN_REQUESTER", "EXPLAIN_TIME", "SOURCE_NAME", "SOURCE_SCHEMA", "SOURCE_VERSION"])
       for t in A.LEFTOVER_TABLES},
    **{("003_explain_tables.sql", f"{t}   "): (A.LEFTOVER_ANY_SQL[t], []) for t in A.LEFTOVER_TABLES},
    ("001_schema_meta.sql", "APP_SETTING"): (C.LIMITS_SQL, ["SETTING_KEY", "SETTING_VALUE", "VALUE_TYPE"]),
    ("001_schema_meta.sql", "DATA_SOURCE"): (C.SOURCES_SQL, ["SCHEMA_NAME", "IS_ENABLED", "ACCESS_MODE", "DATABASE_NAME"]),
}


@pytest.mark.parametrize("script,table", list(GUARD_COLUMNS))
def test_guard_sql_uses_columns_that_exist_in_the_applied_ddl(script, table):
    sql, columns = GUARD_COLUMNS[(script, table)]
    table = table.strip()
    ddl_columns = _columns(script, table)
    assert f"DB2INTEL.{table}" in sql
    for col in columns:
        assert re.search(rf"\b{col}\b", sql), f"{col} not used by guard SQL"
        assert col in ddl_columns, f"{col} not a column of {table}"


def test_audit_statuses_match_the_query_audit_check_constraint():
    text = (SQL_DIR / "001_schema_meta.sql").read_text()
    allowed = re.search(r"CK_QUERY_AUDIT_STATUS CHECK \(STATUS IN \(([^)]*)\)\)", text).group(1)
    assert {s.strip(" '") for s in allowed.split(",")} == AUDIT_STATUSES


def test_guard_internal_sql_never_writes():
    internal = [A.CACHE_LOOKUP_SQL, A.EXPLAIN_LOCATE_SQL, A.EXPLAIN_INSTANCE_SQL, A.EXPLAIN_STATEMENT_SQL, A.EXPLAIN_OBJECT_SQL, A.EXPLAIN_OPERATOR_SQL,
                A.EXPLAIN_LEFTOVER_SQL, *A.LEFTOVER_BY_KEY_SQL.values(), *A.LEFTOVER_ANY_SQL.values(), A.INDEX_TABLE_SQL, C.SERVER_SQL, C.STMT_CONC_SQL, C.EXPLAIN_TABLES_SQL,
                C.LIMITS_SQL, C.SOURCES_SQL, C.udf_shadow_sql(3), E.SESSION_USER_SQL, E.AUTHORITIES_SQL,
                E.GROUPS_SQL, E.ROLES_SQL, E.TABAUTH_SQL + "(GRANTEETYPE = ? AND GRANTEE = ?)"]
    for sql in internal:
        assert sql.startswith("SELECT ")
        assert not re.search(r"\b(INSERT|UPDATE|DELETE|MERGE|DROP|CREATE|ALTER|GRANT|REVOKE|CALL|COMMIT)\b", sql), sql
