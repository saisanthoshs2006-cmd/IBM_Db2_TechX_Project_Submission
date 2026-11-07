"""Phase 2C hardening of existing guard code, with stub drivers only:
statement-timeout read-back, CURRENT PATH pinning, realistic SECTNO values, API settings."""
from __future__ import annotations

import pytest

from db2intel.config import ApiSettings, ConfigError, load_api_settings
from db2intel.db.connection import DbError
from db2intel.guard import analysis as A
from db2intel.guard.sessions import (
    CURRENT_PATH_SQL, SET_SYSTEM_PATH_SQL, Db2AnalysisSession, Db2ExecutionSession,
)
from guard_fakes import CTX, GOOD_SQL, FakeAnalysis, StubConnection, StubDriver, no_db_driver  # noqa: F401


# ---- execute_capped: the statement timeout must be read back -------------------------------------
def test_execute_reads_timeout_back_from_the_statement():
    drv = StubDriver(rows=[(1, 2)])
    Db2ExecutionSession(StubConnection(drv)).execute_capped("SELECT A, B FROM T", 5, 30)
    kinds = [c[0] for c in drv.calls]
    assert kinds.index("get_option") < kinds.index("execute")
    (call,) = [c for c in drv.calls if c[0] == "get_option"]
    assert call == ("get_option", "stmt1", StubDriver.SQL_ATTR_QUERY_TIMEOUT, 0)  # statement, not connection


@pytest.mark.parametrize("readback", [False, None, True, 0, 29, 31, "30", 30.0])
def test_execute_refuses_when_timeout_is_not_confirmed(readback):
    drv = StubDriver(rows=[(1, 2)], timeout_readback=readback)
    with pytest.raises(DbError, match="could not be confirmed"):
        Db2ExecutionSession(StubConnection(drv)).execute_capped("SELECT A, B FROM T", 5, 30)
    assert "execute" not in [c[0] for c in drv.calls] and drv.calls[-1][0] == "free_stmt"


def test_execute_refuses_when_readback_raises():
    drv = StubDriver(fail={"get_option": "not supported"})
    with pytest.raises(DbError):
        Db2ExecutionSession(StubConnection(drv)).execute_capped("SELECT A FROM T", 5, 30)
    assert "execute" not in [c[0] for c in drv.calls]


def test_stub_mirrors_ibm_db_connection_level_readback():
    """ibm_db 3.3.0 cannot read SQL_ATTR_QUERY_TIMEOUT from a connection handle (returns False)."""
    assert StubDriver().get_option("conn", StubDriver.SQL_ATTR_QUERY_TIMEOUT, 1) is False


# ---- CURRENT PATH pinning ---------------------------------------------------------------------
class PathConnection(StubConnection):
    def __init__(self, driver, path_rows):
        super().__init__(driver)
        self.path_rows = path_rows

    def query(self, sql, params=()):
        self.queries.append((sql, params))
        assert sql == CURRENT_PATH_SQL
        return self.path_rows


def test_pin_system_path_uses_prepare_execute_and_reads_back():
    drv = StubDriver()
    conn = PathConnection(drv, [('"SYSIBM","SYSFUN","SYSPROC","SYSIBMADM"',)])
    assert Db2AnalysisSession(conn).pin_system_path() == ("SYSIBM", "SYSFUN", "SYSPROC", "SYSIBMADM")
    assert drv.calls[0] == ("prepare", SET_SYSTEM_PATH_SQL, None) and drv.calls[1][0] == "execute"
    assert drv.calls[2][0] == "free_stmt" and conn.queries == [(CURRENT_PATH_SQL, ())]


@pytest.mark.parametrize("rows", [[('"SYSIBM","DB2INST1"',)], [('"SYSIBM","SYSFUN","EVIL"',)], [], [(None,)],
                                  [("",)], [('"SYSIBM"',), ('"SYSFUN"',)]])
def test_pin_system_path_refuses_anything_but_system_schemas(rows):
    with pytest.raises(DbError):
        Db2AnalysisSession(PathConnection(StubDriver(), rows)).pin_system_path()


def test_pin_system_path_reports_driver_failure():
    drv = StubDriver(fail={"execute": "SQL0104N ... SQLSTATE=42601"})
    with pytest.raises(DbError) as info:
        Db2AnalysisSession(PathConnection(drv, [])).pin_system_path()
    assert info.value.sqlstate == "42601" and drv.calls[-1][0] == "free_stmt"


def test_set_path_sql_is_a_fixed_special_register_statement():
    assert SET_SYSTEM_PATH_SQL == "SET CURRENT PATH = SYSTEM PATH" and "?" not in SET_SYSTEM_PATH_SQL


# ---- realistic SECTNO / STMTNO values (2B run on TESTDB: SECTNO 10, 22, 34, 45) -----------------
@pytest.mark.parametrize("section", [(1, 10), (1, 22), (1, 34), (1, 45), (7, 45)])
def test_analysis_with_real_section_numbers_is_approved(section):
    fake = FakeAnalysis(section=section)
    decision = A.analyze(GOOD_SQL, fake, CTX)
    assert decision.status == A.APPROVED, decision
    assert fake.rollbacks >= 1 and not fake.explain_rows_present


def test_analysis_rejects_rows_from_a_different_section():
    # statement rows say section 22 but dependent object rows belong to section 10
    fake = FakeAnalysis(section=(1, 22), objects=[("DB2INTEL_DEMO", "CUSTOMER", "TA", "S", 1, 10)])
    decision = A.analyze(GOOD_SQL, fake, CTX)
    assert decision.status != A.APPROVED


# ---- API settings ------------------------------------------------------------------------------
def test_api_settings_defaults():
    api, llm = load_api_settings({})
    assert (api.host, api.port, api.pool_size, api.check_deadline_seconds, api.max_rows) == ("127.0.0.1", 8000, 2, 60, 500)
    assert api.token == "" and llm.provider == "none"


def test_api_settings_from_env_and_token_is_not_in_repr():
    api, llm = load_api_settings({"APP_PORT": "9000", "DB2INTEL_API_TOKEN": "x" * 20, "DB2INTEL_GUARD_WORKERS": "3",
                                  "LLM_PROVIDER": "OLLAMA", "LLM_MODEL": "m", "OLLAMA_BASE_URL": "http://127.0.0.1:1/"})
    assert api.port == 9000 and api.pool_size == 3 and "x" * 20 not in repr(api)
    assert llm.provider == "ollama" and llm.base_url == "http://127.0.0.1:1"


def test_planned_llm_provider_does_not_break_settings_loading():
    _, llm = load_api_settings({"LLM_PROVIDER": "openai"})
    with pytest.raises(ConfigError):
        llm.validate()


@pytest.mark.parametrize("env", [
    {"DB2INTEL_API_HOST": "0.0.0.0"}, {"DB2INTEL_API_HOST": "10.0.0.1"}, {"DB2INTEL_API_TOKEN": "short"},
    {"DB2INTEL_GUARD_WORKERS": "0"}, {"DB2INTEL_GUARD_WORKERS": "5"}, {"DB2INTEL_CHECK_DEADLINE_SECONDS": "301"},
    {"DB2INTEL_CHECK_DEADLINE_SECONDS": "1"}, {"APP_PORT": "x"}, {"DB2INTEL_MAX_BODY_BYTES": "10"},
])
def test_api_settings_rejected(env):
    with pytest.raises(ConfigError):
        load_api_settings(env)


def test_loopback_hosts_accepted():
    for host in ("127.0.0.1", "::1", "localhost"):
        ApiSettings(host=host).validate()
