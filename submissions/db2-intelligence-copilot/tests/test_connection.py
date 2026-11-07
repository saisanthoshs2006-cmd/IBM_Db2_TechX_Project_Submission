"""Db2Connection error handling with stub drivers. No database is contacted and no SQL runs."""
import sys

import pytest

from db2intel.config import ConfigError, load_settings
from db2intel.db import connection as connection_module
from db2intel.db import migrate as migrate_module
from db2intel.db.connection import Db2Connection, DbError

FAKE_TEST_PASSWORD = "example-fake-test-password-0000"  # fake test value, never a real credential


class ExplodingDriver:
    """Any use of this driver is a test failure: proves configuration errors stop before the driver."""

    def __getattr__(self, name):
        raise AssertionError(f"driver was used: ibm_db.{name}")


class FailingDriver:
    SQL_AUTOCOMMIT_OFF = 0

    def __init__(self, message, errormsg=None, errormsg_raises=False, autocommit_raises=False):
        self.message, self.errormsg, self.errormsg_raises = message, errormsg, errormsg_raises
        self.autocommit_raises, self.connect_calls, self.closed = autocommit_raises, [], False

    def connect(self, conn_str, *_a):
        self.connect_calls.append(conn_str)
        if self.message is not None:
            raise Exception(self.message)
        return object()

    def conn_errormsg(self, *_a):
        if self.errormsg_raises:
            raise RuntimeError("driver has no pending message")
        return self.errormsg if self.errormsg is not None else self.message

    def autocommit(self, *_a):
        if self.autocommit_raises:
            raise Exception("[IBM][CLI Driver] CLI0106E Connection is closed. SQLSTATE=08003")

    def close(self, _c):
        self.closed = True


def install(monkeypatch, driver):
    monkeypatch.setitem(sys.modules, "ibm_db", driver)
    return driver


def settings(**env):
    return load_settings({"DB2_PASSWORD": FAKE_TEST_PASSWORD, **env}).db2


# ---- configuration errors never reach the driver -----------------------------------------
def test_missing_password_is_a_config_error_and_never_touches_the_driver(monkeypatch):
    install(monkeypatch, ExplodingDriver())
    with pytest.raises(ConfigError, match="DB2_PASSWORD is not set"):
        Db2Connection(load_settings({}).db2)


def test_injected_password_is_a_config_error_and_never_touches_the_driver(monkeypatch):
    install(monkeypatch, ExplodingDriver())
    with pytest.raises(ConfigError, match="DB2_PASSWORD contains a character") as info:
        Db2Connection(load_settings({"DB2_PASSWORD": "pw;DATABASE=SAMPLE"}).db2)
    assert "pw;DATABASE" not in str(info.value)


def test_cli_missing_password_reports_config_error_without_driver(monkeypatch, capsys):
    install(monkeypatch, ExplodingDriver())
    monkeypatch.setattr(migrate_module, "load_settings", lambda: load_settings({}))
    assert migrate_module.main(["status"]) == 1
    err = capsys.readouterr().err
    assert err.startswith("error: DB2_PASSWORD is not set") and "Traceback" not in err


# ---- genuine connection failures ---------------------------------------------------------
AUTH_FAIL = ('[IBM][CLI Driver] SQL30082N  Security processing failed with reason "24" '
             '("USERNAME AND/OR PASSWORD INVALID").  SQLSTATE=08001 SQLCODE=-30082')
COMM_FAIL = ('[IBM][CLI Driver] SQL30081N  A communication error has been detected. '
             'Communication protocol being used: "TCP/IP".  SQLSTATE=08001 SQLCODE=-30081')


@pytest.mark.parametrize("raw,hint", [
    (AUTH_FAIL, "check DB2_USER and DB2_PASSWORD"),
    (COMM_FAIL, "check that Db2 is running"),
    ("[IBM][CLI Driver] SQL1013N  The database alias name or database name \"NOPE\" could not be found. "
     "SQLSTATE=42705 SQLCODE=-1013", "check DB2_DATABASE"),
])
def test_connection_failure_is_a_clear_dberror(monkeypatch, raw, hint):
    install(monkeypatch, FailingDriver(raw))
    with pytest.raises(DbError) as info:
        Db2Connection(settings())
    msg = str(info.value)
    assert msg.startswith("cannot connect to database TESTDB at localhost:50000 as user db2inst1: ")
    assert hint in msg and FAKE_TEST_PASSWORD not in msg
    assert info.value.sqlstate == raw.split("SQLSTATE=")[1][:5]


def test_driver_message_echoing_credentials_is_redacted(monkeypatch):
    s = settings()
    leaky = f"[IBM][CLI Driver] connect failed for '{s.connection_string()}' (pwd {FAKE_TEST_PASSWORD}) SQLSTATE=08001"
    install(monkeypatch, FailingDriver(leaky))
    with pytest.raises(DbError) as info:
        Db2Connection(s)
    assert FAKE_TEST_PASSWORD not in str(info.value) and "PWD=" not in str(info.value)
    assert "***" in str(info.value) and info.value.sqlstate == "08001"


def test_failing_errormsg_does_not_hide_the_connection_error(monkeypatch):
    install(monkeypatch, FailingDriver(AUTH_FAIL, errormsg_raises=True))
    with pytest.raises(DbError, match="SQL30082N") as info:
        Db2Connection(settings())
    assert info.value.sqlstate == "08001"


def test_empty_driver_message_still_reports_something(monkeypatch):
    install(monkeypatch, FailingDriver("", errormsg=""))
    with pytest.raises(DbError, match=r"^cannot connect to database TESTDB .*: Exception$"):
        Db2Connection(settings())


def test_autocommit_failure_closes_connection_and_raises(monkeypatch):
    driver = install(monkeypatch, FailingDriver(None, autocommit_raises=True))
    with pytest.raises(DbError, match="could not disable autocommit"):
        Db2Connection(settings())
    assert driver.closed


def test_successful_connect_uses_validated_connection_string(monkeypatch):
    driver = install(monkeypatch, FailingDriver(None))
    Db2Connection(settings())
    assert driver.connect_calls == [settings().connection_string()]


def test_cli_reports_connection_failure_cleanly_without_secrets(monkeypatch, capsys):
    install(monkeypatch, FailingDriver(AUTH_FAIL))
    monkeypatch.setattr(migrate_module, "load_settings", lambda: load_settings({"DB2_PASSWORD": FAKE_TEST_PASSWORD}))
    assert migrate_module.main(["status"]) == 1
    err = capsys.readouterr().err
    assert err.startswith("error: cannot connect to database TESTDB at localhost:50000 as user db2inst1")
    assert "check DB2_USER and DB2_PASSWORD" in err and FAKE_TEST_PASSWORD not in err and "Traceback" not in err


def test_module_has_no_import_time_driver_dependency():
    assert "ibm_db" not in vars(connection_module)
