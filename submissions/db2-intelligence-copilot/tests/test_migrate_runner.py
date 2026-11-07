"""Migration runner behaviour against FakeDb (no real database)."""
import re

import pytest

from db2intel.db.migrate import (
    MIGRATIONS,
    TEARDOWN_CONFIRMATION,
    MigrationError,
    MigrationRunner,
    load_migrations,
)
from db2intel.db.sql_policy import PolicyViolation

from conftest import SQL_DIR, FakeDb


def runner(db, sql_dir=SQL_DIR, **kw):
    return MigrationRunner(db, sql_dir, expected_dim=768, log=lambda _msg: None, **kw)


def checksums():
    return {s.name: s.checksum for s in load_migrations(SQL_DIR, 768)}


# ---- up: fresh install, order, ledger --------------------------------------------
def test_up_applies_001_002_003_each_in_its_own_transaction(fake_db):
    assert runner(fake_db).up() == list(MIGRATIONS)
    assert fake_db.committed["schemas"] == {"DB2INTEL", "DB2INTEL_DEMO"}
    assert fake_db.committed["ledger"] == checksums()
    assert fake_db.commits == 3 and fake_db.rollbacks == 0

    executed = fake_db.executed()
    first_demo = next(i for i, s in enumerate(executed) if s.startswith("CREATE SCHEMA DB2INTEL_DEMO"))
    first_explain = next(i for i, s in enumerate(executed) if s.startswith("CREATE TABLE DB2INTEL.EXPLAIN_INSTANCE"))
    ledger_rows = [i for i, s in enumerate(executed) if s.startswith("INSERT INTO DB2INTEL.SCHEMA_MIGRATION")]
    assert executed[0] == "CREATE SCHEMA DB2INTEL"
    assert len(ledger_rows) == 3
    assert ledger_rows[0] < first_demo < ledger_rows[1] < first_explain < ledger_rows[2]
    assert not any(s.upper().startswith("DROP") for s in executed), "teardown must never run during up"


def test_up_is_idempotent(fake_db):
    runner(fake_db).up()
    before = list(fake_db.executed())
    assert runner(fake_db).up() == []
    assert fake_db.executed() == before  # no statement re-executed


def test_protected_tables_unchanged_after_up(fake_db):
    snapshot = __import__("copy").deepcopy((fake_db.committed["protected"], fake_db.committed["rows"]))
    runner(fake_db).up()
    assert (fake_db.committed["protected"], fake_db.committed["rows"]) == snapshot


# ---- partial failure and rollback -------------------------------------------------
def test_failure_inside_002_rolls_back_002_and_keeps_001(fake_db):
    fake_db.fail_when(r"^INSERT INTO DB2INTEL_DEMO\.SALES_ORDER", "23513")  # e.g. a CHECK violation
    with pytest.raises(MigrationError, match=r"002_demo_data\.sql failed at statement \d+ of 29 SQLSTATE=23513"):
        runner(fake_db).up()
    assert fake_db.committed["schemas"] == {"DB2INTEL"}
    assert set(fake_db.committed["ledger"]) == {"001_schema_meta.sql"}
    assert not any(o.startswith("DB2INTEL_DEMO.") for o in fake_db.committed["objects"])

    assert "003_explain_tables.sql" not in fake_db.committed["ledger"], "003 must not start after 002 failed"
    fake_db.fail_on.clear()  # problem fixed: rerun applies 002, then 003
    assert runner(fake_db).up() == ["002_demo_data.sql", "003_explain_tables.sql"]
    assert fake_db.committed["ledger"] == checksums()


def test_failure_inside_001_leaves_database_untouched(fake_db):
    fake_db.fail_when(r"^CREATE TABLE DB2INTEL\.QUERY_AUDIT", "42601")
    with pytest.raises(MigrationError, match="001_schema_meta.sql failed"):
        runner(fake_db).up()
    assert fake_db.committed["schemas"] == set() and fake_db.committed["objects"] == set()
    assert fake_db.commits == 0 and fake_db.rollbacks == 1
    assert not any("DB2INTEL_DEMO" in s for s in fake_db.executed()), "002 must not start after 001 failed"


def test_ledger_insert_failure_rolls_back_the_script(fake_db):
    fake_db.fail_when(r"^INSERT INTO DB2INTEL\.SCHEMA_MIGRATION", "57011")
    with pytest.raises(MigrationError):
        runner(fake_db).up()
    assert fake_db.committed["schemas"] == set()


@pytest.mark.parametrize("change", ["delete_row", "update_same_count", "new_index", "alter_table"])
def test_any_change_to_db2inst1_during_migration_is_rolled_back(fake_db, change):
    original = __import__("copy").deepcopy(fake_db.committed)

    def tamper(db, sql):
        if not sql.startswith("CREATE TABLE DB2INTEL.QUERY_FEEDBACK"):
            return
        w = db.work
        if change == "delete_row":
            w["rows"]["EMPLOYEE_INFO"].pop()
        elif change == "update_same_count":  # row count unchanged, salary changed
            w["rows"]["EMPLOYEE_SALARY"][0] = (1, "99999.00", "500.00")
        elif change == "new_index":
            w["indexes"].append(("DB2INTEL", "IX_SNEAKY", "EMPLOYEE_INFO", "2026-11-06 00:00:00"))
        elif change == "alter_table":
            w["protected"][0] = ("EMPLOYEE_INFO", "T", "2026-11-06 00:00:00")

    fake_db.on_execute = tamper
    with pytest.raises(MigrationError, match="DB2INST1 objects changed"):
        runner(fake_db).up()
    assert fake_db.committed == original  # nothing committed, DB2INST1 restored by rollback


# ---- refusal conditions (nothing executed) -----------------------------------------
def test_modified_applied_script_stops_the_run(fake_db):
    runner(fake_db).up()
    fake_db.committed["ledger"]["001_schema_meta.sql"] = "0" * 64
    fake_db.work = __import__("copy").deepcopy(fake_db.committed)
    executed = len(fake_db.executed())
    with pytest.raises(MigrationError, match="modified after it was applied"):
        runner(fake_db).up()
    assert len(fake_db.executed()) == executed


def test_existing_schema_without_ledger_is_refused(fake_db):
    fake_db.committed["schemas"].add("DB2INTEL_DEMO")
    fake_db.work = __import__("copy").deepcopy(fake_db.committed)
    with pytest.raises(MigrationError, match="DB2INTEL_DEMO already exists"):
        runner(fake_db).up()
    assert fake_db.executed() == []


def test_unknown_ledger_entry_is_refused(fake_db):
    runner(fake_db).up()
    fake_db.committed["ledger"]["003_mystery.sql"] = "x"
    fake_db.work = __import__("copy").deepcopy(fake_db.committed)
    with pytest.raises(MigrationError, match="unknown migration"):
        runner(fake_db).up()


@pytest.mark.parametrize("server,allowed", [("SAMPLE", ("TESTDB", "SAMPLE")), ("PRODDB", ("TESTDB",))])
def test_target_database_is_enforced(server, allowed):
    db = FakeDb(server=server)
    with pytest.raises(MigrationError, match="refusing to run against"):
        runner(db, allowed_databases=allowed).up()
    assert db.executed() == []


def test_policy_violation_is_detected_before_connecting(sql_copy, fake_db):
    path = sql_copy / "002_demo_data.sql"
    path.write_text(path.read_text() + "\nDELETE FROM DB2INST1.EMPLOYEE_INFO;\n")
    with pytest.raises(PolicyViolation):
        runner(fake_db, sql_copy).up()
    assert fake_db.calls == []


def test_dimension_mismatch_is_detected_before_connecting(fake_db):
    with pytest.raises(PolicyViolation, match="VECTOR dimensions"):
        MigrationRunner(fake_db, SQL_DIR, expected_dim=384, log=lambda _m: None).up()
    assert fake_db.calls == []


# ---- status ---------------------------------------------------------------------------
def test_status_reports_pending_then_applied(fake_db):
    assert [s.state for s in runner(fake_db).status()] == ["pending", "pending", "pending"]
    runner(fake_db).up()
    assert [s.state for s in runner(fake_db).status()] == ["applied", "applied", "applied"]


# ---- teardown ---------------------------------------------------------------------------
def test_teardown_requires_exact_confirmation(fake_db):
    runner(fake_db).up()
    calls = len(fake_db.calls)
    for wrong in ["", "yes", "drop db2intel and db2intel_demo", "DROP DB2INTEL"]:
        with pytest.raises(MigrationError, match="requires --confirm"):
            runner(fake_db).teardown(wrong)
    assert len(fake_db.calls) == calls


def test_teardown_removes_only_project_objects(fake_db):
    runner(fake_db).up()
    protected = __import__("copy").deepcopy((fake_db.committed["protected"], fake_db.committed["rows"]))
    dropped = runner(fake_db).teardown(TEARDOWN_CONFIRMATION)
    assert fake_db.committed["schemas"] == set() and fake_db.committed["objects"] == set()
    assert (fake_db.committed["protected"], fake_db.committed["rows"]) == protected
    assert all(re.match(r"^DROP (TABLE|VIEW|SCHEMA) DB2INTEL(_DEMO)?\b", s) for s in dropped)


def test_teardown_is_repeatable(fake_db):
    runner(fake_db).up()
    runner(fake_db).teardown(TEARDOWN_CONFIRMATION)
    assert runner(fake_db).teardown(TEARDOWN_CONFIRMATION) == []  # everything skipped via 42704


def test_teardown_refuses_to_drop_schema_containing_foreign_objects(fake_db):
    runner(fake_db).up()
    fake_db.committed["objects"].add("DB2INTEL.SOMEONE_ELSES_TABLE")
    fake_db.work = __import__("copy").deepcopy(fake_db.committed)
    with pytest.raises(MigrationError, match="Rolled back; nothing was dropped"):
        runner(fake_db).teardown(TEARDOWN_CONFIRMATION)
    assert "DB2INTEL.SOMEONE_ELSES_TABLE" in fake_db.committed["objects"]
    assert "DB2INTEL_DEMO.ORDER_ITEM" in fake_db.committed["objects"]  # rollback restored everything


def test_tampered_teardown_is_rejected_before_connecting(sql_copy, fake_db):
    path = sql_copy / "900_teardown.sql"
    path.write_text(path.read_text() + "\nDROP TABLE DB2INST1.EMPLOYEE_INFO;\n")
    with pytest.raises(PolicyViolation):
        runner(fake_db, sql_copy).teardown(TEARDOWN_CONFIRMATION)
    assert fake_db.calls == []


def test_teardown_refuses_sample_database():
    db = FakeDb(server="SAMPLE")
    with pytest.raises(MigrationError, match="read-only"):
        runner(db, allowed_databases=("SAMPLE",)).teardown(TEARDOWN_CONFIRMATION)
    assert db.executed() == []


# ---- analyze -----------------------------------------------------------------------------
def test_analyze_only_touches_project_tables(fake_db):
    runner(fake_db).up()
    done = runner(fake_db).analyze()
    assert done and all(t.startswith(("DB2INTEL.", "DB2INTEL_DEMO.")) for t in done)
    calls = [s for s in fake_db.executed() if s.startswith("CALL")]
    assert len(calls) == len(done)


# ---- review fixes: teardown must not affect objects outside the project ----------------
@pytest.mark.parametrize("catalog,dependent", [
    ("SYSCAT.TABDEP", ("DB2INST1.V_EMP_ORDERS", "DB2INTEL_DEMO.SALES_ORDER")),
    ("SYSCAT.TRIGDEP", ("DB2INST1.TRG_AUDIT", "DB2INTEL.QUERY_AUDIT")),
    ("SYSCAT.ROUTINEDEP", ("DB2INST1.SQL261106", "DB2INTEL_DEMO.CUSTOMER")),
    ("SYSCAT.REFERENCES", ("DB2INST1.EMPLOYEE_INFO", "DB2INTEL_DEMO.REGION")),
])
def test_teardown_refuses_when_outside_objects_depend_on_project_objects(fake_db, catalog, dependent):
    runner(fake_db).up()
    fake_db.committed["foreign_deps"] = {catalog: [dependent]}
    fake_db.work = __import__("copy").deepcopy(fake_db.committed)
    executed = len(fake_db.executed())
    with pytest.raises(MigrationError, match="teardown refused.*" + re.escape(dependent[0])):
        runner(fake_db).teardown(TEARDOWN_CONFIRMATION)
    assert len(fake_db.executed()) == executed  # not a single DROP was sent
    assert "DB2INTEL_DEMO.ORDER_ITEM" in fake_db.committed["objects"]


# ---- review fixes: host allow-list and clean error handling in the CLI ------------------
from db2intel.config import load_settings  # noqa: E402
from db2intel.db import connection as connection_module  # noqa: E402
from db2intel.db import migrate as migrate_module  # noqa: E402
from db2intel.db.migrate import check_migration_host  # noqa: E402


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "::1", "LOCALHOST"])
def test_local_hosts_are_allowed(host):
    s = load_settings({"DB2_HOST": host})
    check_migration_host(s.db2, s.migration.allowed_hosts)


@pytest.mark.parametrize("host", ["db2.prod.example.com", "10.0.0.5", "192.168.1.20"])
def test_remote_hosts_are_refused(host):
    s = load_settings({"DB2_HOST": host})
    with pytest.raises(MigrationError, match="refusing to run migrations against host"):
        check_migration_host(s.db2, s.migration.allowed_hosts)


@pytest.mark.parametrize("command", [["status"], ["up"], ["analyze"], ["teardown", "--confirm", TEARDOWN_CONFIRMATION]])
def test_cli_refuses_remote_host_without_connecting(monkeypatch, capsys, command):
    monkeypatch.setattr(migrate_module, "load_settings",
                        lambda: load_settings({"DB2_HOST": "db2.prod.example.com", "DB2_PASSWORD": "x"}))

    def must_not_connect(*_a, **_k):
        raise AssertionError("a connection was attempted")

    monkeypatch.setattr(connection_module, "Db2Connection", must_not_connect)
    assert migrate_module.main(command) == 1
    assert "refusing to run migrations against host" in capsys.readouterr().err


def test_cli_reports_missing_password_cleanly(monkeypatch, capsys):
    monkeypatch.setattr(migrate_module, "load_settings", lambda: load_settings({}))
    assert migrate_module.main(["status"]) == 1
    assert "DB2_PASSWORD is not set" in capsys.readouterr().err


def test_cli_reports_bad_config_cleanly(monkeypatch, capsys):
    monkeypatch.setattr(migrate_module, "load_settings", lambda: load_settings({"DB2_PORT": "fifty"}))
    assert migrate_module.main(["plan"]) == 1
    assert "DB2_PORT must be an integer" in capsys.readouterr().err


def test_plan_never_connects(monkeypatch, capsys):
    def must_not_connect(*_a, **_k):
        raise AssertionError("plan attempted a connection")

    monkeypatch.setattr(connection_module, "Db2Connection", must_not_connect)
    monkeypatch.setattr(migrate_module, "load_settings", lambda: load_settings({}))
    assert migrate_module.main(["plan"]) == 0
    assert "no database contacted" in capsys.readouterr().out


def test_up_help_names_every_migration_in_order(monkeypatch, capsys):
    def must_not_connect(*_a, **_k):
        raise AssertionError("--help attempted a connection")

    monkeypatch.setattr(connection_module, "Db2Connection", must_not_connect)
    with pytest.raises(SystemExit) as exit_info:
        migrate_module.main(["--help"])
    assert exit_info.value.code == 0
    text = " ".join(capsys.readouterr().out.split())  # undo argparse line wrapping
    positions = [text.find(name) for name in MIGRATIONS]
    assert -1 not in positions, text
    assert positions == sorted(positions)
    assert "then 002" not in text


# ---- review fixes: driver errors from commit / rollback become DbError -------------------
class _StubIbmDb:
    SQL_AUTOCOMMIT_OFF = 0

    def __init__(self, fail_commit=False, fail_rollback=False):
        self.fail_commit, self.fail_rollback, self.closed = fail_commit, fail_rollback, False

    def connect(self, *_a):
        return object()

    def autocommit(self, *_a):
        pass

    def commit(self, _c):
        if self.fail_commit:
            raise Exception("[IBM][CLI Driver] SQL30081N communication error SQLSTATE=08001")

    def rollback(self, _c):
        if self.fail_rollback:
            raise Exception("[IBM][CLI Driver] SQL30081N communication error SQLSTATE=08001")

    def close(self, _c):
        self.closed = True

    def conn_errormsg(self):
        return ""


def _stub_connection(monkeypatch, stub):
    monkeypatch.setitem(__import__("sys").modules, "ibm_db", stub)
    return connection_module.Db2Connection(load_settings({"DB2_PASSWORD": "x"}).db2)


def test_commit_failure_is_reported_as_dberror(monkeypatch):
    conn = _stub_connection(monkeypatch, _StubIbmDb(fail_commit=True))
    with pytest.raises(connection_module.DbError) as info:
        conn.commit()
    assert info.value.sqlstate == "08001"


def test_rollback_failure_is_reported_as_dberror(monkeypatch):
    conn = _stub_connection(monkeypatch, _StubIbmDb(fail_rollback=True))
    with pytest.raises(connection_module.DbError):
        conn.rollback()


def test_close_never_raises_on_dead_connection(monkeypatch):
    stub = _StubIbmDb(fail_rollback=True)
    conn = _stub_connection(monkeypatch, stub)
    conn.close()
    assert stub.closed
