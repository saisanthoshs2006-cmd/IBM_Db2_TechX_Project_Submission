"""Offline tests of the G2 integration tooling (gate G2.0). No Db2, no real ibm_db.

Covers the SQL allow-list, the guarded driver, the snapshot, the supervisor (with fake child
scripts) and IT1/IT2 run end to end against it_fakes.FakeIbmDb.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
import time
import uuid
from pathlib import Path

import pytest

import it_fakes as F
from db2intel import config as config_module
from db2intel.db.connection import Db2Connection, DbError
from db2intel.guard import analysis as A
from integration import it_driver as D
from integration import it_harness as H
from integration import it_sql as Q
from integration import snapshot as S
from integration import supervisor as V

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FAKE_ENV = {"DB2_HOST": "localhost", "DB2_PORT": "50000", "DB2_DATABASE": "TESTDB", "DB2_USER": "db2inst1",
            "DB2_PASSWORD": "example-fake-value-0123"}
T = 30  # query timeout used throughout


def marked(sql=Q.PK_LOOKUP):
    return A.with_marker(sql, A.marker_for(str(uuid.uuid4())))


@pytest.fixture
def fake_settings(monkeypatch):
    real = config_module.load_settings
    monkeypatch.setattr(config_module, "load_settings", lambda env=None: real(FAKE_ENV))


@pytest.fixture
def ibm_db_slot(monkeypatch):
    """Whatever sys.modules['ibm_db'] holds is restored after the test."""
    monkeypatch.setitem(sys.modules, "ibm_db", sys.modules.get("ibm_db"))
    if sys.modules["ibm_db"] is None:
        monkeypatch.delitem(sys.modules, "ibm_db")


@pytest.fixture
def fake_driver(monkeypatch, ibm_db_slot, fake_settings):
    """Routes it_driver.install to a GuardedDriver around a FakeIbmDb. Returns a factory."""
    made = {}
    original = D.install

    def make(**knobs):
        fake = F.FakeIbmDb(**knobs)
        made["fake"] = fake
        monkeypatch.setattr(D, "install", lambda timeout_s, real=None: original(timeout_s, real=fake))
        return fake

    return make


def good_snapshot(**changes):
    snap = {
        "server": ["TESTDB", "DB2INST1"],
        "explain": {t: 0 for t in Q.EXPLAIN_TABLE_NAMES},
        "audit_rows": 0,
        "ledger": [[str(v) for v in row] for row in F.LEDGER],
        "protected": {"EMPLOYEE_INFO": [3, "c6e96adb4bcfc5d5" + "0" * 48],
                      "EMPLOYEE_SALARY": [3, "9f9edd2017255f98" + "0" * 48]},
    }
    snap.update(changes)
    return snap


# ==== it_sql: the allow-list ======================================================================
def test_every_select_is_a_plain_read_only_select():
    for label, sql in Q.SELECT_SQL.items():
        assert Q.is_plain_select(sql), label


def test_the_only_executable_statement_that_is_not_a_select_is_the_explain_call():
    assert {s for s in Q.EXECUTABLE_SQL if not Q.is_plain_select(s)} == {Q.CALL_EXPLAIN_SQL}
    assert Q.CALL_EXPLAIN_SQL == "CALL SYSPROC.EXPLAIN_FROM_SECTION(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"


def test_prepare_only_statements_are_not_executable():
    assert not Q.PREPARE_ONLY_SQL & Q.EXECUTABLE_SQL
    assert not any(Q.MARKED_PK_LOOKUP_RE.match(s) for s in Q.EXECUTABLE_SQL)


def test_the_eleven_explain_tables_match_the_guard_and_migration_003():
    from db2intel.guard import context as C
    assert len(Q.EXPLAIN_TABLE_NAMES) == 11
    assert Q.EXPLAIN_COUNT_SQL == C.EXPLAIN_COUNT_SQL


def test_protected_tables_are_only_read_with_select_star():
    touching = {s for s in Q.EXECUTABLE_SQL | Q.PREPARE_ONLY_SQL if "DB2INST1" in s}
    assert touching == {"SELECT * FROM DB2INST1.EMPLOYEE_INFO", "SELECT * FROM DB2INST1.EMPLOYEE_SALARY"}


def test_it2_selects_are_the_production_guard_statements():
    assert set(Q.IT2_SELECTS.values()) == {A.CACHE_LOOKUP_SQL, A.EXPLAIN_LOCATE_SQL, A.EXPLAIN_INSTANCE_SQL,
                                           A.EXPLAIN_STATEMENT_SQL, A.EXPLAIN_OBJECT_SQL, A.EXPLAIN_OPERATOR_SQL,
                                           A.EXPLAIN_LEFTOVER_SQL}


def test_listing_names_every_statement():
    listed = {sql for _, _, sql in Q.listing()}
    assert Q.EXECUTABLE_SQL <= listed and Q.PREPARE_ONLY_SQL <= listed
    kinds = {kind for kind, _, _ in Q.listing()}
    assert kinds == {"SELECT", "PREPARE", "CALL", "ATTR"}


@pytest.mark.parametrize("sql", [
    marked(),
])
def test_marked_pk_lookup_pattern_accepts_the_guard_marker(sql):
    assert Q.MARKED_PK_LOOKUP_RE.match(sql)


@pytest.mark.parametrize("sql", [
    Q.PK_LOOKUP,
    marked().replace("*/ SELECT", "*/  SELECT"),
    marked() + " ",
    marked() + "\n",
    marked() + "; DELETE FROM DB2INST1.EMPLOYEE_SALARY",
    marked("SELECT * FROM DB2INST1.EMPLOYEE_SALARY"),
    marked("SELECT C.COMPANY_NAME FROM DB2INTEL_DEMO.CUSTOMER C WHERE C.CUSTOMER_ID = 43"),
    "/* DB2INTEL_REQ_" + "a" * 32 + " */ " + Q.PK_LOOKUP,
    "/* DB2INTEL_REQ_" + "A" * 31 + " */ " + Q.PK_LOOKUP,
])
def test_marked_pk_lookup_pattern_rejects_anything_else(sql):
    assert not Q.MARKED_PK_LOOKUP_RE.match(sql)


def test_tooling_modules_never_import_ibm_db():
    code = ("import sys; import integration.it_sql, integration.snapshot, integration.supervisor, "
            "integration.it_harness, integration.it_driver; "
            "print('ibm_db' in sys.modules)")
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(PROJECT_ROOT / "src"), str(PROJECT_ROOT / "tests")])}
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, cwd=PROJECT_ROOT, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "False"


def test_sql_listing_runs_as_a_module():
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(PROJECT_ROOT / "src"), str(PROJECT_ROOT / "tests")])}
    out = subprocess.run([sys.executable, "-m", "integration.it_sql"], capture_output=True, text=True, env=env,
                         cwd=PROJECT_ROOT, timeout=60)
    assert out.returncode == 0 and Q.CALL_EXPLAIN_SQL in out.stdout and "MON_GET_PKG_CACHE_STMT" in out.stdout


# ==== guarded driver ============================================================================
def guarded(**knobs):
    fake = F.FakeIbmDb(**knobs)
    return D.GuardedDriver(fake, T), fake, F.FakeConn()


def real_calls(fake, name):
    return [c for c in fake.calls if c[0] == name]


def test_driver_needs_a_query_timeout_attribute_and_a_valid_timeout():
    class NoTimeout:
        pass
    with pytest.raises(D.DriverRefused):
        D.GuardedDriver(NoTimeout(), T)
    for bad in (0, 121, -1, 30.0, "30", True):
        with pytest.raises(D.DriverRefused):
            D.GuardedDriver(F.FakeIbmDb(), bad)


def test_prepare_of_an_allowed_select_adds_and_verifies_the_timeout():
    drv, fake, conn = guarded()
    stmt = drv.prepare(conn, Q.AUDIT_COUNT_SQL)
    assert stmt.options == {fake.SQL_ATTR_QUERY_TIMEOUT: T}
    assert drv.log == [("prepare", Q.AUDIT_COUNT_SQL)]


def test_prepare_keeps_caller_options_and_overrides_any_caller_timeout():
    drv, fake, conn = guarded()
    stmt = drv.prepare(conn, marked(), {fake.SQL_ATTR_DEFERRED_PREPARE: 0, fake.SQL_ATTR_QUERY_TIMEOUT: 999})
    assert stmt.options == {fake.SQL_ATTR_DEFERRED_PREPARE: 0, fake.SQL_ATTR_QUERY_TIMEOUT: T}


@pytest.mark.parametrize("read_back", [False, 0, 29, 31, True, "30"])
def test_prepare_is_refused_and_freed_when_the_timeout_does_not_read_back(read_back):
    drv, fake, conn = guarded(statement_read_back=read_back)
    freed = []
    fake.free_stmt = lambda stmt: freed.append(stmt) or True
    with pytest.raises(D.DriverRefused, match="reads back"):
        drv.prepare(conn, Q.AUDIT_COUNT_SQL)
    assert len(freed) == 1 and drv.log == []


@pytest.mark.parametrize("sql", [
    "DELETE FROM DB2INST1.EMPLOYEE_SALARY",
    "SELECT 2 FROM SYSIBM.SYSDUMMY1",
    "select count(*) from DB2INTEL.QUERY_AUDIT",
    Q.AUDIT_COUNT_SQL + " ",
    Q.AUDIT_COUNT_SQL + "; COMMIT",
    "CALL SYSPROC.EXPLAIN_FROM_SECTION(?, ?, ?, ?, ?, ?, ?, ?, ?)",
    "CALL SYSPROC.ADMIN_CMD(?)",
    "SET CURRENT PATH = SYSTEM PATH",
    marked("SELECT * FROM DB2INST1.EMPLOYEE_SALARY"),
    None,
    b"SELECT 1 FROM SYSIBM.SYSDUMMY1",
])
def test_prepare_refuses_anything_off_the_allow_list_before_the_driver_sees_it(sql):
    drv, fake, conn = guarded()
    with pytest.raises(D.DriverRefused, match="allow-list"):
        drv.prepare(conn, sql)
    assert real_calls(fake, "prepare") == []


def test_allowed_selects_and_the_call_execute():
    drv, fake, conn = guarded()
    stmt = drv.prepare(conn, Q.SERVER_SQL)
    assert drv.execute(stmt) is True
    assert real_calls(fake, "execute") == [("execute", Q.SERVER_SQL, ())]


@pytest.mark.parametrize("sql", [Q.IT1_PROBE_SQL, "marked"])
def test_prepare_only_statements_can_never_execute(sql):
    drv, fake, conn = guarded()
    stmt = drv.prepare(conn, marked() if sql == "marked" else sql)
    with pytest.raises(D.DriverRefused, match="execute refused"):
        drv.execute(stmt)
    assert real_calls(fake, "execute") == []


def test_execute_refuses_statements_it_did_not_prepare_or_already_freed():
    drv, fake, conn = guarded()
    foreign = fake.prepare(conn, Q.SERVER_SQL)
    with pytest.raises(D.DriverRefused):
        drv.execute(foreign)
    stmt = drv.prepare(conn, Q.SERVER_SQL)
    drv.free_stmt(stmt)
    with pytest.raises(D.DriverRefused):
        drv.execute(stmt)
    assert real_calls(fake, "execute") == []


@pytest.mark.parametrize("call", [
    lambda d, c: d.commit(c),
    lambda d, c: d.exec_immediate(c, "SELECT 1 FROM SYSIBM.SYSDUMMY1"),
    lambda d, c: d.autocommit(c, d.SQL_AUTOCOMMIT_ON),
    lambda d, c: d.autocommit(c),
    lambda d, c: d.pconnect("x", "", ""),
    lambda d, c: d.execute_many(None, ()),
    lambda d, c: d.next_result(None),
])
def test_writes_and_unknown_driver_functions_are_refused(call):
    drv, fake, conn = guarded()
    with pytest.raises(D.DriverRefused):
        call(drv, conn)
    assert [c[0] for c in fake.calls] == []


def test_autocommit_off_and_harmless_functions_pass_through():
    drv, fake, conn = guarded()
    drv.autocommit(conn, drv.SQL_AUTOCOMMIT_OFF)
    drv.rollback(conn)
    drv.close(conn)
    assert [c[0] for c in fake.calls] == ["autocommit", "rollback", "close"]
    assert drv.SQL_PARAM_OUTPUT == fake.SQL_PARAM_OUTPUT


@pytest.mark.parametrize("options", [
    {1277: 0}, {0: 30, 1277: 0}, {0: 0}, {0: 121}, {0: "30"}, {0: True}, {0: 30.5}, [], None,
])
def test_set_option_only_accepts_a_query_timeout(options):
    drv, fake, conn = guarded()
    with pytest.raises(D.DriverRefused):
        drv.set_option(conn, options, 1)
    assert real_calls(fake, "set_option") == []


def test_set_option_with_a_query_timeout_passes():
    drv, fake, conn = guarded()
    assert drv.set_option(conn, {fake.SQL_ATTR_QUERY_TIMEOUT: 37}, 1) is True
    assert conn.default_timeout == 37


def test_prepare_without_timeout_is_only_for_the_it1_probe_and_cannot_execute():
    drv, fake, conn = guarded()
    for sql in (Q.SERVER_SQL, Q.CALL_EXPLAIN_SQL, marked()):
        with pytest.raises(D.DriverRefused):
            drv.prepare_without_timeout(conn, sql)
    stmt = drv.prepare_without_timeout(conn, Q.IT1_PROBE_SQL)
    assert stmt.options == {}
    with pytest.raises(D.DriverRefused):
        drv.execute(stmt)


def explain_call(drv, fake, conn, inputs=None, types=None):
    stmt = drv.prepare(conn, Q.CALL_EXPLAIN_SQL)
    inputs = inputs or (b"\x01" * 32, "M", None, -1, "DB2INTEL")
    types = types or [fake.SQL_PARAM_INPUT] * 4 + [fake.SQL_PARAM_INPUT_OUTPUT] + [fake.SQL_PARAM_OUTPUT] * 5
    for n, value in enumerate(inputs + ("",) * 5, 1):
        drv.bind_param(stmt, n, value, types[n - 1])
    return stmt


def test_prepared_explain_call_runs_with_valid_inputs():
    drv, fake, conn = guarded()
    fake.state.cache.append(["01" * 32, 1.0, 0, marked()])
    stmt = explain_call(drv, fake, conn)
    assert drv.execute(stmt) is True and len(fake.state.pending) == 1


@pytest.mark.parametrize("inputs", [
    (b"\x01" * 32, "P", None, -1, "DB2INTEL"),
    (b"\x01" * 32, "M", "X", -1, "DB2INTEL"),
    (b"\x01" * 32, "M", None, 0, "DB2INTEL"),
    (b"\x01" * 32, "M", None, -1, "SYSTOOLS"),
    ("01" * 32, "M", None, -1, "DB2INTEL"),
    (b"", "M", None, -1, "DB2INTEL"),
    (b"\x01" * 65, "M", None, -1, "DB2INTEL"),
])
def test_prepared_explain_call_refuses_other_inputs(inputs):
    drv, fake, conn = guarded()
    stmt = explain_call(drv, fake, conn, inputs=inputs)
    with pytest.raises(D.DriverRefused):
        drv.execute(stmt)
    assert real_calls(fake, "execute") == []


def test_prepared_explain_call_refuses_missing_bindings_or_a_params_tuple():
    drv, fake, conn = guarded()
    stmt = drv.prepare(conn, Q.CALL_EXPLAIN_SQL)
    for n, value in enumerate((b"\x01" * 32, "M", None, -1), 1):
        drv.bind_param(stmt, n, value, fake.SQL_PARAM_INPUT)
    with pytest.raises(D.DriverRefused):
        drv.execute(stmt)
    full = explain_call(drv, fake, conn)
    with pytest.raises(D.DriverRefused):
        drv.execute(full, (b"\x01" * 32, "M", None, -1, "DB2INTEL"))
    assert real_calls(fake, "execute") == []


def test_bind_param_rules():
    drv, fake, conn = guarded()
    select = drv.prepare(conn, Q.SERVER_SQL)
    with pytest.raises(D.DriverRefused):
        drv.bind_param(select, 1, "x", fake.SQL_PARAM_INPUT)
    call = drv.prepare(conn, Q.CALL_EXPLAIN_SQL)
    for n, ptype in ((0, fake.SQL_PARAM_INPUT), (11, fake.SQL_PARAM_OUTPUT), (1, fake.SQL_PARAM_OUTPUT),
                     (4, fake.SQL_PARAM_INPUT_OUTPUT), (5, fake.SQL_PARAM_OUTPUT), (6, fake.SQL_PARAM_INPUT),
                     (10, None)):
        with pytest.raises(D.DriverRefused):
            drv.bind_param(call, n, "x", ptype)
    assert real_calls(fake, "bind_param") == []


def test_callproc_only_explain_from_section_with_the_approved_inputs():
    drv, fake, conn = guarded()
    fake.state.cache.append(["01" * 32, 1.0, 0, marked()])
    ok = (b"\x01" * 32, "M", None, -1, "DB2INTEL", "", "", "", "", "")
    for name, params in (("SYSPROC.ADMIN_CMD", ok), ("SYSPROC.EXPLAIN_FROM_SECTION", ok[:9]),
                         ("SYSPROC.EXPLAIN_FROM_SECTION", list(ok)),
                         ("SYSPROC.EXPLAIN_FROM_SECTION", (b"\x01" * 32, "M", None, -1, "OTHER") + ok[5:])):
        with pytest.raises(D.DriverRefused):
            drv.callproc(conn, name, params)
    assert real_calls(fake, "callproc") == []
    assert drv.callproc(conn, Q.EXPLAIN_PROC, ok)[6] == "DB2INST1"


def test_install_replaces_ibm_db_once(ibm_db_slot):
    fake = F.FakeIbmDb()
    drv = D.install(T, real=fake)
    assert sys.modules["ibm_db"] is drv
    with pytest.raises(D.DriverRefused, match="already installed"):
        D.install(T, real=fake)


def test_db2connection_through_the_guarded_driver_cannot_write(ibm_db_slot):
    fake = F.FakeIbmDb()
    D.install(T, real=fake)
    conn = Db2Connection(config_module.load_settings(FAKE_ENV).db2)
    assert conn.query(Q.SERVER_SQL) == [("TESTDB", "DB2INST1")]
    with pytest.raises(DbError):
        conn.execute("DELETE FROM DB2INST1.EMPLOYEE_SALARY")
    with pytest.raises(DbError):
        conn.execute("SELECT 1 FROM SYSIBM.SYSDUMMY1")  # no params -> exec_immediate -> refused
    with pytest.raises(DbError):
        conn.commit()
    with pytest.raises(DbError):
        conn.query("SELECT * FROM DB2INST1.EMPLOYEE_SALARY WHERE 1 = 1")
    conn.close()
    assert not real_calls(fake, "commit") and not real_calls(fake, "exec_immediate")
    assert [c[1] for c in real_calls(fake, "prepare")] == [Q.SERVER_SQL]


# ==== snapshot ==================================================================================
class SnapConn:
    def __init__(self, fake):
        self.fake, self.handle, self.rollbacks = fake, F.FakeConn(), 0

    def query(self, sql, params=()):
        stmt = self.fake.prepare(self.handle, sql)
        self.fake.execute(stmt, params)
        return list(stmt.rows)

    def rollback(self):
        self.rollbacks += 1


def test_take_snapshot_collects_every_part_and_rolls_back():
    conn = SnapConn(F.FakeIbmDb())
    snap = S.take_snapshot(conn)
    assert set(snap) == set(S.PARTS) and conn.rollbacks == 1
    assert snap["server"] == ["TESTDB", "DB2INST1"]
    assert snap["explain"] == {t: 0 for t in Q.EXPLAIN_TABLE_NAMES}
    assert snap["protected"]["EMPLOYEE_INFO"][0] == 3 and len(snap["protected"]["EMPLOYEE_INFO"][1]) == 64
    assert S.snapshot_problems(json.loads(json.dumps(snap))) == []


def test_take_snapshot_rolls_back_even_when_a_query_fails():
    conn = SnapConn(F.FakeIbmDb())
    conn.query = lambda sql, params=(): (_ for _ in ()).throw(DbError("boom"))
    with pytest.raises(DbError):
        S.take_snapshot(conn)
    assert conn.rollbacks == 1


def test_fingerprint_is_the_migration_runner_method():
    rows = [(2, "b"), (1, "a")]
    import hashlib
    expected = hashlib.sha256("\n".join(sorted(repr(tuple(r)) for r in rows)).encode()).hexdigest()
    assert S.fingerprint(rows) == [2, expected]
    assert S.fingerprint(list(reversed(rows))) == S.fingerprint(rows)


def test_baseline_accepts_the_recorded_state():
    assert S.baseline_problems(good_snapshot()) == []


@pytest.mark.parametrize("change, problem", [
    ({"server": ["SAMPLE", "DB2INST1"]}, "expected TESTDB"),
    ({"explain": {**{t: 0 for t in Q.EXPLAIN_TABLE_NAMES}, "EXPLAIN_STREAM": 1}}, "not empty"),
    ({"audit_rows": 1}, "QUERY_AUDIT"),
    ({"ledger": [[str(v) for v in r] for r in F.LEDGER[:2]]}, "ledger"),
    ({"protected": {"EMPLOYEE_INFO": [3, "f" * 64], "EMPLOYEE_SALARY": [3, "9f9edd2017255f98" + "0" * 48]}},
     "EMPLOYEE_INFO fingerprint"),
    ({"protected": {"EMPLOYEE_INFO": [4, "c6e96adb4bcfc5d5" + "0" * 48],
                    "EMPLOYEE_SALARY": [3, "9f9edd2017255f98" + "0" * 48]}}, "EMPLOYEE_INFO fingerprint"),
])
def test_baseline_rejects_any_deviation(change, problem):
    problems = S.baseline_problems(good_snapshot(**change))
    assert problems and problem in " ".join(problems)


@pytest.mark.parametrize("snap", [
    None, [], {}, {**good_snapshot(), "extra": 1},
    good_snapshot(server=["TESTDB"]), good_snapshot(server=None),
    good_snapshot(explain={t: 0 for t in Q.EXPLAIN_TABLE_NAMES[:10]}),
    good_snapshot(explain={t: -1 for t in Q.EXPLAIN_TABLE_NAMES}),
    good_snapshot(explain={t: "0" for t in Q.EXPLAIN_TABLE_NAMES}),
    good_snapshot(explain={t: True for t in Q.EXPLAIN_TABLE_NAMES}),
    good_snapshot(audit_rows="0"), good_snapshot(audit_rows=-1),
    good_snapshot(ledger=[["001"]]), good_snapshot(ledger="x"),
    good_snapshot(protected={"EMPLOYEE_INFO": [3, "ab"]}),
    good_snapshot(protected={"EMPLOYEE_INFO": [3, "a" * 64], "EMPLOYEE_SALARY": ["3", "a" * 64]}),
])
def test_malformed_snapshots_are_rejected(snap):
    assert S.snapshot_problems(snap) and S.baseline_problems(snap)


def test_compare_reports_each_part():
    pre = good_snapshot()
    assert S.compare(pre, good_snapshot()) == {
        "server": True, "explain": True, "audit_rows": True, "ledger": True, "protected": True,
        "explain_tables": {t: [0, 0] for t in Q.EXPLAIN_TABLE_NAMES}}
    post = good_snapshot(audit_rows=1, explain={**pre["explain"], "EXPLAIN_OBJECT": 2})
    cmp = S.compare(pre, post)
    assert (cmp["audit_rows"], cmp["explain"], cmp["ledger"]) == (False, False, True)
    assert cmp["explain_tables"]["EXPLAIN_OBJECT"] == [0, 2]
    assert S.compare(pre, {"bad": 1}) == {}


def test_snapshot_keeps_only_counts_and_hashes_never_row_data():
    snap = S.take_snapshot(SnapConn(F.FakeIbmDb()))
    text = json.dumps(snap)
    assert "SENTINEL-ROW-DATA" not in text and "50000.00" not in text and "Rao" not in text


def test_summary_never_contains_row_data():
    snap = S.take_snapshot(SnapConn(F.FakeIbmDb()))
    text = "\n".join(S.summary(snap))
    assert "SENTINEL-ROW-DATA" not in text and "50000.00" not in text
    assert "EMPLOYEE_INFO: 3 rows" in text


def test_write_snapshot_end_to_end_through_the_guarded_driver(tmp_path, fake_driver, capsys):
    fake = fake_driver()
    out = tmp_path / "snap.json"
    assert S.write_snapshot(out) == 0
    data = json.loads(out.read_text())
    assert S.snapshot_problems(data) == [] and not (tmp_path / "snap.json.partial").exists()
    assert not real_calls(fake, "commit") and not real_calls(fake, "exec_immediate")
    assert all(c[1] in Q.EXECUTABLE_SQL for c in real_calls(fake, "prepare"))
    printed = capsys.readouterr().out
    assert "SENTINEL-ROW-DATA" not in printed and FAKE_ENV["DB2_PASSWORD"] not in printed


def test_write_snapshot_reports_a_failed_connection_without_writing(tmp_path, fake_driver, capsys):
    fake_driver(connect_error="SQL30082N PWD=example-fake-value-0123 rejected")
    out = tmp_path / "snap.json"
    assert S.write_snapshot(out) == 1
    assert not out.exists()
    printed = capsys.readouterr().out
    assert "SNAPSHOT FAILED" in printed and FAKE_ENV["DB2_PASSWORD"] not in printed


def test_write_snapshot_refuses_a_remote_host(tmp_path, monkeypatch, ibm_db_slot):
    real = config_module.load_settings
    monkeypatch.setattr(config_module, "load_settings", lambda env=None: real({**FAKE_ENV, "DB2_HOST": "db.example.com"}))
    fake = F.FakeIbmDb()
    monkeypatch.setattr(D, "install", lambda timeout_s, real=None, _orig=D.install: _orig(timeout_s, real=fake))
    assert S.write_snapshot(tmp_path / "snap.json") == 1
    assert fake.calls == []


# ==== supervisor ================================================================================
def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def script(tmp_path, name, body):
    path = tmp_path / f"{name}.py"
    path.write_text(textwrap.dedent(body))
    return [sys.executable, str(path)]


def snapshot_script(tmp_path, pre=None, post=None, post_mode="ok"):
    pre = good_snapshot() if pre is None else pre
    post = good_snapshot() if post is None else post
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    (data / "pre_data.json").write_text(json.dumps(pre))
    (data / "post_data.json").write_text(json.dumps(post))
    cmd = script(tmp_path, "snap", f"""
        import sys, time
        from pathlib import Path
        out = Path(sys.argv[1])
        Path({str(data / 'calls.log')!r}).open("a").write(out.name + "\\n")
        mode = "ok" if out.name == "pre.json" else {post_mode!r}
        if mode == "fail":
            sys.exit(1)
        if mode == "hang":
            time.sleep(60)
        if mode == "garbage":
            out.write_text("{{not json"); sys.exit(0)
        if mode == "silent":
            sys.exit(0)
        out.write_text(Path({str(data)!r}, out.stem + "_data.json").read_text())
    """)
    return lambda out: cmd + [str(out)]


def snapshot_calls(tmp_path):
    log = tmp_path / "data" / "calls.log"
    return log.read_text().split() if log.exists() else []


def it_script(tmp_path, body, step="it1"):
    """Fake integration test child: `body` runs with WORKDIR and STEP defined."""
    return script(tmp_path, "it", f"import json, sys, time\nfrom pathlib import Path\n"
                                  f"WORKDIR = Path({str(tmp_path / 'work')!r}); STEP = {step!r}\n"
                                  + textwrap.dedent(body))


WRITES_PASSED = 'WORKDIR.joinpath(f"results_{STEP}.json").write_text(json.dumps({"step": STEP, "outcome": "passed"}))'


def run(tmp_path, body=WRITES_PASSED, step="it1", deadline=5, snapshot_deadline=5, **snap):
    test_cmd = it_script(tmp_path, body, step) if step != "snapshot" else None
    return V.supervise(step, test_cmd, snapshot_script(tmp_path, **snap), tmp_path / "work",
                       deadline=deadline, snapshot_deadline=snapshot_deadline)


def test_child_past_deadline_is_sigkilled_and_reaped(tmp_path):
    started = time.monotonic()
    result = V.run_child(script(tmp_path, "sleeper", "import time; time.sleep(60)"), 1, "test")
    assert result.timed_out and result.returncode == -signal.SIGKILL
    assert time.monotonic() - started < 10 and not alive(result.pid)


def test_child_ignoring_sigterm_and_sigint_is_still_killed(tmp_path):
    cmd = script(tmp_path, "stubborn", """
        import signal, time
        signal.signal(signal.SIGTERM, signal.SIG_IGN); signal.signal(signal.SIGINT, signal.SIG_IGN)
        time.sleep(60)
    """)
    result = V.run_child(cmd, 1, "test")
    assert result.timed_out and result.returncode == -signal.SIGKILL and not alive(result.pid)


def test_grandchildren_in_the_process_group_are_killed_too(tmp_path):
    pidfile = tmp_path / "grandchild.pid"
    cmd = script(tmp_path, "parent", f"""
        import subprocess, sys, time
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        open({str(pidfile)!r}, "w").write(str(p.pid))
        time.sleep(60)
    """)
    assert V.run_child(cmd, 2, "test").timed_out
    grandchild = int(pidfile.read_text())
    for _ in range(50):
        if not alive(grandchild):
            break
        time.sleep(0.1)
    assert not alive(grandchild)


def test_child_runs_in_the_project_root_with_the_given_environment(tmp_path):
    out = tmp_path / "where.txt"
    cmd = script(tmp_path, "where", f"import os; open({str(out)!r}, 'w').write(os.getcwd() + '|' + os.environ.get('MARK', ''))")
    assert V.run_child(cmd, 5, "test", env={**os.environ, "MARK": "m1"}).returncode == 0
    assert out.read_text() == f"{PROJECT_ROOT}|m1"


def test_missing_executable_is_a_start_error(tmp_path):
    result = V.run_child([str(tmp_path / "nope")], 5, "test")
    assert result.start_error and result.returncode is None


def test_clean_run_is_pass(tmp_path):
    code, report = run(tmp_path)
    assert (code, report["overall"]) == (0, "PASS")
    assert snapshot_calls(tmp_path) == ["pre.json", "post.json"]
    saved = json.loads((tmp_path / "work" / "report.json").read_text())
    assert saved["exit_code"] == 0 and saved["pass_conditions"]["results_recorded"] is True


def test_timeout_kills_the_test_and_the_post_snapshot_is_still_taken(tmp_path):
    code, report = run(tmp_path, "time.sleep(60)", deadline=1)
    assert code == 1 and report["overall"] == "FAILED" and report["test"]["timed_out"]
    assert snapshot_calls(tmp_path) == ["pre.json", "post.json"]
    assert report["pass_conditions"]["cleanup_verified"] is False


def test_a_skipped_test_that_writes_no_results_is_not_pass(tmp_path):
    code, report = run(tmp_path, "sys.exit(0)")
    assert code == 1 and report["pass_conditions"]["results_recorded"] is False


@pytest.mark.parametrize("results", [
    {"step": "it1", "outcome": "failed"}, {"step": "it2", "outcome": "passed"}, {"outcome": "passed"}, ["passed"],
])
def test_results_must_say_passed_for_this_step(tmp_path, results):
    body = f'WORKDIR.joinpath("results_it1.json").write_text(json.dumps({results!r}))'
    code, report = run(tmp_path, body)
    assert code == 1 and report["pass_conditions"]["results_recorded"] is False


def test_failing_test_with_unchanged_database_is_failed(tmp_path):
    code, report = run(tmp_path, WRITES_PASSED + "\nsys.exit(1)")
    assert code == 1 and report["overall"] == "FAILED"


def test_changed_database_is_changed_and_nothing_is_cleaned_up(tmp_path):
    pre = good_snapshot()
    post = good_snapshot(explain={**pre["explain"], "EXPLAIN_INSTANCE": 1})
    code, report = run(tmp_path, post=post)
    assert code == 2 and report["overall"] == "CHANGED"
    assert report["comparison"]["explain_tables"]["EXPLAIN_INSTANCE"] == [0, 1]
    assert snapshot_calls(tmp_path) == ["pre.json", "post.json"]


@pytest.mark.parametrize("part", [
    {"audit_rows": 1}, {"server": ["TESTDB", "OTHER"]}, {"ledger": [[str(v) for v in r] for r in F.LEDGER[:2]]},
    {"protected": {"EMPLOYEE_INFO": [3, "c6e96adb4bcfc5d5" + "1" * 48],
                   "EMPLOYEE_SALARY": [3, "9f9edd2017255f98" + "0" * 48]}},
])
def test_any_changed_part_is_changed(tmp_path, part):
    code, report = run(tmp_path, post=good_snapshot(**part))
    assert code == 2 and report["overall"] == "CHANGED"


@pytest.mark.parametrize("mode", ["fail", "garbage", "silent", "hang"])
def test_unusable_post_snapshot_is_incomplete(tmp_path, mode):
    code, report = run(tmp_path, post_mode=mode, snapshot_deadline=2)
    assert code == 3 and report["overall"] == "INCOMPLETE"


@pytest.mark.parametrize("pre", [
    good_snapshot(explain={**{t: 0 for t in Q.EXPLAIN_TABLE_NAMES}, "EXPLAIN_OPERATOR": 3}),
    good_snapshot(audit_rows=2),
    good_snapshot(server=["SAMPLE", "DB2INST1"]),
    {"not": "a snapshot"},
])
def test_bad_baseline_never_starts_the_test(tmp_path, pre):
    marker = tmp_path / "started"
    code, report = run(tmp_path, f"open({str(marker)!r}, 'w').write('x')", pre=pre)
    assert code == 4 and report["overall"] == "NOT STARTED"
    assert not marker.exists() and snapshot_calls(tmp_path) == ["pre.json"]


def test_snapshot_step_takes_one_snapshot_and_runs_nothing_else(tmp_path):
    code, report = run(tmp_path, step="snapshot")
    assert (code, report["overall"]) == (0, "PASS")
    assert snapshot_calls(tmp_path) == ["pre.json"] and report["test"] is None


def test_snapshot_step_with_a_bad_baseline_is_not_started(tmp_path):
    code, report = run(tmp_path, step="snapshot", pre=good_snapshot(audit_rows=1))
    assert (code, report["overall"]) == (4, "NOT STARTED") and snapshot_calls(tmp_path) == ["pre.json"]


def test_work_directory_must_be_new_and_empty(tmp_path):
    (tmp_path / "work").mkdir()
    (tmp_path / "work" / "pre.json").write_text("{}")
    with pytest.raises(ValueError, match="not empty"):
        run(tmp_path)


def test_unknown_step_is_refused(tmp_path):
    with pytest.raises(ValueError):
        V.supervise("it3", None, None, tmp_path / "work")


def test_unwritable_report_is_never_pass(tmp_path, monkeypatch):
    real_replace = os.replace
    monkeypatch.setattr(os, "replace", lambda a, b: (_ for _ in ()).throw(OSError("disk full"))
                        if str(b).endswith("report.json") else real_replace(a, b))
    code, report = run(tmp_path)
    assert code == 3 and report["overall"] == "INCOMPLETE" and report["report_written"] is False


@pytest.mark.parametrize("argv, message", [
    (["--step", "it1"], "--workdir"),
    (["--step", "it9", "--workdir", "/tmp/x"], "invalid choice"),
    (["--step", "it1", "--workdir", str(PROJECT_ROOT / "runs")], "outside the project"),
    (["--step", "it1", "--workdir", str(PROJECT_ROOT)], "outside the project"),
    (["--step", "it1", "--workdir", "/tmp/x", "--query-timeout", "60", "--snapshot-deadline", "60"], "shorter"),
])
def test_main_refuses_bad_arguments(argv, message, capsys):
    with pytest.raises(SystemExit):
        V.main(argv)
    assert message in capsys.readouterr().err


def test_commands_for_a_real_run(tmp_path):
    test_cmd, snap, test_env, snap_env = V.commands("it2", tmp_path, 25)
    assert test_cmd[1:4] == ["-m", "pytest", "-p"] and test_cmd[-1] == "tests/integration/test_it2.py"
    assert test_env["DB2INTEL_IT"] == "1" and test_env[V.RUN_DIR_ENV] == str(tmp_path)
    assert test_env[V.STEP_ENV] == "it2" and test_env["DB2INTEL_IT_QUERY_TIMEOUT"] == "25"
    assert V.STEP_ENV not in snap_env and V.RUN_DIR_ENV not in snap_env
    assert snap(tmp_path / "pre.json")[1:3] == ["-m", "integration.snapshot"]
    assert V.commands("snapshot", tmp_path, 25)[0] is None


def test_decide_is_pass_only_when_every_condition_holds():
    import random
    rng = random.Random(7)
    for _ in range(400):
        facts = V.new_facts(rng.choice(["it1", "it2", "snapshot"]), 10, 10)
        facts["pre_snapshot"] = rng.choice([good_snapshot(), good_snapshot(audit_rows=1), None])
        facts["pre_error"] = rng.choice([None, "x"])
        facts["baseline_problems"] = rng.choice([[], ["x"], None])
        facts["post_snapshot"] = rng.choice([good_snapshot(), good_snapshot(audit_rows=1), None])
        facts["post_error"] = rng.choice([None, "x"])
        facts["test"] = rng.choice([None, {"started": True, "exit_code": 0, "timed_out": False, "interrupted": False},
                                    {"started": True, "exit_code": 1, "timed_out": False, "interrupted": False},
                                    {"started": True, "exit_code": 0, "timed_out": True, "interrupted": False}])
        facts["results"] = rng.choice([None, {"step": facts["step"], "outcome": "passed"}, {"outcome": "failed"}])
        facts["interrupted"] = rng.choice([False, True])
        overall, conditions, _ = V.decide(facts)
        assert (overall == "PASS") == all(conditions.values())


# ==== harness ===================================================================================
def make_run_dir(tmp_path, pre=None):
    work = tmp_path / "run"
    work.mkdir()
    (work / "pre.json").write_text(json.dumps(good_snapshot() if pre is None else pre))
    return work


def env_for(work, step="it1", **extra):
    return {H.RUN_DIR_ENV: str(work), H.STEP_ENV: step, **extra}


def test_supervised_run_accepts_a_fresh_supervised_directory(tmp_path):
    work = make_run_dir(tmp_path)
    run_ = H.supervised_run("it1", env_for(work, DB2INTEL_IT_QUERY_TIMEOUT="25"))
    assert (run_.workdir, run_.step, run_.timeout) == (work, "it1", 25)


@pytest.mark.parametrize("case", ["no env", "other step", "no pre", "bad pre", "unreadable pre", "post exists",
                                  "results exist", "bad timeout", "timeout range"])
def test_supervised_run_skips_outside_a_fresh_supervised_run(tmp_path, case):
    work = make_run_dir(tmp_path, pre=good_snapshot(audit_rows=1) if case == "bad pre" else None)
    env = env_for(work)
    if case == "no env":
        env = {}
    elif case == "other step":
        env = env_for(work, "it2")
    elif case == "no pre":
        (work / "pre.json").unlink()
    elif case == "unreadable pre":
        (work / "pre.json").write_text("{nope")
    elif case == "post exists":
        (work / "post.json").write_text("{}")
    elif case == "results exist":
        (work / "results_it1.json").write_text("{}")
    elif case == "bad timeout":
        env["DB2INTEL_IT_QUERY_TIMEOUT"] = "x"
    elif case == "timeout range":
        env["DB2INTEL_IT_QUERY_TIMEOUT"] = "0"
    with pytest.raises(pytest.skip.Exception):
        H.supervised_run("it1", env)


def test_recording_marks_passed_only_when_the_block_completes(tmp_path):
    run_ = H.Run(tmp_path, "it1", 30)
    with H.recording(run_, {"a": 1}):
        pass
    assert json.loads(run_.results_path.read_text()) == {"a": 1, "step": "it1", "outcome": "passed"}
    with pytest.raises(AssertionError):
        with H.recording(run_, {}):
            raise AssertionError("nope")
    saved = json.loads(run_.results_path.read_text())
    assert saved["outcome"] == "failed" and "nope" in saved["error"]


def test_integration_tests_skip_in_a_normal_run_even_with_it_enabled(tmp_path):
    blocker = tmp_path / "blocker"  # any attempt to load the real driver fails in this subprocess
    blocker.mkdir()
    (blocker / "ibm_db.py").write_text("raise ImportError('ibm_db is blocked in this offline test')\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("DB2INTEL_IT")}
    env["PYTHONPATH"] = os.pathsep.join([str(blocker), str(PROJECT_ROOT / "src"), str(PROJECT_ROOT / "tests")])
    for extra in ({}, {"DB2INTEL_IT": "1"}):
        out = subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-rs", "tests/integration"],
                             capture_output=True, text=True, env={**env, **extra}, cwd=PROJECT_ROOT, timeout=120)
        assert out.returncode == 0, out.stdout + out.stderr
        assert "3 skipped" in out.stdout and "passed" not in out.stdout


# ==== IT1 / IT2 end to end against the fake ====================================================
@pytest.fixture
def it_env(tmp_path, monkeypatch, fake_driver):
    def setup(step, server="TESTDB", **knobs):
        fake = fake_driver(**knobs)
        pre = S.take_snapshot(SnapConn(fake))  # taken while the fake still reports TESTDB
        fake.server = server
        fake.calls.clear()  # only the integration test's own calls are inspected
        monkeypatch.setattr(Q, "EXPECTED_FINGERPRINTS", {t: (n, d[:16]) for t, (n, d) in pre["protected"].items()})
        work = tmp_path / step
        work.mkdir()
        (work / "pre.json").write_text(json.dumps(pre))
        for k, v in env_for(work, step, DB2INTEL_IT_QUERY_TIMEOUT=str(T)).items():
            monkeypatch.setenv(k, v)
        return fake, work
    return setup


def results(work, step):
    return json.loads((work / f"results_{step}.json").read_text())


def test_it1_end_to_end_records_the_timeout_facts(it_env):
    from integration import test_it1
    fake, work = it_env("it1")
    test_it1.test_it1_query_timeout_read_back()
    r = results(work, "it1")
    assert r["outcome"] == "passed" and r["statement_read_back"] == T
    assert r["statement_default"] == "0" and r["connection_read_back"] == "False"
    assert r["connection_set_returned"] == "True" and r["inherited_read_back"] == repr(r["connection_default"])
    assert not real_calls(fake, "callproc") and not real_calls(fake, "commit")
    executed = [c[1] for c in real_calls(fake, "execute")]
    assert executed == [Q.SERVER_SQL]


def test_it1_records_when_the_connection_default_is_not_inherited(it_env):
    from integration import test_it1
    _, work = it_env("it1", inherit_connection_timeout=False)
    test_it1.test_it1_query_timeout_read_back()
    assert results(work, "it1")["inherited_read_back"] == "0"


def test_it1_fails_and_records_when_the_statement_timeout_does_not_read_back(it_env):
    from integration import test_it1
    _, work = it_env("it1", statement_read_back=False)
    with pytest.raises(DbError, match="reads back False"):  # refused on the identity query
        test_it1.test_it1_query_timeout_read_back()
    assert results(work, "it1")["outcome"] == "failed"


def test_it2_end_to_end_compares_three_paths_and_verifies_cleanup(it_env):
    from integration import test_it2
    fake, work = it_env("it2")
    test_it2.test_it2_explain_from_section_paths()
    r = results(work, "it2")
    assert r["outcome"] == "passed", r.get("error")
    assert r["instances_located"] == 3 and r["instance_counts"] == [1, 1, 1] and r["all_instances_identical"]
    assert r["path2_timeout_read_back"] == T and r["path2_execute_returned"] == "True"
    assert r["path3_statement_timeout"] == repr(r["connection_default"])
    assert r["leftover_marker_rows"] == 0 and set(r["leftover_counts"].values()) == {0}
    assert fake.state.pending == [] and fake.state.committed == []
    assert not real_calls(fake, "commit") and not real_calls(fake, "exec_immediate")
    executed = [c[1] for c in real_calls(fake, "execute")]
    assert executed.count(Q.CALL_EXPLAIN_SQL) == 1 and len(real_calls(fake, "callproc")) == 2
    assert all(s in Q.EXECUTABLE_SQL for s in executed)
    assert not any(Q.MARKED_PK_LOOKUP_RE.match(s) for s in executed)


def test_it2_detects_explain_rows_left_after_rollback(it_env):
    from integration import test_it2
    _, work = it_env("it2", rollback_keeps_rows=True)
    with pytest.raises(AssertionError):
        test_it2.test_it2_explain_from_section_paths()
    r = results(work, "it2")
    assert r["outcome"] == "failed" and r["leftover_marker_rows"] > 0


def test_it2_detects_explain_rows_without_the_marker_left_after_rollback(it_env):
    from integration import test_it2
    _, work = it_env("it2", foreign_rows_after_rollback=True)
    with pytest.raises(AssertionError, match="explain rows remain after rollback"):
        test_it2.test_it2_explain_from_section_paths()
    r = results(work, "it2")
    assert r["leftover_marker_rows"] == 0 and r["leftover_counts"]["EXPLAIN_INSTANCE"] == 1


def test_it2_detects_a_different_plan_from_the_prepared_call(it_env):
    from integration import test_it2
    _, work = it_env("it2", vary_prepared_call_cost=True)
    with pytest.raises(AssertionError, match="different explain rows"):
        test_it2.test_it2_explain_from_section_paths()
    r = results(work, "it2")
    assert r["all_instances_identical"] is False and set(r["leftover_counts"].values()) == {0}


def test_it2_still_rolls_back_and_counts_when_the_prepared_call_fails(it_env):
    from integration import test_it2
    fake, work = it_env("it2", prepared_call_error=True)
    with pytest.raises(Exception, match="SQL0440N"):
        test_it2.test_it2_explain_from_section_paths()
    r = results(work, "it2")
    assert r["outcome"] == "failed" and set(r["leftover_counts"].values()) == {0}
    assert fake.state.pending == [] and real_calls(fake, "rollback")


def test_it2_records_when_callproc_does_not_inherit_the_connection_timeout(it_env):
    from integration import test_it2
    _, work = it_env("it2", inherit_connection_timeout=False)
    test_it2.test_it2_explain_from_section_paths()
    assert results(work, "it2")["path3_statement_timeout"] == "0"


def test_it_tests_refuse_a_non_testdb_server(it_env):
    from integration import test_it1
    _, work = it_env("it1", server="SAMPLE")
    with pytest.raises(RuntimeError, match="expected TESTDB"):
        test_it1.test_it1_query_timeout_read_back()
