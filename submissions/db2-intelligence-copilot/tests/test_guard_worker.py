"""Guard worker pool: deadline + SIGKILL, bounded pool, degraded latch, protocol validation.

Workers are real subprocesses running fake backends from tests/fake_guard_backends.py. No test
here uses the db2 backend except to prove that it refuses to start in offline mode.
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path

import pytest

from db2intel.guard import worker as W

TESTS_DIR = str(Path(__file__).resolve().parent)
SQL = "SELECT 1 FROM SYSIBM.SYSDUMMY1"


def pool(backend, **kw):
    kw.setdefault("check_deadline", 10)
    kw.setdefault("startup_deadline", 10)
    kw.setdefault("queue_wait", 0)
    # Test-only variables for the fake backends are not on the worker allow-list: pass them as extra_env.
    env = {**os.environ, W.OFFLINE_ENV: "1"}
    return W.GuardPool(backend=f"fake_guard_backends:{backend}", extra_pythonpath=(TESTS_DIR,), env=env,
                       extra_env=kw.pop("env", {}), **kw)


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def wait_dead(pid, seconds=5.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if not alive(pid):
            return True
        time.sleep(0.05)
    return False


@pytest.fixture
def pools():
    made = []

    def make(*a, **kw):
        p = pool(*a, **kw)
        made.append(p)
        return p

    yield make
    for p in made:
        p.close()


# ---- happy path ----------------------------------------------------------------------------
def test_approved_check_round_trip_and_worker_reuse(pools):
    p = pools("Approving")
    first = p.check(SQL, origin=W.ORIGIN_HUMAN)
    second = p.check(SQL, origin=W.ORIGIN_HUMAN)
    assert first["status"] == "APPROVED" and first["code"] == "approved"
    assert first["reason"] == second["reason"]  # same worker pid answered both
    assert p.status()["workers_started"] == 1 and p.status()["idle_workers"] == 1 and p.degraded is None


def test_blocked_decision_is_returned_and_worker_kept(pools):
    p = pools("Blocking")
    d = p.check(SQL, origin=W.ORIGIN_HUMAN)
    assert d["status"] == "BLOCKED" and d["sqlstate"] == "42704" and p.degraded is None
    assert p.status()["idle_workers"] == 1


def test_sql_reaches_the_worker_unchanged(pools, tmp_path):
    echo = tmp_path / "echo.txt"
    p = pools("EchoSql", env={"ECHO_FILE": str(echo)})
    p.check("SELECT  C.CITY FROM DB2INTEL_DEMO.CUSTOMER C", origin=W.ORIGIN_HUMAN)
    assert echo.read_text() == "SELECT  C.CITY FROM DB2INTEL_DEMO.CUSTOMER C\n"


def test_stdout_noise_in_the_worker_does_not_corrupt_the_protocol(pools):
    p = pools("Noisy")
    assert p.check(SQL, origin=W.ORIGIN_HUMAN)["status"] == "APPROVED"
    assert p.check(SQL, origin=W.ORIGIN_HUMAN)["status"] == "APPROVED" and p.degraded is None


# ---- deadline, SIGKILL and the degraded latch --------------------------------------------------
def test_deadline_kills_worker_latches_degraded_and_refuses_later_checks(pools):
    p = pools("Hanging", check_deadline=1)
    started = time.monotonic()
    with pytest.raises(W.WorkerTimeout):
        p.check(SQL, origin=W.ORIGIN_HUMAN)
    assert time.monotonic() - started < 8
    assert p.degraded and "deadline" in p.degraded and "not verified" in p.degraded
    assert p.status()["workers_killed"] == 1 and p.status()["idle_workers"] == 0
    with pytest.raises(W.Degraded):
        p.check(SQL, origin=W.ORIGIN_HUMAN)
    assert p.status()["workers_started"] == 1  # no new worker after the latch


def _recording(p):
    taken = []
    original = p._take_worker

    def record():
        worker = original()
        taken.append(worker)
        return worker

    p._take_worker = record
    return taken


def test_worker_ignoring_sigterm_and_sigint_is_still_killed(pools):
    p = pools("IgnoresSignals", check_deadline=1)
    taken = _recording(p)
    started = time.monotonic()
    with pytest.raises(W.WorkerTimeout):
        p.check(SQL, origin=W.ORIGIN_HUMAN)
    (worker,) = taken
    assert p.status()["workers_killed"] == 1 and not alive(worker.pid)
    assert worker.proc.returncode == -9 and time.monotonic() - started < 8


def test_grandchild_of_a_killed_worker_is_killed_too(pools, tmp_path):
    pidfile = tmp_path / "grandchild.pid"
    p = pools("HangingWithGrandchild", check_deadline=2, env={"GRANDCHILD_PIDFILE": str(pidfile)})
    with pytest.raises(W.WorkerTimeout):
        p.check(SQL, origin=W.ORIGIN_HUMAN)
    assert wait_dead(int(pidfile.read_text()))


def test_killed_worker_process_is_gone_and_reaped(pools):
    p = pools("Hanging", check_deadline=1)
    taken = []
    original = p._take_worker

    def record():
        worker = original()
        taken.append(worker)
        return worker

    p._take_worker = record
    with pytest.raises(W.WorkerTimeout):
        p.check(SQL, origin=W.ORIGIN_HUMAN)
    (worker,) = taken
    assert worker.proc.returncode is not None and worker.proc.returncode < 0  # reaped, killed by a signal
    assert not alive(worker.pid)


@pytest.mark.parametrize("backend,exc", [
    ("Crashing", W.WorkerFailed),
    ("Malformed", W.WorkerFailed),
    ("WrongRequestId", W.WorkerFailed),
    ("ApprovedWithoutSql", W.WorkerFailed),
    ("Raising", W.WorkerFailed),
    ("HugeMessage", W.WorkerFailed),
])
def test_worker_failure_mid_check_latches_degraded(pools, backend, exc):
    p = pools(backend)
    with pytest.raises(exc) as info:
        p.check(SQL, origin=W.ORIGIN_HUMAN)
    assert "hunter2" not in str(info.value)
    assert p.degraded and "not verified" in p.degraded
    with pytest.raises(W.Degraded):
        p.check(SQL, origin=W.ORIGIN_HUMAN)


def test_cleanup_failed_decision_is_returned_then_latches(pools):
    p = pools("CleanupFailed")
    d = p.check(SQL, origin=W.ORIGIN_HUMAN)
    assert d["status"] == "ERROR" and d["code"] == "cleanup_failed"
    assert p.degraded and "cleanup_failed" in p.degraded and p.status()["idle_workers"] == 0
    with pytest.raises(W.Degraded):
        p.check(SQL, origin=W.ORIGIN_HUMAN)


def test_latch_is_permanent_and_reported_once(pools):
    seen = []
    p = pools("CleanupFailed", on_degraded=seen.append)
    p.check(SQL, origin=W.ORIGIN_HUMAN)
    p._latch("a later reason")
    assert len(seen) == 1 and p.degraded == seen[0]


# ---- startup ------------------------------------------------------------------------------------
def test_startup_failure_is_unavailable_not_degraded_and_hides_details(pools):
    p = pools("StartupFails")
    with pytest.raises(W.WorkerStartError) as info:
        p.check(SQL, origin=W.ORIGIN_HUMAN)
    assert "hunter2" not in str(info.value) and p.degraded is None


def test_startup_hang_is_bounded_by_the_startup_deadline(pools):
    p = pools("StartupHangs", startup_deadline=1)
    started = time.monotonic()
    with pytest.raises(W.WorkerStartError):
        p.check(SQL, origin=W.ORIGIN_HUMAN)
    assert time.monotonic() - started < 8 and p.degraded is None


def test_db2_backend_refuses_to_start_in_offline_mode():
    # Belt and braces: an empty password would also stop any connection attempt before ibm_db loads.
    env = {**os.environ, W.OFFLINE_ENV: "1", "DB2_PASSWORD": "", "DB2_HOST": "invalid.invalid", "DB2_PORT": "1"}
    p = W.GuardPool(backend=W.DB2_BACKEND, env=env, startup_deadline=20, queue_wait=0)
    try:
        with pytest.raises(W.WorkerStartError, match="backend_refused"):
            p.check(SQL, origin=W.ORIGIN_HUMAN)
    finally:
        p.close()


def test_unknown_backend_spec_fails_to_start(pools):
    p = W.GuardPool(backend="no_module_spec", env={**os.environ, W.OFFLINE_ENV: "1"}, queue_wait=0)
    try:
        with pytest.raises(W.WorkerStartError):
            p.check(SQL, origin=W.ORIGIN_HUMAN)
    finally:
        p.close()


# ---- bounded pool ---------------------------------------------------------------------------------
def test_pool_is_bounded_and_busy_requests_are_rejected(pools):
    p = pools("Slow", size=1, queue_wait=0, env={"SLOW_SECONDS": "1.5"})
    results = {}

    def first():
        results["first"] = p.check(SQL, origin=W.ORIGIN_HUMAN)

    t = threading.Thread(target=first)
    t.start()
    time.sleep(0.6)  # first request holds the only slot
    with pytest.raises(W.PoolBusy):
        p.check(SQL, origin=W.ORIGIN_HUMAN)
    t.join(10)
    assert results["first"]["status"] == "APPROVED" and p.status()["busy_rejections"] == 1
    assert p.status()["workers_started"] == 1 and p.degraded is None


def test_concurrent_checks_never_exceed_pool_size(pools):
    p = pools("Slow", size=2, queue_wait=10, env={"SLOW_SECONDS": "0.3"})
    errors = []

    def run():
        try:
            p.check(SQL, origin=W.ORIGIN_HUMAN)
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert not errors and p.status()["workers_started"] <= 2 and p.status()["checks"] == 6


# ---- origin gate (G4) and input validation ------------------------------------------------------
@pytest.mark.parametrize("origin", [W.ORIGIN_AI, "", "Human", None, "ai_reviewed"])
def test_non_human_origin_is_refused_before_any_worker_starts(pools, origin):
    p = pools("Approving")
    with pytest.raises(W.AISqlNotAllowed):
        p.check(SQL, origin=origin)
    assert p.status()["workers_started"] == 0 and W.AI_SQL_CHECK_ENABLED is False


@pytest.mark.parametrize("sql", ["", "   ", "x" * 20_001, None, 42])
def test_invalid_sql_is_refused_before_any_worker_starts(pools, sql):
    p = pools("Approving")
    with pytest.raises(ValueError):
        p.check(sql, origin=W.ORIGIN_HUMAN)
    assert p.status()["workers_started"] == 0


@pytest.mark.parametrize("kw", [{"size": 0}, {"size": 5}, {"check_deadline": 0}, {"check_deadline": 301},
                                {"startup_deadline": 0}, {"queue_wait": -1}, {"queue_wait": 31}])
def test_pool_limits_are_validated(kw):
    with pytest.raises(ValueError):
        W.GuardPool(**kw)


def test_closed_pool_refuses_checks(pools):
    p = pools("Approving")
    p.check(SQL, origin=W.ORIGIN_HUMAN)
    p.close()
    with pytest.raises(W.WorkerStartError):
        p.check(SQL, origin=W.ORIGIN_HUMAN)


def test_close_stops_idle_workers(pools):
    p = pools("Approving")
    p.check(SQL, origin=W.ORIGIN_HUMAN)
    worker = p._idle[0]
    p.close()
    assert not worker.alive()


# ---- decision validation ----------------------------------------------------------------------------
RID = "11111111-2222-3333-4444-555555555555"
GOOD = {"request_id": RID, "status": "APPROVED", "code": "approved", "reason": "ok", "sql": "SELECT 1",
        "estimated_cost": 1.0, "explain_cost": 1.0, "objects": [["S", "T", "TA"]], "plan": [[1, "RETURN", 1.0]],
        "sqlstate": None}


def test_valid_decision_passes():
    d = W.validate_decision(dict(GOOD), RID)
    assert d["objects"] == (("S", "T", "TA"),) and d["plan"] == ((1, "RETURN", 1.0),)


@pytest.mark.parametrize("change", [
    {"request_id": "other"}, {"status": "OK"}, {"code": "Approved"}, {"code": "x" * 65}, {"code": 1},
    {"reason": None}, {"reason": "x" * 4001}, {"sql": 5}, {"estimated_cost": -1}, {"estimated_cost": float("nan")},
    {"estimated_cost": True}, {"explain_cost": "1"}, {"objects": [["S", "T"]]}, {"objects": "S.T"},
    {"plan": [["1", "RETURN", 1.0]]}, {"plan": [[True, "RETURN", 1.0]]}, {"sqlstate": "4270"}, {"sqlstate": 42704},
    {"sql": None}, {"code": "blocked"},
])
def test_malformed_decisions_are_rejected(change):
    with pytest.raises(W._ProtocolError):
        W.validate_decision({**GOOD, **change}, RID)


def test_non_dict_decision_is_rejected():
    with pytest.raises(W._ProtocolError):
        W.validate_decision(["APPROVED"], RID)


def test_decision_to_message_round_trips_through_validation():
    from db2intel.guard.analysis import GuardDecision, PlanOperator

    decision = GuardDecision(RID, "APPROVED", "approved", "all checks passed", sql="SELECT 1 FROM SYSIBM.SYSDUMMY1",
                             estimated_cost=7.0, explain_cost=6.5, objects=(("DB2INTEL_DEMO", "CUSTOMER", "TA"),),
                             plan=(PlanOperator(1, "RETURN", 7.0),))
    import json
    clean = W.validate_decision(json.loads(json.dumps(W.decision_to_message(decision))), RID)
    assert clean["sql"] == decision.sql and clean["plan"] == ((1, "RETURN", 7.0),)


def test_worker_module_never_imports_execution_code():
    source = Path(W.__file__).read_text()
    for name in ("execute_approved", "execute_capped", "Db2ExecutionSession", "guard.execution", "commit("):
        assert name not in source, name


# ---- message size cap and the real backend's startup order (in-process fakes, no driver) ----------
def test_oversized_message_is_a_protocol_error_not_a_wait():
    r, w = os.pipe()
    worker = W.GuardWorker.__new__(W.GuardWorker)
    worker._buf = b""

    class Proc:
        stdout = os.fdopen(r, "rb")

    worker.proc = Proc()

    def writer():
        with os.fdopen(w, "wb") as fh:
            fh.write(b"x" * (W.MAX_MESSAGE_BYTES + 70_000))  # no newline, then stay open briefly
            fh.flush()
            time.sleep(3)

    t = threading.Thread(target=writer)
    t.start()
    started = time.monotonic()
    with pytest.raises(W._ProtocolError):
        worker._read(time.monotonic() + 20)
    assert time.monotonic() - started < 3
    t.join()
    Proc.stdout.close()


@pytest.fixture
def backend_fakes(monkeypatch):
    import db2intel.config as config
    import db2intel.db.connection as connection
    import db2intel.db.migrate as migrate
    import db2intel.guard.context as context
    import db2intel.guard.sessions as sessions
    from guard_fakes import CTX

    calls = []

    class Settings:
        class migration:
            allowed_hosts = ("localhost",)
            allowed_databases = ("TESTDB",)
        db2 = "db2-settings"

    class Conn:
        def __init__(self, settings):
            calls.append(("connect", settings))

        def close(self):
            calls.append(("close",))

    class Session:
        def __init__(self, conn):
            calls.append(("session",))

        def pin_system_path(self):
            calls.append(("pin_system_path",))

        def rollback(self):
            calls.append(("rollback",))

    def preflight(session, dbs):
        calls.append(("preflight", dbs))
        if calls_fail.get("preflight"):
            raise RuntimeError("preflight failed")
        return CTX

    def explain_empty(session):
        calls.append(("explain_empty",))
        if calls_fail.get("explain_rows"):
            raise context.ExplainTablesNotEmpty("explain tables in DB2INTEL are not empty (EXPLAIN_INSTANCE=1)")

    def fake_load_settings(env):
        calls.append(("settings", env))
        return Settings

    calls_fail = {}
    monkeypatch.delenv(W.OFFLINE_ENV, raising=False)
    monkeypatch.setattr(W, "worker_settings_env", lambda: {"DB2_HOST": "localhost"})  # never read the real .env
    monkeypatch.setattr(config, "load_settings", fake_load_settings)
    monkeypatch.setattr(context, "check_explain_tables_empty", explain_empty)
    monkeypatch.setattr(migrate, "check_migration_host", lambda db2, hosts: calls.append(("host_check", hosts)))
    monkeypatch.setattr(connection, "Db2Connection", Conn)
    monkeypatch.setattr(sessions, "Db2AnalysisSession", Session)
    monkeypatch.setattr(context, "load_guard_context", preflight)
    return calls, calls_fail


def test_db2_backend_startup_order(backend_fakes):
    calls, _ = backend_fakes
    backend = W.Db2Backend()
    assert [c[0] for c in calls] == ["settings", "host_check", "connect", "session", "pin_system_path", "preflight",
                                     "explain_empty", "rollback"]
    assert backend.context()["allowed_schemas"] == ["DB2INTEL_DEMO"]
    backend.close()
    assert calls[-1] == ("close",)


def test_db2_backend_closes_connection_when_preflight_fails(backend_fakes):
    calls, fail = backend_fakes
    fail["preflight"] = True
    with pytest.raises(RuntimeError):
        W.Db2Backend()
    assert [c[0] for c in calls][-2:] == ["rollback", "close"]


def test_db2_backend_refuses_in_offline_mode_before_loading_settings(monkeypatch):
    import db2intel.config as config

    monkeypatch.setenv(W.OFFLINE_ENV, "1")
    monkeypatch.setattr(config, "load_settings", lambda: (_ for _ in ()).throw(AssertionError("settings loaded")))
    with pytest.raises(W.BackendRefused):
        W.Db2Backend()
