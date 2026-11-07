"""Graceful shutdown: GuardPool.close() is idempotent and cleans up idle and active workers, the
FastAPI lifespan hook closes the pool exactly once, and SIGTERM to a real server process closes the
pool and leaves no worker processes behind.

No database: workers run fake backends from tests/fake_guard_backends.py with DB2INTEL_OFFLINE=1.
"""
from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from db2intel.api import app as A
from db2intel.config import ApiSettings
from db2intel.guard import worker as W

TESTS_DIR = Path(__file__).resolve().parent
SRC_DIR = TESTS_DIR.parent / "src"
SQL = "SELECT 1 FROM SYSIBM.SYSDUMMY1"
GOOD = "SELECT C.COMPANY_NAME FROM DB2INTEL_DEMO.CUSTOMER C WHERE C.CUSTOMER_ID = 42"
TOKEN = "example-fake-api-token-0123456789"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def fake_pool(backend, **kw):
    kw.setdefault("check_deadline", 10)
    kw.setdefault("startup_deadline", 10)
    kw.setdefault("queue_wait", 0)
    return W.GuardPool(backend=f"fake_guard_backends:{backend}", extra_pythonpath=(str(TESTS_DIR),),
                       env={**os.environ, W.OFFLINE_ENV: "1"}, **kw)


def gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def wait_gone(pid: int, seconds: float = 10.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if gone(pid):
            return True
        time.sleep(0.05)
    return gone(pid)


def wait_for(predicate, seconds: float = 10.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


# ---- GuardPool.close() ---------------------------------------------------------------------------
def test_close_without_any_worker_started():
    p = fake_pool("Approving")
    assert p.close() is True
    assert p.closed and p.status()["workers_started"] == 0 and p.status()["idle_workers"] == 0
    assert p.close() is False


def test_close_is_idempotent_and_reaps_idle_workers():
    p = fake_pool("Approving")
    pid = int(p.check(SQL, origin=W.ORIGIN_HUMAN)["reason"].split()[-1])
    assert not p._busy and p.status()["idle_workers"] == 1 and not gone(pid)
    assert p.close() is True
    assert wait_gone(pid, 1.0)  # reaped by close(), not left as a zombie
    for _ in range(3):
        assert p.close() is False
    with pytest.raises(W.WorkerStartError, match="closed"):
        p.check(SQL, origin=W.ORIGIN_HUMAN)


def test_close_kills_an_active_worker_and_its_process_group(tmp_path):
    pidfile = tmp_path / "grandchild.pid"
    p = W.GuardPool(backend="fake_guard_backends:HangingWithGrandchild", extra_pythonpath=(str(TESTS_DIR),),
                    env={**os.environ, W.OFFLINE_ENV: "1"}, extra_env={"GRANDCHILD_PIDFILE": str(pidfile)},
                    check_deadline=60, startup_deadline=10, queue_wait=0)
    outcome = {}

    def run():
        try:
            p.check(SQL, origin=W.ORIGIN_HUMAN)
        except Exception as exc:  # expected: the worker is killed mid-check
            outcome["error"] = exc

    thread = threading.Thread(target=run)
    thread.start()
    assert wait_for(lambda: p._busy and pidfile.exists() and pidfile.read_text().strip())
    worker_pid = next(iter(p._busy)).pid
    grandchild = int(pidfile.read_text())
    started = time.monotonic()
    assert p.close() is True
    thread.join(10)
    elapsed = time.monotonic() - started
    assert not thread.is_alive() and elapsed < 10  # far below the 60 s check deadline
    assert isinstance(outcome.get("error"), W.WorkerFailed)
    assert gone(worker_pid)  # killed and reaped before close() returned
    assert wait_gone(grandchild)
    assert not p._busy
    assert p.close() is False


def test_close_alone_kills_and_reaps_an_active_worker_whose_thread_is_stuck(tmp_path):
    # A worker handed to a check whose thread never reads again: close() must not rely on that
    # thread. It kills the whole process group and reaps the worker itself.
    pidfile = tmp_path / "grandchild.pid"
    p = W.GuardPool(backend="fake_guard_backends:GrandchildAtStartup", extra_pythonpath=(str(TESTS_DIR),),
                    env={**os.environ, W.OFFLINE_ENV: "1"}, extra_env={"GRANDCHILD_PIDFILE": str(pidfile)},
                    check_deadline=10, startup_deadline=10, queue_wait=0)
    worker = p._take_worker()  # now busy, with no reader
    grandchild = int(pidfile.read_text())
    try:
        assert worker in p._busy and not gone(grandchild)
        assert p.close(reap_seconds=10) is True
        assert worker.proc.returncode is not None  # reaped by close() itself (set by wait, not poll)
        assert wait_gone(grandchild, 5.0)  # killed with the group
    finally:
        if not gone(grandchild):
            os.kill(grandchild, signal.SIGKILL)
        worker.kill()


def test_close_kills_an_active_worker_that_ignores_sigterm():
    p = fake_pool("IgnoresSignals", check_deadline=60)
    thread = threading.Thread(target=lambda: _capture(p))
    thread.start()
    assert wait_for(lambda: p._busy)
    time.sleep(0.5)  # let it install its handlers and start the check
    pid = next(iter(p._busy)).pid
    assert p.close() is True
    thread.join(10)
    assert not thread.is_alive() and gone(pid)


def test_close_kills_a_reused_worker_that_is_mid_check():
    p = fake_pool("HangsOnSecondCheck", check_deadline=60)
    pid = int(p.check(SQL, origin=W.ORIGIN_HUMAN)["reason"].split()[-1])  # worker goes back to idle
    outcome = {}
    thread = threading.Thread(target=lambda: outcome.setdefault("r", _capture(p)))
    thread.start()
    assert wait_for(lambda: p._busy)  # the idle worker was handed out again
    time.sleep(0.2)  # let it receive the request
    assert next(iter(p._busy)).pid == pid
    assert p.close() is True
    thread.join(10)
    assert not thread.is_alive() and isinstance(outcome["r"], W.WorkerFailed)
    assert gone(pid) and not p._busy


def _capture(p):
    try:
        return p.check(SQL, origin=W.ORIGIN_HUMAN)
    except Exception as exc:
        return exc


def test_worker_that_finishes_starting_after_close_is_killed(monkeypatch):
    p = fake_pool("Approving")
    created = []

    class Recording(W.GuardWorker):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            created.append(self)
            p.close()  # the pool closes while this worker is starting

    monkeypatch.setattr(W, "GuardWorker", Recording)
    with pytest.raises(W.WorkerStartError, match="closed"):
        p.check(SQL, origin=W.ORIGIN_HUMAN)
    assert len(created) == 1 and created[0].proc.poll() is not None
    assert p.status()["workers_started"] == 0 and not p._busy


def test_checks_never_leave_workers_marked_busy():
    p = fake_pool("Blocking")
    try:
        for _ in range(3):
            p.check(SQL, origin=W.ORIGIN_HUMAN)
        assert not p._busy
    finally:
        p.close()
    p = fake_pool("Crashing")
    try:
        with pytest.raises(W.WorkerFailed):
            p.check(SQL, origin=W.ORIGIN_HUMAN)
        assert not p._busy
    finally:
        p.close()


# ---- application lifecycle ----------------------------------------------------------------------
class CountingPool:
    def __init__(self, raises=False):
        self.closes = 0
        self.raises = raises
        self.degraded = None

    def close(self):
        self.closes += 1
        if self.raises:
            raise RuntimeError("close failed PWD=example-fake-pw")
        return True

    def status(self):
        return {"size": 1, "idle_workers": 0, "degraded": None}


def make_app(pool):
    return A.create_app(ApiSettings(token=TOKEN), pool=pool, pipeline=None)


def test_lifespan_shutdown_closes_the_pool_exactly_once():
    pool = CountingPool()
    app = make_app(pool)
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        assert pool.closes == 0
    assert pool.closes == 1 and app.state.ctx.shut_down


def test_repeated_shutdown_does_not_close_twice():
    pool = CountingPool()
    app = make_app(pool)
    with TestClient(app):
        pass
    assert A.shutdown_app(app) is False  # e.g. main()'s finally after the lifespan hook ran
    with TestClient(app):  # a second lifespan cycle
        pass
    assert pool.closes == 1


def test_concurrent_shutdown_closes_once():
    pool = CountingPool()
    app = make_app(pool)
    barrier = threading.Barrier(8)
    results = []

    def go():
        barrier.wait()
        results.append(A.shutdown_app(app))

    threads = [threading.Thread(target=go) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert pool.closes == 1 and sorted(results) == [False] * 7 + [True]


def test_shutdown_without_a_pool():
    app = A.create_app(ApiSettings(), pool=None, pipeline=None)
    with TestClient(app):
        pass
    assert app.state.ctx.shut_down and A.shutdown_app(app) is False


def test_failing_close_does_not_break_shutdown(caplog):
    pool = CountingPool(raises=True)
    app = make_app(pool)
    with TestClient(app):
        pass
    assert pool.closes == 1 and A.shutdown_app(app) is False
    assert "example-fake-pw" not in caplog.text


@pytest.mark.parametrize("outcome", ["returns", "raises", "no_lifespan"])
def test_main_closes_the_pool_once(monkeypatch, outcome):
    import uvicorn

    from db2intel.api import __main__ as M

    pool = CountingPool()
    app = make_app(pool)
    monkeypatch.setattr(M, "build_app", lambda: (app, app.state.ctx.api))

    def fake_run(asgi_app, **kw):
        if outcome == "no_lifespan":  # e.g. uvicorn exits before its lifespan shutdown runs
            return
        with TestClient(asgi_app):  # what uvicorn does: startup, serve, lifespan shutdown
            pass
        if outcome == "raises":
            raise KeyboardInterrupt

    monkeypatch.setattr(uvicorn, "run", fake_run)
    if outcome == "raises":
        with pytest.raises(KeyboardInterrupt):
            M.main()
    else:
        assert M.main() == 0
    assert pool.closes == 1


# ---- SIGTERM to a real server process ---------------------------------------------------------------
def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, tmp_path, backend, deadline=10, extra_env=None):
        self.port = free_port()
        self.close_log = tmp_path / "close.log"
        self.out = open(tmp_path / "server.out", "wb")
        env = {**os.environ, W.OFFLINE_ENV: "1", "PYTHONPATH": f"{SRC_DIR}{os.pathsep}{TESTS_DIR}", **(extra_env or {})}
        self.proc = subprocess.Popen(
            [sys.executable, str(TESTS_DIR / "sigterm_server.py"), str(self.port), backend, str(self.close_log), str(deadline)],
            env=env, stdout=self.out, stderr=subprocess.STDOUT, start_new_session=True)
        self.client = httpx.Client(base_url=f"http://127.0.0.1:{self.port}", timeout=30)
        if not wait_for(self._up, 20):
            self.stop()
            raise AssertionError("server did not start: " + (tmp_path / "server.out").read_text()[-500:])

    def _up(self):
        try:
            return self.client.get("/health").status_code == 200
        except httpx.TransportError:
            return False

    def sigterm(self, seconds=20) -> int:
        self.proc.send_signal(signal.SIGTERM)
        return self.proc.wait(timeout=seconds)

    def closes(self) -> list[str]:
        return self.close_log.read_text().splitlines() if self.close_log.exists() else []

    def stop(self):
        self.client.close()
        if self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGKILL)
            self.proc.wait()
        self.out.close()


@pytest.fixture
def server(tmp_path):
    started = []

    def start(*a, **k):
        s = Server(tmp_path, *a, **k)
        started.append(s)
        return s

    yield start
    for s in started:
        s.stop()


def test_sigterm_with_no_worker_started(server):
    s = server("Approving")
    assert s.client.get("/api/v1/guard/status", headers=AUTH).json()["pool"]["workers_started"] == 0
    assert s.sigterm() == -signal.SIGTERM  # uvicorn re-raises the signal after its graceful shutdown
    assert s.closes() == ["close returned=True"]


def test_sigterm_closes_the_pool_and_reaps_the_idle_worker(server):
    s = server("Approving")
    r = s.client.post("/api/v1/guard/check", json={"sql": GOOD}, headers=AUTH)
    assert r.status_code == 200 and r.json()["status"] == "APPROVED" and r.json()["executed"] is False
    worker_pid = int(r.json()["reason"].split()[-1])
    assert not gone(worker_pid)
    assert s.sigterm() == -signal.SIGTERM
    assert s.closes() == ["close returned=True"]  # exactly once, from the lifespan hook
    assert wait_gone(worker_pid)


def test_sigterm_during_a_check_waits_for_it_and_leaves_no_processes(server, tmp_path):
    pidfile = tmp_path / "grandchild.pid"
    s = server("HangingWithGrandchild", deadline=3, extra_env={"GRANDCHILD_PIDFILE": str(pidfile)})
    responses = []
    thread = threading.Thread(target=lambda: responses.append(
        s.client.post("/api/v1/guard/check", json={"sql": GOOD}, headers=AUTH)))
    thread.start()
    assert wait_for(lambda: pidfile.exists() and pidfile.read_text().strip())
    grandchild = int(pidfile.read_text())
    assert s.sigterm(seconds=30) == -signal.SIGTERM
    thread.join(10)
    # uvicorn let the in-flight request finish: the worker hit its deadline and was killed
    assert responses and responses[0].status_code == 504 and responses[0].json()["executed"] is False
    assert s.closes() == ["close returned=True"]
    assert wait_gone(grandchild)
    assert subprocess.run(["pgrep", "-f", f"sigterm_server.py {s.port}"], capture_output=True).stdout == b""
