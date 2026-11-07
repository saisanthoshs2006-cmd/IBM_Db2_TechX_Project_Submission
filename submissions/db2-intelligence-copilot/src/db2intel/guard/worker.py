"""Guard worker subprocesses: prepare-only checks with a hard deadline (Phase 2C).

Why a subprocess: ibm_db has no cancel call, a Python thread cannot be killed, and
SQL_ATTR_QUERY_TIMEOUT cannot be confirmed on a connection handle (ibm_db 3.3.0), so the
EXPLAIN_FROM_SECTION call has no verified Db2-side bound. A worker process that misses its
deadline is SIGKILLed with its whole process group; Db2 then rolls back the dropped
connection's unit of work. Nothing in this module ever commits.

Parent side
  GuardPool    at most `size` workers, a bounded wait for a free slot (PoolBusy otherwise),
               a deadline per check, and a degraded latch. Once latched, every later check is
               refused until the process restarts. It latches when cleanup cannot be shown to
               have happened: a cleanup_failed decision, a worker killed at its deadline, a
               worker that died or broke the protocol mid-check, or an unexpected backend error.
               Nothing is cleaned up automatically. It also latches when a worker refuses to
               start because the explain tables are not empty.
  check(sql, origin=...) accepts only ORIGIN_HUMAN. AI-generated SQL is refused here
               (AISqlNotAllowed) until gate G4 is approved; AI_SQL_CHECK_ENABLED is False.
  Environment  workers get an allow-listed environment (worker_env): the Db2 connection
               settings, locale, PATH and driver library paths. The API token, LLM settings
               and any other API keys are never passed to a worker.
  stderr       discarded, or (with a WorkerStderrLog) redacted, truncated per line and written
               to a size-bounded log file with one rotation.

Child side (python -m db2intel.guard.worker --backend db2)
  One JSON message per line on the original stdout; anything else the child prints goes to
  stderr. The "db2" backend reads only allow-listed keys from .env (worker_settings_env),
  connects, pins CURRENT PATH, runs the read-only guard preflight, checks with read-only
  COUNT(*) queries that all 11 explain tables are empty (refusing to start otherwise) and then
  answers check requests with guard.analysis.analyze(), which prepares only and rolls back.
  With DB2INTEL_OFFLINE=1 the db2 backend refuses to start (the test suite sets it). There is
  no execute request.
"""
from __future__ import annotations

import argparse
import importlib
import json
import math
import os
import re
import select
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 1_000_000
MAX_SQL_CHARS = 20_000
ORIGIN_HUMAN = "human"
ORIGIN_AI = "ai"
AI_SQL_CHECK_ENABLED = False  # gate G4: AI-generated SQL is never prepared in Phase 2C
DB2_BACKEND = "db2"
OFFLINE_ENV = "DB2INTEL_OFFLINE"
EXPLAIN_NOT_EMPTY_CODE = "explain_tables_not_empty"
LATCHING_STARTUP_CODES = frozenset({EXPLAIN_NOT_EMPTY_CODE})  # conditions a restart cannot clear

STATUSES = frozenset({"APPROVED", "BLOCKED", "COST_REJECTED", "ERROR"})
_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SQLSTATE_RE = re.compile(r"^[0-9A-Z]{5}$")
_SRC_DIR = Path(__file__).resolve().parents[2]  # .../src


# ---- errors raised to the API ---------------------------------------------------------------
class GuardServiceError(RuntimeError):
    code = "guard_error"


class PoolBusy(GuardServiceError):
    code = "busy"


class Degraded(GuardServiceError):
    code = "degraded"


class AISqlNotAllowed(GuardServiceError):
    code = "ai_sql_not_checkable"


class WorkerStartError(GuardServiceError):
    code = "guard_unavailable"

    def __init__(self, message: str, startup_code: str | None = None):
        super().__init__(message)
        self.startup_code = startup_code  # the worker's startup_error code, when it sent one


class WorkerTimeout(GuardServiceError):
    code = "check_timeout"


class WorkerFailed(GuardServiceError):
    code = "worker_failed"


class _ProtocolError(Exception):
    pass


# ---- decision validation (parent never trusts the child's message shape) --------------------
def _opt_cost(value, what: str):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise _ProtocolError(f"invalid {what}")
    return float(value)


def _short_str(value, what: str, limit: int, optional: bool = False):
    if value is None and optional:
        return None
    if not isinstance(value, str) or len(value) > limit:
        raise _ProtocolError(f"invalid {what}")
    return value


def validate_decision(raw: Any, request_id: str) -> dict:
    """Return a clean decision dict, or raise _ProtocolError."""
    if not isinstance(raw, dict):
        raise _ProtocolError("decision is not an object")
    if raw.get("request_id") != request_id:
        raise _ProtocolError("decision is for a different request")
    status = raw.get("status")
    if status not in STATUSES:
        raise _ProtocolError("invalid status")
    code = raw.get("code")
    if not isinstance(code, str) or not _CODE_RE.match(code):
        raise _ProtocolError("invalid code")
    sqlstate = raw.get("sqlstate")
    if sqlstate is not None and (not isinstance(sqlstate, str) or not _SQLSTATE_RE.match(sqlstate)):
        raise _ProtocolError("invalid sqlstate")
    objects = raw.get("objects", [])
    plan = raw.get("plan", [])
    if not isinstance(objects, list) or len(objects) > 1000 or not isinstance(plan, list) or len(plan) > 5000:
        raise _ProtocolError("invalid objects or plan")
    clean_objects = []
    for item in objects:
        if not (isinstance(item, list) and len(item) == 3 and all(isinstance(v, str) and len(v) <= 128 for v in item)):
            raise _ProtocolError("invalid object entry")
        clean_objects.append(tuple(item))
    clean_plan = []
    for item in plan:
        if not (isinstance(item, list) and len(item) == 3 and isinstance(item[0], int) and not isinstance(item[0], bool)
                and isinstance(item[1], str) and len(item[1]) <= 32):
            raise _ProtocolError("invalid plan entry")
        clean_plan.append((item[0], item[1], _opt_cost(item[2], "operator cost")))
    decision = {
        "request_id": request_id,
        "status": status,
        "code": code,
        "reason": _short_str(raw.get("reason"), "reason", 4000),
        "sql": _short_str(raw.get("sql"), "sql", MAX_SQL_CHARS + 100, optional=True),
        "estimated_cost": _opt_cost(raw.get("estimated_cost"), "estimated cost"),
        "explain_cost": _opt_cost(raw.get("explain_cost"), "explain cost"),
        "objects": tuple(clean_objects),
        "plan": tuple(clean_plan),
        "sqlstate": sqlstate,
    }
    if status == "APPROVED" and (decision["sql"] is None or code != "approved"):
        raise _ProtocolError("approved decision without SQL")
    return decision


def decision_to_message(decision) -> dict:
    """GuardDecision -> JSON-safe dict (child side)."""
    return {
        "request_id": decision.request_id,
        "status": decision.status,
        "code": decision.code,
        "reason": decision.reason,
        "sql": decision.sql,
        "estimated_cost": decision.estimated_cost,
        "explain_cost": decision.explain_cost,
        "objects": [list(o) for o in decision.objects],
        "plan": [[op.operator_id, op.operator_type, op.total_cost] for op in decision.plan],
        "sqlstate": decision.sqlstate,
    }


# ---- parent: one worker process ------------------------------------------------------------
def worker_argv(backend: str, python: str = sys.executable) -> list[str]:
    return [python, "-m", "db2intel.guard.worker", "--backend", backend]


# Only these variables reach a worker. Everything else (the API token, LLM settings, OpenAI or
# watsonx keys, unrelated shell variables) is dropped. DB2_* carries the connection settings,
# including DB2_PASSWORD, which the worker needs to connect.
WORKER_ENV_NAMES = frozenset({
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "TZ", "TMPDIR", "SYSTEMROOT", "PYTHONHOME",
    OFFLINE_ENV, "DB2INTEL_MIGRATION_DATABASES", "DB2INTEL_MIGRATION_HOSTS",
    "EMBEDDING_PROVIDER", "EMBEDDING_MODEL", "EMBEDDING_DIM", "EMBEDDING_TIMEOUT_SECONDS", "OLLAMA_BASE_URL",
    "IBM_DB_HOME", "DB2INSTANCE", "DB2DSDRIVER_CFG_PATH", "DYLD_LIBRARY_PATH", "LD_LIBRARY_PATH", "LIBPATH",
})
WORKER_ENV_PREFIXES = ("DB2_", "LC_")
# Never passed to a worker, not even through extra_env.
WORKER_ENV_DENIED = frozenset({"DB2INTEL_API_TOKEN", "OPENAI_API_KEY", "WATSONX_APIKEY", "WATSONX_PROJECT_ID"})


def worker_env_allowed(name: str) -> bool:
    return name not in WORKER_ENV_DENIED and (name in WORKER_ENV_NAMES or name.startswith(WORKER_ENV_PREFIXES))


def worker_env(extra_pythonpath: tuple[str, ...] = (), base: Mapping[str, str] | None = None,
               extra_env: Mapping[str, str] | None = None) -> dict:
    """The worker's environment: the allow-listed part of `base` (default os.environ).

    extra_env adds variables that are not on the allow-list; it exists for the fake backends in
    the test suite. Denied names are removed even from extra_env.
    """
    source = os.environ if base is None else base
    env = {k: v for k, v in source.items() if worker_env_allowed(k)}
    env.update({k: v for k, v in (extra_env or {}).items() if k not in WORKER_ENV_DENIED})
    paths = [str(_SRC_DIR), *extra_pythonpath]
    if source.get("PYTHONPATH"):
        paths.append(source["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(paths)
    env["PYTHONUNBUFFERED"] = "1"
    return env


def worker_settings_env(environ: Mapping[str, str] | None = None, dotenv_path: Path | None = None) -> dict:
    """Child side: settings for load_settings() without importing .env wholesale.

    load_settings() with no argument would copy every .env key (the API token and any API keys
    included) into the worker's os.environ. Here only allow-listed .env keys are used, and the
    process environment wins over .env, as with load_dotenv.
    """
    from db2intel.config import load_dotenv

    file_values: dict = {}
    load_dotenv(dotenv_path, file_values)
    env = {k: v for k, v in file_values.items() if worker_env_allowed(k)}
    env.update(os.environ if environ is None else environ)
    return env


SECRET_NAME_RE = re.compile(r"(?i)(PASSWORD|PASSWD|PWD|TOKEN|SECRET|API_?KEY|APIKEY)")
_REDACT_AUTH_RE = re.compile(r"(?i)\b(authorization|proxy-authorization)(\s*[=:]\s*)[^\r\n]*")  # whole header value
_REDACT_ASSIGN_RE = re.compile(
    r"(?i)\b(pwd|password|passwd|token|api[_-]?key|apikey|secret|authorization)(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s;,&]+)")
_REDACT_BEARER_RE = re.compile(r"(?i)\bbearer\s+[^\s;,]+")
_REDACT_KEYS_RE = re.compile(r"(sk-[A-Za-z0-9_\-]{8,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
MIN_SECRET_LEN = 4  # shorter values are not replaced literally (they would mangle every line)


def secret_values(env: Mapping[str, str]) -> tuple[str, ...]:
    """Values of variables whose names look secret, for literal redaction."""
    return tuple(sorted({v for k, v in env.items() if SECRET_NAME_RE.search(k) and len(v) >= MIN_SECRET_LEN},
                        key=len, reverse=True))


class WorkerStderrLog:
    """Bounded, redacted sink for guard worker stderr.

    Each line is redacted (known secret values, key=value credentials, bearer tokens, API and
    private keys), stripped of control characters and truncated before it reaches disk. The
    file is rotated once to <name>.1<suffix> when it would exceed max_bytes, so the log never
    uses more than about 2 * max_bytes. Files are created with mode 0600.
    """

    def __init__(self, path: Path | str, *, max_bytes: int = 1_000_000, max_line_chars: int = 500,
                 secrets: tuple[str, ...] = ()):
        if not 1_000 <= max_bytes <= 100_000_000 or not 80 <= max_line_chars <= 10_000:
            raise ValueError("invalid worker log limits")
        self.path = Path(path)
        if self.path.suffix != ".log":
            raise ValueError("the worker log file name must end in .log (the repository ignores *.log)")
        self.backup = self.path.with_name(f"{self.path.stem}.1{self.path.suffix}")
        self.max_bytes = max_bytes
        self.max_line_chars = max_line_chars
        self._secrets = tuple(s for s in secrets if len(s) >= MIN_SECRET_LEN)
        self._lock = threading.Lock()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    def redact(self, text: str) -> str:
        for value in self._secrets:
            text = text.replace(value, "***")
        text = _REDACT_AUTH_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}***", text)
        text = _REDACT_ASSIGN_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}***", text)
        text = _REDACT_BEARER_RE.sub("Bearer ***", text)
        text = _REDACT_KEYS_RE.sub("***", text)
        return _CONTROL_RE.sub(" ", text)

    def write(self, pid: int, raw: bytes, truncated: bool = False) -> None:
        line = self.redact(raw.decode("utf-8", "replace").rstrip("\r\n"))
        if len(line) > self.max_line_chars:
            line, truncated = line[: self.max_line_chars], True
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        entry = f"{stamp} pid={pid} {line}{' [truncated]' if truncated else ''}\n".encode("utf-8")
        with self._lock:
            try:
                size = self.path.stat().st_size
            except FileNotFoundError:
                size = 0
            if size and size + len(entry) > self.max_bytes:
                os.replace(self.path, self.backup)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, entry)
            finally:
                os.close(fd)

    def drain(self, pid: int, stream) -> threading.Thread:
        """Read `stream` to EOF in a daemon thread so the worker never blocks on a full pipe."""
        limit = self.max_line_chars * 4  # bytes; enough for max_line_chars of UTF-8 text

        def run():
            skipping = False  # inside the rest of an over-long line
            try:
                while True:
                    chunk = stream.readline(limit)
                    if not chunk:
                        return
                    cut = len(chunk) >= limit and not chunk.endswith(b"\n")  # line longer than limit
                    if not skipping:
                        try:
                            self.write(pid, chunk, truncated=cut)
                        except OSError:
                            pass  # logging must never break a check
                    skipping = cut
            except (OSError, ValueError):
                return
            finally:
                try:
                    stream.close()
                except Exception:
                    pass

        thread = threading.Thread(target=run, name=f"guard-worker-stderr-{pid}", daemon=True)
        thread.start()
        return thread


class GuardWorker:
    """A started worker process. Not thread-safe: the pool hands it to one request at a time."""

    def __init__(self, argv: list[str], env: dict, startup_deadline: float,
                 stderr_log: WorkerStderrLog | None = None):
        self._buf = b""
        self.context: dict = {}
        try:
            self.proc = subprocess.Popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE if stderr_log is not None else subprocess.DEVNULL,
                env=env, start_new_session=True, close_fds=True,
            )
        except OSError as exc:
            raise WorkerStartError(f"could not start the guard worker ({type(exc).__name__})") from None
        if stderr_log is not None:
            stderr_log.drain(self.proc.pid, self.proc.stderr)
        try:
            msg = self._read(time.monotonic() + startup_deadline)
        except WorkerTimeout:
            self.kill()
            raise WorkerStartError("the guard worker did not become ready before its startup deadline") from None
        except (WorkerFailed, _ProtocolError):
            self.kill()
            raise WorkerStartError("the guard worker exited during startup") from None
        if msg.get("type") == "ready" and isinstance(msg.get("context"), dict):
            self.context = msg["context"]
            return
        self.kill()
        code = msg.get("code") if isinstance(msg.get("code"), str) and _CODE_RE.match(msg.get("code", "")) else "startup_failed"
        raise WorkerStartError(f"the guard worker could not start ({code})", startup_code=code)

    @property
    def pid(self) -> int:
        return self.proc.pid

    def alive(self) -> bool:
        return self.proc.poll() is None

    def _read(self, deadline: float) -> dict:
        fd = self.proc.stdout.fileno()
        while b"\n" not in self._buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WorkerTimeout("deadline reached")
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                continue
            chunk = os.read(fd, 65_536)
            if not chunk:
                raise WorkerFailed("the guard worker exited unexpectedly")
            self._buf += chunk
            if len(self._buf) > MAX_MESSAGE_BYTES:
                raise _ProtocolError("message too large")
        line, self._buf = self._buf.split(b"\n", 1)
        try:
            msg = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise _ProtocolError("message is not JSON") from None
        if not isinstance(msg, dict) or msg.get("v") != PROTOCOL_VERSION:
            raise _ProtocolError("wrong protocol version")
        return msg

    def request(self, payload: dict, deadline_seconds: float) -> dict:
        deadline = time.monotonic() + deadline_seconds
        data = (json.dumps({"v": PROTOCOL_VERSION, **payload}) + "\n").encode("utf-8")
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            raise WorkerFailed("the guard worker is not accepting requests") from None
        return self._read(deadline)

    def signal_kill(self) -> None:
        """SIGKILL the worker's process group without touching its pipes.

        Used by GuardPool.close() for a worker that another thread is reading from: that thread
        sees EOF and discards the worker. Closing the pipes here could pull a file descriptor
        out from under its select() call.
        """
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    def kill(self) -> None:
        """SIGKILL the worker's process group and reap it."""
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # uninterruptible I/O; nothing more can be done here
            pass
        for stream in (self.proc.stdin, self.proc.stdout):
            try:
                stream.close()
            except Exception:
                pass

    def close(self) -> None:
        """Ask the worker to exit (EOF on stdin), then make sure it is gone."""
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        self.kill()


# ---- parent: the pool ------------------------------------------------------------------------
@dataclass
class PoolStats:
    started: int = 0
    killed: int = 0
    checks: int = 0
    busy_rejections: int = 0


class GuardPool:
    def __init__(self, size: int = 2, check_deadline: float = 60, startup_deadline: float = 60,
                 queue_wait: float = 2, backend: str = DB2_BACKEND, python: str = sys.executable,
                 extra_pythonpath: tuple[str, ...] = (), env: Mapping[str, str] | None = None,
                 on_degraded: Callable[[str], None] | None = None, extra_env: Mapping[str, str] | None = None,
                 stderr_log: Path | str | None = None):
        if not 1 <= size <= 4:
            raise ValueError("pool size must be between 1 and 4")
        if not 0 < check_deadline <= 300 or not 0 < startup_deadline <= 300 or not 0 <= queue_wait <= 30:
            raise ValueError("invalid pool deadlines")
        self.size = size
        self.check_deadline = check_deadline
        self.startup_deadline = startup_deadline
        self.queue_wait = queue_wait
        self.backend = backend
        self._argv = worker_argv(backend, python)
        base = os.environ if env is None else env
        self._env = worker_env(extra_pythonpath, base, extra_env)
        # Secrets are collected from the full environment, including variables a worker never sees.
        self._stderr_log = None if stderr_log is None else WorkerStderrLog(
            stderr_log, secrets=secret_values({**base, **(extra_env or {})}))
        self._slots = threading.BoundedSemaphore(size)
        self._lock = threading.Lock()
        self._idle: list[GuardWorker] = []
        self._busy: set[GuardWorker] = set()  # handed to a check, not yet returned or discarded
        self._degraded: str | None = None
        self._on_degraded = on_degraded
        self.stats = PoolStats()
        self._closed = False

    # degraded latch: set once, never cleared while this process lives
    @property
    def degraded(self) -> str | None:
        return self._degraded

    def _latch(self, reason: str) -> None:
        with self._lock:
            if self._degraded is None:
                self._degraded = reason
                if self._on_degraded:
                    try:
                        self._on_degraded(reason)
                    except Exception:
                        pass

    def status(self) -> dict:
        with self._lock:
            return {
                "size": self.size,
                "idle_workers": len(self._idle),
                "degraded": self._degraded,
                "check_deadline_seconds": self.check_deadline,
                "ai_sql_check_enabled": AI_SQL_CHECK_ENABLED,
                "workers_started": self.stats.started,
                "workers_killed": self.stats.killed,
                "checks": self.stats.checks,
                "busy_rejections": self.stats.busy_rejections,
                "worker_stderr_logged": self._stderr_log is not None,
            }

    def _take_worker(self) -> GuardWorker:
        with self._lock:
            while self._idle:
                worker = self._idle.pop()
                if worker.alive():
                    self._busy.add(worker)
                    return worker
                worker.kill()
        try:
            worker = GuardWorker(self._argv, self._env, self.startup_deadline, self._stderr_log)
        except WorkerStartError as exc:
            if exc.startup_code in LATCHING_STARTUP_CODES:
                self._latch("a guard worker found rows in the explain tables at startup; they must be inspected "
                            "manually (nothing is cleaned up automatically)")
                raise Degraded(self._degraded) from None
            raise
        with self._lock:
            closed = self._closed
            if not closed:
                self.stats.started += 1
                self._busy.add(worker)
        if closed:  # the pool was closed while this worker was starting
            worker.kill()
            raise WorkerStartError("the guard pool is closed")
        return worker

    def _discard(self, worker: GuardWorker) -> None:
        worker.kill()
        with self._lock:
            self.stats.killed += 1

    def check(self, sql: str, *, origin: str) -> dict:
        """Prepare-only check of human-written SQL in a worker. Never executes the query."""
        if origin != ORIGIN_HUMAN:  # gate G4 (AI-generated SQL) is not approved
            raise AISqlNotAllowed("AI-generated SQL is not prepared or explained until gate G4 is approved")
        if not isinstance(sql, str) or not sql.strip() or len(sql) > MAX_SQL_CHARS:
            raise ValueError("sql must be a non-empty string of at most 20000 characters")
        if self._closed:
            raise WorkerStartError("the guard pool is closed")
        if self._degraded:
            raise Degraded(self._degraded)
        if not self._slots.acquire(timeout=self.queue_wait):
            with self._lock:
                self.stats.busy_rejections += 1
            raise PoolBusy("all guard workers are busy; try again shortly")
        worker = None
        try:
            if self._degraded:  # latched while this request waited
                raise Degraded(self._degraded)
            worker = self._take_worker()
            request_id = str(uuid.uuid4())
            with self._lock:
                self.stats.checks += 1
            try:
                reply = worker.request({"type": "check", "id": request_id, "sql": sql}, self.check_deadline)
            except WorkerTimeout:
                self._discard(worker)
                self._latch(f"a guard worker was killed at its {self.check_deadline:g}s deadline; "
                            "cleanup of its explain rows was not verified")
                raise WorkerTimeout(f"the check did not finish within {self.check_deadline:g}s; the worker was killed") from None
            except (WorkerFailed, _ProtocolError):
                self._discard(worker)
                self._latch("a guard worker failed during a check; cleanup was not verified")
                raise WorkerFailed("the guard worker failed during the check") from None

            if reply.get("type") == "result" and reply.get("id") == request_id:
                try:
                    decision = validate_decision(reply.get("decision"), request_id)
                except _ProtocolError:
                    self._discard(worker)
                    self._latch("a guard worker returned a malformed decision; cleanup was not verified")
                    raise WorkerFailed("the guard worker returned a malformed decision") from None
                if decision["code"] == "cleanup_failed":
                    self._discard(worker)
                    self._latch("explain rows could not be shown to be removed after rollback (cleanup_failed)")
                else:
                    with self._lock:
                        if self._closed:
                            worker.close()
                        else:
                            self._idle.append(worker)
                return decision
            # an error reply (unexpected exception in the backend) or a mismatched id
            self._discard(worker)
            self._latch("a guard worker reported an unexpected error during a check; cleanup was not verified")
            raise WorkerFailed("the guard check failed unexpectedly")
        finally:
            if worker is not None:
                with self._lock:
                    self._busy.discard(worker)
            self._slots.release()

    def close(self, reap_seconds: float = 10) -> bool:
        """Shut the pool down. Idempotent: returns True for the call that closed it, else False.

        Idle workers get EOF on stdin and are reaped (SIGKILLed after 5s if they linger). Workers
        still inside a check are SIGKILLed with their process group; the thread running that check
        sees EOF, fails the check and discards the worker, and this call waits up to reap_seconds
        for each of them to be reaped. Workers that finish starting after this call are killed.
        """
        with self._lock:
            if self._closed:
                return False
            self._closed = True
            idle, self._idle = self._idle, []
            busy = list(self._busy)
        for worker in busy:
            worker.signal_kill()
        for worker in idle:
            worker.close()
        for worker in busy:
            try:
                worker.proc.wait(timeout=reap_seconds)
            except subprocess.TimeoutExpired:  # uninterruptible I/O; nothing more can be done here
                pass
        return True

    @property
    def closed(self) -> bool:
        return self._closed


# ---- child ---------------------------------------------------------------------------------
class BackendRefused(RuntimeError):
    def __init__(self, message: str, code: str = "backend_refused"):
        super().__init__(message)
        self.code = code


class Db2Backend:
    """Real backend: one analysis connection, autocommit OFF, prepare-only, never commits."""

    def __init__(self):
        if os.environ.get(OFFLINE_ENV) == "1":
            raise BackendRefused("offline mode: the Db2 guard backend is disabled")
        from db2intel.config import load_settings
        from db2intel.db.connection import Db2Connection
        from db2intel.db.migrate import check_migration_host
        from db2intel.guard.context import ExplainTablesNotEmpty, check_explain_tables_empty, load_guard_context
        from db2intel.guard.sessions import Db2AnalysisSession

        settings = load_settings(worker_settings_env())
        check_migration_host(settings.db2, settings.migration.allowed_hosts)
        self._conn = Db2Connection(settings.db2)
        try:
            self._session = Db2AnalysisSession(self._conn)
            try:
                self._session.pin_system_path()
                self.ctx = load_guard_context(self._session, settings.migration.allowed_databases)
                check_explain_tables_empty(self._session)  # read-only COUNT(*); never deletes
            except ExplainTablesNotEmpty as exc:
                raise BackendRefused(str(exc), code=EXPLAIN_NOT_EMPTY_CODE) from None
            finally:
                self._session.rollback()
        except BaseException:
            self._conn.close()
            raise

    def context(self) -> dict:
        return {"database": self.ctx.database, "allowed_schemas": sorted(self.ctx.allowed_schemas),
                "max_rows": self.ctx.limits.max_rows, "max_estimated_cost": self.ctx.limits.max_estimated_cost}

    def check(self, sql: str, request_id: str) -> dict:
        from db2intel.guard.analysis import analyze

        return decision_to_message(analyze(sql, self._session, self.ctx, request_id))

    def close(self) -> None:
        self._conn.close()


def load_backend(spec: str):
    if spec == DB2_BACKEND:
        return Db2Backend()
    module_name, _, attr = spec.partition(":")
    if not module_name or not attr:
        raise BackendRefused(f"unknown backend {spec!r}")
    return getattr(importlib.import_module(module_name), attr)()


def _child(spec: str) -> int:
    # Keep the protocol on a private copy of stdout; route anything else printed to stderr.
    proto = os.fdopen(os.dup(1), "w", encoding="utf-8", buffering=1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr

    def send(**msg):
        proto.write(json.dumps({"v": PROTOCOL_VERSION, **msg}) + "\n")
        proto.flush()

    try:
        backend = load_backend(spec)
    except BackendRefused as exc:
        print(f"guard worker refused to start: {exc.code}", file=sys.stderr)
        send(type="startup_error", code=exc.code if _CODE_RE.match(exc.code) else "backend_refused")
        return 1
    except Exception as exc:  # message withheld: it may contain connection details
        print(f"guard worker startup failed: {type(exc).__name__}", file=sys.stderr)
        send(type="startup_error", code="startup_failed")
        return 1
    try:
        send(type="ready", context=backend.context())
        for line in sys.stdin:
            try:
                msg = json.loads(line)
            except ValueError:
                send(type="error", id=None, code="bad_request")
                return 1
            if not isinstance(msg, dict) or msg.get("v") != PROTOCOL_VERSION or msg.get("type") != "check":
                send(type="error", id=None, code="bad_request")
                return 1
            req_id, sql = msg.get("id"), msg.get("sql")
            if not isinstance(req_id, str) or not isinstance(sql, str):
                send(type="error", id=req_id if isinstance(req_id, str) else None, code="bad_request")
                return 1
            try:
                decision = backend.check(sql, req_id)
            except Exception as exc:
                print(f"guard worker check failed: {type(exc).__name__}", file=sys.stderr)
                send(type="error", id=req_id, code="check_failed")
                return 1
            send(type="result", id=req_id, decision=decision)
        return 0
    finally:
        try:
            backend.close()
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m db2intel.guard.worker")
    parser.add_argument("--backend", default=DB2_BACKEND)
    args = parser.parse_args(argv)
    return _child(args.backend)


if __name__ == "__main__":
    # Run as the importable module, not as __main__: otherwise a backend that imports
    # db2intel.guard.worker gets a second copy whose BackendRefused this module would not catch.
    from db2intel.guard import worker as _module

    sys.exit(_module.main())
