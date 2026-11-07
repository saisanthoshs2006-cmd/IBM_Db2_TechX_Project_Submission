"""Fake guard-worker backends, loaded inside real worker subprocesses by tests.

None of them imports ibm_db or opens a connection. Each mimics one behaviour of the real
backend (db2intel.guard.worker.Db2Backend) that the pool must handle.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

CONTEXT = {"database": "TESTDB", "allowed_schemas": ["DB2INTEL_DEMO"], "max_rows": 500, "max_estimated_cost": 50000.0}


def _decision(request_id, status="APPROVED", code="approved", reason="all checks passed", sql=None, **extra):
    base = {
        "request_id": request_id, "status": status, "code": code, "reason": reason,
        "sql": sql if sql is not None else ("SELECT 1 FROM SYSIBM.SYSDUMMY1 FETCH FIRST 500 ROWS ONLY" if status == "APPROVED" else None),
        "estimated_cost": 7.0, "explain_cost": 6.9,
        "objects": [["DB2INTEL_DEMO", "CUSTOMER", "TA"]], "plan": [[1, "RETURN", 7.0]], "sqlstate": None,
    }
    base.update(extra)
    return base


class Base:
    def __init__(self):
        assert "ibm_db" not in sys.modules
        self.pid = os.getpid()

    def context(self):
        return dict(CONTEXT, pid=self.pid)

    def close(self):
        pass


class Approving(Base):
    def check(self, sql, request_id):
        return _decision(request_id, reason=f"pid {self.pid}")


class Blocking(Base):
    def check(self, sql, request_id):
        return _decision(request_id, "BLOCKED", "prepare_failed",
                         'prepare failed: [IBM][CLI Driver][DB2/LINUXX8664] SQL0204N  "DB2INTEL_DEMO.NOPE" is an '
                         "undefined name.  SQLSTATE=42704", sqlstate="42704")


class Hanging(Base):
    def check(self, sql, request_id):
        time.sleep(120)


class HangingWithGrandchild(Base):
    def check(self, sql, request_id):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
        with open(os.environ["GRANDCHILD_PIDFILE"], "w") as fh:
            fh.write(str(child.pid))
        time.sleep(120)


class IgnoresSignals(Base):
    def check(self, sql, request_id):
        import signal
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        time.sleep(120)


class Crashing(Base):
    def check(self, sql, request_id):
        os._exit(3)


class CleanupFailed(Base):
    def check(self, sql, request_id):
        return _decision(request_id, "ERROR", "cleanup_failed",
                         "explain rows are still present after rollback: EXPLAIN_OBJECT=2")


class Malformed(Base):
    def check(self, sql, request_id):
        return _decision(request_id, status="MAYBE")


class WrongRequestId(Base):
    def check(self, sql, request_id):
        return _decision("00000000-0000-0000-0000-000000000000")


class ApprovedWithoutSql(Base):
    def check(self, sql, request_id):
        return dict(_decision(request_id), sql=None)


class Raising(Base):
    def check(self, sql, request_id):
        raise RuntimeError("PWD=hunter2 should never be shown")


class Noisy(Base):
    """Prints to stdout during startup and checks; the protocol channel must stay clean."""

    def __init__(self):
        print("noise on stdout during startup")
        super().__init__()

    def check(self, sql, request_id):
        print("noise on stdout during check", flush=True)
        os.write(1, b"raw noise on fd 1\n")
        return _decision(request_id)


class Slow(Base):
    def check(self, sql, request_id):
        time.sleep(float(os.environ.get("SLOW_SECONDS", "1.5")))
        return _decision(request_id)


class EchoSql(Base):
    def check(self, sql, request_id):
        with open(os.environ["ECHO_FILE"], "a") as fh:
            fh.write(sql + "\n")
        return _decision(request_id)


class StartupFails(Base):
    def __init__(self):
        raise RuntimeError("cannot connect: PWD=hunter2")


class StartupHangs(Base):
    def __init__(self):
        time.sleep(120)


class HugeMessage(Base):
    def check(self, sql, request_id):
        return _decision(request_id, reason="x" * 2_000_000)


# ---- G1.2 -----------------------------------------------------------------------------------
class EnvReport(Base):
    """Reports the names of the variables in its own environment (never their values)."""

    def context(self):
        return dict(CONTEXT, env_keys=sorted(os.environ))


class StderrNoise(Base):
    """Writes secrets, an over-long line and control characters to stderr (fd 2 and sys.stderr)."""

    def __init__(self):
        super().__init__()
        secret = os.environ.get("DB2_PASSWORD", "")
        os.write(2, f"driver says: connect failed PWD={secret};UID=db2inst1\n".encode())
        os.write(2, f"echo of the raw password {secret} in free text\n".encode())
        os.write(2, b"Authorization: Bearer example-fake-bearer-value-123\n")
        os.write(2, ("key sk-example-fake-key-0123 and " + "AKIA" + "EXAMPLEFAKEKEY12\n").encode())  # built at runtime
        os.write(2, b"ctrl\x1b[31mchars\x07here\n")
        os.write(2, b"L" * 100_000 + b"\n")
        sys.stderr.write("after the long line\n")
        sys.stderr.flush()

    def check(self, sql, request_id):
        os.write(2, b"stderr during check\n")
        return _decision(request_id)


class ExplainRowsAtStartup(Base):
    """Refuses to start the way Db2Backend does when the explain tables are not empty."""

    def __init__(self):
        from db2intel.guard.worker import EXPLAIN_NOT_EMPTY_CODE, BackendRefused

        raise BackendRefused("explain tables in DB2INTEL are not empty (EXPLAIN_INSTANCE=1)",
                             code=EXPLAIN_NOT_EMPTY_CODE)


class RefusesWithOddCode(Base):
    def __init__(self):
        from db2intel.guard.worker import BackendRefused

        raise BackendRefused("refused", code="Not A Valid Code!")


class HangsOnSecondCheck(Base):
    """Approves the first check, then hangs: lets a test close the pool while a reused worker is busy."""

    def __init__(self):
        super().__init__()
        self.calls = 0

    def check(self, sql, request_id):
        self.calls += 1
        if self.calls > 1:
            time.sleep(120)
        return _decision(request_id, reason=f"pid {self.pid}")


class GrandchildAtStartup(Base):
    """Starts a grandchild process during startup and records its pid in GRANDCHILD_PIDFILE."""

    def __init__(self):
        super().__init__()
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
        with open(os.environ["GRANDCHILD_PIDFILE"], "w") as fh:
            fh.write(str(child.pid))

    def check(self, sql, request_id):
        return _decision(request_id)
