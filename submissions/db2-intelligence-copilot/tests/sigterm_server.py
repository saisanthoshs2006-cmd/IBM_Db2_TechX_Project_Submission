"""Test helper (not a test): runs the real API entry point, db2intel.api.__main__.main(), under
uvicorn on 127.0.0.1 with a guard pool whose workers use a fake backend, so SIGTERM shutdown can be
tested with live worker processes and no database.

Usage: python sigterm_server.py PORT BACKEND CLOSE_LOG [CHECK_DEADLINE]
Every GuardPool.close() call appends one line to CLOSE_LOG.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from db2intel.api import __main__ as entry
from db2intel.api.app import create_app
from db2intel.config import ApiSettings
from db2intel.guard import worker as W

TOKEN = "example-fake-api-token-0123456789"
TESTS_DIR = str(Path(__file__).resolve().parent)


class RecordingPool(W.GuardPool):
    def __init__(self, close_log: str, **kw):
        super().__init__(**kw)
        self._close_log = close_log

    def close(self, *args, **kwargs):
        result = super().close(*args, **kwargs)
        with open(self._close_log, "a") as fh:
            fh.write(f"close returned={result}\n")
        return result


def main() -> int:
    port, backend, close_log = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    deadline = float(sys.argv[4]) if len(sys.argv) > 4 else 10
    env = {**os.environ, W.OFFLINE_ENV: "1"}
    extra = {k: v for k, v in os.environ.items() if k == "GRANDCHILD_PIDFILE"}
    pool = RecordingPool(close_log, size=1, backend=f"fake_guard_backends:{backend}", extra_pythonpath=(TESTS_DIR,),
                         env=env, extra_env=extra, check_deadline=deadline, startup_deadline=10, queue_wait=0)
    api = ApiSettings(token=TOKEN, port=port)
    app = create_app(api, pool=pool, pipeline=None)
    entry.build_app = lambda: (app, api)  # the rest of main() is the real entry point
    return entry.main()


if __name__ == "__main__":
    sys.exit(main())
