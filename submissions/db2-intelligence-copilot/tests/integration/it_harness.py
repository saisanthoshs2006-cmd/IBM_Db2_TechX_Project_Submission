"""Helpers shared by the G2 integration tests. Importing this module connects to nothing.

An integration test only runs inside a supervised run: DB2INTEL_IT=1 (checked by conftest),
plus a run directory from the supervisor that holds a valid pre-snapshot and no results yet.
Started any other way, the test skips, and the supervisor reports the run as not PASS.
"""
from __future__ import annotations

import contextlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

import pytest

from integration import it_sql as Q
from integration.snapshot import baseline_problems

RUN_DIR_ENV = "DB2INTEL_IT_RUN_DIR"
STEP_ENV = "DB2INTEL_IT_STEP"
TIMEOUT_ENV = "DB2INTEL_IT_QUERY_TIMEOUT"


@dataclass(frozen=True)
class Run:
    workdir: Path
    step: str
    timeout: int

    @property
    def results_path(self) -> Path:
        return self.workdir / f"results_{self.step}.json"


def supervised_run(step: str, environ=None) -> Run:
    """The supervised run this test belongs to, or pytest.skip with the reason."""
    env = os.environ if environ is None else environ
    if env.get(STEP_ENV) != step or not env.get(RUN_DIR_ENV):
        pytest.skip(f"{step} runs only through the supervisor (python -m integration.supervisor --step {step})")
    workdir = Path(env[RUN_DIR_ENV])
    try:
        pre = json.loads((workdir / "pre.json").read_text())
    except (OSError, ValueError):
        pytest.skip("no readable pre-snapshot in the run directory")
    problems = baseline_problems(pre)
    if problems:
        pytest.skip(f"the pre-snapshot is not the expected baseline: {problems}")
    if (workdir / "post.json").exists() or (workdir / f"results_{step}.json").exists():
        pytest.skip("the run directory already holds results: start a new supervised run")
    try:
        timeout = int(env.get(TIMEOUT_ENV, "30"))
    except ValueError:
        pytest.skip("invalid query timeout")
    if not 1 <= timeout <= 120:
        pytest.skip("invalid query timeout")
    return Run(workdir, step, timeout)


def write_results(run: Run, facts: dict) -> None:
    path = run.results_path
    tmp = path.with_name(path.name + ".partial")
    tmp.write_text(json.dumps(facts, indent=2, sort_keys=True, default=repr))
    os.replace(tmp, path)


@contextlib.contextmanager
def recording(run: Run, facts: dict):
    """Writes the results file last: outcome 'passed' only if the block completed."""
    facts.update(step=run.step, outcome="failed")
    try:
        yield facts
        facts["outcome"] = "passed"
    except BaseException as exc:
        facts["error"] = f"{type(exc).__name__}: {exc}"[:2000]
        raise
    finally:
        write_results(run, facts)


def connect(timeout: int):
    """(guarded driver, Db2Connection) to the local TESTDB, autocommit OFF."""
    from db2intel.config import load_settings
    from db2intel.db.connection import Db2Connection
    from db2intel.db.migrate import check_migration_host
    from integration import it_driver

    driver = it_driver.install(timeout)
    settings = load_settings()
    check_migration_host(settings.db2, settings.migration.allowed_hosts)
    conn = Db2Connection(settings.db2)
    try:
        rows = conn.query(Q.SERVER_SQL)
        server = str(rows[0][0]).strip() if len(rows) == 1 else None
        if server != Q.EXPECTED_DATABASE:
            raise RuntimeError(f"connected to {server!r}, expected {Q.EXPECTED_DATABASE}")
    except BaseException:
        conn.close()
        raise
    return driver, conn


def leftover_counts(conn) -> dict[str, int]:
    """Whole-table counts of all 11 explain tables on this connection."""
    return {t: conn.query(sql)[0][0] for t, sql in Q.EXPLAIN_COUNT_SQL.items()}
