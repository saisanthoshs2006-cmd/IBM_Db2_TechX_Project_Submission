"""Supervisor for the G2 integration run (promoted from the Phase 2B supervisor).

Never connects to Db2 and never imports ibm_db: every Db2 contact happens in a child process
(subprocess.Popen, own session and process group) that goes through the guarded driver.

  --step snapshot   G2.1: one snapshot (pre.json) and the baseline check. Nothing else.
  --step it1        G2.2: pre-snapshot -> pytest tests/integration/test_it1.py -> post-snapshot
  --step it2        G2.3: pre-snapshot -> pytest tests/integration/test_it2.py -> post-snapshot
  --step it3        G2.4: pre-snapshot -> pytest tests/integration/test_it3.py -> post-snapshot
                    (the production guard's preflight and analyze() through the guarded driver)

For it1/it2 the test only starts if the baseline is exact (server TESTDB, all 11 explain tables
empty, QUERY_AUDIT empty, ledger 001-003, employee fingerprints as recorded). The post-snapshot
is ALWAYS attempted once the test was started: after a pass, a failure, a timeout or Ctrl-C.

Deadlines are enforced here: on expiry (or Ctrl-C) the child's process group gets SIGKILL and
the supervisor waits until the child has terminated. Dropping the connection makes Db2 roll back
the open unit of work; nothing in G2 commits. Nothing is ever cleaned up automatically: if the
post-snapshot differs, the run stops with CHANGED and the difference is reported.

PASS requires every condition in pass_conditions(); a missing or malformed fact counts as false.
Exit codes: 0 PASS, 1 FAILED (database unchanged, something else failed), 2 CHANGED,
3 INCOMPLETE (no usable post-snapshot, or the report could not be written), 4 NOT STARTED.
"""
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from integration.snapshot import baseline_problems, compare, snapshot_problems

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_DEADLINE_S = 240
SNAPSHOT_DEADLINE_S = 60
KILL_REPORT_S = 30
STEPS = ("snapshot", "it1", "it2", "it3")
RUN_DIR_ENV = "DB2INTEL_IT_RUN_DIR"
STEP_ENV = "DB2INTEL_IT_STEP"
MATCH_CONDITIONS = ("server_matches", "explain_counts_match", "query_audit_matches", "ledger_matches",
                    "fingerprints_match")
PASS, FAILED, CHANGED, INCOMPLETE, NOT_STARTED = "PASS", "FAILED", "CHANGED", "INCOMPLETE", "NOT STARTED"
EXIT_CODES = {PASS: 0, FAILED: 1, CHANGED: 2, INCOMPLETE: 3, NOT_STARTED: 4}


def log(message: str) -> None:
    print(f"[supervisor] {message}", flush=True)


@contextlib.contextmanager
def sigint_ignored():
    try:
        previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    except ValueError:  # not the main thread
        previous = None
    try:
        yield
    finally:
        if previous is not None:
            signal.signal(signal.SIGINT, previous)


# ---- children ---------------------------------------------------------------------------------
@dataclass
class ChildResult:
    label: str
    pid: int | None
    returncode: int | None
    timed_out: bool = False
    interrupted: bool = False
    elapsed: float = 0.0
    start_error: str | None = None

    @property
    def killed(self) -> bool:
        return self.timed_out or self.interrupted

    def facts(self) -> dict:
        return {"started": self.start_error is None and self.pid is not None, "pid": self.pid,
                "exit_code": self.returncode, "timed_out": self.timed_out, "interrupted": self.interrupted,
                "start_error": self.start_error, "elapsed_s": round(self.elapsed, 1)}


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)  # the child leads its own session/process group
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.kill()
    except ProcessLookupError:
        pass


def _reap(proc, label: str) -> int:
    """Wait until a SIGKILLed child has terminated. Ctrl-C cannot cut this short."""
    noted = False
    report_at = time.monotonic() + KILL_REPORT_S
    while True:
        try:
            if noted:
                return proc.wait()
            return proc.wait(timeout=max(0.05, report_at - time.monotonic()))
        except subprocess.TimeoutExpired:
            log(f"{label}: still not terminated {KILL_REPORT_S} s after SIGKILL; waiting for it to terminate")
            noted = True
        except KeyboardInterrupt:
            log(f"{label}: Ctrl-C ignored: SIGKILL already sent, waiting for the child to terminate")
            _kill_group(proc)


def run_child(cmd: list[str], deadline: float, label: str, env: dict | None = None) -> ChildResult:
    started = time.monotonic()
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, start_new_session=True, env=env, cwd=PROJECT_ROOT)
    except OSError as exc:
        return ChildResult(label, None, None, start_error=f"could not start: {exc}")
    log(f"{label}: started pid {proc.pid}, deadline {deadline} s")
    try:
        rc = proc.wait(timeout=deadline)
        return ChildResult(label, proc.pid, rc, elapsed=time.monotonic() - started)
    except subprocess.TimeoutExpired:
        log(f"{label}: TIMEOUT after {deadline} s; sending SIGKILL to pid {proc.pid} and its process group")
        _kill_group(proc)
        rc = _reap(proc, label)
        return ChildResult(label, proc.pid, rc, timed_out=True, elapsed=time.monotonic() - started)
    except KeyboardInterrupt:
        log(f"{label}: Ctrl-C; sending SIGKILL to pid {proc.pid} and its process group")
        _kill_group(proc)
        rc = _reap(proc, label)
        return ChildResult(label, proc.pid, rc, interrupted=True, elapsed=time.monotonic() - started)


def take_snapshot(cmd: list[str], out: Path, deadline: float, label: str, env: dict | None = None):
    """(data or None, error or None, interrupted). Malformed data is kept for the report."""
    for stale in (out, out.with_name(out.name + ".partial")):
        if stale.exists():
            stale.unlink()
    result = run_child(cmd, deadline, label, env=env)
    if result.start_error:
        return None, f"{label} {result.start_error}", False
    if result.killed:
        why = "timeout" if result.timed_out else "interrupted by Ctrl-C"
        return None, f"{label} was killed ({why}) before completing", result.interrupted
    if result.returncode != 0:
        return None, f"{label} exited with status {result.returncode}", False
    try:
        data = json.loads(out.read_text())
    except (OSError, ValueError) as exc:
        return None, f"{label} output is missing or unreadable: {type(exc).__name__}", False
    problems = snapshot_problems(data)
    if problems:
        return data, f"{label} output is malformed: {'; '.join(problems)}", False
    return data, None, False


def read_results(workdir: Path, step: str):
    """The results file the integration test writes as its very last action."""
    try:
        data = json.loads((workdir / f"results_{step}.json").read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


# ---- decision (pure) ----------------------------------------------------------------------------
def pass_conditions(facts: dict) -> dict[str, bool]:
    pre, post = facts.get("pre_snapshot"), facts.get("post_snapshot")
    baseline_ok = ("pre_error" in facts and facts["pre_error"] is None and isinstance(pre, dict)
                   and facts.get("baseline_problems") == [] and not baseline_problems(pre))
    not_interrupted = facts.get("interrupted") is False
    if facts.get("step") == "snapshot":
        return {"baseline_valid": baseline_ok, "not_interrupted": not_interrupted}
    test = facts.get("test") if isinstance(facts.get("test"), dict) else {}
    post_ok = ("post_error" in facts and facts["post_error"] is None and isinstance(post, dict)
               and not snapshot_problems(post))
    cmp = compare(pre, post) if baseline_ok and post_ok else {}
    exit_code = test.get("exit_code")
    child_ok = (test.get("started") is True and type(exit_code) is int and exit_code == 0
                and test.get("timed_out") is False and test.get("interrupted") is False)
    results = facts.get("results")
    results_ok = (isinstance(results, dict) and results.get("step") == facts.get("step")
                  and results.get("outcome") == "passed")
    post_explain_empty = post_ok and all(n == 0 for n in post["explain"].values())
    return {
        "baseline_valid": baseline_ok,
        "test_completed_successfully": child_ok,
        "results_recorded": results_ok,
        "cleanup_verified": child_ok and results_ok and post_explain_empty,
        "post_snapshot_completed": post_ok,
        "server_matches": cmp.get("server") is True,
        "explain_counts_match": cmp.get("explain") is True,
        "query_audit_matches": cmp.get("audit_rows") is True,
        "ledger_matches": cmp.get("ledger") is True,
        "fingerprints_match": cmp.get("protected") is True,
        "not_interrupted": not_interrupted,
    }


def decide(facts: dict) -> tuple[str, dict[str, bool], dict]:
    """(overall, conditions, comparison). PASS if and only if every condition is true."""
    conditions = pass_conditions(facts)
    if facts.get("step") == "snapshot":
        overall = PASS if all(conditions.values()) else NOT_STARTED
        return overall, conditions, {}
    pre, post = facts.get("pre_snapshot"), facts.get("post_snapshot")
    comparison = compare(pre, post) if conditions["baseline_valid"] and conditions["post_snapshot_completed"] else {}
    if not conditions["baseline_valid"]:
        overall = NOT_STARTED
    elif not conditions["post_snapshot_completed"]:
        overall = INCOMPLETE
    elif not all(conditions[c] for c in MATCH_CONDITIONS):
        overall = CHANGED
    elif all(conditions.values()):
        overall = PASS
    else:
        overall = FAILED
    assert (overall == PASS) == all(conditions.values())
    return overall, conditions, comparison


# ---- run ----------------------------------------------------------------------------------------
def new_facts(step: str, deadline: float, snapshot_deadline: float) -> dict:
    return {"step": step, "python": sys.executable, "deadline_s": deadline, "snapshot_deadline_s": snapshot_deadline,
            "pre_snapshot": None, "pre_error": "pre-snapshot was not taken", "baseline_problems": None,
            "test": None, "results": None, "post_snapshot": None, "post_error": "post-snapshot was not taken",
            "interrupted": False}


def _collect(facts: dict, test_cmd, snapshot_cmd, workdir: Path, test_env, snapshot_env) -> None:
    pre_path, post_path = workdir / "pre.json", workdir / "post.json"
    data, error, interrupted = take_snapshot(snapshot_cmd(pre_path), pre_path, facts["snapshot_deadline_s"], "pre-snapshot",
                                            snapshot_env)
    facts.update(pre_snapshot=data, pre_error=error)
    facts["interrupted"] = facts["interrupted"] or interrupted
    if error is not None:
        return
    facts["baseline_problems"] = baseline_problems(data)
    if facts["step"] == "snapshot" or facts["baseline_problems"] or facts["interrupted"]:
        return

    result = run_child(test_cmd, facts["deadline_s"], f"test {facts['step']}", env=test_env)
    facts["test"] = result.facts()
    facts["interrupted"] = facts["interrupted"] or result.interrupted
    facts["results"] = read_results(workdir, facts["step"])

    # Always attempted once the test was started, also after a timeout or a first Ctrl-C.
    data, error, interrupted = take_snapshot(snapshot_cmd(post_path), post_path, facts["snapshot_deadline_s"], "post-snapshot",
                                            snapshot_env)
    facts.update(post_snapshot=data, post_error=error)
    facts["interrupted"] = facts["interrupted"] or interrupted


def supervise(step: str, test_cmd: list[str] | None, snapshot_cmd, workdir: Path, test_env: dict | None = None,
              snapshot_env: dict | None = None, deadline: float = TEST_DEADLINE_S, snapshot_deadline: float = SNAPSHOT_DEADLINE_S) -> tuple[int, dict]:
    if step not in STEPS:
        raise ValueError(f"unknown step {step!r}")
    workdir.mkdir(parents=True, exist_ok=True)
    stale = [p.name for p in workdir.iterdir()]
    if stale:  # a run never reuses evidence from an earlier run
        raise ValueError(f"work directory {workdir} is not empty: {stale}")
    facts = new_facts(step, deadline, snapshot_deadline)
    try:
        _collect(facts, test_cmd, snapshot_cmd, workdir, test_env, snapshot_env)
    except KeyboardInterrupt:
        facts["interrupted"] = True
        log("Ctrl-C: remaining steps skipped; the report will not be PASS")
    with sigint_ignored():
        return finish(facts, workdir)


def finish(facts: dict, workdir: Path) -> tuple[int, dict]:
    overall, conditions, comparison = decide(facts)
    report = {**facts, "pass_conditions": conditions, "comparison": comparison, "overall": overall}
    path = workdir / "report.json"
    try:
        tmp = path.with_name(path.name + ".partial")
        tmp.write_text(json.dumps({**report, "report_written": True, "exit_code": EXIT_CODES[overall]},
                                  indent=2, sort_keys=True, default=str))
        os.replace(tmp, path)
        report["report_written"] = True
    except Exception as exc:
        report["report_written"] = False
        report["report_error"] = f"{type(exc).__name__}: {exc}"
        if overall == PASS:  # a PASS that cannot be recorded is not a PASS
            overall = report["overall"] = INCOMPLETE
    report["exit_code"] = EXIT_CODES[overall]

    print("\n========== supervisor report ==========", flush=True)
    print(f"{'step':15} {facts['step']}", flush=True)
    print(f"{'overall':15} {overall}", flush=True)
    if facts.get("pre_error"):
        print(f"{'pre-snapshot':15} {facts['pre_error']}", flush=True)
    if facts.get("baseline_problems"):
        print(f"{'baseline':15} {facts['baseline_problems']}", flush=True)
    if facts["step"] != "snapshot" and facts.get("post_error"):
        print(f"{'post-snapshot':15} {facts['post_error']}", flush=True)
    failed = [name for name, ok in conditions.items() if not ok]
    print(f"{'not met':15} {', '.join(failed) if failed else '(none)'}", flush=True)
    print(f"{'report':15} {path if report['report_written'] else 'NOT WRITTEN: ' + report['report_error']}", flush=True)
    return report["exit_code"], report


def commands(step: str, workdir: Path, query_timeout: int):
    """(test argv or None, snapshot argv factory, test env, snapshot env) for a real run."""
    pythonpath = os.pathsep.join([str(PROJECT_ROOT / "src"), str(PROJECT_ROOT / "tests")])
    base_env = {**os.environ, "PYTHONPATH": pythonpath}
    snapshot_cmd = lambda out: [sys.executable, "-m", "integration.snapshot", str(out)]  # noqa: E731
    if step == "snapshot":
        return None, snapshot_cmd, None, base_env
    test_cmd = [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "--tb=short", "-rs",
                f"tests/integration/test_{step}.py"]
    test_env = {**base_env, "DB2INTEL_IT": "1", RUN_DIR_ENV: str(workdir), STEP_ENV: step,
                "DB2INTEL_IT_QUERY_TIMEOUT": str(query_timeout)}
    return test_cmd, snapshot_cmd, test_env, base_env


def _ibm_db_installed() -> bool:
    """Whether this interpreter (the one the children run under) can import ibm_db; never imports it."""
    try:
        return importlib.util.find_spec("ibm_db") is not None
    except ValueError:  # already in sys.modules without a spec: it is importable
        return sys.modules.get("ibm_db") is not None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--step", choices=STEPS, required=True)
    parser.add_argument("--workdir", type=Path, required=True,
                        help="new, empty directory outside the repository for pre/post snapshots and the report")
    parser.add_argument("--deadline", type=int, default=TEST_DEADLINE_S, choices=range(30, 601), metavar="30..600")
    parser.add_argument("--snapshot-deadline", type=int, default=SNAPSHOT_DEADLINE_S, choices=range(10, 301), metavar="10..300")
    parser.add_argument("--query-timeout", type=int, default=30, choices=range(1, 121), metavar="1..120")
    args = parser.parse_args(argv)
    if args.query_timeout >= min(args.deadline, args.snapshot_deadline):
        parser.error("--query-timeout must be shorter than both deadlines")
    if not _ibm_db_installed():
        print(f"[supervisor] NOT STARTED: ibm_db is not installed for {sys.executable}; run the supervisor with "
              "the project environment, e.g. ~/.venvs/db2-intelligence-copilot/bin/python", flush=True)
        return EXIT_CODES[NOT_STARTED]
    workdir = args.workdir.resolve()
    if workdir == PROJECT_ROOT or PROJECT_ROOT in workdir.parents:
        parser.error("--workdir must be outside the project directory (run evidence is never committed)")
    test_cmd, snapshot_cmd, test_env, snapshot_env = commands(args.step, workdir, args.query_timeout)
    code, _ = supervise(args.step, test_cmd, snapshot_cmd, workdir, test_env, snapshot_env,
                        args.deadline, args.snapshot_deadline)
    return code


if __name__ == "__main__":
    sys.exit(main())
