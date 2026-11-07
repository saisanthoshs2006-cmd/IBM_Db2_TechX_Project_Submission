"""G1.2 offline hardening: worker environment allow-list, guard pool needs a token, redacted
worker stderr log, explain tables must be empty at worker startup, integration-test skeleton.

No test here connects to Db2. Worker tests run real subprocesses with fake backends.
"""
from __future__ import annotations

import os
import stat
import subprocess
import sys
import time
import tomllib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from db2intel.api import app as A
from db2intel.config import DEFAULT_WORKER_LOG, PROJECT_ROOT, ApiSettings, ConfigError, load_api_settings
from db2intel.guard import context as C
from db2intel.guard import worker as W

TESTS_DIR = str(Path(__file__).resolve().parent)
SQL = "SELECT 1 FROM SYSIBM.SYSDUMMY1"
TOKEN = "example-fake-api-token-0123456789"
FAKE_PW = "example-fake-db-password-sentinel"
BASE_ENV = {
    "PATH": "/usr/bin:/bin", "HOME": "/home/example", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
    "DB2_HOST": "localhost", "DB2_PORT": "50000", "DB2_DATABASE": "TESTDB", "DB2_USER": "db2inst1",
    "DB2_PASSWORD": FAKE_PW, "DB2_SECURITY": "false", W.OFFLINE_ENV: "1",
    "DB2INTEL_MIGRATION_DATABASES": "TESTDB", "DB2INTEL_MIGRATION_HOSTS": "localhost",
    "DB2INTEL_API_TOKEN": TOKEN, "OPENAI_API_KEY": "example-fake-openai-key-0123",
    "WATSONX_APIKEY": "example-fake-watsonx-key-0123", "WATSONX_PROJECT_ID": "example-fake-project",
    "LLM_PROVIDER": "ollama", "LLM_BASE_URL": "http://localhost:11434", "DB2INTEL_LLM_ALLOW_REMOTE": "false",
    "AWS_SECRET_ACCESS_KEY": "example-fake-aws-secret-0123", "GITHUB_TOKEN": "example-fake-gh-token-0123",
    "UNRELATED_VARIABLE": "value", "DB2INTEL_GUARD_WORKERS": "2",
}
FAKE_SETTINGS_ENV = {"DB2_HOST": "localhost", "DB2_PASSWORD": FAKE_PW}
# Fake key shapes for the redaction tests, assembled at runtime so that the repository's secret
# scan (which uses the same patterns) does not see literal keys in this file.
FAKE_AKIA = "AKIA" + "EXAMPLEFAKEKEY12"
FAKE_PEM = "-----BEGIN RSA " + "PRIVATE KEY-----"
NEVER_IN_WORKER = ("DB2INTEL_API_TOKEN", "OPENAI_API_KEY", "WATSONX_APIKEY", "WATSONX_PROJECT_ID", "LLM_PROVIDER",
                   "LLM_BASE_URL", "DB2INTEL_LLM_ALLOW_REMOTE", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN",
                   "UNRELATED_VARIABLE", "DB2INTEL_GUARD_WORKERS")


def fake_pool(backend, **kw):
    kw.setdefault("check_deadline", 10)
    kw.setdefault("startup_deadline", 10)
    kw.setdefault("queue_wait", 0)
    kw.setdefault("env", {**os.environ, W.OFFLINE_ENV: "1"})
    return W.GuardPool(backend=f"fake_guard_backends:{backend}", extra_pythonpath=(TESTS_DIR,), **kw)


def wait_for(predicate, seconds=10.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


# ---- (a) worker environment allow-list ------------------------------------------------------------
def test_worker_env_keeps_only_allow_listed_variables():
    env = W.worker_env((), BASE_ENV)
    for name in NEVER_IN_WORKER:
        assert name not in env, name
    for name in ("PATH", "HOME", "LANG", "LC_ALL", "DB2_HOST", "DB2_PORT", "DB2_DATABASE", "DB2_USER",
                 "DB2_PASSWORD", "DB2_SECURITY", W.OFFLINE_ENV, "DB2INTEL_MIGRATION_DATABASES",
                 "DB2INTEL_MIGRATION_HOSTS"):
        assert env[name] == BASE_ENV[name], name
    assert env["PYTHONUNBUFFERED"] == "1"
    assert env["PYTHONPATH"].split(os.pathsep)[0] == str(W._SRC_DIR)


@pytest.mark.parametrize("name", sorted(W.WORKER_ENV_DENIED))
def test_denied_names_are_dropped_even_from_extra_env(name):
    assert name not in W.worker_env((), {}, {name: "example-fake-value-0123"})
    assert not W.worker_env_allowed(name)


def test_extra_env_adds_test_variables_and_pythonpath_is_composed():
    env = W.worker_env(("/extra/path",), {"PYTHONPATH": "/parent/path"}, {"ECHO_FILE": "/tmp/x"})
    assert env["ECHO_FILE"] == "/tmp/x"
    assert env["PYTHONPATH"].split(os.pathsep) == [str(W._SRC_DIR), "/extra/path", "/parent/path"]


def test_db2intel_prefix_is_not_allowed_wholesale():
    # DB2_ is an allowed prefix, DB2INTEL_ is not: only the listed DB2INTEL_ names pass.
    assert not W.worker_env_allowed("DB2INTEL_API_TOKEN")
    assert not W.worker_env_allowed("DB2INTEL_ANYTHING_ELSE")
    assert W.worker_env_allowed("DB2INTEL_MIGRATION_HOSTS")


def test_pool_environment_is_filtered():
    p = W.GuardPool(backend="fake_guard_backends:Approving", env=BASE_ENV)
    try:
        assert set(NEVER_IN_WORKER).isdisjoint(p._env)
        assert p._env["DB2_PASSWORD"] == FAKE_PW
    finally:
        p.close()


def test_real_worker_process_sees_no_denied_variables():
    env = {**os.environ, **{k: v for k, v in BASE_ENV.items() if k not in ("PATH", "HOME")}}
    p = fake_pool("EnvReport", env=env)
    try:
        worker = p._take_worker()
        keys = set(worker.context["env_keys"])
        worker.close()
    finally:
        p.close()
    assert set(NEVER_IN_WORKER).isdisjoint(keys)
    assert {"DB2_PASSWORD", W.OFFLINE_ENV, "PYTHONPATH"} <= keys
    platform_added = {"LC_CTYPE", "PWD", "SHLVL", "_"}  # the OS or Python may add these on its own
    assert all(W.worker_env_allowed(k) or k in ("PYTHONPATH", "PYTHONUNBUFFERED") or k.startswith("__")
               or k in platform_added for k in keys), sorted(keys)


def test_worker_settings_env_reads_only_allow_listed_dotenv_keys(tmp_path):
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        "DB2_HOST=localhost\nDB2_PASSWORD=example-fake-from-file\nDB2INTEL_API_TOKEN=example-fake-file-token-0123\n"
        "OPENAI_API_KEY=example-fake-file-key\nLLM_PROVIDER=ollama\nDB2INTEL_MIGRATION_HOSTS=localhost\n"
    )
    env = W.worker_settings_env({"DB2_HOST": "127.0.0.1"}, dotenv)
    assert env == {"DB2_HOST": "127.0.0.1", "DB2_PASSWORD": "example-fake-from-file",
                   "DB2INTEL_MIGRATION_HOSTS": "localhost"}


def test_worker_settings_env_does_not_touch_os_environ(tmp_path, monkeypatch):
    dotenv = tmp_path / ".env"
    dotenv.write_text("OPENAI_API_KEY=example-fake-file-key\nDB2_PORT=50000\n")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("DB2_PORT", raising=False)
    W.worker_settings_env(None, dotenv)
    assert "OPENAI_API_KEY" not in os.environ and "DB2_PORT" not in os.environ


# ---- (b) the guard pool requires a token ------------------------------------------------------------
def test_create_app_refuses_a_pool_without_a_token():
    p = W.GuardPool(backend="fake_guard_backends:Approving", env={})
    try:
        with pytest.raises(ConfigError, match="DB2INTEL_API_TOKEN"):
            A.create_app(ApiSettings(), pool=p, pipeline=None)
        A.create_app(ApiSettings(token=TOKEN), pool=p, pipeline=None)  # with a token it is accepted
    finally:
        p.close()


def _build(env, **kw):
    from db2intel.api.__main__ import build_app

    base = {"EMBEDDING_PROVIDER": "deterministic", "EMBEDDING_DIM": "768", "LLM_PROVIDER": "none",
            "DB2_PASSWORD": FAKE_PW}
    return build_app({**base, **env}, **kw)


def test_build_app_without_token_has_no_pool_and_says_why():
    app, _ = _build({})
    ctx = app.state.ctx
    assert ctx.pool is None and "DB2INTEL_API_TOKEN" in ctx.guard_disabled_reason
    client = TestClient(app, raise_server_exceptions=False)
    status = client.get("/api/v1/guard/status").json()
    assert status["guard_check_available"] is False and "DB2INTEL_API_TOKEN" in status["guard_disabled_reason"]
    r = client.post("/api/v1/guard/check", json={"sql": "SELECT C.COMPANY_NAME FROM DB2INTEL_DEMO.CUSTOMER C"})
    assert r.status_code == 503 and r.json()["code"] == "guard_disabled" and r.json()["executed"] is False


def test_build_app_with_token_enables_the_pool_without_starting_workers():
    app, _ = _build({"DB2INTEL_API_TOKEN": TOKEN, "DB2INTEL_WORKER_LOG": "off"})
    pool = app.state.ctx.pool
    try:
        assert pool is not None and app.state.ctx.guard_disabled_reason is None
        assert pool.status()["workers_started"] == 0 and pool.status()["worker_stderr_logged"] is False
        assert TOKEN not in str(pool._env.values())
    finally:
        pool.close()


def test_build_app_default_worker_log_is_under_the_project(monkeypatch):
    seen = {}

    class Recorder(W.GuardPool):
        def __init__(self, **kw):
            seen.update(kw)
            super().__init__(**{**kw, "stderr_log": None})

    monkeypatch.setattr(W, "GuardPool", Recorder)
    app, _ = _build({"DB2INTEL_API_TOKEN": TOKEN})
    app.state.ctx.pool.close()
    assert seen["stderr_log"] == PROJECT_ROOT / DEFAULT_WORKER_LOG


def test_guard_disabled_by_caller_is_reported():
    app, _ = _build({"DB2INTEL_API_TOKEN": TOKEN}, with_guard_pool=False)
    assert app.state.ctx.pool is None and "caller" in app.state.ctx.guard_disabled_reason


def test_main_prints_why_the_guard_is_disabled(monkeypatch, capsys):
    import uvicorn

    from db2intel.api import __main__ as M

    built = _build({})  # built before build_app is replaced below
    monkeypatch.setattr(M, "build_app", lambda: built)
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    assert M.main() == 0
    assert "guard/check is disabled" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["logs/guard-worker.txt", "logs/guard-worker", "/tmp/x.log.bak"])
def test_worker_log_setting_must_end_in_dot_log(value):
    with pytest.raises(ConfigError, match="DB2INTEL_WORKER_LOG"):
        load_api_settings({"DB2INTEL_WORKER_LOG": value})


def test_worker_log_setting_defaults_and_off():
    assert load_api_settings({})[0].worker_log == DEFAULT_WORKER_LOG
    assert load_api_settings({"DB2INTEL_WORKER_LOG": "off"})[0].worker_log == "off"


# ---- (c) bounded, redacted worker stderr log --------------------------------------------------------
def test_redaction_rules(tmp_path):
    log = W.WorkerStderrLog(tmp_path / "w.log", secrets=(FAKE_PW, "abc"))
    out = log.redact(
        f"PWD={FAKE_PW};UID=db2inst1 password: 'x y' token=example-fake-1 api-key=example-fake-2 "
        f"secret = example-fake-3 free {FAKE_PW} Bearer abc.def sk-example-fake-key-0123 {FAKE_AKIA} "
        f"{FAKE_PEM} a\x1b[0mb\x00c"
    )
    assert FAKE_PW not in out
    for leaked in ("'x y'", "example-fake-1", "example-fake-2", "example-fake-3", "abc.def", "sk-example", "AKIAEXAMPLE",
                   "BEGIN RSA", "\x1b", "\x00"):
        assert leaked not in out, leaked
    assert "PWD=***" in out and "UID=db2inst1" in out and "Bearer ***" in out


@pytest.mark.parametrize("line", ["Authorization: Bearer example-fake-bearer-value-123",
                                  "authorization=Basic ZXhhbXBsZTpmYWtl", "Proxy-Authorization: Digest x=example-fake"])
def test_authorization_header_value_is_fully_redacted(tmp_path, line):
    out = W.WorkerStderrLog(tmp_path / "w.log").redact(line)
    assert out.endswith("***") and "example-fake" not in out and "ZXhhbXBsZTpmYWtl" not in out


def test_secret_values_takes_secret_named_variables_only():
    values = W.secret_values({"DB2_PASSWORD": FAKE_PW, "DB2INTEL_API_TOKEN": TOKEN, "X_SECRET": "abcd",
                              "OPENAI_API_KEY": "example-fake-openai", "DB2_HOST": "localhost", "SHORT_PWD": "abc"})
    assert set(values) == {FAKE_PW, TOKEN, "abcd", "example-fake-openai"}
    assert list(values) == sorted(values, key=len, reverse=True)  # longest first


def test_pool_redacts_secrets_from_the_full_environment(tmp_path):
    # The token never reaches a worker, but it is still redacted if anything prints it.
    p = W.GuardPool(backend="fake_guard_backends:Approving", env=BASE_ENV, stderr_log=tmp_path / "w.log")
    try:
        secrets = set(p._stderr_log._secrets)
        assert {FAKE_PW, TOKEN, BASE_ENV["OPENAI_API_KEY"], BASE_ENV["GITHUB_TOKEN"]} <= secrets
        assert "DB2INTEL_API_TOKEN" not in p._env
    finally:
        p.close()


def test_log_lines_are_truncated_and_file_is_private(tmp_path):
    log = W.WorkerStderrLog(tmp_path / "sub" / "w.log", max_line_chars=100)
    log.write(42, b"x" * 1000 + b"\n")
    text = (tmp_path / "sub" / "w.log").read_text()
    assert "pid=42 " + "x" * 100 + " [truncated]" in text and "x" * 101 not in text
    assert stat.S_IMODE((tmp_path / "sub" / "w.log").stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "sub").stat().st_mode) == 0o700


def test_log_rotates_once_and_stays_bounded(tmp_path):
    log = W.WorkerStderrLog(tmp_path / "w.log", max_bytes=2_000, max_line_chars=100)
    for i in range(500):
        log.write(1, f"line {i} ".encode() + b"y" * 80 + b"\n")
    files = sorted(p.name for p in tmp_path.iterdir())
    assert files == ["w.1.log", "w.log"]
    assert all((tmp_path / f).stat().st_size <= 2_000 for f in files)
    assert "line 499 " in (tmp_path / "w.log").read_text()


@pytest.mark.parametrize("kw", [{"max_bytes": 10}, {"max_line_chars": 10}, {"max_bytes": 10**9}])
def test_log_limits_are_validated(tmp_path, kw):
    with pytest.raises(ValueError):
        W.WorkerStderrLog(tmp_path / "w.log", **kw)


@pytest.mark.parametrize("name", ["w.txt", "w", "w.log.bak"])
def test_log_name_must_end_in_dot_log(tmp_path, name):
    with pytest.raises(ValueError, match=r"\.log"):
        W.WorkerStderrLog(tmp_path / name)


def test_default_log_files_are_git_ignored():
    for rel in (DEFAULT_WORKER_LOG, DEFAULT_WORKER_LOG.replace(".log", ".1.log")):
        r = subprocess.run(["git", "check-ignore", "-q", rel], cwd=PROJECT_ROOT, capture_output=True)
        if r.returncode == 128:
            pytest.skip("not inside a git work tree")
        assert r.returncode == 0, f"{rel} is not git-ignored"


def test_real_worker_stderr_is_redacted_and_bounded(tmp_path):
    log_path = tmp_path / "logs" / "guard-worker.log"
    env = {**os.environ, W.OFFLINE_ENV: "1", "DB2_PASSWORD": FAKE_PW}
    p = fake_pool("StderrNoise", env=env, stderr_log=log_path)
    try:
        assert p.status()["worker_stderr_logged"] is True
        assert p.check(SQL, origin=W.ORIGIN_HUMAN)["status"] == "APPROVED"
    finally:
        p.close()
    assert wait_for(lambda: log_path.exists() and "stderr during check" in log_path.read_text())
    text = log_path.read_text()
    assert FAKE_PW not in text
    assert "PWD=***" in text and "Authorization: ***" in text and "example-fake-bearer-value" not in text
    assert "sk-example" not in text and "AKIAEXAMPLE" not in text and "\x1b" not in text and "\x07" not in text
    assert "[truncated]" in text and "L" * 501 not in text
    assert "after the long line" in text  # the line after an over-long one is kept
    assert len(text) < 5_000


def test_without_a_log_stderr_is_discarded(tmp_path):
    p = fake_pool("StderrNoise", env={**os.environ, W.OFFLINE_ENV: "1", "DB2_PASSWORD": FAKE_PW})
    try:
        assert p.status()["worker_stderr_logged"] is False
        assert p.check(SQL, origin=W.ORIGIN_HUMAN)["status"] == "APPROVED"
    finally:
        p.close()


# ---- (d) explain tables must be empty before the pool accepts checks ---------------------------------
class CountDb:
    def __init__(self, counts=None, rows=None):
        self.counts = counts or {}
        self.rows = rows
        self.sql = []

    def query(self, sql, params=()):
        self.sql.append((sql, params))
        if self.rows is not None:
            return self.rows
        table = sql.rsplit(".", 1)[1]
        return [(self.counts.get(table, 0),)]


def test_count_statements_cover_exactly_the_11_explain_tables_read_only():
    assert set(C.EXPLAIN_COUNT_SQL) == C.EXPLAIN_TABLES and len(C.EXPLAIN_TABLES) == 11
    for table, sql in C.EXPLAIN_COUNT_SQL.items():
        assert sql == f"SELECT COUNT(*) FROM DB2INTEL.{table}"


def test_empty_explain_tables_pass_with_one_count_each():
    db = CountDb()
    C.check_explain_tables_empty(db)
    assert [s for s, _ in db.sql] == list(C.EXPLAIN_COUNT_SQL.values())
    assert all(p == () for _, p in db.sql)


@pytest.mark.parametrize("table", sorted(C.EXPLAIN_TABLES))
def test_any_row_in_any_explain_table_refuses(table):
    with pytest.raises(C.ExplainTablesNotEmpty, match=f"{table}=3"):
        C.check_explain_tables_empty(CountDb({table: 3}))


def test_all_non_empty_tables_are_listed():
    with pytest.raises(C.ExplainTablesNotEmpty) as info:
        C.check_explain_tables_empty(CountDb({"EXPLAIN_INSTANCE": 1, "EXPLAIN_STATEMENT": 2}))
    assert "EXPLAIN_INSTANCE=1" in str(info.value) and "EXPLAIN_STATEMENT=2" in str(info.value)
    assert "manually" in str(info.value)


@pytest.mark.parametrize("rows", [[], [(1,), (2,)], [(1, 2)], [("x",)], [(None,)]])
def test_unreadable_counts_refuse_as_preflight_error(rows):
    with pytest.raises(C.PreflightError) as info:
        C.check_explain_tables_empty(CountDb(rows=rows))
    assert not isinstance(info.value, C.ExplainTablesNotEmpty)


def test_db2_backend_refuses_with_explain_rows_and_closes(backend_fakes):
    calls, fail = backend_fakes
    fail["explain_rows"] = True
    with pytest.raises(W.BackendRefused) as info:
        W.Db2Backend()
    assert info.value.code == W.EXPLAIN_NOT_EMPTY_CODE
    assert [c[0] for c in calls][-3:] == ["explain_empty", "rollback", "close"]


def test_db2_backend_loads_settings_from_the_filtered_env(backend_fakes):
    calls, _ = backend_fakes
    W.Db2Backend().close()
    assert next(c[1] for c in calls if c[0] == "settings") is FAKE_SETTINGS_ENV


def test_explain_rows_at_worker_startup_latch_the_pool():
    reasons = []
    p = fake_pool("ExplainRowsAtStartup", on_degraded=reasons.append)
    try:
        with pytest.raises(W.Degraded, match="explain tables"):
            p.check(SQL, origin=W.ORIGIN_HUMAN)
        assert p.degraded and len(reasons) == 1
        with pytest.raises(W.Degraded):
            p.check(SQL, origin=W.ORIGIN_HUMAN)
        assert p.status()["workers_started"] == 0
    finally:
        p.close()


def test_other_startup_refusals_do_not_latch():
    p = fake_pool("StartupFails")
    try:
        with pytest.raises(W.WorkerStartError) as info:
            p.check(SQL, origin=W.ORIGIN_HUMAN)
        assert info.value.startup_code == "startup_failed" and p.degraded is None
    finally:
        p.close()


def test_invalid_refusal_code_is_replaced():
    p = fake_pool("RefusesWithOddCode")
    try:
        with pytest.raises(W.WorkerStartError) as info:
            p.check(SQL, origin=W.ORIGIN_HUMAN)
        assert info.value.startup_code == "backend_refused" and p.degraded is None
    finally:
        p.close()


def test_api_reports_explain_rows_as_degraded():
    p = fake_pool("ExplainRowsAtStartup")
    try:
        client = TestClient(A.create_app(ApiSettings(token=TOKEN), pool=p, pipeline=None),
                            raise_server_exceptions=False, headers={"Authorization": f"Bearer {TOKEN}"})
        r = client.post("/api/v1/guard/check", json={"sql": "SELECT C.COMPANY_NAME FROM DB2INTEL_DEMO.CUSTOMER C"})
        assert r.status_code == 503 and r.json()["code"] == "degraded" and r.json()["executed"] is False
        assert client.get("/api/v1/guard/status").json()["status"] == "DEGRADED"
    finally:
        p.close()


# ---- (e) db2 marker and integration skeleton ---------------------------------------------------------
def test_db2_marker_is_registered_and_markers_are_strict():
    cfg = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())["tool"]["pytest"]["ini_options"]
    assert any(m.startswith("db2:") for m in cfg["markers"])
    assert "--strict-markers" in cfg["addopts"]


def _run_pytest(args, cwd, extra_env=None):
    env = {k: v for k, v in os.environ.items() if k != "DB2INTEL_IT"}
    env.update(extra_env or {})
    return subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-rs", *args],
                          cwd=cwd, env=env, capture_output=True, text=True, timeout=120)


@pytest.mark.parametrize("it,reason", [(None, "set DB2INTEL_IT=1"), ("1", "gate G2"), ("0", "set DB2INTEL_IT=1")])
def test_integration_skeleton_always_skips(it, reason):
    r = _run_pytest(["tests/integration"], PROJECT_ROOT, {"DB2INTEL_IT": it} if it else None)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "1 skipped" in r.stdout and "passed" not in r.stdout and reason in r.stdout


def test_integration_conftest_leaves_unit_tests_alone():
    r = _run_pytest(["tests/integration", "tests/test_config.py"], PROJECT_ROOT)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "1 skipped" in r.stdout and " passed" in r.stdout


def test_unmarked_test_under_integration_is_rejected(tmp_path):
    (tmp_path / "integration").mkdir()
    (tmp_path / "integration" / "__init__.py").write_text("")
    (tmp_path / "integration" / "conftest.py").write_text(
        (PROJECT_ROOT / "tests" / "integration" / "conftest.py").read_text())
    (tmp_path / "integration" / "test_unmarked.py").write_text("def test_x():\n    pass\n")
    (tmp_path / "pytest.ini").write_text("[pytest]\nmarkers =\n    db2: real Db2\n")
    r = _run_pytest(["integration"], tmp_path)
    assert r.returncode != 0 and "must be marked @pytest.mark.db2" in (r.stdout + r.stderr)


# ---- fixtures ---------------------------------------------------------------------------------------
@pytest.fixture
def backend_fakes(monkeypatch):
    import db2intel.config as config
    import db2intel.db.connection as connection
    import db2intel.db.migrate as migrate
    import db2intel.guard.sessions as sessions
    from guard_fakes import CTX

    calls, fail = [], {}

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

    def explain_empty(session):
        calls.append(("explain_empty",))
        if fail.get("explain_rows"):
            raise C.ExplainTablesNotEmpty("explain tables in DB2INTEL are not empty (EXPLAIN_INSTANCE=1)")

    def fake_load_settings(env):
        calls.append(("settings", env))
        return Settings

    monkeypatch.delenv(W.OFFLINE_ENV, raising=False)
    monkeypatch.setattr(W, "worker_settings_env", lambda: FAKE_SETTINGS_ENV)  # never read the real .env here
    monkeypatch.setattr(config, "load_settings", fake_load_settings)
    monkeypatch.setattr(migrate, "check_migration_host", lambda db2, hosts: calls.append(("host_check", hosts)))
    monkeypatch.setattr(connection, "Db2Connection", Conn)
    monkeypatch.setattr(sessions, "Db2AnalysisSession", Session)
    monkeypatch.setattr(C, "load_guard_context", lambda session, dbs: calls.append(("preflight", dbs)) or CTX)
    monkeypatch.setattr(C, "check_explain_tables_empty", explain_empty)
    return calls, fail
