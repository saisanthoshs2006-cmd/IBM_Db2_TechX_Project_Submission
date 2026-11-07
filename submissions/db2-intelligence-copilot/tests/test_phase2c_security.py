"""Phase 2C security properties, checked statically and at runtime. No database is used.

  * no route can reach execute_approved / execute_capped / Db2ExecutionSession
  * AI-generated SQL is never prepared, explained or executed (gate G4 not approved)
  * a corpus of hostile SQL never reaches the guard pool
  * every response says executed: false; secrets never appear in responses
  * migrations are unchanged; new dependencies are pinned
"""
from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from db2intel.api import app as A
from db2intel.config import ApiSettings
from db2intel.guard import worker as W
from db2intel.nl2sql.llm import StaticLLM

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "db2intel"
NEW_PACKAGES = ("api", "nl2sql", "rag")
EXECUTION_NAMES = {"execute_approved", "execute_capped", "Db2ExecutionSession", "verify_restricted_principal",
                   "ExecutionSession", "exec_immediate", "commit"}
GOOD = "SELECT C.COMPANY_NAME FROM DB2INTEL_DEMO.CUSTOMER C WHERE C.CUSTOMER_ID = 42"


def _python_files(*packages):
    for pkg in packages:
        yield from sorted((SRC / pkg).rglob("*.py"))


def _names_used(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            module = getattr(node, "module", None) or ""
            names.add(module)
            names.update(a.name for a in node.names)
    return names


# ---- static: the new code cannot name the execution path ---------------------------------------
@pytest.mark.parametrize("path", list(_python_files(*NEW_PACKAGES)) + [SRC / "guard" / "worker.py"],
                         ids=lambda p: str(p.relative_to(SRC)))
def test_new_modules_never_reference_execution(path):
    used = _names_used(path)
    assert not (used & EXECUTION_NAMES), sorted(used & EXECUTION_NAMES)
    assert not any(n.endswith("guard.execution") for n in used), path
    if path.parent.name != "guard":  # only the worker's Db2 backend may use the analysis session
        assert not any(n.endswith("guard.sessions") for n in used), path


@pytest.mark.parametrize("path", list(_python_files("nl2sql", "rag")), ids=lambda p: str(p.relative_to(SRC)))
def test_nl2sql_and_rag_cannot_reach_a_database_or_the_worker(path):
    used = _names_used(path)
    forbidden = {"ibm_db", "db2intel.db.connection", "Db2Connection", "db2intel.guard.analysis", "analyze",
                 "prepare_only", "explain_from_section", "db2intel.guard.worker", "GuardPool", "check"}
    assert not (used & forbidden), sorted(used & forbidden)


def test_importing_the_api_loads_no_driver_and_no_execution_code():
    code = ("import sys, json; import db2intel.api.app, db2intel.api.__main__, db2intel.nl2sql.pipeline; "
            "print(json.dumps(sorted(m for m in sys.modules if m.startswith(('ibm_db', 'db2intel')))))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         env={**os.environ, "PYTHONPATH": str(ROOT / "src")}, timeout=60)
    loaded = json.loads(out.stdout)
    for module in ("ibm_db", "db2intel.guard.execution", "db2intel.guard.sessions", "db2intel.guard.analysis",
                   "db2intel.db.connection"):
        assert module not in loaded, module


# ---- runtime: tripwires on every execution and prepare entry point ------------------------------
class Tripwire(Exception):
    pass


@pytest.fixture
def tripwires(monkeypatch):
    """Make every way to execute, prepare, explain or connect raise and record the attempt."""
    from db2intel.db import connection
    from db2intel.guard import analysis, execution, sessions

    hits = []

    def trip(name):
        def fn(*a, **k):
            hits.append(name)
            raise Tripwire(name)
        return fn

    monkeypatch.setattr(execution, "execute_approved", trip("execute_approved"))
    monkeypatch.setattr(execution, "verify_restricted_principal", trip("verify_restricted_principal"))
    monkeypatch.setattr(sessions.Db2ExecutionSession, "execute_capped", trip("execute_capped"))
    monkeypatch.setattr(sessions.Db2AnalysisSession, "prepare_only", trip("prepare_only"))
    monkeypatch.setattr(sessions.Db2AnalysisSession, "explain_from_section", trip("explain_from_section"))
    monkeypatch.setattr(analysis, "analyze", trip("analyze"))
    monkeypatch.setattr(connection.Db2Connection, "__init__", trip("Db2Connection"))
    monkeypatch.setattr(W.GuardWorker, "__init__", trip("GuardWorker"))
    return hits


class SpyPool:
    def __init__(self):
        self.calls = []
        self.degraded = None

    def check(self, sql, *, origin):
        self.calls.append((sql, origin))
        return {"request_id": "r", "status": "BLOCKED", "code": "prepare_failed", "reason": "x", "sql": None,
                "estimated_cost": None, "explain_cost": None, "objects": (), "plan": (), "sqlstate": None}

    def status(self):
        return {"degraded": None}


@pytest.fixture(scope="module")
def index():
    from db2intel.ai.embeddings import DeterministicEmbeddingProvider
    from db2intel.rag.cards import build_cards
    from db2intel.rag.catalog import catalog_from_ddl
    from db2intel.rag.index import InMemoryIndex

    cards = build_cards(catalog_from_ddl(ROOT / "sql" / "002_demo_data.sql", ["DB2INTEL_DEMO"]), ["DB2INTEL_DEMO"])
    return InMemoryIndex(DeterministicEmbeddingProvider(768), cards)


def client_for(index, answers, pool):
    from db2intel.nl2sql.pipeline import AskPipeline

    pipeline = AskPipeline(index, StaticLLM(answers), A.DEFAULT_SOURCES)
    token = "example-fake-api-token-0123456789"  # the guard pool is refused without a token
    return TestClient(A.create_app(ApiSettings(token=token), pool=pool, pipeline=pipeline),
                      raise_server_exceptions=False, headers={"Authorization": f"Bearer {token}"})


# Hostile SQL: each must be BLOCKED by the static guard (never reaching a worker).
BYPASS_CORPUS = [
    "DELETE FROM DB2INTEL_DEMO.CUSTOMER",
    "UPDATE DB2INTEL_DEMO.CUSTOMER SET CREDIT_LIMIT = 0",
    "INSERT INTO DB2INTEL_DEMO.REGION VALUES (9, 'X', 'Y', 'EMEA')",
    "MERGE INTO DB2INTEL_DEMO.REGION R USING SYSIBM.SYSDUMMY1 D ON 1=1 WHEN MATCHED THEN DELETE",
    "DROP TABLE DB2INST1.EMPLOYEE_INFO",
    "TRUNCATE TABLE DB2INST1.EMPLOYEE_SALARY IMMEDIATE",
    "ALTER TABLE DB2INST1.EMPLOYEE_INFO ADD COLUMN X INT",
    "CREATE TABLE DB2INTEL_DEMO.X (A INT)",
    "GRANT SELECT ON DB2INST1.EMPLOYEE_SALARY TO PUBLIC",
    "REVOKE CONNECT ON DATABASE FROM PUBLIC",
    "CALL SYSPROC.ADMIN_CMD('PRUNE HISTORY 2000')",
    "SET CURRENT SCHEMA DB2INST1",
    "COMMIT",
    "ROLLBACK",
    "SELECT * FROM DB2INST1.EMPLOYEE_INFO",
    "SELECT * FROM db2inst1.employee_salary",
    "SELECT * FROM \"DB2INST1\".\"EMPLOYEE_SALARY\"",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER C JOIN DB2INST1.EMPLOYEE_SALARY S ON 1=1",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER WHERE CUSTOMER_ID IN (SELECT ID FROM DB2INST1.EMPLOYEE_INFO)",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER UNION SELECT * FROM DB2INST1.EMPLOYEE_INFO",
    "WITH X AS (SELECT * FROM DB2INST1.EMPLOYEE_SALARY) SELECT * FROM X",
    "SELECT * FROM DB2INTEL.QUERY_AUDIT",
    "SELECT * FROM DB2INTEL.APP_SETTING",
    "SELECT * FROM DB2INTEL.EXPLAIN_STATEMENT",
    "SELECT * FROM SYSCAT.TABLES",
    "SELECT * FROM SYSIBM.SYSTABLES",
    "SELECT * FROM SYSIBMADM.ENV_INST_INFO",
    "SELECT * FROM NULLID.X",
    "SELECT * FROM SAMPLE.DB2INST1.EMPLOYEE",
    "SELECT * FROM CUSTOMER",
    "SELECT * FROM TABLE(MON_GET_PKG_CACHE_STMT('D', NULL, NULL, -2)) AS T",
    "SELECT * FROM XMLTABLE('$d' PASSING 1 AS \"d\") AS X",
    "SELECT * FROM UNNEST(ARRAY[1,2]) AS T(X)",
    "SELECT * FROM LATERAL (SELECT 1 FROM SYSIBM.SYSDUMMY1) T",
    "SELECT * FROM FINAL TABLE (DELETE FROM DB2INTEL_DEMO.CUSTOMER)",
    "SELECT * FROM OLD TABLE (UPDATE DB2INTEL_DEMO.CUSTOMER SET CITY = 'X')",
    "SELECT * FROM NEW TABLE (INSERT INTO DB2INTEL_DEMO.REGION VALUES (9,'X','Y','EMEA'))",
    "SELECT 1 FROM SYSIBM.SYSDUMMY1; DELETE FROM DB2INTEL_DEMO.CUSTOMER",
    "SELECT 1 FROM SYSIBM.SYSDUMMY1 -- ; DELETE",
    "SELECT 1 FROM SYSIBM.SYSDUMMY1 /* hidden */",
    "SELECT 1 FROM SYSIBM.SYSDUMMY1 /* DB2INTEL_REQ_0123456789ABCDEF0123456789ABCDEF */",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER FOR UPDATE",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER FOR UPDATE OF CITY",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER WITH UR",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER WITH RR USE AND KEEP EXCLUSIVE LOCKS",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER SKIP LOCKED DATA",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER OPTIMIZE FOR 1 ROW",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER WHERE CUSTOMER_ID = ?",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER WHERE CUSTOMER_ID = :ID",
    "SELECT SYSPROC.ADMIN_CMD('x') FROM SYSIBM.SYSDUMMY1",
    "SELECT SYSFUN.ABS(1) FROM SYSIBM.SYSDUMMY1",
    "SELECT RAISE_ERROR('70001', 'x') FROM SYSIBM.SYSDUMMY1",
    "SELECT SLEEP(100) FROM SYSIBM.SYSDUMMY1",
    "SELECT REPEAT('x', 32000) FROM SYSIBM.SYSDUMMY1",
    "SELECT DBMS_LOCK.SLEEP(100) FROM SYSIBM.SYSDUMMY1",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER, DB2INTEL_DEMO.REGION",
    "WITH RECURSIVE R(N) AS (SELECT 1 FROM SYSIBM.SYSDUMMY1 UNION ALL SELECT N + 1 FROM R) SELECT N FROM R",
    "WITH R(N) AS (SELECT 1 FROM SYSIBM.SYSDUMMY1 UNION ALL SELECT N + 1 FROM R) SELECT N FROM R",
    "SELECT * FROM (WITH X AS (SELECT 1 AS A FROM SYSIBM.SYSDUMMY1) SELECT A FROM X) T",
    "VALUES 1",
    "EXPLAIN PLAN FOR SELECT 1 FROM SYSIBM.SYSDUMMY1",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER\u0000",
    "SELECT 'unterminated FROM DB2INTEL_DEMO.CUSTOMER",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER WHERE CITY = X'41'",
]


@pytest.mark.parametrize("sql", BYPASS_CORPUS)
def test_bypass_corpus_is_blocked_by_lint_and_never_reaches_the_pool(index, tripwires, sql):
    pool = SpyPool()
    client = client_for(index, "x", pool)
    for path in ("/api/v1/guard/lint", "/api/v1/guard/check"):
        r = client.post(path, json={"sql": sql})
        body = r.json()
        assert body["executed"] is False and r.headers["x-db2intel-executed"] == "false"
        assert r.status_code == 200 and body["status"] == "BLOCKED", (path, sql, body)
        assert body["db_checked"] is False
    assert pool.calls == [] and tripwires == []


@pytest.mark.parametrize("sql", BYPASS_CORPUS)
def test_bypass_corpus_from_the_model_is_never_approved(index, tripwires, sql):
    pool = SpyPool()
    client = client_for(index, f"```sql\n{sql}\n```" if "```" not in sql else sql, pool)
    r = client.post("/api/v1/ask", json={"question": "anything"})
    body = r.json()
    assert body["executed"] is False and body["db_checked"] is False
    assert body["status"] in ("BLOCKED", "NO_SQL") and body["sql"] is None, (sql, body)
    assert pool.calls == [] and tripwires == []


def test_ai_generated_sql_is_never_prepared_explained_or_executed(index, tripwires):
    valid = [f"```sql\n{GOOD}\n```", "SELECT COUNT(*) FROM DB2INTEL_DEMO.SALES_ORDER",
             "WITH T AS (SELECT REGION_ID FROM DB2INTEL_DEMO.REGION) SELECT REGION_ID FROM T"]
    pool = SpyPool()
    client = client_for(index, valid, pool)
    approved = []
    for _ in valid:
        body = client.post("/api/v1/ask", json={"question": "count things"}).json()
        assert body["status"] == "LINT_APPROVED" and body["executed"] is False and body["db_checked"] is False
        approved.append(body)
    # Even when a user submits the model's SQL to /guard/check, it is refused before the pool.
    for body in approved:
        r = client.post("/api/v1/guard/check", json={"sql": body["generated_sql"]})
        assert r.status_code == 403 and r.json()["code"] == "ai_sql_not_checkable"
    assert pool.calls == [] and tripwires == []


def test_pool_refuses_ai_origin_even_if_called_directly(tripwires):
    p = W.GuardPool(backend="fake_guard_backends:Approving")
    with pytest.raises(W.AISqlNotAllowed):
        p.check(GOOD, origin=W.ORIGIN_AI)
    assert p.status()["workers_started"] == 0 and tripwires == []


def test_no_route_reaches_execution_with_any_input(index, tripwires):
    pool = SpyPool()
    client = client_for(index, [f"```sql\n{GOOD}\n```", "DELETE FROM X", ""], pool)
    requests = [("get", "/health", None), ("get", "/api/v1/guard/status", None)]
    for sql in [GOOD, "SELECT 1 FROM SYSIBM.SYSDUMMY1", "DELETE FROM DB2INTEL_DEMO.CUSTOMER"]:
        requests += [("post", "/api/v1/guard/lint", {"sql": sql}), ("post", "/api/v1/guard/check", {"sql": sql})]
    requests += [("post", "/api/v1/ask", {"question": q}) for q in ("a", "b", "c")]
    requests += [("post", "/api/v1/guard/check", {"sql": GOOD, "execute": True}),
                 ("post", "/api/v1/execute", {"sql": GOOD}), ("put", "/api/v1/guard/check", {"sql": GOOD})]
    for method, path, body in requests:
        r = getattr(client, method)(path, json=body) if body is not None else getattr(client, method)(path)
        assert r.json()["executed"] is False and r.headers["x-db2intel-executed"] == "false", (method, path)
    # human SQL that passed lint reached only the pool's check(), with human origin
    assert all(origin == W.ORIGIN_HUMAN for _, origin in pool.calls) and tripwires == []


def test_audit_stays_disabled(index):
    client = client_for(index, "x", SpyPool())
    app = client.app
    from db2intel.guard.audit import DisabledAuditSink
    assert isinstance(app.state.ctx.audit, DisabledAuditSink) and app.state.ctx.audit.ready() is False


# ---- body limit when the declared length is false ----------------------------------------------
def test_body_limit_enforced_on_actual_bytes_not_declared_length():
    seen = []

    async def downstream(scope, receive, send):
        while True:
            message = await receive()
            seen.append(len(message.get("body", b"")))
            if not message.get("more_body"):
                break

    middleware = A.LimitsMiddleware(downstream, max_body_bytes=1_000, token="")
    chunks = [{"type": "http.request", "body": b"x" * 600, "more_body": True},
              {"type": "http.request", "body": b"x" * 600, "more_body": False}]
    sent = []

    async def receive():
        return chunks.pop(0)

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": "/api/v1/guard/lint",
             "headers": [(b"content-length", b"10"), (b"content-type", b"application/json")]}
    asyncio.run(middleware(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    body = json.loads(b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body"))
    assert start["status"] == 413 and body["executed"] is False and body["code"] == "body_too_large"


# ---- secrets ---------------------------------------------------------------------------------------
def test_secrets_never_appear_in_responses(index):
    from db2intel.api.__main__ import build_app

    secret_pw, secret_token = "example-fake-db-password-sentinel", "example-fake-api-token-sentinel-0123"
    env = {"DB2_PASSWORD": secret_pw, "DB2INTEL_API_TOKEN": secret_token, "EMBEDDING_PROVIDER": "deterministic",
           "EMBEDDING_DIM": "768", "LLM_PROVIDER": "none"}
    app, api = build_app(env, with_guard_pool=False)
    assert secret_token not in repr(api)
    client = TestClient(app, raise_server_exceptions=False)
    auth = {"Authorization": f"Bearer {secret_token}"}
    responses = [client.get("/health"), client.get("/api/v1/guard/status", headers=auth),
                 client.post("/api/v1/guard/lint", json={"sql": GOOD}, headers=auth),
                 client.post("/api/v1/guard/check", json={"sql": GOOD}, headers=auth),
                 client.post("/api/v1/ask", json={"question": "customers"}, headers=auth),
                 client.post("/api/v1/ask", json={"question": "customers"}),
                 client.get("/nope")]
    for r in responses:
        assert secret_pw not in r.text and secret_token not in r.text
        assert r.json()["executed"] is False


def test_build_app_does_not_connect_or_start_workers(index, tripwires):
    from db2intel.api.__main__ import build_app

    app, _ = build_app({"EMBEDDING_PROVIDER": "deterministic", "EMBEDDING_DIM": "768", "LLM_PROVIDER": "none",
                        "DB2_PASSWORD": "x", "DB2INTEL_API_TOKEN": "example-fake-api-token-0123456789",
                        "DB2INTEL_WORKER_LOG": "off"}, with_guard_pool=True)
    pool = app.state.ctx.pool
    try:
        assert pool.status()["workers_started"] == 0 and pool.backend == W.DB2_BACKEND and tripwires == []
    finally:
        pool.close()


# ---- repository invariants ----------------------------------------------------------------------
MIGRATION_SHA256 = {
    "001_schema_meta.sql": "4f81cacfb808c8101c17de863b3808dae8325822e0b25a2a7a74667fcc718480",
    "002_demo_data.sql": "5b9712be0317a1866802ae40c2b496642456f81932453297a529804f9f106ced",
    "003_explain_tables.sql": "456da4509120d776f3af0cce4f56d441d0e93c872f39b4214c8706b7171dd6d2",
    "900_teardown.sql": "233ca443e69d27dafa53652003880d3c8276a8ebc9640b46d81d0a11e7b3e782",
}


def test_migration_files_are_unchanged():
    files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT / "sql").glob("*.sql")}
    assert files == MIGRATION_SHA256


def test_runtime_dependencies_are_pinned():
    for name in ("requirements.txt", "requirements-dev.txt"):
        for line in (ROOT / name).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line and not line.startswith("-r"):
                assert "==" in line, f"{name}: {line} is not pinned"
