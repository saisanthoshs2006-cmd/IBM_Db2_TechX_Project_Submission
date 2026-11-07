"""FastAPI routes with fake guard pools and static LLMs. No database, no real guard worker."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from db2intel.ai.embeddings import DeterministicEmbeddingProvider
from db2intel.api import app as A
from db2intel.api.errors import public_reason, sanitize
from db2intel.config import ApiSettings, ConfigError
from db2intel.guard import worker as W
from db2intel.nl2sql.llm import NoLLM, StaticLLM
from db2intel.nl2sql.pipeline import AskPipeline
from db2intel.rag.cards import build_cards
from db2intel.rag.catalog import catalog_from_ddl
from db2intel.rag.index import InMemoryIndex

ROOT = Path(__file__).resolve().parents[1]
GOOD = "SELECT C.COMPANY_NAME FROM DB2INTEL_DEMO.CUSTOMER C WHERE C.CUSTOMER_ID = 42"
TOKEN = "example-fake-api-token-0123456789"


class FakePool:
    """Stands in for GuardPool. Records every call; raises or answers as configured."""

    def __init__(self, decision=None, raises=None):
        self.calls = []
        self.decision = decision
        self.raises = raises
        self.degraded = None

    def check(self, sql, *, origin):
        self.calls.append((sql, origin))
        if self.raises:
            raise self.raises
        return self.decision or {
            "request_id": "r1", "status": "APPROVED", "code": "approved", "reason": "all checks passed",
            "sql": sql + " FETCH FIRST 500 ROWS ONLY", "estimated_cost": 7.0, "explain_cost": 6.9,
            "objects": (("DB2INTEL_DEMO", "CUSTOMER", "TA"),), "plan": ((1, "RETURN", 7.0),), "sqlstate": None,
        }

    def status(self):
        return {"size": 2, "idle_workers": 0, "degraded": self.degraded}


@pytest.fixture(scope="module")
def index():
    cards = build_cards(catalog_from_ddl(ROOT / "sql" / "002_demo_data.sql", ["DB2INTEL_DEMO"]), ["DB2INTEL_DEMO"])
    return InMemoryIndex(DeterministicEmbeddingProvider(768), cards)


def make(index, *, pool=None, llm=None, token=None, max_body=65_536, raise_server_exceptions=False):
    """With a pool and no explicit token, the app gets TOKEN and the client sends it by default
    (the guard pool is refused without a token). An explicit token is never sent automatically."""
    pipeline = AskPipeline(index, llm or NoLLM(), A.DEFAULT_SOURCES) if index is not None else None
    auto = token is None and pool is not None
    token = TOKEN if auto else (token or "")
    app = A.create_app(ApiSettings(token=token, max_body_bytes=max_body), pool=pool, pipeline=pipeline)
    headers = {"Authorization": f"Bearer {TOKEN}"} if auto else None
    return TestClient(app, raise_server_exceptions=raise_server_exceptions, headers=headers), app


def assert_not_executed(response):
    assert response.headers.get("x-db2intel-executed") == "false"
    body = response.json()
    assert body["executed"] is False
    return body


# ---- routes ---------------------------------------------------------------------------------
def test_routes_are_exactly_the_reviewed_set(index):
    _, app = make(index)
    actual = {(m, r.path) for r in app.routes if hasattr(r, "methods") for m in r.methods if m != "HEAD"}
    assert actual == A.EXPECTED_ROUTES
    assert not any("exec" in path or "run" in path for _, path in actual)


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json", "/api/v1/execute", "/api/v1/guard/execute",
                                  "/api/v1/run", "/api/v1/query"])
def test_docs_and_execution_paths_do_not_exist(index, path):
    client, _ = make(index)
    for method in ("get", "post"):
        r = getattr(client, method)(path)
        assert r.status_code == 404
        assert assert_not_executed(r)["code"] == "not_found"


def test_health(index):
    client, _ = make(index)
    r = client.get("/health")
    assert r.status_code == 200 and assert_not_executed(r)["status"] == "ok"


def test_status_reports_flags_and_degraded(index):
    pool = FakePool()
    client, _ = make(index, pool=pool)
    body = assert_not_executed(client.get("/api/v1/guard/status"))
    assert body["execution_enabled"] is False and body["ai_sql_check_enabled"] is False and body["audit"] == "disabled"
    assert body["status"] == "OK"
    pool.degraded = "cleanup_failed"
    assert assert_not_executed(client.get("/api/v1/guard/status"))["status"] == "DEGRADED"


# ---- lint ---------------------------------------------------------------------------------------
def test_lint_approves_and_caps(index):
    pool = FakePool()
    client, _ = make(index, pool=pool)
    body = assert_not_executed(client.post("/api/v1/guard/lint", json={"sql": "select * from db2intel_demo.customer"}))
    assert body["status"] == "LINT_APPROVED" and body["sql"].endswith("FETCH FIRST 500 ROWS ONLY")
    assert body["db_checked"] is False and pool.calls == []


@pytest.mark.parametrize("sql,code", [
    ("DELETE FROM DB2INTEL_DEMO.CUSTOMER", "not_select"),
    ("SELECT * FROM DB2INST1.EMPLOYEE_SALARY", "forbidden_schema"),
    ("SELECT 1 FROM SYSIBM.SYSDUMMY1; SELECT 2 FROM SYSIBM.SYSDUMMY1", "multiple_statements"),
])
def test_lint_blocks(index, sql, code):
    client, _ = make(index)
    body = assert_not_executed(client.post("/api/v1/guard/lint", json={"sql": sql}))
    assert body["status"] == "BLOCKED" and body["code"] == code


# ---- check --------------------------------------------------------------------------------------
def test_check_lints_then_uses_pool_with_human_origin(index):
    pool = FakePool()
    client, _ = make(index, pool=pool)
    body = assert_not_executed(client.post("/api/v1/guard/check", json={"sql": GOOD}))
    assert body["status"] == "APPROVED" and body["db_checked"] is True and body["estimated_cost"] == 7.0
    assert pool.calls == [(GOOD, W.ORIGIN_HUMAN)]


def test_check_blocked_by_lint_never_reaches_pool(index):
    pool = FakePool()
    client, _ = make(index, pool=pool)
    body = assert_not_executed(client.post("/api/v1/guard/check", json={"sql": "DROP TABLE DB2INST1.EMPLOYEE_INFO"}))
    assert body["status"] == "BLOCKED" and body["db_checked"] is False and pool.calls == []


def test_check_refuses_sql_generated_by_the_model(index):
    pool = FakePool()
    client, _ = make(index, pool=pool, llm=StaticLLM(f"```sql\n{GOOD}\n```"))
    ask = assert_not_executed(client.post("/api/v1/ask", json={"question": "customer 42 name"}))
    assert ask["status"] == "LINT_APPROVED"
    for sql in (ask["sql"], ask["generated_sql"], ask["generated_sql"].lower()):
        r = client.post("/api/v1/guard/check", json={"sql": sql})
        assert r.status_code == 403 and assert_not_executed(r)["code"] == "ai_sql_not_checkable"
    assert pool.calls == []


@pytest.mark.parametrize("exc,status,code", [
    (W.Degraded("cleanup_failed"), 503, "degraded"),
    (W.PoolBusy("busy"), 503, "busy"),
    (W.WorkerTimeout("killed"), 504, "check_timeout"),
    (W.WorkerStartError("no"), 503, "guard_unavailable"),
    (W.WorkerFailed("died"), 503, "worker_failed"),
    (W.AISqlNotAllowed("no"), 403, "ai_sql_not_checkable"),
])
def test_check_maps_pool_errors(index, exc, status, code):
    client, _ = make(index, pool=FakePool(raises=exc))
    r = client.post("/api/v1/guard/check", json={"sql": GOOD})
    assert r.status_code == status and assert_not_executed(r)["code"] == code
    if code == "busy":
        assert r.headers["retry-after"] == "2"


def test_check_without_pool_is_disabled(index):
    client, _ = make(index, pool=None)
    r = client.post("/api/v1/guard/check", json={"sql": GOOD})
    assert r.status_code == 503 and assert_not_executed(r)["code"] == "guard_disabled"


def test_check_hides_driver_message_tokens(index):
    decision = {"request_id": "r1", "status": "BLOCKED", "code": "prepare_failed",
                "reason": 'prepare failed: [IBM][CLI Driver][DB2/LINUXX8664] SQL0204N  "DB2INTEL_DEMO.SECRETNAME" is an undefined name.  SQLSTATE=42704',
                "sql": None, "estimated_cost": None, "explain_cost": None, "objects": (), "plan": (), "sqlstate": "42704"}
    client, _ = make(index, pool=FakePool(decision=decision))
    body = assert_not_executed(client.post("/api/v1/guard/check", json={"sql": GOOD}))
    assert body["reason"] == "prepare failed (SQL0204N, SQLSTATE 42704)" and "SECRETNAME" not in body["reason"]


# ---- ask ---------------------------------------------------------------------------------------
def test_ask_never_touches_the_pool(index):
    pool = FakePool()
    client, _ = make(index, pool=pool, llm=StaticLLM(f"```sql\n{GOOD}\n```"))
    body = assert_not_executed(client.post("/api/v1/ask", json={"question": "name of customer 42", "source": "demo"}))
    assert body["status"] == "LINT_APPROVED" and body["db_checked"] is False and pool.calls == []
    assert "not prepared, explained or executed" in body["next_step"] + body["reason"]


def test_ask_without_llm(index):
    client, _ = make(index)
    body = assert_not_executed(client.post("/api/v1/ask", json={"question": "top customers"}))
    assert body["status"] == "NO_SQL" and body["code"] == "llm_unavailable" and body["retrieved"]


def test_ask_unknown_source_is_422(index):
    client, _ = make(index)
    r = client.post("/api/v1/ask", json={"question": "top customers", "source": "sample"})
    assert r.status_code == 422 and assert_not_executed(r)["code"] == "unknown_source"


def test_ask_disabled_without_pipeline():
    client, _ = make(None)
    r = client.post("/api/v1/ask", json={"question": "x"})
    assert r.status_code == 503 and assert_not_executed(r)["code"] == "ask_disabled"


# ---- request validation, limits, auth ----------------------------------------------------------
@pytest.mark.parametrize("path,body", [
    ("/api/v1/guard/lint", {"sql": GOOD, "execute": True}),
    ("/api/v1/guard/check", {"sql": GOOD, "commit": True}),
    ("/api/v1/ask", {"question": "x", "run": True}),
    ("/api/v1/guard/lint", {}),
    ("/api/v1/guard/lint", {"sql": ""}),
    ("/api/v1/guard/lint", {"sql": 5}),
    ("/api/v1/ask", {"question": "x" * 2001}),
    ("/api/v1/ask", {"question": "x", "source": "../etc"}),
])
def test_invalid_bodies_are_422_without_echoing_input(index, path, body):
    pool = FakePool()
    client, _ = make(index, pool=pool)
    r = client.post(path, json=body)
    assert r.status_code == 422
    data = assert_not_executed(r)
    assert data["code"] == "invalid_request" and pool.calls == []
    assert data["problems"] and all(set(p) == {"field", "problem"} for p in data["problems"])
    assert GOOD not in r.text and "x" * 50 not in r.text and "../etc" not in r.text


def test_malformed_json_is_422(index):
    client, _ = make(index)
    r = client.post("/api/v1/guard/lint", content=b"{not json", headers={"content-type": "application/json"})
    assert r.status_code == 422 and assert_not_executed(r)


def test_wrong_method_is_405(index):
    client, _ = make(index)
    r = client.get("/api/v1/guard/check")
    assert r.status_code == 405 and assert_not_executed(r)["code"] == "method_not_allowed"


def test_body_size_limit_by_content_length(index):
    client, _ = make(index, max_body=1_024)
    r = client.post("/api/v1/guard/lint", json={"sql": "SELECT 1 FROM SYSIBM.SYSDUMMY1 " + " " * 2_000})
    assert r.status_code == 413 and assert_not_executed(r)["code"] == "body_too_large"


def test_body_size_limit_when_streamed_without_length(index):
    client, _ = make(index, max_body=1_024)

    def chunks():
        yield b'{"sql": "'
        for _ in range(10):
            yield b"x" * 500
        yield b'"}'

    r = client.post("/api/v1/guard/lint", content=chunks(), headers={"content-type": "application/json"})
    assert r.status_code in (411, 413) and assert_not_executed(r)


def test_token_required_for_api_but_not_health(index):
    pool = FakePool()
    client, _ = make(index, pool=pool, token=TOKEN)
    assert client.get("/health").status_code == 200
    for headers in ({}, {"Authorization": "Bearer wrong"}, {"Authorization": TOKEN}, {"Authorization": f"bearer {TOKEN}"}):
        r = client.post("/api/v1/guard/check", json={"sql": GOOD}, headers=headers)
        assert r.status_code == 401 and assert_not_executed(r)["code"] == "unauthorized"
        assert TOKEN not in r.text
    assert pool.calls == []
    ok = client.post("/api/v1/guard/check", json={"sql": GOOD}, headers={"Authorization": f"Bearer {TOKEN}"})
    assert ok.status_code == 200 and len(pool.calls) == 1


def test_unexpected_exception_is_500_with_generic_message(index):
    class Exploding(FakePool):
        def check(self, sql, *, origin):
            raise RuntimeError("PWD=hunter2 internal detail")

    client, _ = make(index, pool=Exploding())
    r = client.post("/api/v1/guard/check", json={"sql": GOOD})
    assert r.status_code == 500 and assert_not_executed(r)["message"] == "internal error"
    assert "hunter2" not in r.text


# ---- settings -----------------------------------------------------------------------------------
@pytest.mark.parametrize("settings", [ApiSettings(host="0.0.0.0"), ApiSettings(host="192.168.1.5"),
                                      ApiSettings(token="short"), ApiSettings(port=0)])
def test_app_refuses_unsafe_settings(index, settings):
    with pytest.raises(ConfigError):
        A.create_app(settings, pool=None, pipeline=None)


def test_unexpected_route_is_refused_at_startup(index, monkeypatch):
    monkeypatch.setattr(A, "EXPECTED_ROUTES", A.EXPECTED_ROUTES - {("POST", "/api/v1/ask")})
    with pytest.raises(RuntimeError, match="unexpected API routes"):
        A.create_app(ApiSettings(), pool=None, pipeline=None)


# ---- sanitising helpers ---------------------------------------------------------------------------
@pytest.mark.parametrize("raw,expected", [
    ("cannot connect PWD=hunter2;UID=db2inst1", "cannot connect PWD=***;UID=***"),
    ("line1\nline2\x00", "line1 line2"),
    ("x" * 600, "x" * 499 + "…"),
])
def test_sanitize(raw, expected):
    assert sanitize(raw) == expected


@pytest.mark.parametrize("reason,state,expected", [
    ("all checks passed", None, "all checks passed"),
    ("estimated cost 9 is above the limit", None, "estimated cost 9 is above the limit"),
    ("prepare failed: SQL0551N  \"DB2INST1\" lacks privilege SQLSTATE=42501", None, "prepare failed (SQL0551N, SQLSTATE 42501)"),
    ("explain failed: [IBM][CLI Driver] something", None, "explain failed"),
    ("database error", "57014", "database error (SQLSTATE 57014)"),
])
def test_public_reason(reason, state, expected):
    assert public_reason(reason, state) == expected
