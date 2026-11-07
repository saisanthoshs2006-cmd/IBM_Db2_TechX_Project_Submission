"""FastAPI application factory (Phase 2C).

Routes (there is no execution route):
  GET  /health              liveness; no database
  GET  /api/v1/guard/status pool state, degraded latch, feature flags
  POST /api/v1/guard/lint   static SQL guard only; no database
  POST /api/v1/guard/check  lint, then prepare-only analysis of human-written SQL in a worker
  POST /api/v1/ask          question -> schema cards -> LLM -> lint; never touches Db2

Every response, including errors, has "executed": false in its JSON body and the header
X-Db2Intel-Executed: false. Interactive docs and the OpenAPI document are disabled. The server
must bind to a loopback address; an optional bearer token protects /api/*. The guard pool (which
prepares and explains against Db2) is refused unless that token is set. Request bodies are
limited in size. On shutdown (including SIGTERM, which uvicorn turns into a graceful shutdown
before it re-raises the signal) the lifespan hook closes the guard pool exactly once via
shutdown_app(). Audit stays disabled (DisabledAuditSink): nothing is written to QUERY_AUDIT.
"""
from __future__ import annotations

import hmac
import threading
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Mapping

import anyio

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from db2intel.api.errors import EXECUTED_HEADER, error, log, respond, sanitize
from db2intel.api.routes_ask import router as ask_router
from db2intel.api.routes_guard import router as guard_router
from db2intel.config import ApiSettings, ConfigError
from db2intel.guard.audit import DisabledAuditSink
from db2intel.guard.parser import check_allowed_schemas
from db2intel.guard.worker import GuardPool
from db2intel.nl2sql.pipeline import AiSqlRegistry, AskPipeline

EXPECTED_ROUTES = frozenset({
    ("GET", "/health"),
    ("GET", "/api/v1/guard/status"),
    ("POST", "/api/v1/guard/lint"),
    ("POST", "/api/v1/guard/check"),
    ("POST", "/api/v1/ask"),
})
DEFAULT_SOURCES = {"demo": ("DB2INTEL_DEMO",)}


@dataclass
class AppContext:
    api: ApiSettings
    pool: GuardPool | None
    pipeline: AskPipeline | None
    registry: AiSqlRegistry
    lint_schemas: frozenset[str]
    audit: DisabledAuditSink
    guard_disabled_reason: str | None = None
    # acquired (never released) by the one shutdown_app() call that closes the pool
    shutdown_once: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def shut_down(self) -> bool:
        return self.shutdown_once.locked()


def shutdown_app(app: FastAPI) -> bool:
    """Close the guard pool exactly once, whichever caller gets here first (the lifespan hook on a
    graceful or SIGTERM shutdown, or main() when uvicorn returns). Returns True for that call."""
    ctx: AppContext = app.state.ctx
    if not ctx.shutdown_once.acquire(blocking=False):  # atomic: only the first caller gets it
        return False
    if ctx.pool is not None:
        try:
            ctx.pool.close()
        except Exception as exc:  # shutdown must finish; the pool kills what it can on its own
            log.error("closing the guard pool failed: %s", type(exc).__name__)
    return True


@asynccontextmanager
async def _lifespan(app: FastAPI):
    yield
    # pool.close() blocks while workers are reaped; keep the event loop free meanwhile
    await anyio.to_thread.run_sync(shutdown_app, app)


class _BodyTooLarge(Exception):
    pass


class LimitsMiddleware:
    """Pure ASGI: request size limit and optional bearer token, before any route code runs."""

    def __init__(self, app, max_body_bytes: int, token: str):
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.token = token.encode("utf-8") if token else b""

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v for k, v in scope.get("headers", [])}
        path = scope.get("path", "")

        async def reply(response):
            await response(scope, receive, send)

        if self.token and path.startswith("/api/"):
            auth = headers.get("authorization", b"")
            expected = b"Bearer " + self.token
            if not hmac.compare_digest(auth, expected):
                return await reply(error(401, "unauthorized", "a valid bearer token is required"))
        length = headers.get("content-length")
        if length is not None:
            try:
                if int(length) > self.max_body_bytes:
                    return await reply(error(413, "body_too_large", f"request body exceeds {self.max_body_bytes} bytes"))
            except ValueError:
                return await reply(error(400, "bad_request", "invalid Content-Length"))
        elif scope.get("method") in ("POST", "PUT", "PATCH"):
            return await reply(error(411, "length_required", "Content-Length is required"))

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    raise _BodyTooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            await reply(error(413, "body_too_large", f"request body exceeds {self.max_body_bytes} bytes"))


GUARD_NEEDS_TOKEN_REASON = "DB2INTEL_API_TOKEN is not set; the database guard check requires a bearer token"


def create_app(api: ApiSettings, *, pool: GuardPool | None, pipeline: AskPipeline | None,
               sources: Mapping[str, tuple[str, ...]] = DEFAULT_SOURCES,
               guard_disabled_reason: str | None = None) -> FastAPI:
    api.validate()
    if pool is not None and not api.token:  # without a token any local process could trigger prepares
        raise ConfigError(GUARD_NEEDS_TOKEN_REASON)
    if pool is None and guard_disabled_reason is None:
        guard_disabled_reason = "the guard pool is not enabled in this process"
    lint_schemas = check_allowed_schemas(sources.get("demo") or next(iter(sources.values())))
    registry = pipeline.registry if pipeline is not None else AiSqlRegistry()
    app = FastAPI(title="Db2 Intelligence", docs_url=None, redoc_url=None, openapi_url=None, lifespan=_lifespan)
    app.state.ctx = AppContext(api, pool, pipeline, registry, lint_schemas, DisabledAuditSink(),
                               None if pool is not None else guard_disabled_reason)

    @app.get("/health")
    def health():
        return respond(200, {"status": "ok"})

    app.include_router(guard_router)
    app.include_router(ask_router)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
        return error(exc.status_code, code, str(exc.detail) if exc.status_code not in (404, 405) else code.replace("_", " "))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # Report where and why, never the submitted value.
        problems = [{"field": ".".join(str(p) for p in e.get("loc", ())[1:]) or "body", "problem": sanitize(e.get("msg", ""), 200)}
                    for e in exc.errors()[:10]]
        return respond(422, {"status": "ERROR", "code": "invalid_request", "message": "the request body is invalid",
                             "problems": problems})

    @app.exception_handler(Exception)
    async def unexpected(request: Request, exc: Exception):
        log.error("unexpected error in %s: %s", request.url.path, type(exc).__name__)
        return error(500, "internal_error", "internal error")

    app.add_middleware(LimitsMiddleware, max_body_bytes=api.max_body_bytes, token=api.token)

    @app.middleware("http")
    async def executed_header(request: Request, call_next):
        response = await call_next(request)
        response.headers[EXECUTED_HEADER] = "false"
        return response

    actual = {(m, r.path) for r in app.routes if hasattr(r, "methods") for m in r.methods if m != "HEAD"}
    if actual != EXPECTED_ROUTES:  # a new route needs a review of this module and its tests
        raise RuntimeError(f"unexpected API routes: {sorted(actual ^ EXPECTED_ROUTES)}")
    return app
