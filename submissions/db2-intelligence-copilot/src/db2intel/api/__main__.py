"""Run the API locally:  python -m db2intel.api

Starting the server does not connect to Db2. A guard worker (which connects with the .env
settings, prepares only and never commits) starts on the first /api/v1/guard/check request.
The guard pool is only enabled when DB2INTEL_API_TOKEN is set; without it /api/v1/guard/check
answers 503 guard_disabled and everything else works. Worker stderr is redacted and written to
DB2INTEL_WORKER_LOG (default logs/guard-worker.log, git-ignored; "off" discards it).
Schema cards come from sql/002_demo_data.sql (DDL only), so /ask works without a database.
"""
from __future__ import annotations

import sys
from typing import Mapping

from db2intel.config import PROJECT_ROOT, WORKER_LOG_OFF, ConfigError, load_api_settings, load_settings

DEMO_DDL = PROJECT_ROOT / "sql" / "002_demo_data.sql"


def build_app(env: Mapping[str, str] | None = None, *, with_guard_pool: bool = True):
    from db2intel.ai.embeddings import create_embedding_provider
    from db2intel.api.app import DEFAULT_SOURCES, GUARD_NEEDS_TOKEN_REASON, create_app
    from db2intel.guard.worker import GuardPool
    from db2intel.nl2sql.llm import create_llm
    from db2intel.nl2sql.pipeline import AskPipeline
    from db2intel.rag.cards import build_cards
    from db2intel.rag.catalog import catalog_from_ddl
    from db2intel.rag.index import InMemoryIndex

    api, llm_settings = load_api_settings(env)
    settings = load_settings(env)
    schemas = [s for v in DEFAULT_SOURCES.values() for s in v]
    cards = build_cards(catalog_from_ddl(DEMO_DDL, schemas), schemas)
    index = InMemoryIndex(create_embedding_provider(settings.embedding), cards)
    pipeline = AskPipeline(index, create_llm(llm_settings), DEFAULT_SOURCES, max_rows=api.max_rows)
    pool, reason = None, None
    if not with_guard_pool:
        reason = "the guard pool was disabled by the caller"
    elif not api.token:
        reason = GUARD_NEEDS_TOKEN_REASON
    else:
        log_path = None if api.worker_log == WORKER_LOG_OFF else PROJECT_ROOT / api.worker_log
        pool = GuardPool(size=api.pool_size, check_deadline=api.check_deadline_seconds,
                         startup_deadline=api.startup_deadline_seconds, queue_wait=api.queue_wait_seconds,
                         env=env, stderr_log=log_path)
    return create_app(api, pool=pool, pipeline=pipeline, sources=DEFAULT_SOURCES, guard_disabled_reason=reason), api


def main() -> int:
    try:
        app, api = build_app()
    except (ConfigError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    reason = app.state.ctx.guard_disabled_reason
    if reason:
        print(f"note: /api/v1/guard/check is disabled: {reason}", file=sys.stderr)
    import uvicorn

    from db2intel.api.app import shutdown_app

    try:
        uvicorn.run(app, host=api.host, port=api.port, log_level="info", access_log=False)
    finally:
        # Normally a no-op: the lifespan hook has already closed the pool. On SIGTERM uvicorn
        # re-raises the signal after its graceful shutdown, so this line is not reached then.
        shutdown_app(app)
    return 0


if __name__ == "__main__":
    sys.exit(main())
