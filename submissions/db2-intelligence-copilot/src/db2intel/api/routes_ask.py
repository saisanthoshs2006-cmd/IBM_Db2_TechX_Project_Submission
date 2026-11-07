"""/ask: natural language -> guarded SQL text. Offline; nothing is prepared or executed."""
from __future__ import annotations

from fastapi import APIRouter, Request

from db2intel.api.errors import error, respond, sanitize
from db2intel.api.schemas import AskRequest

router = APIRouter(prefix="/api/v1")


@router.post("/ask")
def ask(body: AskRequest, request: Request):
    state = request.app.state.ctx
    if state.pipeline is None:
        return error(503, "ask_disabled", "natural-language questions are not enabled in this process")
    result = state.pipeline.ask(body.question, body.source)
    return respond(200 if result.status != "INVALID" else 422, {
        "status": result.status,
        "code": result.code,
        "reason": sanitize(result.reason),
        "source": result.source,
        "sql": result.sql,
        "generated_sql": result.generated_sql,
        "tables": [list(t) for t in result.tables],
        "row_cap": result.row_cap,
        "retrieved": [{"object": oid, "score": score} for oid, score in result.retrieved],
        "llm": result.llm,
        "next_step": "review the SQL; it was not prepared, explained or executed",
    }, db_checked=False)
