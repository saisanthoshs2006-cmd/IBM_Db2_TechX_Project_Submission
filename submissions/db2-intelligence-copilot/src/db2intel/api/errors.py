"""Uniform, sanitised JSON responses. Every response body carries "executed": false."""
from __future__ import annotations

import logging
import re
from typing import Any

from fastapi.responses import JSONResponse

log = logging.getLogger("db2intel.api")

EXECUTED_HEADER = "X-Db2Intel-Executed"
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SECRET_RE = re.compile(r"(?i)\b(PWD|PASSWORD|UID|USER|TOKEN|APIKEY|API_KEY)\s*=\s*[^;\s]*")
_SQLCODE_RE = re.compile(r"\bSQL\d{4,5}[NWC]\b")
_SQLSTATE_RE = re.compile(r"SQLSTATE=([0-9A-Z]{5})")
MAX_MESSAGE_CHARS = 500


def sanitize(text: Any, limit: int = MAX_MESSAGE_CHARS) -> str:
    text = _CONTROL_RE.sub(" ", str(text))
    text = _SECRET_RE.sub(lambda m: f"{m.group(1)}=***", text)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def public_reason(reason: str | None, sqlstate: str | None) -> str:
    """Guard reasons written by our code are kept. A reason that embeds a Db2 driver message
    is reduced to our prefix plus the SQL code and SQLSTATE, so message tokens never leak."""
    reason = reason or ""
    if sqlstate or _SQLCODE_RE.search(reason) or "[IBM]" in reason:
        prefix = reason.split(":", 1)[0] if ":" in reason else "database error"
        code = _SQLCODE_RE.search(reason)
        state = sqlstate or (m.group(1) if (m := _SQLSTATE_RE.search(reason)) else None)
        details = ", ".join(filter(None, [code.group(0) if code else None, f"SQLSTATE {state}" if state else None]))
        return sanitize(f"{prefix} ({details})" if details else prefix)
    return sanitize(reason)


def respond(status_code: int, payload: dict | None = None, **fields) -> JSONResponse:
    body = {**(payload or {}), **fields}
    body["executed"] = False  # always last, so no payload can override it
    return JSONResponse(status_code=status_code, content=body, headers={EXECUTED_HEADER: "false"})


def error(status_code: int, code: str, message: str) -> JSONResponse:
    return respond(status_code, {"status": "ERROR", "code": code, "message": sanitize(message)})
