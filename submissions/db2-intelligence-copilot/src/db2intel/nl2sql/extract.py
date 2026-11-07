"""Extract exactly one SQL statement from model output, or refuse.

Accepted shapes (after stripping surrounding whitespace):
  * exactly one fenced block (```sql or ```), with nothing outside it
  * bare text with no fence at all
Anything else (prose around the block, two blocks, an unterminated fence, an empty block, text
that does not start with SELECT, WITH or '(') is NO_SQL. One trailing ';' is removed; the SQL
guard rejects any other ';'. Text containing the guard's request-marker prefix is refused.
"""
from __future__ import annotations

import re

from db2intel.guard import rules

MAX_SQL_CHARS = rules.MAX_SQL_CHARS
_FENCE = "```"
_BLOCK_RE = re.compile(r"\A```[ \t]*([A-Za-z0-9_-]*)[ \t]*\n(.*?)\n?[ \t]*```\Z", re.S)
_START_RE = re.compile(r"\A(?:SELECT|WITH)\b|\A\(", re.I)


class ExtractionError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def extract_sql(text: str) -> str:
    if not isinstance(text, str):
        raise ExtractionError("no_text", "the model returned no text")
    body = text.strip()
    if not body:
        raise ExtractionError("empty_answer", "the model returned an empty answer")
    fences = body.count(_FENCE)
    if fences:
        if fences != 2:
            raise ExtractionError("fence_count", "expected exactly one fenced SQL block")
        m = _BLOCK_RE.match(body)
        if not m:
            raise ExtractionError("text_outside_block", "the answer has text outside the SQL block")
        if m.group(1).lower() not in ("", "sql"):
            raise ExtractionError("wrong_language", "the fenced block is not SQL")
        body = m.group(2).strip()
        if not body:
            raise ExtractionError("no_answer", "the model could not answer from the schema")
    if len(body) > MAX_SQL_CHARS:
        raise ExtractionError("too_long", f"the SQL is longer than {MAX_SQL_CHARS} characters")
    if rules.MARKER_PREFIX.upper() in body.upper():
        raise ExtractionError("marker", "the SQL contains a reserved request marker")
    if body.endswith(";"):
        body = body[:-1].rstrip()
    if not _START_RE.match(body):
        raise ExtractionError("not_select", "the answer is not a SELECT statement")
    return body
