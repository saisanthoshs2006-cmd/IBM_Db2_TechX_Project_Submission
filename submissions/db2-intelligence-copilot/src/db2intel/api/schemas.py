"""Request bodies. Unknown fields are rejected; there is no field that can request execution."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from db2intel.guard import rules
from db2intel.nl2sql.prompt import MAX_QUESTION_CHARS


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class SqlRequest(_Strict):
    sql: str = Field(min_length=1, max_length=rules.MAX_SQL_CHARS)


class AskRequest(_Strict):
    question: str = Field(min_length=1, max_length=MAX_QUESTION_CHARS)
    source: str = Field(default="demo", pattern=r"^[a-z][a-z0-9_]{0,31}$")
