"""Natural language -> guarded SQL text. Offline: no database connection, prepare or execute.

  question -> validate -> retrieve schema cards (InMemoryIndex) -> prompt -> LLM -> extract one
  statement -> static SQL guard (lint + row cap) -> AskResult

This module has no reference to a database session, the guard worker pool, the analysis or the
execution code, so AI-generated SQL cannot be prepared, explained or executed from here
(gate G4 is not approved; tests check the import graph). Every result has executed=False and
db_checked=False. Canonical SQL produced here is recorded in an AiSqlRegistry so the API can
refuse a request to /guard/check the same text.
"""
from __future__ import annotations

import hashlib
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Mapping

from db2intel.guard import rules
from db2intel.guard.lexer import GuardViolation
from db2intel.guard.parser import check_allowed_schemas, guard_sql
from db2intel.nl2sql.extract import ExtractionError, extract_sql
from db2intel.nl2sql.llm import LLMError, LLMProvider, LLMUnavailable
from db2intel.nl2sql.prompt import MAX_QUESTION_CHARS, build_prompt
from db2intel.rag.index import InMemoryIndex

LINT_APPROVED, BLOCKED, NO_SQL, INVALID = "LINT_APPROVED", "BLOCKED", "NO_SQL", "INVALID"
_SOURCE_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class AiSqlRegistry:
    """Bounded memory of canonical SQL texts the model produced in this process."""

    def __init__(self, capacity: int = 2_000):
        self._items: OrderedDict[str, None] = OrderedDict()
        self._capacity = capacity
        self._lock = threading.Lock()

    @staticmethod
    def _key(canonical_sql: str) -> str:
        return hashlib.sha256(canonical_sql.encode("utf-8")).hexdigest()

    def add(self, canonical_sql: str) -> None:
        with self._lock:
            self._items[self._key(canonical_sql)] = None
            self._items.move_to_end(self._key(canonical_sql))
            while len(self._items) > self._capacity:
                self._items.popitem(last=False)

    def __contains__(self, canonical_sql: str) -> bool:
        with self._lock:
            return self._key(canonical_sql) in self._items


@dataclass(frozen=True)
class AskResult:
    status: str
    code: str
    reason: str
    source: str
    sql: str | None = None  # canonical guarded SQL with row cap (never executed)
    generated_sql: str | None = None  # the statement extracted from the model output
    tables: tuple[tuple[str, str], ...] = ()
    row_cap: int | None = None
    retrieved: tuple[tuple[str, float], ...] = ()
    llm: str = ""
    executed: bool = field(default=False, init=False)
    db_checked: bool = field(default=False, init=False)


class AskPipeline:
    def __init__(self, index: InMemoryIndex, llm: LLMProvider, sources: Mapping[str, tuple[str, ...]],
                 max_rows: int = 500, top_k: int = 6, registry: AiSqlRegistry | None = None):
        if not sources:
            raise ValueError("at least one data source is required")
        self.sources = {}
        for name, schemas in sources.items():
            if not _SOURCE_RE.match(name):
                raise ValueError(f"invalid data source name {name!r}")
            self.sources[name] = tuple(sorted(check_allowed_schemas(schemas)))
        self.index = index
        self.llm = llm
        self.max_rows = max_rows
        self.top_k = top_k
        self.registry = registry if registry is not None else AiSqlRegistry()

    def ask(self, question: str, source: str) -> AskResult:
        llm_id = self.llm.model_id
        if source not in self.sources:
            return AskResult(INVALID, "unknown_source", "unknown or disabled data source", str(source)[:32], llm=llm_id)
        if not isinstance(question, str) or not question.strip():
            return AskResult(INVALID, "empty_question", "the question is empty", source, llm=llm_id)
        if len(question) > MAX_QUESTION_CHARS:
            return AskResult(INVALID, "question_too_long", f"the question is longer than {MAX_QUESTION_CHARS} characters", source, llm=llm_id)
        if _CONTROL_RE.search(question):
            return AskResult(INVALID, "bad_character", "the question contains control characters", source, llm=llm_id)
        if rules.MARKER_PREFIX.upper() in question.upper():
            return AskResult(INVALID, "marker", "the question contains a reserved request marker", source, llm=llm_id)

        schemas = self.sources[source]
        hits = self.index.search(question, self.top_k, schemas)
        retrieved = tuple((h.card.card_id, round(h.score, 4)) for h in hits)
        if not hits:
            return AskResult(NO_SQL, "no_schema", "no schema objects are available for this source", source,
                             retrieved=retrieved, llm=llm_id)
        prompt = build_prompt(question, [h.card for h in hits], self.max_rows)
        try:
            answer = self.llm.generate(prompt.system, prompt.user)
        except LLMUnavailable as exc:
            return AskResult(NO_SQL, "llm_unavailable", str(exc), source, retrieved=retrieved, llm=llm_id)
        except LLMError as exc:
            return AskResult(NO_SQL, "llm_error", str(exc), source, retrieved=retrieved, llm=llm_id)
        try:
            generated = extract_sql(answer)
        except ExtractionError as exc:
            return AskResult(NO_SQL, exc.code, str(exc), source, retrieved=retrieved, llm=llm_id)
        try:
            guarded = guard_sql(generated, schemas, self.max_rows)
        except GuardViolation as exc:
            return AskResult(BLOCKED, exc.code, str(exc), source, generated_sql=generated, retrieved=retrieved, llm=llm_id)
        self.registry.add(guarded.text)
        return AskResult(LINT_APPROVED, "lint_approved",
                         "passed the static SQL guard; not prepared, explained or executed", source,
                         sql=guarded.text, generated_sql=generated, tables=guarded.tables,
                         row_cap=guarded.row_cap, retrieved=retrieved, llm=llm_id)
