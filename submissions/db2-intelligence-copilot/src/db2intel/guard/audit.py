"""Audit records for guarded queries.

Audit persistence is separate from the analysis and execution connections. Execution refuses
to start unless the audit sink is ready, and withholds results if the audit write fails.

Phase 2A ships only DisabledAuditSink: audit inserts are NOT enabled. A database-backed sink
(one INSERT into DB2INTEL.QUERY_AUDIT on its own connection) needs separate approval.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

# Must match CK_QUERY_AUDIT_STATUS in sql/001_schema_meta.sql.
AUDIT_STATUSES = frozenset({"SUCCESS", "BLOCKED", "COST_REJECTED", "ERROR", "NO_SQL"})
# Column sizes in DB2INTEL.QUERY_AUDIT.
QUESTION_MAX, BLOCK_REASON_MAX, ERROR_MESSAGE_MAX = 1000, 254, 500


class AuditUnavailable(RuntimeError):
    """The audit trail cannot be written, so the guarded action must not proceed."""


@dataclass(frozen=True)
class AuditRecord:
    request_id: str
    question: str
    generated_sql: str | None
    status: str
    block_reason: str | None = None
    estimated_cost: float | None = None
    row_count: int | None = None
    execution_ms: int | None = None
    total_ms: int | None = None
    error_sqlstate: str | None = None
    error_message: str | None = None

    def __post_init__(self):
        if self.status not in AUDIT_STATUSES:
            raise ValueError(f"audit status {self.status!r} is not one of {sorted(AUDIT_STATUSES)}")
        if len(self.request_id) != 36:
            raise ValueError("request_id must be a 36-character UUID")
        if not self.question or not self.question.strip():
            raise ValueError("question is required")
        for name in ("estimated_cost", "row_count", "execution_ms", "total_ms"):
            value = getattr(self, name)
            if value is not None and value < 0:
                raise ValueError(f"{name} must not be negative")
        if self.error_sqlstate is not None and len(self.error_sqlstate) != 5:
            raise ValueError("error_sqlstate must be 5 characters")


def _clip(text: str | None, limit: int) -> str | None:
    if text is None:
        return None
    return text if len(text) <= limit else text[: limit - 3] + "..."


def make_record(*, request_id: str, question: str, generated_sql: str | None, status: str,
                reason: str | None = None, estimated_cost: float | None = None, row_count: int | None = None,
                execution_ms: int | None = None, total_ms: int | None = None, sqlstate: str | None = None,
                error_message: str | None = None) -> AuditRecord:
    """Build a record that fits the QUERY_AUDIT columns (long text is clipped, never dropped)."""
    return AuditRecord(
        request_id=request_id,
        question=_clip(question, QUESTION_MAX),
        generated_sql=generated_sql,
        status=status,
        block_reason=_clip(reason, BLOCK_REASON_MAX),
        estimated_cost=estimated_cost,
        row_count=row_count,
        execution_ms=execution_ms,
        total_ms=total_ms,
        error_sqlstate=sqlstate,
        error_message=_clip(error_message, ERROR_MESSAGE_MAX),
    )


class AuditSink(Protocol):
    def ready(self) -> bool: ...
    def write(self, record: AuditRecord) -> None: ...


class DisabledAuditSink:
    """The Phase 2A sink: never ready, so execution is refused."""

    def ready(self) -> bool:
        return False

    def write(self, record: AuditRecord) -> None:
        raise AuditUnavailable("audit persistence is not enabled")
