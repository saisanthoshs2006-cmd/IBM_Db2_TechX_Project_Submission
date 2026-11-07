"""Schema cards: the only schema text an LLM prompt ever sees.

A card is built from TableMeta alone: object names, column names and declared types, nullability,
primary and foreign keys, and catalog remarks written by the schema owner. It never contains a
row value, a CHECK constraint, a DEFAULT value or a generated-column expression (TableMeta does
not carry them). Remarks are cleaned: control characters removed, whitespace collapsed, prompt
delimiters and code fences neutralised, and length capped, because remarks are free text that
reaches the prompt. Objects and foreign keys outside the allowed schemas are dropped.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from db2intel.guard.parser import check_allowed_schemas
from db2intel.rag.catalog import TableMeta

MAX_REMARK_CHARS = 300
MAX_CARD_CHARS = 6_000
_IDENT_RE = re.compile(r"^[A-Z][A-Z0-9_#$@]{0,127}$")
_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9 _(),]{0,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")
# Sequences that delimit prompt sections or code; removed from any free text placed in a prompt.
PROMPT_DELIMITERS = ("<<<", ">>>", "```", "~~~")


def clean_text(text: str | None, limit: int = MAX_REMARK_CHARS) -> str:
    if not text:
        return ""
    text = _CONTROL_RE.sub(" ", str(text))
    for delim in PROMPT_DELIMITERS:
        while delim in text:
            text = text.replace(delim, " ")
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


@dataclass(frozen=True)
class SchemaCard:
    card_id: str  # SCHEMA.NAME
    schema: str
    name: str
    kind: str  # TABLE | VIEW
    columns: tuple[str, ...]
    text: str


def build_card(table: TableMeta, allowed: frozenset[str]) -> SchemaCard | None:
    if table.schema not in allowed or not _IDENT_RE.match(table.schema) or not _IDENT_RE.match(table.name):
        return None
    if table.kind not in ("TABLE", "VIEW"):
        return None
    pk = set(table.primary_key)
    lines = [f"{table.kind} {table.schema}.{table.name}"]
    remark = clean_text(table.remark)
    if remark:
        lines.append(f"Description: {remark}")
    lines.append("Columns:")
    names = []
    for col in table.columns:
        if not _IDENT_RE.match(col.name):
            continue
        parts = [col.name]
        if col.data_type and _TYPE_RE.match(col.data_type):
            parts.append(col.data_type)
        if col.nullable is False:
            parts.append("NOT NULL")
        if col.name in pk:
            parts.append("PRIMARY KEY")
        if col.generated:
            parts.append("GENERATED")
        line = "- " + " ".join(parts)
        col_remark = clean_text(col.remark)
        if col_remark:
            line += f": {col_remark}"
        lines.append(line)
        names.append(col.name)
    fk_lines = []
    for fk in table.foreign_keys:
        idents = (*fk.columns, fk.ref_schema, fk.ref_table, *fk.ref_columns)
        if fk.ref_schema not in allowed or not all(_IDENT_RE.match(i) for i in idents):
            continue
        fk_lines.append(f"- ({', '.join(fk.columns)}) -> {fk.ref_schema}.{fk.ref_table} ({', '.join(fk.ref_columns)})")
    if fk_lines:
        lines.append("Foreign keys:")
        lines.extend(fk_lines)
    text = "\n".join(lines)
    if len(text) > MAX_CARD_CHARS:
        text = text[:MAX_CARD_CHARS]
    return SchemaCard(f"{table.schema}.{table.name}", table.schema, table.name, table.kind, tuple(names), text)


def build_cards(tables: Iterable[TableMeta], allowed_schemas: Iterable[str]) -> list[SchemaCard]:
    allowed = check_allowed_schemas(allowed_schemas)
    cards = [c for c in (build_card(t, allowed) for t in tables) if c is not None]
    ids = [c.card_id for c in cards]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate schema objects in catalog")
    return sorted(cards, key=lambda c: c.card_id)
