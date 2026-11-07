"""Static safety policy for migration and teardown scripts.

Checked before any database connection is opened. A script that violates the
policy is never sent to Db2.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from db2intel.db.sql_script import SqlScript, mask_literals

PROJECT_SCHEMAS = frozenset({"DB2INTEL", "DB2INTEL_DEMO"})
READABLE_SYSTEM_OBJECTS = frozenset({"SYSIBM.SYSDUMMY1"})

_ID = r"[A-Z_][A-Z0-9_]*"
_QNAME = rf"{_ID}(?:\.{_ID})?"

# Statement shapes allowed in initialization migrations, with the group holding each target name.
_MIGRATION_FORMS: tuple[tuple[str, re.Pattern], ...] = (
    ("CREATE SCHEMA", re.compile(rf"^CREATE\s+SCHEMA\s+({_ID})$")),
    ("CREATE TABLE", re.compile(rf"^CREATE\s+TABLE\s+({_QNAME})\s*\(")),
    ("CREATE INDEX", re.compile(rf"^CREATE\s+(?:UNIQUE\s+)?INDEX\s+({_QNAME})\s+ON\s+({_QNAME})\s*\(")),
    ("CREATE VIEW", re.compile(rf"^CREATE\s+VIEW\s+({_QNAME})\s+AS\s")),
    ("ALTER TABLE ADD CONSTRAINT", re.compile(rf"^ALTER\s+TABLE\s+({_QNAME})\s+ADD\s+CONSTRAINT\s")),
    ("COMMENT ON TABLE", re.compile(rf"^COMMENT\s+ON\s+TABLE\s+({_QNAME})\s+IS\s")),
    ("COMMENT ON COLUMNS", re.compile(rf"^COMMENT\s+ON\s+({_QNAME})\s*\(")),
    ("INSERT", re.compile(rf"^INSERT\s+INTO\s+({_QNAME})\s*\(")),
)

# The only two statement shapes allowed in the teardown script.
_TEARDOWN_FORMS: tuple[re.Pattern, ...] = (
    re.compile(r"^DROP\s+(?:TABLE|VIEW)\s+(DB2INTEL|DB2INTEL_DEMO)\.[A-Z_][A-Z0-9_]*$"),
    re.compile(r"^DROP\s+SCHEMA\s+(DB2INTEL|DB2INTEL_DEMO)\s+RESTRICT$"),
)

# Phrases that legitimately contain otherwise-forbidden words.
_BENIGN_PHRASES = (
    re.compile(r"\bON\s+DELETE\s+(?:CASCADE|SET\s+NULL|RESTRICT|NO\s+ACTION)\b"),
    re.compile(r"\bFOR\s+EACH\s+ROW\s+ON\s+UPDATE\s+AS\s+ROW\s+CHANGE\s+TIMESTAMP\b"),
)
_FORBIDDEN_IN_MIGRATIONS = re.compile(
    r"\b(DROP|DELETE|UPDATE|TRUNCATE|MERGE|GRANT|REVOKE|CALL|RENAME|DATABASE|TRANSFER|EXECUTE|"
    r"BUFFERPOOL|TABLESPACE|DB2INST1|SAMPLE|TESTDB)\b"
)
# Sequence access can change an object in another schema (an unqualified sequence
# resolves to CURRENT SCHEMA, i.e. DB2INST1).
_FORBIDDEN_PHRASES = re.compile(r"\b(NEXT\s+VALUE|PREVIOUS\s+VALUE|NEXTVAL|PREVVAL)\b")
_REFERENCE_RE = re.compile(rf"\b(?:FROM|JOIN|REFERENCES)\s+({_QNAME})")
# "FROM a [alias], b" - only the first name follows FROM, so comma joins are rejected
# outright instead of risking an unchecked second table reference.
_CLAUSE_WORDS = (
    "WHERE|GROUP|ORDER|HAVING|FETCH|UNION|EXCEPT|INTERSECT|JOIN|INNER|LEFT|RIGHT|FULL|CROSS|ON"
)
_COMMA_JOIN_RE = re.compile(rf"\bFROM\s+{_QNAME}(?:\s+(?:AS\s+)?(?!(?:{_CLAUSE_WORDS})\b){_ID})?\s*,")
_CTE_NAME_RE = re.compile(rf"(?:\bWITH|,)\s*({_ID})\s*(?:\([^()]*\))?\s*AS\s*\(")


class PolicyViolation(ValueError):
    """A script contains a statement outside the allowed policy."""


@dataclass(frozen=True)
class StatementInfo:
    kind: str
    targets: tuple[str, ...]


def _canonical(stmt: str) -> str:
    return " ".join(mask_literals(stmt).upper().split())


def _schema_of(name: str) -> str | None:
    return name.split(".", 1)[0] if "." in name else None


def classify_migration_statement(stmt: str) -> StatementInfo:
    canon = _canonical(stmt)
    for kind, pattern in _MIGRATION_FORMS:
        match = pattern.match(canon)
        if match:
            return StatementInfo(kind, tuple(match.groups()))
    raise PolicyViolation(f"statement type not allowed in a migration: {canon[:80]}...")


def check_migration_statement(stmt: str) -> StatementInfo:
    info = classify_migration_statement(stmt)
    canon = _canonical(stmt)

    scrubbed = canon
    for phrase in _BENIGN_PHRASES:
        scrubbed = phrase.sub(" ", scrubbed)
    forbidden = _FORBIDDEN_IN_MIGRATIONS.search(scrubbed) or _FORBIDDEN_PHRASES.search(scrubbed)
    if forbidden:
        raise PolicyViolation(f"forbidden keyword {forbidden.group(1)!r} in: {canon[:80]}...")
    if _COMMA_JOIN_RE.search(canon):
        raise PolicyViolation(f"comma-separated FROM list is not allowed (use explicit JOIN): {canon[:80]}...")

    for target in info.targets:
        schema = target if info.kind == "CREATE SCHEMA" else _schema_of(target)
        if schema not in PROJECT_SCHEMAS:
            raise PolicyViolation(f"{info.kind} target {target!r} is outside {sorted(PROJECT_SCHEMAS)}")

    cte_names = set(_CTE_NAME_RE.findall(canon))
    for ref in _REFERENCE_RE.findall(canon):
        if ref in READABLE_SYSTEM_OBJECTS:
            continue
        schema = _schema_of(ref)
        if schema is None and ref in cte_names:
            continue
        if schema not in PROJECT_SCHEMAS:
            raise PolicyViolation(f"reference to {ref!r} is outside {sorted(PROJECT_SCHEMAS)}")
    return info


def check_migration_script(script: SqlScript) -> list[StatementInfo]:
    if not script.statements:
        raise PolicyViolation(f"{script.name} contains no statements")
    infos = []
    for index, stmt in enumerate(script.statements, start=1):
        try:
            infos.append(check_migration_statement(stmt))
        except PolicyViolation as exc:
            raise PolicyViolation(f"{script.name} statement {index}: {exc}") from None
    return infos


def check_teardown_script(script: SqlScript) -> None:
    if not script.statements:
        raise PolicyViolation(f"{script.name} contains no statements")
    for index, stmt in enumerate(script.statements, start=1):
        canon = _canonical(stmt)
        if not any(pattern.match(canon) for pattern in _TEARDOWN_FORMS):
            raise PolicyViolation(f"{script.name} statement {index} is not an allowed DROP: {canon[:80]}")


_VECTOR_RE = re.compile(r"\bVECTOR\s*\(\s*(\d+)\s*,\s*(FLOAT32|INT8)\s*\)")
_DIM_SETTING_RE = re.compile(r"\(\s*'embedding\.dimension'\s*,\s*'(\d+)'")


def vector_dimensions(script: SqlScript) -> set[int]:
    """All VECTOR(n, type) dimensions declared in the script."""
    dims: set[int] = set()
    for stmt in script.statements:
        dims.update(int(d) for d, _ in _VECTOR_RE.findall(_canonical(stmt)))
    return dims


def check_vector_dimensions(script: SqlScript, expected_dim: int) -> None:
    """Every VECTOR column and the seeded embedding.dimension setting must equal expected_dim."""
    dims = vector_dimensions(script)
    if dims and dims != {expected_dim}:
        raise PolicyViolation(
            f"{script.name} declares VECTOR dimensions {sorted(dims)} but the embedding model produces {expected_dim}"
        )
    seeded = _DIM_SETTING_RE.findall(script.text)
    if dims and seeded != [str(expected_dim)]:
        raise PolicyViolation(
            f"{script.name} seeds embedding.dimension={seeded} but VECTOR columns use {expected_dim}"
        )
