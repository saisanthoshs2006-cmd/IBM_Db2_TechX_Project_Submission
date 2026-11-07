"""Load SQL migration scripts: comment stripping, statement splitting, checksums."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

_LITERAL_RE = re.compile(r"'(?:[^']|'')*'")


class SqlScriptError(ValueError):
    """The script cannot be parsed safely."""


@dataclass(frozen=True)
class SqlScript:
    name: str
    text: str
    statements: tuple[str, ...]
    checksum: str


def normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def checksum(text: str) -> str:
    """SHA-256 of the script with normalized line endings (stable across git autocrlf)."""
    return hashlib.sha256(normalize_newlines(text).encode("utf-8")).hexdigest()


def mask_literals(sql: str) -> str:
    """Replace the contents of every string literal with '' (for static analysis only)."""
    return _LITERAL_RE.sub("''", sql)


def split_statements(text: str) -> list[str]:
    """Split on ';' outside string literals and drop '--' comments outside literals.

    Block comments are rejected so that no statement can hide inside one.
    """
    text = normalize_newlines(text)
    statements: list[str] = []
    buf: list[str] = []
    i, n, in_literal = 0, len(text), False
    while i < n:
        ch = text[i]
        if in_literal:
            buf.append(ch)
            if ch == "'":
                if i + 1 < n and text[i + 1] == "'":  # escaped quote ''
                    buf.append("'")
                    i += 1
                else:
                    in_literal = False
        elif ch == "'":
            in_literal = True
            buf.append(ch)
        elif text.startswith("--", i):
            newline = text.find("\n", i)
            i = n if newline == -1 else newline
            continue
        elif text.startswith("/*", i):
            raise SqlScriptError("block comments are not allowed in migration scripts")
        elif ch == ";":
            stmt = "".join(buf).strip()
            if stmt:
                statements.append(stmt)
            buf = []
        else:
            buf.append(ch)
        i += 1
    if in_literal:
        raise SqlScriptError("unterminated string literal")
    if "".join(buf).strip():
        raise SqlScriptError("last statement is not terminated with ';'")
    return statements


def load_script(path: Path) -> SqlScript:
    text = path.read_text(encoding="utf-8")
    return SqlScript(
        name=path.name,
        text=text,
        statements=tuple(split_statements(text)),
        checksum=checksum(text),
    )
