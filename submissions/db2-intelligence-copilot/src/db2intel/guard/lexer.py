"""Strict tokenizer for generated Db2 SELECT statements.

Anything the tokenizer cannot classify without ambiguity is rejected: comments, delimited
identifiers, typed string prefixes (X'..', G'..'), parameter markers, host variables, ODBC
escapes, non-ASCII text outside string literals and unusual whitespace.
"""
from __future__ import annotations

from dataclasses import dataclass

from db2intel.guard.rules import (
    ALLOWED_FUNCTIONS, CAST_TYPES, MARKER_PREFIX, MAX_SQL_CHARS, MAX_TOKENS, SPECIAL_FORMS,
)

_CALLABLE = ALLOWED_FUNCTIONS | SPECIAL_FORMS | CAST_TYPES  # rendered as NAME(...) without a space


class GuardViolation(ValueError):
    """The SQL is not acceptable. `code` is a stable machine-readable reason."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


IDENT, NUMBER, STRING, OP, EOF = "IDENT", "NUMBER", "STRING", "OP", "EOF"

_WHITESPACE = " \t\n\r"
_TWO_CHAR_OPS = ("<=", ">=", "<>", "!=", "||")
_ONE_CHAR_OPS = "(),.+-*/=<>;"
_IDENT_START = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_"
_IDENT_CHARS = _IDENT_START + "0123456789"
_DIGITS = "0123456789"


@dataclass(frozen=True)
class Token:
    kind: str
    value: str  # identifiers upper-cased; everything else verbatim
    pos: int

    def is_word(self, *words: str) -> bool:
        return self.kind == IDENT and self.value in words

    def is_op(self, *ops: str) -> bool:
        return self.kind == OP and self.value in ops

    def __str__(self) -> str:
        return "end of statement" if self.kind == EOF else repr(self.value)


def tokenize(sql: str) -> list[Token]:
    if not isinstance(sql, str):
        raise GuardViolation("not_text", "SQL must be text")
    if len(sql) > MAX_SQL_CHARS:
        raise GuardViolation("too_long", f"SQL is longer than {MAX_SQL_CHARS} characters")
    tokens: list[Token] = []
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch in _WHITESPACE:
            i += 1
            continue
        if sql.startswith("--", i) or sql.startswith("/*", i) or sql.startswith("*/", i):
            raise GuardViolation("comment", f"comments are not allowed (position {i})")
        if ch == "'":
            i = _string(sql, i, tokens)
        elif ch == '"':
            raise GuardViolation("delimited_identifier", f"delimited (double-quoted) identifiers are not allowed (position {i})")
        elif ch in _IDENT_START:
            j = i
            while j < n and sql[j] in _IDENT_CHARS:
                j += 1
            if j < n and sql[j] == "'":
                raise GuardViolation("typed_literal", f"prefixed string literals such as X'..' are not allowed (position {i})")
            if j < n and (sql[j] in "@#$" or ord(sql[j]) > 127):
                raise GuardViolation("bad_identifier", f"identifier with unsupported characters at position {i}")
            word = sql[i:j]
            if len(word) > 128:
                raise GuardViolation("bad_identifier", f"identifier longer than 128 characters at position {i}")
            if word.upper().startswith(MARKER_PREFIX):
                raise GuardViolation("marker", "SQL may not contain the guard's request marker")
            tokens.append(Token(IDENT, word.upper(), i))
            i = j
        elif ch in _DIGITS or (ch == "." and i + 1 < n and sql[i + 1] in _DIGITS):
            i = _number(sql, i, tokens)
        elif sql[i:i + 2] in _TWO_CHAR_OPS:
            tokens.append(Token(OP, sql[i:i + 2], i))
            i += 2
        elif ch in _ONE_CHAR_OPS:
            tokens.append(Token(OP, ch, i))
            i += 1
        elif ch == "?":
            raise GuardViolation("parameter_marker", "parameter markers (?) are not allowed")
        elif ch == ":":
            raise GuardViolation("host_variable", "host variables (:name) are not allowed")
        else:
            shown = repr(ch) if ord(ch) < 128 else f"U+{ord(ch):04X}"
            raise GuardViolation("bad_character", f"character {shown} is not allowed outside string literals (position {i})")
        if len(tokens) > MAX_TOKENS:
            raise GuardViolation("too_long", f"SQL has more than {MAX_TOKENS} tokens")
    tokens.append(Token(EOF, "", n))
    return tokens


def _string(sql: str, start: int, tokens: list[Token]) -> int:
    i, n = start + 1, len(sql)
    while i < n:
        ch = sql[i]
        if ch == "'":
            if i + 1 < n and sql[i + 1] == "'":  # escaped quote
                i += 2
                continue
            raw = sql[start:i + 1]
            if MARKER_PREFIX in raw.upper():
                raise GuardViolation("marker", "SQL may not contain the guard's request marker")
            tokens.append(Token(STRING, raw, start))
            return i + 1
        if ord(ch) < 32 and ch not in "\t\n\r" or ch == "\x7f":
            raise GuardViolation("bad_character", f"control character in string literal (position {i})")
        i += 1
    raise GuardViolation("unterminated_string", f"unterminated string literal starting at position {start}")


def _number(sql: str, start: int, tokens: list[Token]) -> int:
    i, n = start, len(sql)
    while i < n and sql[i] in _DIGITS:
        i += 1
    if i < n and sql[i] == ".":
        i += 1
        while i < n and sql[i] in _DIGITS:
            i += 1
    if i < n and sql[i] in "eE":
        j = i + 1
        if j < n and sql[j] in "+-":
            j += 1
        if j >= n or sql[j] not in _DIGITS:
            raise GuardViolation("bad_number", f"malformed number at position {start}")
        i = j
        while i < n and sql[i] in _DIGITS:
            i += 1
    if i < n and (sql[i] in _IDENT_CHARS or sql[i] in ".'\""):
        raise GuardViolation("bad_number", f"number directly followed by {sql[i]!r} at position {start}")
    if i - start > 40:
        raise GuardViolation("bad_number", f"number literal too long at position {start}")
    tokens.append(Token(NUMBER, sql[start:i], start))
    return i


def render(tokens: list[Token]) -> str:
    """Canonical single-line SQL from tokens. Never creates '--' or '/*' (operators are spaced)."""
    out: list[str] = []
    prev: Token | None = None
    for tok in tokens:
        if tok.kind == EOF:
            break
        if prev is not None and not (
            prev.is_op(".", "(") or tok.is_op(".", ")", ",")
            or (tok.is_op("(") and prev.kind == IDENT and prev.value in _CALLABLE)
        ):
            out.append(" ")
        out.append(tok.value)
        prev = tok
    return "".join(out)
