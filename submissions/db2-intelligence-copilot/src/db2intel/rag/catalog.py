"""Schema metadata for retrieval: table and view names, column names and types, keys, remarks.

Two sources, both producing the same TableMeta objects:
  catalog_from_ddl(path)       parses CREATE TABLE / CREATE VIEW / COMMENT ON statements of a
                               migration script on disk. INSERT statements, CHECK constraints,
                               DEFAULT values and generated-column expressions are never read,
                               so no data value can reach a schema card. No database is used.
  catalog_from_db(db, schemas) fixed read-only SELECTs on SYSCAT.TABLES, SYSCAT.COLUMNS and
                               SYSCAT.REFERENCES only; never on a user table. Requires a
                               connection, so it is used only after its gate is approved.

Denied schemas (DB2INST1, DB2INTEL, SYS*, ...) are refused by both, using the guard's own rule.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Protocol, Sequence

from db2intel.db.sql_script import load_script
from db2intel.guard.parser import check_allowed_schemas

_IDENT = r"[A-Z][A-Z0-9_#$@]*"
_IDENT_RE = re.compile(rf"^{_IDENT}$")
_QNAME_RE = re.compile(rf"^({_IDENT})\.({_IDENT})$")
_COLUMN_STOP_WORDS = frozenset({
    "NOT", "NULL", "DEFAULT", "GENERATED", "CONSTRAINT", "PRIMARY", "UNIQUE", "REFERENCES", "CHECK",
    "WITH", "IMPLICITLY", "INLINE", "COMPACT", "LOGGED", "NOT", "FOR", "COMPRESS",
})
_CONSTRAINT_STARTS = ("CONSTRAINT", "PRIMARY", "UNIQUE", "FOREIGN", "CHECK", "PERIOD", "LIKE")


class CatalogError(ValueError):
    pass


@dataclass(frozen=True)
class ColumnMeta:
    name: str
    data_type: str | None  # None for view columns read from DDL (type not declared there)
    nullable: bool | None
    generated: bool = False
    remark: str | None = None


@dataclass(frozen=True)
class ForeignKey:
    columns: tuple[str, ...]
    ref_schema: str
    ref_table: str
    ref_columns: tuple[str, ...]


@dataclass(frozen=True)
class TableMeta:
    schema: str
    name: str
    kind: str  # "TABLE" | "VIEW"
    columns: tuple[ColumnMeta, ...]
    primary_key: tuple[str, ...] = ()
    foreign_keys: tuple[ForeignKey, ...] = ()
    remark: str | None = None

    @property
    def qualified(self) -> str:
        return f"{self.schema}.{self.name}"


# ---- tiny SQL text helpers (string-literal and parenthesis aware) ---------------------------
def _split_top_level(text: str, sep: str = ",") -> list[str]:
    parts, depth, buf, i, n = [], 0, [], 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "'":
            j = i + 1
            while j < n:
                if text[j] == "'":
                    if j + 1 < n and text[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            buf.append(text[i:j + 1])
            i = j + 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
        i += 1
    if "".join(buf).strip():
        parts.append("".join(buf).strip())
    return parts


def _paren_body(text: str, start: int) -> tuple[str, int]:
    """Text inside the parenthesis opening at text[start], and the index after its close."""
    if text[start] != "(":
        raise CatalogError("expected '('")
    depth, i, n = 0, start, len(text)
    while i < n:
        ch = text[i]
        if ch == "'":  # skip the literal; '' is an escaped quote inside it
            i += 1
            while i < n:
                if text[i] == "'":
                    if i + 1 < n and text[i + 1] == "'":
                        i += 2
                        continue
                    break
                i += 1
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:i], i + 1
        i += 1
    raise CatalogError("unbalanced parentheses")


def _string_literal(text: str) -> str:
    text = text.strip()
    if len(text) < 2 or text[0] != "'" or text[-1] != "'":
        raise CatalogError("expected a string literal")
    return text[1:-1].replace("''", "'")


def _names(text: str) -> tuple[str, ...]:
    names = tuple(n.strip().upper() for n in text.split(","))
    if not names or any(not _IDENT_RE.match(n) for n in names):
        raise CatalogError(f"bad column list {text!r}")
    return names


def _qname(text: str) -> tuple[str, str]:
    m = _QNAME_RE.match(text.strip().upper())
    if not m:
        raise CatalogError(f"expected SCHEMA.NAME, got {text!r}")
    return m.group(1), m.group(2)


# ---- DDL source ----------------------------------------------------------------------------
@dataclass
class _Draft:
    schema: str
    name: str
    kind: str
    columns: list
    primary_key: tuple = ()
    foreign_keys: tuple = ()
    remark: str | None = None
    column_remarks: dict | None = None


def _parse_column(element: str) -> ColumnMeta | None:
    words = element.split()
    name = words[0].upper()
    if not _IDENT_RE.match(name):
        return None
    type_words = []
    for word in words[1:]:
        if word.upper() in _COLUMN_STOP_WORDS:
            break
        type_words.append(word)
    data_type = re.sub(r"\s*,\s*", ",", re.sub(r"\s*\(\s*", "(", " ".join(type_words))).replace(" )", ")").upper()
    upper = " ".join(w.upper() for w in words)
    return ColumnMeta(name=name, data_type=data_type or None, nullable="NOT NULL" not in upper,
                      generated=" GENERATED " in f" {upper} ")


def _parse_create_table(stmt: str) -> _Draft:
    m = re.match(r"CREATE\s+TABLE\s+(\S+)\s*\(", stmt, re.I)
    schema, name = _qname(m.group(1))
    body, _ = _paren_body(stmt, m.end() - 1)
    columns, pk, fks = [], (), []
    for element in _split_top_level(body):
        head = element.split(None, 1)[0].upper() if element.split() else ""
        if head in _CONSTRAINT_STARTS:
            text = element
            if head == "CONSTRAINT":  # CONSTRAINT name <definition>
                text = element.split(None, 2)[2] if len(element.split(None, 2)) == 3 else ""
            upper = text.upper()
            if upper.startswith("PRIMARY KEY"):
                inner, _ = _paren_body(text, text.index("("))
                pk = _names(inner)
            elif upper.startswith("FOREIGN KEY"):
                cols, after = _paren_body(text, text.index("("))
                rest = text[after:].strip()
                rm = re.match(r"REFERENCES\s+(\S+)\s*\(", rest, re.I)
                if rm:
                    ref_cols, _ = _paren_body(rest, rm.end() - 1)
                    ref_schema, ref_table = _qname(rm.group(1))
                    fks.append(ForeignKey(_names(cols), ref_schema, ref_table, _names(ref_cols)))
            continue  # CHECK, UNIQUE and other constraints are not read (they may hold literals)
        column = _parse_column(element)
        if column is not None:
            columns.append(column)
    return _Draft(schema, name, "TABLE", columns, pk, tuple(fks))


def _parse_create_view(stmt: str) -> _Draft:
    m = re.match(r"CREATE\s+VIEW\s+(\S+)\s+AS\s+", stmt, re.I)
    schema, name = _qname(m.group(1))
    query = stmt[m.end():]
    sm = re.match(r"\s*SELECT\s+", query, re.I)
    if not sm:
        raise CatalogError(f"view {schema}.{name}: only SELECT views are supported")
    rest = query[sm.end():]
    # the select list ends at the first top-level FROM
    depth, end, i, upper = 0, None, 0, rest.upper()
    while i < len(rest):
        ch = rest[i]
        if ch == "'":
            i = rest.index("'", i + 1) + 1
            continue
        depth += ch == "("
        depth -= ch == ")"
        if depth == 0 and upper.startswith("FROM", i) and (i == 0 or not rest[i - 1].isalnum()) and \
                (i + 4 >= len(rest) or not rest[i + 4].isalnum() and rest[i + 4] != "_"):
            end = i
            break
        i += 1
    if end is None:
        raise CatalogError(f"view {schema}.{name}: FROM not found")
    columns = []
    for item in _split_top_level(rest[:end]):
        am = re.search(rf"\bAS\s+({_IDENT})\s*$", item, re.I)
        if am:
            col = am.group(1).upper()
        else:
            tail = item.strip().split(".")[-1].upper()
            if not _IDENT_RE.match(tail):
                raise CatalogError(f"view {schema}.{name}: cannot name select item {item!r}")
            col = tail
        columns.append(ColumnMeta(name=col, data_type=None, nullable=None))
    return _Draft(schema, name, "VIEW", columns)


def catalog_from_ddl(path: Path, allowed_schemas: Iterable[str]) -> list[TableMeta]:
    allowed = check_allowed_schemas(allowed_schemas)
    drafts: dict[str, _Draft] = {}
    for stmt in load_script(Path(path)).statements:
        canon = " ".join(stmt.split())
        head = canon[:40].upper()
        if head.startswith("CREATE TABLE "):
            draft = _parse_create_table(canon)
        elif head.startswith("CREATE VIEW "):
            draft = _parse_create_view(canon)
        elif head.startswith("COMMENT ON "):
            _apply_comment(canon, drafts)
            continue
        else:
            continue  # INSERT, CREATE INDEX, CREATE SCHEMA, ...: never read
        if draft.schema in allowed:
            drafts[f"{draft.schema}.{draft.name}"] = draft
    return [_finish(d) for _, d in sorted(drafts.items())]


def _apply_comment(canon: str, drafts: dict[str, _Draft]) -> None:
    m = re.match(r"COMMENT ON TABLE (\S+) IS (.+)$", canon, re.I)
    if m:
        draft = drafts.get("%s.%s" % _qname(m.group(1)))
        if draft:
            draft.remark = _string_literal(m.group(2))
        return
    m = re.match(r"COMMENT ON COLUMN (\S+)\.(\S+) IS (.+)$", canon, re.I)
    if m:
        draft = drafts.get("%s.%s" % _qname(m.group(1)))
        if draft:
            draft.column_remarks = {**(draft.column_remarks or {}), m.group(2).upper(): _string_literal(m.group(3))}
        return
    m = re.match(r"COMMENT ON (\S+)\s*\(", canon, re.I)
    if m:
        draft = drafts.get("%s.%s" % _qname(m.group(1)))
        body, _ = _paren_body(canon, m.end() - 1)
        if draft:
            remarks = dict(draft.column_remarks or {})
            for item in _split_top_level(body):
                cm = re.match(rf"({_IDENT})\s+IS\s+(.+)$", item.strip(), re.I)
                if not cm:
                    raise CatalogError(f"bad column comment {item!r}")
                remarks[cm.group(1).upper()] = _string_literal(cm.group(2))
            draft.column_remarks = remarks


def _finish(d: _Draft) -> TableMeta:
    remarks = d.column_remarks or {}
    columns = tuple(ColumnMeta(c.name, c.data_type, c.nullable, c.generated, remarks.get(c.name)) for c in d.columns)
    return TableMeta(d.schema, d.name, d.kind, columns, d.primary_key, d.foreign_keys, d.remark)


# ---- SYSCAT source (read-only; needs a database connection and its approval gate) -----------
TABLES_SQL = (
    "SELECT RTRIM(TABSCHEMA), RTRIM(TABNAME), TYPE, REMARKS FROM SYSCAT.TABLES "
    "WHERE TABSCHEMA = ? AND TYPE IN ('T', 'V') ORDER BY TABNAME"
)
COLUMNS_SQL = (
    "SELECT RTRIM(TABNAME), RTRIM(COLNAME), RTRIM(TYPENAME), LENGTH, SCALE, NULLS, GENERATED, REMARKS "
    "FROM SYSCAT.COLUMNS WHERE TABSCHEMA = ? ORDER BY TABNAME, COLNO"
)
PRIMARY_KEY_SQL = (
    "SELECT RTRIM(K.TABNAME), RTRIM(K.COLNAME) FROM SYSCAT.KEYCOLUSE K JOIN SYSCAT.TABCONST C "
    "ON C.CONSTNAME = K.CONSTNAME AND C.TABSCHEMA = K.TABSCHEMA AND C.TABNAME = K.TABNAME "
    "WHERE K.TABSCHEMA = ? AND C.TYPE = 'P' ORDER BY K.TABNAME, K.COLSEQ"
)
REFERENCES_SQL = (
    "SELECT RTRIM(TABNAME), FK_COLNAMES, RTRIM(REFTABSCHEMA), RTRIM(REFTABNAME), PK_COLNAMES "
    "FROM SYSCAT.REFERENCES WHERE TABSCHEMA = ? ORDER BY TABNAME, CONSTNAME"
)
CATALOG_QUERIES = (TABLES_SQL, COLUMNS_SQL, PRIMARY_KEY_SQL, REFERENCES_SQL)
_SIZED_TYPES = frozenset({"CHARACTER", "CHAR", "VARCHAR", "GRAPHIC", "VARGRAPHIC", "BINARY", "VARBINARY"})


class Queryable(Protocol):
    def query(self, sql: str, params: Sequence[Any] = ()) -> list[tuple]: ...


def _type_text(typename: str, length, scale) -> str:
    t = str(typename).strip().upper()
    if t == "DECIMAL":
        return f"DECIMAL({int(length)},{int(scale)})"
    if t in _SIZED_TYPES:
        return f"{t}({int(length)})"
    return t


def catalog_from_db(db: Queryable, allowed_schemas: Iterable[str]) -> list[TableMeta]:
    allowed = check_allowed_schemas(allowed_schemas)
    tables: list[TableMeta] = []
    for schema in sorted(allowed):
        cols: dict[str, list[ColumnMeta]] = {}
        for tab, col, typename, length, scale, nulls, generated, remark in db.query(COLUMNS_SQL, (schema,)):
            cols.setdefault(str(tab), []).append(ColumnMeta(
                str(col), _type_text(typename, length, scale), str(nulls).strip() == "Y",
                str(generated or "").strip() != "", remark))
        pks: dict[str, list[str]] = {}
        for tab, col in db.query(PRIMARY_KEY_SQL, (schema,)):
            pks.setdefault(str(tab), []).append(str(col))
        fks: dict[str, list[ForeignKey]] = {}
        for tab, fk_cols, ref_schema, ref_table, pk_cols in db.query(REFERENCES_SQL, (schema,)):
            fks.setdefault(str(tab), []).append(ForeignKey(
                tuple(str(fk_cols).split()), str(ref_schema), str(ref_table), tuple(str(pk_cols).split())))
        for tabschema, name, kind, remark in db.query(TABLES_SQL, (schema,)):
            if str(tabschema) != schema:
                raise CatalogError("catalog returned a table from another schema")
            name = str(name)
            tables.append(TableMeta(schema, name, "VIEW" if str(kind).strip() == "V" else "TABLE",
                                    tuple(cols.get(name, [])), tuple(pks.get(name, [])),
                                    tuple(fks.get(name, [])), remark))
    return tables
