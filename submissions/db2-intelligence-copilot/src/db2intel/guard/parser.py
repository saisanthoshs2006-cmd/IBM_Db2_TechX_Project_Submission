"""Structural parser for the read-only SELECT subset the copilot may run.

The parser consumes every token through an explicit grammar. Any token the grammar does not
expect is rejected, so DML, DDL, CALL, dynamic SQL, table functions, user-defined functions,
locking clauses and anything else outside the subset fail closed, whatever their spelling.

Grammar (top level):
    statement  := query [';'] EOF
    query      := [WITH cte {',' cte}] fullselect [ORDER BY sort] [OFFSET n ROWS] [FETCH FIRST [n] ROWS ONLY]
    fullselect := term {(UNION | EXCEPT | INTERSECT) [ALL | DISTINCT] term}
    term       := subselect | '(' query ')'
    subselect  := SELECT [DISTINCT | ALL] items FROM table_ref [WHERE e] [GROUP BY e {, e}] [HAVING e]
    table_ref  := primary {[INNER | LEFT [OUTER] | RIGHT [OUTER] | FULL [OUTER]] JOIN primary ON e | CROSS JOIN primary}
    primary    := schema.table [alias] | cte_name [alias] | '(' query ')' [alias] | '(' table_ref ')'

WITH is accepted only at the start of the statement, CTEs may not reference themselves
(no recursion) and comma-separated FROM lists are rejected (use explicit JOIN).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from db2intel.guard import rules
from db2intel.guard.lexer import EOF, IDENT, NUMBER, OP, STRING, GuardViolation, Token, render, tokenize

_COMPARISON_OPS = ("=", "<>", "!=", "<", ">", "<=", ">=")


@dataclass(frozen=True)
class GuardedSql:
    """A statement that passed the static guard, with the row cap applied."""

    text: str  # canonical SQL to prepare (no trailing ';', no comments)
    tables: tuple[tuple[str, str], ...]  # (schema, name) of every base table/view referenced
    ctes: tuple[str, ...]
    functions: tuple[str, ...]
    row_cap: int
    original_fetch: int | None  # FETCH FIRST n of the user's statement, if any
    cap_action: str  # "appended" | "lowered" | "kept"


@dataclass
class _Fetch:
    count_index: int | None  # token index of n in FETCH FIRST n ROWS ONLY (None means 1 row)
    value: int


@dataclass
class _State:
    tables: list = field(default_factory=list)
    functions: set = field(default_factory=set)
    ctes: list = field(default_factory=list)


def check_allowed_schemas(allowed_schemas) -> frozenset[str]:
    allowed = frozenset(s.strip().upper() for s in allowed_schemas)
    if not allowed:
        raise ValueError("at least one allowed schema is required")
    for schema in allowed:
        if _schema_denied(schema):
            raise ValueError(f"schema {schema} can never be an allowed data-source schema")
    return allowed


def _schema_denied(schema: str) -> bool:
    return schema in rules.HARD_DENIED_SCHEMAS or schema.startswith(rules.DENIED_SCHEMA_PREFIXES)


class _Parser:
    def __init__(self, tokens: list[Token], allowed: frozenset[str]):
        self.toks = tokens
        self.i = 0
        self.allowed = allowed
        self.state = _State()
        self.visible_ctes: set[str] = set()
        self.depth = 0
        self.top_fetch: _Fetch | None = None

    # ---- token helpers ------------------------------------------------------------------
    @property
    def tok(self) -> Token:
        return self.toks[self.i]

    def peek(self, k: int = 1) -> Token:
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def advance(self) -> Token:
        tok = self.tok
        if tok.kind != EOF:
            self.i += 1
        return tok

    def accept_word(self, *words: str) -> Token | None:
        return self.advance() if self.tok.is_word(*words) else None

    def accept_op(self, *ops: str) -> Token | None:
        return self.advance() if self.tok.is_op(*ops) else None

    def expect_word(self, *words: str) -> Token:
        if not self.tok.is_word(*words):
            self.fail(f"expected {' or '.join(words)}")
        return self.advance()

    def expect_op(self, op: str) -> Token:
        if not self.tok.is_op(op):
            self.fail(f"expected {op!r}")
        return self.advance()

    def fail(self, expected: str):
        tok = self.tok
        if tok.is_op(";"):
            raise GuardViolation("multiple_statements", "only one statement is allowed")
        if tok.is_word(*rules.STATEMENT_WORDS):
            raise GuardViolation("not_select", f"{tok.value} is not allowed: only read-only SELECT queries are accepted")
        raise GuardViolation("syntax", f"{expected}, found {tok} at position {tok.pos}")

    def enter(self):
        self.depth += 1
        if self.depth > rules.MAX_NESTING:
            raise GuardViolation("too_deep", f"query is nested more than {rules.MAX_NESTING} levels")

    def leave(self):
        self.depth -= 1

    def name(self, what: str) -> str:
        tok = self.tok
        if tok.kind != IDENT:
            self.fail(f"expected {what}")
        if tok.value in rules.RESERVED:
            if tok.value in rules.STATEMENT_WORDS:
                self.fail(f"expected {what}")
            raise GuardViolation("reserved_word", f"{tok.value} is a reserved word and cannot be used as {what} (position {tok.pos})")
        self.advance()
        return tok.value

    def is_name(self, tok: Token) -> bool:
        return tok.kind == IDENT and tok.value not in rules.RESERVED

    # ---- statement / query --------------------------------------------------------------
    def statement(self):
        if not self.tok.is_word("SELECT", "WITH") and not self.tok.is_op("("):
            if self.tok.kind == EOF:
                raise GuardViolation("empty", "SQL is empty")
            self.fail("expected SELECT or WITH")
        self.query(top=True)
        if self.accept_op(";") and self.tok.kind != EOF:
            raise GuardViolation("multiple_statements", "only one statement is allowed")
        if self.tok.kind != EOF:
            if self.tok.is_word("FOR", "WITH", "SKIP", "OPTIMIZE", "USE", "KEEP"):
                raise GuardViolation("locking_clause", f"{self.tok.value} clauses (isolation, locking, FOR UPDATE, OPTIMIZE) are not allowed")
            if self.tok.is_word("LIMIT"):
                raise GuardViolation("syntax", "LIMIT is not supported: use FETCH FIRST n ROWS ONLY")
            self.fail("expected end of statement")

    def query(self, top: bool = False):
        self.enter()
        if self.tok.is_word("WITH"):
            if not top:
                raise GuardViolation("nested_with", f"WITH is only allowed at the start of the statement (position {self.tok.pos})")
            self.advance()
            self.cte()
            while self.accept_op(","):
                self.cte()
        self.fullselect()
        if self.accept_word("ORDER"):
            self.expect_word("BY")
            self.sort_list()
        if self.accept_word("OFFSET"):
            self.integer("OFFSET")
            self.expect_word("ROW", "ROWS")
        fetch = None
        if self.accept_word("FETCH"):
            self.expect_word("FIRST", "NEXT")
            if self.tok.kind == NUMBER:
                index = self.i
                fetch = _Fetch(index, self.integer("FETCH FIRST"))
            else:
                fetch = _Fetch(None, 1)
            self.expect_word("ROW", "ROWS")
            self.expect_word("ONLY")
        if top:
            self.top_fetch = fetch
        self.leave()

    def integer(self, clause: str) -> int:
        tok = self.tok
        if tok.kind != NUMBER or not tok.value.isdigit() or len(tok.value) > 9:
            raise GuardViolation("syntax", f"{clause} needs a whole number, found {tok}")
        self.advance()
        return int(tok.value)

    def cte(self):
        name = self.name("a common table expression name")
        if name in self.visible_ctes:
            raise GuardViolation("duplicate_cte", f"common table expression {name} is defined twice")
        if self.accept_op("("):
            self.name_list("a column name")
            self.expect_op(")")
        self.expect_word("AS")
        self.expect_op("(")
        self.query()
        self.expect_op(")")
        # Visible only after its own definition: a self-reference (recursion) is rejected.
        self.visible_ctes.add(name)
        self.state.ctes.append(name)

    def name_list(self, what: str):
        self.name(what)
        while self.accept_op(","):
            self.name(what)

    def fullselect(self):
        self.term()
        while self.accept_word("UNION", "EXCEPT", "INTERSECT"):
            self.accept_word("ALL", "DISTINCT")
            self.term()

    def term(self):
        if self.accept_op("("):
            if not (self.tok.is_word("SELECT", "WITH") or self.tok.is_op("(")):
                self.fail("expected a query inside parentheses")
            self.query()
            self.expect_op(")")
        else:
            self.subselect()

    def subselect(self):
        self.enter()
        self.expect_word("SELECT")
        self.accept_word("DISTINCT", "ALL")
        self.select_item()
        while self.accept_op(","):
            self.select_item()
        if self.tok.is_word("INTO"):
            raise GuardViolation("not_select", "SELECT ... INTO is not allowed")
        self.expect_word("FROM")
        self.table_ref()
        if self.tok.is_op(","):
            raise GuardViolation("comma_join", "comma-separated FROM lists are not allowed: use explicit JOIN ... ON")
        if self.accept_word("WHERE"):
            self.expr()
        if self.accept_word("GROUP"):
            self.expect_word("BY")
            self.expr()
            while self.accept_op(","):
                self.expr()
        if self.accept_word("HAVING"):
            self.expr()
        self.leave()

    def select_item(self):
        if self.accept_op("*"):
            return
        if self.is_name(self.tok) and self.peek().is_op(".") and self.peek(2).is_op("*"):
            self.advance(), self.advance(), self.advance()
            return
        self.expr()
        if self.accept_word("AS"):
            self.name("a column alias")
        elif self.is_name(self.tok) and not self.peek().is_op("(", "."):
            self.advance()

    # ---- FROM clause --------------------------------------------------------------------
    def table_ref(self):
        self.table_primary()
        while True:
            if self.accept_word("CROSS"):
                self.expect_word("JOIN")
                self.table_primary()
                continue
            if self.accept_word("INNER"):
                self.expect_word("JOIN")
            elif self.accept_word("LEFT", "RIGHT", "FULL"):
                self.accept_word("OUTER")
                self.expect_word("JOIN")
            elif not self.accept_word("JOIN"):
                return
            self.table_primary()
            self.expect_word("ON")
            self.expr()

    def table_primary(self):
        tok = self.tok
        if tok.is_word("TABLE", "LATERAL", "XMLTABLE", "UNNEST"):
            raise GuardViolation("table_function", f"{tok.value} table references are not allowed")
        if tok.is_word("FINAL", "NEW", "OLD"):
            raise GuardViolation("data_change", f"{tok.value} TABLE (data-change table references) is not allowed")
        if self.accept_op("("):
            if self.tok.is_word("SELECT", "WITH"):
                self.query()
                self.expect_op(")")
                self.correlation()
            elif self.is_name(self.tok):
                self.table_ref()
                self.expect_op(")")
            else:
                self.fail("expected a subquery or a joined table inside parentheses")
            return
        first = self.name("a table name")
        if self.accept_op("."):
            second = self.name("a table name")
            if self.tok.is_op("."):
                raise GuardViolation("syntax", "three-part names are not allowed")
            if self.tok.is_op("("):
                raise GuardViolation("table_function", f"table function {first}.{second}(...) is not allowed")
            self.check_table(first, second)
        else:
            if self.tok.is_op("("):
                raise GuardViolation("table_function", f"table function {first}(...) is not allowed")
            if first not in self.visible_ctes:
                raise GuardViolation(
                    "unqualified_table",
                    f"table {first} must be qualified with its schema (for example DB2INTEL_DEMO.{first})",
                )
        self.correlation()

    def correlation(self):
        if self.accept_word("AS"):
            self.name("a correlation name")
        elif self.is_name(self.tok):
            self.advance()
        else:
            return
        if self.accept_op("("):
            self.name_list("a column name")
            self.expect_op(")")

    def check_table(self, schema: str, name: str):
        if (schema, name) in rules.READABLE_SYSTEM_OBJECTS:
            pass
        elif _schema_denied(schema):
            raise GuardViolation("forbidden_schema", f"schema {schema} may not be queried")
        elif schema not in self.allowed:
            raise GuardViolation("schema_not_allowed", f"schema {schema} is not an enabled data source")
        self.state.tables.append((schema, name))

    # ---- expressions --------------------------------------------------------------------
    def expr(self):
        self.enter()
        self.and_expr()
        while self.accept_word("OR"):
            self.and_expr()
        self.leave()

    def and_expr(self):
        self.not_expr()
        while self.accept_word("AND"):
            self.not_expr()

    def not_expr(self):
        if self.accept_word("NOT"):
            self.enter()
            self.not_expr()
            self.leave()
        else:
            self.predicate()

    def predicate(self):
        self.concat()
        tok = self.tok
        if tok.is_op(*_COMPARISON_OPS):
            self.advance()
            if self.accept_word("ANY", "SOME", "ALL"):
                self.subquery_in_parens()
            else:
                self.concat()
            return
        if self.accept_word("IS"):
            self.accept_word("NOT")
            self.expect_word("NULL")
            return
        negated = bool(self.accept_word("NOT"))
        if self.accept_word("BETWEEN"):
            self.concat()
            self.expect_word("AND")
            self.concat()
        elif self.accept_word("LIKE"):
            self.concat()
            if self.accept_word("ESCAPE"):
                self.concat()
        elif self.accept_word("IN"):
            self.expect_op("(")
            if self.tok.is_word("SELECT", "WITH"):
                self.query()
            else:
                self.expr()
                while self.accept_op(","):
                    self.expr()
            self.expect_op(")")
        elif negated:
            self.fail("expected BETWEEN, LIKE or IN after NOT")

    def subquery_in_parens(self):
        self.expect_op("(")
        if not self.tok.is_word("SELECT", "WITH"):
            self.fail("expected a subquery")
        self.query()
        self.expect_op(")")

    def concat(self):
        self.additive()
        while self.accept_op("||"):
            self.additive()

    def additive(self):
        self.multiplicative()
        while self.accept_op("+", "-"):
            self.multiplicative()

    def multiplicative(self):
        self.unary()
        while self.accept_op("*", "/"):
            self.unary()

    def unary(self):
        if self.accept_op("+", "-"):
            self.enter()
            self.unary()
            self.leave()
            return
        self.primary()
        # Labeled durations: CURRENT DATE - 30 DAYS
        if self.tok.is_word(*rules.DURATIONS) and not self.peek().is_op("("):
            self.advance()

    def primary(self):
        tok = self.tok
        if tok.kind in (NUMBER, STRING):
            self.advance()
            return
        if tok.is_op("("):
            self.advance()
            if self.tok.is_word("SELECT", "WITH"):
                self.query()
            else:
                self.expr()
                if self.tok.is_op(","):
                    raise GuardViolation("syntax", f"row value expressions are not supported (position {self.tok.pos})")
            self.expect_op(")")
            return
        if tok.kind != IDENT:
            self.fail("expected an expression")
        word = tok.value
        if word in ("NULL", "TRUE", "FALSE"):
            self.advance()
            return
        if word == "CASE":
            self.case()
            return
        if word == "EXISTS":
            self.advance()
            self.subquery_in_parens()
            return
        if word == "CURRENT":
            self.advance()
            self.expect_word("DATE", "TIME", "TIMESTAMP")
            return
        if self.peek().is_op("("):
            self.function_call()
            return
        if self.peek().is_op(".") and self.peek(2).kind == IDENT and self.peek(3).is_op("("):
            raise GuardViolation("function_not_allowed", f"schema-qualified function {word}.{self.peek(2).value} is not allowed")
        # column reference: name or qualifier.name
        self.name("a column name")
        if self.accept_op("."):
            self.name("a column name")
            if self.tok.is_op("."):
                raise GuardViolation("syntax", "three-part column names are not allowed")

    def case(self):
        self.expect_word("CASE")
        if not self.tok.is_word("WHEN"):
            self.expr()
        self.expect_word("WHEN")
        self.expr()
        self.expect_word("THEN")
        self.expr()
        while self.accept_word("WHEN"):
            self.expr()
            self.expect_word("THEN")
            self.expr()
        if self.accept_word("ELSE"):
            self.expr()
        self.expect_word("END")

    def function_call(self):
        name_tok = self.advance()
        fname = name_tok.value
        if fname == "CAST":
            self.expect_op("(")
            self.expr()
            self.expect_word("AS")
            self.cast_type()
            self.expect_op(")")
            self.state.functions.add("CAST")
            return
        if fname == "EXTRACT":
            self.expect_op("(")
            self.expect_word(*rules.EXTRACT_FIELDS)
            self.expect_word("FROM")
            self.expr()
            self.expect_op(")")
            self.state.functions.add("EXTRACT")
            return
        if fname not in rules.ALLOWED_FUNCTIONS:
            if fname in rules.STATEMENT_WORDS:
                self.i -= 1
                self.fail("expected an expression")
            raise GuardViolation("function_not_allowed", f"function {fname} is not on the allow-list (position {name_tok.pos})")
        self.state.functions.add(fname)
        self.expect_op("(")
        if fname in rules.AGGREGATE_FUNCTIONS and self.accept_word("DISTINCT", "ALL"):
            self.expr()
        elif fname in ("COUNT", "COUNT_BIG") and self.accept_op("*"):
            pass
        elif not self.tok.is_op(")"):
            self.expr()
            while self.accept_op(","):
                self.expr()
        self.expect_op(")")
        if fname in rules.RANKING_FUNCTIONS:
            self.expect_word("OVER")
            self.window()
        elif fname in rules.AGGREGATE_FUNCTIONS and self.accept_word("OVER"):
            self.window()

    def cast_type(self):
        self.expect_word(*rules.CAST_TYPES)
        if self.accept_op("("):
            self.integer("type length")
            if self.accept_op(","):
                self.integer("type scale")
            self.expect_op(")")

    def window(self):
        self.expect_op("(")
        if self.accept_word("PARTITION"):
            self.expect_word("BY")
            self.expr()
            while self.accept_op(","):
                self.expr()
        if self.accept_word("ORDER"):
            self.expect_word("BY")
            self.sort_list()
        if self.accept_word("ROWS", "RANGE"):
            if self.accept_word("BETWEEN"):
                self.frame_bound()
                self.expect_word("AND")
                self.frame_bound()
            else:
                self.frame_bound()
        self.expect_op(")")

    def frame_bound(self):
        if self.accept_word("UNBOUNDED"):
            self.expect_word("PRECEDING", "FOLLOWING")
        elif self.accept_word("CURRENT"):
            self.expect_word("ROW")
        else:
            self.integer("window frame")
            self.expect_word("PRECEDING", "FOLLOWING")

    def sort_list(self):
        while True:
            self.expr()
            self.accept_word("ASC", "DESC")
            if self.accept_word("NULLS"):
                self.expect_word("FIRST", "LAST")
            if not self.accept_op(","):
                return


def _run(parser: _Parser) -> None:
    try:
        parser.statement()
    except RecursionError:
        raise GuardViolation("too_deep", "query is too deeply nested") from None


def guard_sql(sql: str, allowed_schemas, max_rows: int) -> GuardedSql:
    """Parse, validate and cap one SELECT statement. Raises GuardViolation if it is not acceptable."""
    if not isinstance(max_rows, int) or isinstance(max_rows, bool) or not 1 <= max_rows <= 100_000:
        raise ValueError("max_rows must be an integer between 1 and 100000")
    allowed = check_allowed_schemas(allowed_schemas)
    tokens = tokenize(sql)
    parser = _Parser(tokens, allowed)
    _run(parser)

    body = [t for t in tokens if t.kind != EOF]
    if body and body[-1].is_op(";"):
        body = body[:-1]
    fetch = parser.top_fetch
    if fetch is None:
        body += [Token(IDENT, "FETCH", -1), Token(IDENT, "FIRST", -1), Token(NUMBER, str(max_rows), -1),
                 Token(IDENT, "ROWS", -1), Token(IDENT, "ONLY", -1)]
        action, original = "appended", None
    elif fetch.value > max_rows:
        body[fetch.count_index] = Token(NUMBER, str(max_rows), -1)
        action, original = "lowered", fetch.value
    else:
        action, original = "kept", fetch.value
    text = render(body)

    # Invariant: the rendered text tokenizes back to exactly the same tokens and still parses.
    again = tokenize(text)
    if [(t.kind, t.value) for t in again if t.kind != EOF] != [(t.kind, t.value) for t in body]:
        raise GuardViolation("render_mismatch", "internal error: canonical SQL does not match the parsed tokens")
    check = _Parser(again, allowed)
    _run(check)
    final_fetch = check.top_fetch
    if final_fetch is None or final_fetch.value > max_rows:
        raise GuardViolation("row_cap", "internal error: row cap is not in effect")

    return GuardedSql(
        text=text,
        tables=tuple(dict.fromkeys(parser.state.tables)),
        ctes=tuple(parser.state.ctes),
        functions=tuple(sorted(parser.state.functions)),
        row_cap=max_rows,
        original_fetch=original,
        cap_action=action,
    )
