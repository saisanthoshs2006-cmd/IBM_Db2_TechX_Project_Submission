"""Static SQL guard: tokenizer and structural parser. Offline; no driver, no database."""
import random

import pytest

from db2intel.guard import rules
from db2intel.guard.lexer import GuardViolation, render, tokenize
from db2intel.guard.parser import check_allowed_schemas, guard_sql
from guard_fakes import no_db_driver  # noqa: F401  (autouse: blocks the Db2 driver)

ALLOWED = {"DB2INTEL_DEMO"}


def ok(sql, **kw):
    return guard_sql(sql, kw.get("allowed", ALLOWED), kw.get("max_rows", 500))


def rejected(sql, code=None):
    with pytest.raises(GuardViolation) as info:
        ok(sql)
    if code:
        assert info.value.code == code, f"{info.value.code}: {info.value}"
    return info.value


# ---- accepted queries --------------------------------------------------------------------
ACCEPTED = [
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER",
    "select c.company_name from db2intel_demo.customer c where c.customer_id = 42",
    "SELECT R.REGION_NAME, SUM(I.LINE_AMOUNT) AS NET FROM DB2INTEL_DEMO.ORDER_ITEM I "
    "JOIN DB2INTEL_DEMO.SALES_ORDER O ON O.ORDER_ID = I.ORDER_ID "
    "JOIN DB2INTEL_DEMO.CUSTOMER C ON C.CUSTOMER_ID = O.CUSTOMER_ID "
    "JOIN DB2INTEL_DEMO.REGION R ON R.REGION_ID = C.REGION_ID GROUP BY R.REGION_NAME ORDER BY NET DESC",
    "SELECT C.SEGMENT, COUNT(DISTINCT O.ORDER_ID) FROM DB2INTEL_DEMO.CUSTOMER C LEFT OUTER JOIN "
    "DB2INTEL_DEMO.SALES_ORDER O ON O.CUSTOMER_ID = C.CUSTOMER_ID GROUP BY C.SEGMENT HAVING COUNT(*) > 5",
    "WITH A AS (SELECT CUSTOMER_ID, COUNT(*) N FROM DB2INTEL_DEMO.SALES_ORDER GROUP BY CUSTOMER_ID), "
    "B (CID, N) AS (SELECT * FROM A WHERE N > 3) SELECT B.*, RANK() OVER (ORDER BY N DESC) AS RK FROM B",
    "SELECT REGION_NAME FROM DB2INTEL_DEMO.REGION UNION ALL SELECT SEGMENT FROM DB2INTEL_DEMO.CUSTOMER "
    "EXCEPT SELECT 'x' FROM SYSIBM.SYSDUMMY1",
    "(SELECT PRODUCT_ID FROM DB2INTEL_DEMO.PRODUCT) INTERSECT (SELECT PRODUCT_ID FROM DB2INTEL_DEMO.ORDER_ITEM)",
    "SELECT X.N FROM (SELECT COUNT(*) AS N FROM DB2INTEL_DEMO.CUSTOMER) AS X",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER C WHERE C.CUSTOMER_ID IN (SELECT CUSTOMER_ID FROM DB2INTEL_DEMO.SALES_ORDER)",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER C WHERE EXISTS (SELECT 1 FROM DB2INTEL_DEMO.SALES_ORDER O "
    "WHERE O.CUSTOMER_ID = C.CUSTOMER_ID AND O.STATUS NOT IN ('CANCELLED', 'RETURNED'))",
    "SELECT C.COMPANY_NAME, (SELECT MAX(O.ORDER_DATE) FROM DB2INTEL_DEMO.SALES_ORDER O "
    "WHERE O.CUSTOMER_ID = C.CUSTOMER_ID) AS LAST_ORDER FROM DB2INTEL_DEMO.CUSTOMER C",
    "SELECT YEAR(ORDER_DATE) Y, CAST(SUM(NET_AMOUNT) AS DECIMAL(14, 2)) FROM DB2INTEL_DEMO.V_ORDER_SUMMARY "
    "WHERE ORDER_DATE >= CURRENT DATE - 12 MONTHS GROUP BY YEAR(ORDER_DATE)",
    "SELECT CASE WHEN CREDIT_LIMIT > 10000 THEN 'HIGH' WHEN CREDIT_LIMIT IS NULL THEN 'NONE' ELSE 'LOW' END "
    "FROM DB2INTEL_DEMO.CUSTOMER WHERE COMPANY_NAME LIKE 'A!%%' ESCAPE '!' AND CREDIT_LIMIT BETWEEN 1 AND 2",
    "SELECT EXTRACT(YEAR FROM ORDER_DATE), COALESCE(SHIP_DATE, ORDER_DATE) FROM DB2INTEL_DEMO.SALES_ORDER",
    "SELECT SUM(LINE_AMOUNT) OVER (PARTITION BY ORDER_ID ORDER BY LINE_NO ROWS BETWEEN UNBOUNDED PRECEDING "
    "AND CURRENT ROW) FROM DB2INTEL_DEMO.ORDER_ITEM",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER C CROSS JOIN DB2INTEL_DEMO.REGION R",
    "SELECT * FROM (DB2INTEL_DEMO.CUSTOMER C JOIN DB2INTEL_DEMO.REGION R ON R.REGION_ID = C.REGION_ID)",
    "SELECT UPPER(TRIM(COMPANY_NAME)) || ' / ' || SEGMENT FROM DB2INTEL_DEMO.CUSTOMER ORDER BY 1 NULLS LAST",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER WHERE CUSTOMER_ID = -(-5) AND 1.5E2 > 0 AND .5 < 1;",
    "SELECT 1 FROM SYSIBM.SYSDUMMY1",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER WHERE IS_ACTIVE = TRUE OR NOT (CUSTOMER_ID <> 3 AND CUSTOMER_ID != 4)",
]


@pytest.mark.parametrize("sql", ACCEPTED)
def test_accepted_queries(sql):
    g = ok(sql)
    assert all(schema == "DB2INTEL_DEMO" or (schema, n) in rules.READABLE_SYSTEM_OBJECTS for schema, n in g.tables)
    for forbidden in ("--", "/*", "*/", ";", "?", '"'):
        assert forbidden not in g.text.replace("'A!%%'", "")


def test_tables_ctes_and_functions_are_reported():
    g = ok(ACCEPTED[4])
    assert g.tables == (("DB2INTEL_DEMO", "SALES_ORDER"),)
    assert g.ctes == ("A", "B")
    assert g.functions == ("COUNT", "RANK")


# ---- quoted strings, escaped quotes, things that only look dangerous inside literals ------
@pytest.mark.parametrize("literal", [
    "'O''Brien'", "'; DROP TABLE DB2INST1.EMPLOYEE_INFO; --'", "'/* not a comment */'",
    "'x'' ; DELETE FROM DB2INTEL_DEMO.CUSTOMER --'", "''''", "''", "'DB2INST1.EMPLOYEE_SALARY'",
    "'Ünïcödé ✓'",
])
def test_dangerous_text_inside_string_literals_is_inert(literal):
    g = ok(f"SELECT COMPANY_NAME FROM DB2INTEL_DEMO.CUSTOMER WHERE COMPANY_NAME = {literal}")
    assert g.tables == (("DB2INTEL_DEMO", "CUSTOMER"),)
    assert literal in g.text


@pytest.mark.parametrize("sql,code", [
    ("SELECT 'abc FROM DB2INTEL_DEMO.CUSTOMER", "unterminated_string"),
    ("SELECT 'it''s FROM DB2INTEL_DEMO.CUSTOMER", "unterminated_string"),
    ("SELECT 'a\x00b' FROM DB2INTEL_DEMO.CUSTOMER", "bad_character"),
    ("SELECT X'41' FROM DB2INTEL_DEMO.CUSTOMER", "typed_literal"),
    ("SELECT G'x' FROM DB2INTEL_DEMO.CUSTOMER", "typed_literal"),
    ("SELECT N'x' FROM DB2INTEL_DEMO.CUSTOMER", "typed_literal"),
])
def test_malformed_or_typed_literals_are_rejected(sql, code):
    rejected(sql, code)


# ---- comments ----------------------------------------------------------------------------
@pytest.mark.parametrize("sql", [
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER -- trailing",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER --\n; DROP TABLE X",
    "SELECT /* hidden */ * FROM DB2INTEL_DEMO.CUSTOMER",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER /*+ OPTGUIDELINE */",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER WHERE 1 = 1 */",
    "SELECT 5--3 FROM DB2INTEL_DEMO.CUSTOMER",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER /* unterminated",
])
def test_comments_are_rejected(sql):
    rejected(sql, "comment")


# ---- statements other than SELECT ----------------------------------------------------------
@pytest.mark.parametrize("sql", [
    "INSERT INTO DB2INTEL_DEMO.REGION (REGION_ID) VALUES (9)",
    "UPDATE DB2INTEL_DEMO.CUSTOMER SET CREDIT_LIMIT = 0",
    "DELETE FROM DB2INTEL_DEMO.CUSTOMER",
    "MERGE INTO DB2INTEL_DEMO.CUSTOMER C USING DB2INTEL_DEMO.REGION R ON 1 = 1 WHEN MATCHED THEN DELETE",
    "TRUNCATE TABLE DB2INTEL_DEMO.CUSTOMER IMMEDIATE",
    "CREATE TABLE DB2INTEL_DEMO.X (A INT)",
    "ALTER TABLE DB2INTEL_DEMO.CUSTOMER ADD COLUMN X INT",
    "DROP TABLE DB2INST1.EMPLOYEE_INFO",
    "GRANT SELECT ON DB2INST1.EMPLOYEE_SALARY TO PUBLIC",
    "REVOKE CONNECT ON DATABASE FROM PUBLIC",
    "CALL SYSPROC.ADMIN_CMD('RUNSTATS ON TABLE DB2INST1.EMPLOYEE_INFO')",
    "EXECUTE IMMEDIATE 'DROP TABLE DB2INST1.EMPLOYEE_INFO'",
    "PREPARE S1 FROM 'DELETE FROM DB2INST1.EMPLOYEE_INFO'",
    "SET CURRENT SCHEMA DB2INST1",
    "VALUES (1)",
    "LOCK TABLE DB2INTEL_DEMO.CUSTOMER IN EXCLUSIVE MODE",
    "COMMIT",
    "ROLLBACK",
    "DECLARE GLOBAL TEMPORARY TABLE T (A INT)",
    "EXPLAIN PLAN FOR SELECT * FROM DB2INTEL_DEMO.CUSTOMER",
    "REFRESH TABLE DB2INTEL_DEMO.MQT",
    "RENAME TABLE DB2INTEL_DEMO.CUSTOMER TO C2",
    "COMMENT ON TABLE DB2INTEL_DEMO.CUSTOMER IS 'x'",
    "TRANSFER OWNERSHIP OF TABLE DB2INTEL_DEMO.CUSTOMER TO USER X",
])
def test_non_select_statements_are_rejected(sql):
    rejected(sql, "not_select")


@pytest.mark.parametrize("sql", [
    "BEGIN DELETE FROM DB2INTEL_DEMO.CUSTOMER; END",
    "SAVEPOINT S ON ROLLBACK RETAIN CURSORS",
    "WITH X AS (DELETE FROM DB2INTEL_DEMO.CUSTOMER) SELECT 1 FROM SYSIBM.SYSDUMMY1",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER WHERE CUSTOMER_ID = (DELETE FROM DB2INTEL_DEMO.CUSTOMER)",
    "SELECT INSERT('abc', 1, 1, 'x') FROM SYSIBM.SYSDUMMY1",
])
def test_statements_hidden_in_other_positions_are_rejected(sql):
    rejected(sql)


# ---- multiple statements -------------------------------------------------------------------
@pytest.mark.parametrize("sql", [
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER; DROP TABLE DB2INST1.EMPLOYEE_INFO",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER; SELECT * FROM DB2INTEL_DEMO.REGION",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER;;",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER WHERE COMPANY_NAME = '' OR 1 = 1; DELETE FROM DB2INTEL_DEMO.CUSTOMER",
    ";",
])
def test_multiple_statements_are_rejected(sql):
    rejected(sql, "multiple_statements")


def test_one_trailing_semicolon_is_accepted_and_removed():
    assert ok("SELECT * FROM DB2INTEL_DEMO.CUSTOMER ;").text == "SELECT * FROM DB2INTEL_DEMO.CUSTOMER FETCH FIRST 500 ROWS ONLY"


# ---- schemas and objects -------------------------------------------------------------------
@pytest.mark.parametrize("sql", [
    "SELECT * FROM DB2INST1.EMPLOYEE_INFO",
    "SELECT * FROM db2inst1 . employee_salary",
    "SELECT * FROM DB2INTEL.QUERY_AUDIT",
    "SELECT * FROM DB2INTEL.EXPLAIN_STATEMENT",
    "SELECT * FROM DB2INTEL_TRIAL.EXPLAIN_STATEMENT",
    "SELECT * FROM SYSCAT.TABLES",
    "SELECT * FROM SYSIBM.SYSTABLES",
    "SELECT * FROM SYSIBMADM.DBCFG",
    "SELECT * FROM SYSTOOLS.EXPLAIN_STATEMENT",
    "SELECT * FROM SYSSTAT.TABLES",
    "SELECT 1 FROM DB2INTEL_DEMO.CUSTOMER UNION SELECT SALARY FROM DB2INST1.EMPLOYEE_SALARY",
    "SELECT (SELECT MAX(SALARY) FROM DB2INST1.EMPLOYEE_SALARY) FROM DB2INTEL_DEMO.CUSTOMER",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER WHERE EXISTS (SELECT 1 FROM SYSCAT.TABLES)",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER C WHERE C.CUSTOMER_ID IN (SELECT ID FROM DB2INST1.EMPLOYEE_INFO)",
    "WITH E AS (SELECT * FROM DB2INST1.EMPLOYEE_INFO) SELECT * FROM E",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER C JOIN DB2INST1.EMPLOYEE_INFO E ON 1 = 1",
    "SELECT * FROM (SELECT * FROM DB2INST1.EMPLOYEE_INFO) X",
])
def test_forbidden_schemas_are_rejected_everywhere(sql):
    rejected(sql, "forbidden_schema")


@pytest.mark.parametrize("sql,code", [
    ("SELECT * FROM SALES.ORDERS", "schema_not_allowed"),
    ("SELECT * FROM CUSTOMER", "unqualified_table"),
    ("SELECT * FROM EMPLOYEE_INFO", "unqualified_table"),
    ("SELECT * FROM TESTDB.DB2INTEL_DEMO.CUSTOMER", "syntax"),
    ('SELECT * FROM "DB2INST1"."EMPLOYEE_INFO"', "delimited_identifier"),
    ('SELECT * FROM DB2INTEL_DEMO."customer"', "delimited_identifier"),
    ("SELECT * FROM DB2INTEL_DEMO.CUSTOMER, DB2INST1.EMPLOYEE_INFO", "comma_join"),
    ("SELECT * FROM DB2INTEL_DEMO.CUSTOMER A, DB2INTEL_DEMO.REGION B", "comma_join"),
    ("SELECT DB2INTEL_DEMO.CUSTOMER.COMPANY_NAME.X FROM DB2INTEL_DEMO.CUSTOMER", "syntax"),
])
def test_unqualified_unknown_and_ambiguous_names_are_rejected(sql, code):
    rejected(sql, code)


def test_cte_named_like_a_protected_table_reads_only_its_definition():
    g = ok("WITH EMPLOYEE_INFO AS (SELECT 1 AS X FROM SYSIBM.SYSDUMMY1) SELECT * FROM EMPLOYEE_INFO")
    assert g.tables == (("SYSIBM", "SYSDUMMY1"),)


def test_allowed_schemas_can_never_include_protected_schemas():
    for schema in ("DB2INST1", "DB2INTEL", "SYSCAT", "SYSIBM", "SYSIBMADM", "SYSTOOLS", "db2inst1"):
        with pytest.raises(ValueError):
            check_allowed_schemas({schema})
    with pytest.raises(ValueError):
        check_allowed_schemas(set())


def test_other_allowed_schema_is_honoured_and_demo_is_then_refused():
    assert ok("SELECT * FROM SALES.ORDERS", allowed={"SALES"}).tables == (("SALES", "ORDERS"),)
    with pytest.raises(GuardViolation):
        guard_sql("SELECT * FROM DB2INTEL_DEMO.CUSTOMER", {"SALES"}, 500)


# ---- CTEs ----------------------------------------------------------------------------------
def test_cte_may_reference_an_earlier_cte():
    assert ok("WITH A AS (SELECT 1 AS X FROM SYSIBM.SYSDUMMY1), B AS (SELECT X FROM A), C AS (SELECT X FROM B) "
              "SELECT * FROM C").ctes == ("A", "B", "C")


@pytest.mark.parametrize("sql,code", [
    ("WITH R (N) AS (SELECT 1 FROM SYSIBM.SYSDUMMY1 UNION ALL SELECT N + 1 FROM R) SELECT * FROM R", "unqualified_table"),
    ("WITH A AS (SELECT * FROM B), B AS (SELECT 1 AS X FROM SYSIBM.SYSDUMMY1) SELECT * FROM A", "unqualified_table"),
    ("WITH A AS (SELECT 1 AS X FROM SYSIBM.SYSDUMMY1), A AS (SELECT 2 AS X FROM SYSIBM.SYSDUMMY1) SELECT * FROM A", "duplicate_cte"),
    ("WITH A AS (WITH B AS (SELECT 1 AS X FROM SYSIBM.SYSDUMMY1) SELECT * FROM B) SELECT * FROM A", "nested_with"),
    ("SELECT * FROM (WITH A AS (SELECT 1 AS X FROM SYSIBM.SYSDUMMY1) SELECT * FROM A) T", "nested_with"),
    ("SELECT * FROM DB2INTEL_DEMO.CUSTOMER WHERE CUSTOMER_ID IN (WITH A AS (SELECT 1 AS X FROM SYSIBM.SYSDUMMY1) SELECT X FROM A)", "nested_with"),
    ("WITH SELECT AS (SELECT 1 AS X FROM SYSIBM.SYSDUMMY1) SELECT * FROM SYSIBM.SYSDUMMY1", "reserved_word"),
    ("WITH ORDER AS (SELECT 1 AS X FROM SYSIBM.SYSDUMMY1) SELECT * FROM ORDER", "reserved_word"),
])
def test_recursive_misordered_duplicate_and_nested_ctes_are_rejected(sql, code):
    rejected(sql, code)


# ---- functions ----------------------------------------------------------------------------
@pytest.mark.parametrize("sql", [
    "SELECT MYUDF(CUSTOMER_ID) FROM DB2INTEL_DEMO.CUSTOMER",
    "SELECT RAND() FROM DB2INTEL_DEMO.CUSTOMER",
    "SELECT VECTOR_DISTANCE(A, B, COSINE) FROM DB2INTEL_DEMO.CUSTOMER",
    "SELECT XMLQUERY('db2-fn:xmlcolumn(\"X\")') FROM DB2INTEL_DEMO.CUSTOMER",
    "SELECT SLEEP(100) FROM DB2INTEL_DEMO.CUSTOMER",
    "SELECT GETENV('PATH') FROM DB2INTEL_DEMO.CUSTOMER",
    "SELECT ROLLUP(SEGMENT) FROM DB2INTEL_DEMO.CUSTOMER",
])
def test_functions_outside_the_allow_list_are_rejected(sql):
    rejected(sql, "function_not_allowed")


@pytest.mark.parametrize("sql", [
    "SELECT SYSPROC.ADMIN_CMD('RUNSTATS') FROM DB2INTEL_DEMO.CUSTOMER",
    "SELECT DB2INST1.ROUND(1) FROM DB2INTEL_DEMO.CUSTOMER",
    "SELECT SYSIBM.SUM(LINE_AMOUNT) FROM DB2INTEL_DEMO.ORDER_ITEM",
])
def test_schema_qualified_functions_are_rejected(sql):
    rejected(sql, "function_not_allowed")


@pytest.mark.parametrize("sql,code", [
    ("SELECT * FROM TABLE(MON_GET_PKG_CACHE_STMT('D', NULL, NULL, -2)) AS T", "table_function"),
    ("SELECT * FROM TABLE(SYSPROC.ADMIN_CMD('x')) T", "table_function"),
    ("SELECT * FROM DB2INTEL_DEMO.CUSTOMER C, LATERAL (SELECT 1 FROM SYSIBM.SYSDUMMY1) X", "comma_join"),
    ("SELECT * FROM DB2INTEL_DEMO.CUSTOMER C JOIN LATERAL (SELECT 1 AS X FROM SYSIBM.SYSDUMMY1) X ON 1 = 1", "table_function"),
    ("SELECT * FROM XMLTABLE('$d' PASSING 1 AS D) X", "table_function"),
    ("SELECT * FROM UNNEST(A) AS U", "table_function"),
    ("SELECT * FROM DB2INTEL_DEMO.MY_TABLE_FUNC(1) AS T", "table_function"),
    ("SELECT * FROM MY_TABLE_FUNC(1) AS T", "table_function"),
    ("SELECT * FROM FINAL TABLE (INSERT INTO DB2INTEL_DEMO.REGION (REGION_ID) VALUES (9))", "data_change"),
    ("SELECT * FROM NEW TABLE (UPDATE DB2INTEL_DEMO.CUSTOMER SET CREDIT_LIMIT = 0)", "data_change"),
    ("SELECT * FROM OLD TABLE (DELETE FROM DB2INTEL_DEMO.CUSTOMER)", "data_change"),
])
def test_table_functions_and_data_change_references_are_rejected(sql, code):
    rejected(sql, code)


def test_ranking_functions_require_over():
    rejected("SELECT ROW_NUMBER() FROM DB2INTEL_DEMO.CUSTOMER", "syntax")


# ---- locking, isolation and other trailing clauses ------------------------------------------
@pytest.mark.parametrize("tail", [
    "FOR UPDATE", "FOR UPDATE OF CREDIT_LIMIT", "FOR READ ONLY", "FOR FETCH ONLY", "WITH UR", "WITH CS",
    "WITH RR", "WITH RS USE AND KEEP EXCLUSIVE LOCKS", "SKIP LOCKED DATA", "OPTIMIZE FOR 1 ROW",
    "FOR SYSTEM_TIME AS OF CURRENT TIMESTAMP",
])
def test_locking_and_isolation_clauses_are_rejected(tail):
    rejected(f"SELECT * FROM DB2INTEL_DEMO.CUSTOMER {tail}", "locking_clause")


@pytest.mark.parametrize("sql,code", [
    ("SELECT * FROM DB2INTEL_DEMO.CUSTOMER LIMIT 10", "syntax"),
    ("SELECT * FROM DB2INTEL_DEMO.CUSTOMER TABLESAMPLE BERNOULLI(10)", "syntax"),
    ("SELECT COMPANY_NAME INTO X FROM DB2INTEL_DEMO.CUSTOMER", "not_select"),
    ("SELECT COMPANY_NAME INTO :X FROM DB2INTEL_DEMO.CUSTOMER", "host_variable"),
    ("SELECT * FROM DB2INTEL_DEMO.CUSTOMER WHERE CUSTOMER_ID = ?", "parameter_marker"),
    ("SELECT {fn NOW()} FROM DB2INTEL_DEMO.CUSTOMER", "bad_character"),
    ("SELECT CURRENT USER FROM SYSIBM.SYSDUMMY1", "syntax"),
    ("SELECT CURRENT SCHEMA FROM SYSIBM.SYSDUMMY1", "syntax"),
    ("SELECT (1, 2) FROM SYSIBM.SYSDUMMY1", "syntax"),
    ("SELECT * FROM DB2INTEL_DEMO.CUSTOMER WHERE A = B = C", "syntax"),
    ("SELECT FROM DB2INTEL_DEMO.CUSTOMER", "reserved_word"),
    ("SELECT * DB2INTEL_DEMO.CUSTOMER", "syntax"),
    ("SELECT *", "syntax"),
    ("SELECT 1", "syntax"),
    ("", "empty"),
    ("   \n\t ", "empty"),
    ("FROM DB2INTEL_DEMO.CUSTOMER", "syntax"),
    ("SELECT 'DB2INTEL_REQ_0123' FROM SYSIBM.SYSDUMMY1", "marker"),
    ("SELECT DB2INTEL_REQ_ABC FROM SYSIBM.SYSDUMMY1", "marker"),
    ("SELECT 1x FROM SYSIBM.SYSDUMMY1", "bad_number"),
    ("SELECT 0x1F FROM SYSIBM.SYSDUMMY1", "bad_number"),
    ("SELECT 1E FROM SYSIBM.SYSDUMMY1", "bad_number"),
    ("SELECT A@B FROM DB2INTEL_DEMO.CUSTOMER", "bad_identifier"),
    ("SELECT A#B FROM DB2INTEL_DEMO.CUSTOMER", "bad_identifier"),
])
def test_ambiguous_or_unsupported_syntax_is_rejected(sql, code):
    rejected(sql, code)


@pytest.mark.parametrize("char", [";", "；", " ", " ", "\x0b", "\x0c", "\x00", "|", "&", "%", "[", "\\", "`", "$", "~", "^"])
def test_unusual_characters_outside_literals_are_rejected(char):
    rejected(f"SELECT * FROM DB2INTEL_DEMO.CUSTOMER{char}WHERE 1 = 1")


def test_too_long_and_too_deep_inputs_are_rejected_cleanly():
    rejected("SELECT " + "1 + " * 6000 + "1 FROM SYSIBM.SYSDUMMY1", "too_long")
    rejected("SELECT " + "(" * 200 + "1" + ")" * 200 + " FROM SYSIBM.SYSDUMMY1", "too_deep")
    rejected("SELECT " + "- " * 500 + "1 FROM SYSIBM.SYSDUMMY1", "too_deep")
    rejected("SELECT 1 FROM SYSIBM.SYSDUMMY1 WHERE " + "NOT " * 500 + "1 = 1", "too_deep")
    nested = "SELECT 1 AS X FROM SYSIBM.SYSDUMMY1"
    for _ in range(80):
        nested = f"SELECT * FROM ({nested}) T"
    rejected(nested, "too_deep")


# ---- tokenizer and renderer ---------------------------------------------------------------
def test_render_never_creates_comment_or_combined_operators():
    toks = tokenize("SELECT 1 - -1, 2 / (3 * 4), 5 < -6, 7 > 8 FROM SYSIBM.SYSDUMMY1")
    text = render(toks)
    assert "--" not in text and "/*" not in text and "*/" not in text
    assert [(t.kind, t.value) for t in tokenize(text)] == [(t.kind, t.value) for t in toks]


def test_identifiers_are_uppercased_but_literals_are_kept():
    assert ok("select company_name from db2intel_demo.customer where segment = 'Small Biz'").text == (
        "SELECT COMPANY_NAME FROM DB2INTEL_DEMO.CUSTOMER WHERE SEGMENT = 'Small Biz' FETCH FIRST 500 ROWS ONLY")


def test_guarded_text_is_a_fixed_point():
    for sql in ACCEPTED:
        g = ok(sql)
        again = ok(g.text)
        assert again.text == g.text and again.cap_action == "kept"


# ---- randomized robustness: never crash, never accept a forbidden reference ----------------
_SOUP = ["SELECT", "FROM", "WHERE", "WITH", "AS", "(", ")", ",", ";", "'x'", "''", "1", "*", "=", "UNION",
         "DB2INTEL_DEMO.CUSTOMER", "DB2INST1.EMPLOYEE_INFO", "SYSCAT.TABLES", "DELETE", "INSERT", "CALL",
         "TABLE", "FINAL", "--", "/*", "*/", "JOIN", "ON", "A", "B", ".", "FETCH", "FIRST", "ROWS", "ONLY",
         "ORDER", "BY", "EXISTS", "IN", "NOT", "CASE", "WHEN", "THEN", "END", "COUNT", "SUM", "'", '"', "?"]


def _forbidden_reference(text: str) -> bool:
    return any(s in text for s in ("DB2INST1", "SYSCAT", "DELETE", "INSERT", "CALL", "FINAL TABLE"))


def test_random_token_soup_never_crashes_or_leaks():
    rng = random.Random(20261106)
    accepted = 0
    for _ in range(4000):
        sql = " ".join(rng.choice(_SOUP) for _ in range(rng.randint(1, 25)))
        try:
            g = ok(sql)
        except GuardViolation:
            continue
        accepted += 1
        assert not _forbidden_reference(g.text.replace("'x'", "")), sql
        assert all(s == "DB2INTEL_DEMO" for s, _ in g.tables), sql


def test_random_mutations_of_valid_queries_never_crash_or_leak():
    rng = random.Random(7)
    for _ in range(3000):
        base = list(rng.choice(ACCEPTED))
        for _ in range(rng.randint(1, 4)):
            pos = rng.randrange(len(base) + 1)
            op = rng.random()
            if op < 0.4 and base:
                del base[min(pos, len(base) - 1)]
            else:
                base.insert(pos, rng.choice(list("();,'\"-/*?.:= ") + [" DB2INST1.EMPLOYEE_INFO ", " DELETE ", " UNION SELECT * FROM SYSCAT.TABLES "]))
        sql = "".join(base)
        try:
            g = ok(sql)
        except GuardViolation:
            continue
        assert "--" not in g.text and "/*" not in g.text
        assert all(s == "DB2INTEL_DEMO" or (s, n) in rules.READABLE_SYSTEM_OBJECTS for s, n in g.tables), sql
