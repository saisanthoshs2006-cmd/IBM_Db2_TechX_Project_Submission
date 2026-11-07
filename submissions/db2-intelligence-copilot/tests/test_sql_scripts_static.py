"""Static verification of the real SQL scripts (no database)."""
import re

import pytest

from db2intel.db.migrate import MIGRATIONS, TEARDOWN_SCRIPT, load_migrations, load_teardown
from db2intel.db.sql_policy import (
    PolicyViolation,
    check_migration_statement,
    check_teardown_script,
    check_vector_dimensions,
    vector_dimensions,
)
from db2intel.db.sql_script import SqlScript, load_script, mask_literals

from conftest import SQL_DIR

ID = r"[A-Z_][A-Z0-9_]*"


def canon(stmt: str) -> str:
    return " ".join(mask_literals(stmt).upper().split())


@pytest.fixture(scope="module")
def migrations():
    return load_migrations(SQL_DIR, expected_dim=768)


@pytest.fixture(scope="module")
def teardown():
    return load_teardown(SQL_DIR)


# ---- execution order ------------------------------------------------------------
def test_init_order_is_exactly_001_then_002_then_003():
    assert MIGRATIONS == ("001_schema_meta.sql", "002_demo_data.sql", "003_explain_tables.sql")


def test_exactly_three_migration_files_exist_and_all_are_registered():
    files = sorted(p.name for p in SQL_DIR.glob("*.sql") if not p.name.startswith("9"))
    assert files == list(MIGRATIONS) and len(files) == 3


def test_teardown_is_never_part_of_initialization():
    assert TEARDOWN_SCRIPT not in MIGRATIONS
    assert all(not name.startswith("9") for name in MIGRATIONS)


def test_sql_directory_holds_only_the_four_reviewed_scripts():
    assert sorted(p.name for p in SQL_DIR.glob("*.sql")) == [
        "001_schema_meta.sql", "002_demo_data.sql", "003_explain_tables.sql", "900_teardown.sql"]


# ---- schema scope -----------------------------------------------------------------
def test_each_migration_only_creates_objects_in_its_own_schema(migrations):
    expected = {"001_schema_meta.sql": "DB2INTEL", "002_demo_data.sql": "DB2INTEL_DEMO",
                "003_explain_tables.sql": "DB2INTEL"}
    for script in migrations:
        for stmt in script.statements:
            info = check_migration_statement(stmt)
            for target in info.targets:
                assert target.split(".")[0] == expected[script.name], (script.name, stmt[:60])


@pytest.mark.parametrize("word", ["DB2INST1", "TESTDB", "SAMPLE", "EMPLOYEE_INFO", "EMPLOYEE_SALARY"])
def test_no_executable_reference_to_protected_objects(migrations, teardown, word):
    for script in [*migrations, teardown]:
        for stmt in script.statements:
            assert not re.search(rf"\b{word}\b", canon(stmt)), (script.name, stmt[:80])


def test_teardown_drops_exactly_the_objects_the_migrations_create(migrations, teardown):
    created = set()
    for script in migrations:
        for stmt in script.statements:
            if m := re.match(rf"^CREATE (?:TABLE|VIEW) ({ID}\.{ID})", canon(stmt)):
                created.add(m.group(1))
    dropped = {m.group(1) for s in teardown.statements
               if (m := re.match(rf"^DROP (?:TABLE|VIEW) ({ID}\.{ID})$", canon(s)))}
    assert dropped == created


def test_teardown_drops_only_project_schemas_with_restrict(teardown):
    schemas = [canon(s) for s in teardown.statements if canon(s).startswith("DROP SCHEMA")]
    assert schemas == ["DROP SCHEMA DB2INTEL_DEMO RESTRICT", "DROP SCHEMA DB2INTEL RESTRICT"]


def test_teardown_drops_children_before_parents(migrations, teardown):
    order = [m.group(1) for s in teardown.statements
             if (m := re.match(rf"^DROP (?:TABLE|VIEW) ({ID}\.{ID})$", canon(s)))]
    position = {name: i for i, name in enumerate(order)}
    for script in migrations:
        for stmt in script.statements:
            c = canon(stmt)
            owner = re.match(rf"^(?:CREATE TABLE|ALTER TABLE) ({ID}\.{ID})", c)
            if not owner:
                continue
            for parent in re.findall(rf"REFERENCES ({ID}\.{ID})", c):
                if parent != owner.group(1) and not c.startswith("ALTER"):
                    assert position[owner.group(1)] < position[parent], (owner.group(1), parent)


@pytest.mark.parametrize("bad", [
    "DROP TABLE DB2INST1.EMPLOYEE_INFO;",
    "DROP TABLE DB2INST1.EMPLOYEE_SALARY;",
    "DROP SCHEMA DB2INST1 RESTRICT;",
    "DROP DATABASE TESTDB;",
    "DROP DATABASE SAMPLE;",
    "DROP SCHEMA DB2INTEL;",
    "DROP TABLE EMPLOYEE_INFO;",
    "DELETE FROM DB2INTEL.QUERY_AUDIT;",
    "DROP TABLE DB2INTEL.X; DROP TABLE DB2INST1.Y;",
    "DROP TABLESPACE USERSPACE1;",
])
def test_teardown_policy_rejects_anything_else(bad):
    script = SqlScript("900_teardown.sql", bad, tuple(s.strip() for s in bad.split(";") if s.strip()), "x")
    with pytest.raises(PolicyViolation):
        check_teardown_script(script)


@pytest.mark.parametrize("bad", [
    "CREATE TABLE DB2INST1.T (X INT)",
    "CREATE TABLE T (X INT)",
    "INSERT INTO DB2INST1.EMPLOYEE_INFO (EMP_ID) VALUES (1)",
    "INSERT INTO DB2INTEL.T (X) SELECT EMP_ID FROM DB2INST1.EMPLOYEE_INFO",
    "CREATE VIEW DB2INTEL.V AS SELECT * FROM SYSCAT.TABLES",
    "DROP TABLE DB2INTEL.T",
    "DELETE FROM DB2INTEL.T",
    "UPDATE DB2INTEL.T SET X = 1",
    "CALL SYSPROC.ADMIN_CMD('REORG TABLE DB2INST1.EMPLOYEE_INFO')",
    "GRANT DBADM ON DATABASE TO USER PUBLIC",
    "CREATE INDEX DB2INTEL.IX ON DB2INST1.EMPLOYEE_INFO (EMP_ID)",
    "ALTER TABLE DB2INTEL.T DROP COLUMN X",
    "CREATE SCHEMA DB2INST1",
])
def test_migration_policy_rejects_out_of_scope_statements(bad):
    with pytest.raises(PolicyViolation):
        check_migration_statement(bad)


# ---- VECTOR columns ----------------------------------------------------------------
def test_every_vector_column_is_768_float32_and_setting_matches(migrations):
    meta = migrations[0]
    assert vector_dimensions(meta) == {768}
    check_vector_dimensions(meta, 768)
    with pytest.raises(PolicyViolation):
        check_vector_dimensions(meta, 384)
    assert vector_dimensions(migrations[1]) == set()
    assert vector_dimensions(migrations[2]) == set()


def _create_tables(script):
    for stmt in script.statements:
        c = " ".join(stmt.upper().split())
        if m := re.match(rf"^CREATE TABLE ({ID}\.{ID}) \((.*)\)(?: ORGANIZE BY ROW)?$", c):
            yield m.group(1), m.group(2)


def _is_constraint(part: str) -> bool:
    """Named (CONSTRAINT x ...) or unnamed (PRIMARY KEY / FOREIGN KEY / UNIQUE ...) table constraint."""
    return part.startswith(("CONSTRAINT", "PRIMARY KEY", "FOREIGN KEY", "UNIQUE", "CHECK"))


def test_every_create_table_statement_is_parsed_by_the_static_checks(migrations):
    for script in migrations:
        creates = [s for s in script.statements if canon(s).startswith("CREATE TABLE")]
        assert len(list(_create_tables(script))) == len(creates), script.name


def _split_top_level(body: str) -> list[str]:
    parts, depth, cur = [], 0, []
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur).strip())
    return parts


def test_vector_columns_follow_db2_restrictions(migrations):
    """Db2: VECTOR cannot have DEFAULT, be in a PK/unique/FK, or be indexed."""
    meta = migrations[0]
    vector_cols = {}
    for table, body in _create_tables(meta):
        for part in _split_top_level(body):
            if re.match(rf"^{ID} VECTOR\(", part):
                col = part.split()[0]
                vector_cols.setdefault(table, set()).add(col)
                assert "NOT NULL" in part and "DEFAULT" not in part, part
        for part in _split_top_level(body):
            if part.startswith("CONSTRAINT") and re.search(r"PRIMARY KEY|UNIQUE|FOREIGN KEY", part):
                cols = re.search(r"(?:PRIMARY KEY|UNIQUE|FOREIGN KEY) \(([^)]*)\)", part).group(1)
                assert not set(c.strip() for c in cols.split(",")) & vector_cols.get(table, set()), part
    assert vector_cols == {
        "DB2INTEL.SCHEMA_EMBEDDING": {"EMBEDDING"},
        "DB2INTEL.VERIFIED_QUERY_EMBEDDING": {"EMBEDDING"},
    }
    for stmt in meta.statements:
        c = " ".join(stmt.upper().split())
        if m := re.match(rf"^CREATE INDEX {ID}\.{ID} ON ({ID}\.{ID}) \(([^)]*)\)", c):
            assert not {x.strip() for x in m.group(2).split(",")} & vector_cols.get(m.group(1), set())


# ---- row size on 4K pages ------------------------------------------------------------
def _byte_count(defn: str) -> int:
    """Conservative Db2 row-organized byte count per column (SQL Reference 'byte counts')."""
    d = defn.split(None, 1)[1]
    nullable = 0 if "NOT NULL" in d else 1
    rules = [
        (r"^BIGINT", 8), (r"^INTEGER", 4), (r"^SMALLINT", 2), (r"^DOUBLE", 8),
        (r"^DATE", 4), (r"^TIMESTAMP", 10),
    ]
    for pattern, size in rules:
        if re.match(pattern, d):
            return size + nullable
    if m := re.match(r"^CHAR\((\d+)(?: OCTETS)?\)", d):
        return int(m.group(1)) + nullable
    if m := re.match(r"^VARCHAR\((\d+)(?: OCTETS)?\)", d):
        return int(m.group(1)) + 4 + nullable
    if m := re.match(r"^DECIMAL\((\d+), ?\d+\)", d):
        return int(m.group(1)) // 2 + 1 + nullable
    if m := re.match(r"^VECTOR\((\d+), FLOAT32\)", d):
        return int(m.group(1)) * 4 + 64 + nullable  # +64 bytes as a generous header allowance
    if re.match(r"^[CB]LOB", d):
        return 316 + nullable  # largest LOB descriptor size
    raise AssertionError(f"no byte-count rule for {defn}")


def test_every_table_fits_the_4005_byte_row_limit_of_4k_pages(migrations):
    for script in migrations:
        for table, body in _create_tables(script):
            cols = [p for p in _split_top_level(body) if not _is_constraint(p)]
            size = sum(_byte_count(c) for c in cols)
            assert size < 4005, f"{table} estimated {size} bytes"


# ---- other Db2 rules ------------------------------------------------------------------
def test_comments_fit_db2_254_byte_limit(migrations):
    for script in migrations:
        for stmt in script.statements:
            if stmt.upper().lstrip().startswith("COMMENT ON"):
                for literal in re.findall(r"'((?:[^']|'')*)'", stmt):
                    assert len(literal.replace("''", "'").encode("utf-8")) <= 254, literal[:40]


def test_generated_column_only_references_earlier_columns(migrations):
    demo = migrations[1]
    body = dict(_create_tables(demo))["DB2INTEL_DEMO.ORDER_ITEM"]
    names = [p.split()[0] for p in _split_top_level(body) if not p.startswith("CONSTRAINT")]
    gen = next(p for p in _split_top_level(body) if "GENERATED ALWAYS AS" in p)
    expr_cols = set(re.findall(rf"\b({ID})\b", gen.split("GENERATED ALWAYS AS", 1)[1])) & set(names)
    assert expr_cols == {"QUANTITY", "UNIT_PRICE", "DISCOUNT_PCT"}
    assert all(names.index(c) < names.index("LINE_AMOUNT") for c in expr_cols)


def test_row_change_timestamp_columns_are_not_null_without_default(migrations):
    for script in migrations:
        for table, body in _create_tables(script):
            rct = [p for p in _split_top_level(body) if "ROW CHANGE TIMESTAMP" in p]
            assert len(rct) <= 1, table
            for p in rct:
                assert "NOT NULL" in p and " DEFAULT " not in p


def test_set_null_foreign_keys_are_on_nullable_columns(migrations):
    for script in migrations:
        nullable = {}
        for table, body in _create_tables(script):
            for p in _split_top_level(body):
                if not p.startswith("CONSTRAINT"):
                    nullable[(table, p.split()[0])] = "NOT NULL" not in p
        for stmt in script.statements:
            c = " ".join(stmt.upper().split())
            owner = re.match(rf"^(?:CREATE TABLE|ALTER TABLE) ({ID}\.{ID})", c)
            for cols in re.findall(r"FOREIGN KEY \(([^)]*)\) REFERENCES [^)]*\) ON DELETE SET NULL", c):
                for col in cols.split(","):
                    assert nullable[(owner.group(1), col.strip())], (owner.group(1), col)


def test_every_statement_ends_up_parsed(migrations, teardown):
    counts = {s.name: len(s.statements) for s in [*migrations, teardown]}
    assert counts == {"001_schema_meta.sql": 29, "002_demo_data.sql": 29, "003_explain_tables.sql": 17,
                      "900_teardown.sql": 28}
    for name in counts:
        assert load_script(SQL_DIR / name).checksum


# ---- review fixes: policy gaps ------------------------------------------------------------
@pytest.mark.parametrize("bad", [
    "INSERT INTO DB2INTEL.T (X) SELECT A.X FROM DB2INTEL.A A, EMPLOYEE_INFO E",
    "INSERT INTO DB2INTEL.T (X) SELECT X FROM DB2INTEL.A, EMPLOYEE_SALARY",
    "CREATE VIEW DB2INTEL.V AS SELECT * FROM DB2INTEL.A AS A, DB2INTEL.B AS B",
    "INSERT INTO DB2INTEL.T (X) VALUES (NEXT VALUE FOR SOME_SEQ)",
    "INSERT INTO DB2INTEL.T (X) VALUES (PREVIOUS VALUE FOR SOME_SEQ)",
    "INSERT INTO DB2INTEL.T (X) VALUES (SOME_SEQ.NEXTVAL)",
])
def test_policy_rejects_comma_joins_and_sequence_access(bad):
    with pytest.raises(PolicyViolation):
        check_migration_statement(bad)


@pytest.mark.parametrize("ok", [
    "INSERT INTO DB2INTEL.T (X) WITH S (N) AS (SELECT 1 FROM SYSIBM.SYSDUMMY1 UNION ALL SELECT N + 1 FROM S WHERE N < 3), "
    "P (I) AS (VALUES (1), (2)) SELECT S.N FROM S JOIN P ON P.I = S.N",
    "CREATE VIEW DB2INTEL.V AS SELECT A.X FROM DB2INTEL.A A JOIN DB2INTEL.B B ON B.X = A.X GROUP BY A.X",
])
def test_policy_still_accepts_cte_and_join_forms(ok):
    check_migration_statement(ok)
