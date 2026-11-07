"""Migration 003 (Db2 explain tables in DB2INTEL): definitions, keys, indexes, order and teardown.

No database is used. The definitions were verified against Db2 12.1.5 in a rolled-back trial;
these tests pin that verified text and check every structural property offline.
"""
import copy
import hashlib
import re

import pytest

from db2intel.db import migrate as migrate_module
from db2intel.db.migrate import (
    MIGRATIONS,
    TEARDOWN_CONFIRMATION,
    MigrationError,
    MigrationRunner,
    created_objects,
    load_migrations,
    load_teardown,
)
from db2intel.db.sql_policy import PolicyViolation
from db2intel.db.sql_script import load_script, mask_literals

from conftest import SQL_DIR

NAME = "003_explain_tables.sql"
ID = r"[A-Z_][A-Z0-9_]*"
# SHA-256 of the 17 statements exactly as verified in the DB2INTEL_TRIAL rolled-back trial
# (qualifier mapped back to DB2INTEL). Comment-only edits do not change it; any SQL edit does.
VERIFIED_STATEMENTS_SHA256 = "38fe95237d834170e02ebc59b5512d43df15ab7bbad5bfee60681a2f99d16749"

KEY = ["EXPLAIN_REQUESTER", "EXPLAIN_TIME", "SOURCE_NAME", "SOURCE_SCHEMA", "SOURCE_VERSION"]
STMT_KEY = KEY + ["EXPLAIN_LEVEL", "STMTNO", "SECTNO"]
EXPECTED_PK = {
    "EXPLAIN_INSTANCE": KEY,
    "EXPLAIN_STATEMENT": STMT_KEY,
    "EXPLAIN_OPERATOR": STMT_KEY + ["OPERATOR_ID"],
    "EXPLAIN_DIAGNOSTIC": STMT_KEY + ["DIAGNOSTIC_ID"],
    "OBJECT_METRICS": ["EXECUTABLE_ID", "EXECUTION_TIME", "OBJECT_SCHEMA", "OBJECT_NAME", "OBJECT_TYPE",
                       "OBJECT_TENANTID", "MEMBER", "DATA_PARTITION_ID"],
}
EXPECTED_FK = {  # child -> parent
    "EXPLAIN_STATEMENT": "EXPLAIN_INSTANCE",
    "EXPLAIN_ARGUMENT": "EXPLAIN_STATEMENT",
    "EXPLAIN_OBJECT": "EXPLAIN_STATEMENT",
    "EXPLAIN_OPERATOR": "EXPLAIN_STATEMENT",
    "EXPLAIN_PREDICATE": "EXPLAIN_STATEMENT",
    "EXPLAIN_STREAM": "EXPLAIN_STATEMENT",
    "EXPLAIN_DIAGNOSTIC": "EXPLAIN_STATEMENT",
    "EXPLAIN_DIAGNOSTIC_DATA": "EXPLAIN_DIAGNOSTIC",
    "EXPLAIN_ACTUALS": "EXPLAIN_OPERATOR",
}
EXPECTED_TABLES = set(EXPECTED_PK) | set(EXPECTED_FK) | {"EXPLAIN_INSTANCE"}
EXPECTED_INDEXES = {
    "STMT_I1": ("EXPLAIN_STATEMENT", ["EXPLAIN_TIME", "EXPLAIN_LEVEL", "STMTNO", "SECTNO"]),
    "ARG_I1": ("EXPLAIN_ARGUMENT", ["EXPLAIN_TIME", "EXPLAIN_LEVEL", "STMTNO", "SECTNO", "OPERATOR_ID"]),
    "PRD_I1": ("EXPLAIN_PREDICATE", ["EXPLAIN_TIME", "EXPLAIN_LEVEL", "STMTNO", "SECTNO", "OPERATOR_ID"]),
    "STM_I1": ("EXPLAIN_STREAM", ["EXPLAIN_TIME", "EXPLAIN_LEVEL", "STMTNO", "SECTNO"]),
    "OBJ_I1": ("EXPLAIN_OBJECT", ["EXPLAIN_TIME", "EXPLAIN_LEVEL", "STMTNO", "SECTNO"]),
    "EXP_DIAG_DAT_I1": ("EXPLAIN_DIAGNOSTIC_DATA",
                        ["EXPLAIN_TIME", "EXPLAIN_LEVEL", "STMTNO", "SECTNO", "DIAGNOSTIC_ID", "ORDINAL"]),
}


def canon(stmt):
    return " ".join(mask_literals(stmt).upper().split())


def split_top_level(body):
    parts, depth, cur = [], 0, []
    for ch in body:
        depth += (ch == "(") - (ch == ")")
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur).strip())
    return parts


def cols(text):
    return [c.strip() for c in text.split(",")]


@pytest.fixture(scope="module")
def script():
    return load_script(SQL_DIR / NAME)


@pytest.fixture(scope="module")
def tables(script):
    """{table: {"columns": {name: definition}, "pk": [...], "fks": [(cols, parent, tail)], "suffix": str}}"""
    out = {}
    for stmt in script.statements:
        c = canon(stmt)
        m = re.match(rf"^CREATE TABLE DB2INTEL\.({ID}) \((.*)\)( ORGANIZE BY ROW)?$", c)
        if not m:
            continue
        info = {"columns": {}, "pk": None, "fks": [], "suffix": m.group(3)}
        for part in split_top_level(m.group(2)):
            if pk := re.match(r"^PRIMARY KEY \(([^)]*)\) ENFORCED$", part):
                info["pk"] = cols(pk.group(1))
            elif fk := re.match(rf"^FOREIGN KEY \(([^)]*)\) REFERENCES DB2INTEL\.({ID}) (.*)$", part):
                info["fks"].append((cols(fk.group(1)), fk.group(2), fk.group(3)))
            else:
                name, definition = part.split(None, 1)
                info["columns"][name] = definition
        out[m.group(1)] = info
    return out


@pytest.fixture(scope="module")
def indexes(script):
    out = {}
    for stmt in script.statements:
        if m := re.match(rf"^CREATE INDEX DB2INTEL\.({ID}) ON DB2INTEL\.({ID}) \(([^)]*)\)$", canon(stmt)):
            out[m.group(1)] = (m.group(2), cols(m.group(3)))
    return out


# ---- provenance and statement shape ---------------------------------------------------------
def test_003_sql_is_exactly_the_trial_verified_text(script):
    digest = hashlib.sha256("\n;\n".join(script.statements).encode()).hexdigest()
    assert digest == VERIFIED_STATEMENTS_SHA256


def test_003_header_records_provenance_and_verification(script):
    for needle in ["EXPLAIN.DDL", "899bd940e141148d", "EXPLAIN_FROM_SECTION", "rolled-back trial", "ADVISE_*"]:
        assert needle in script.text, needle


def test_003_contains_only_create_table_and_create_index(script):
    kinds = [canon(s).split(" (")[0].split()[:2] for s in script.statements]
    assert [k for k in kinds if k == ["CREATE", "TABLE"]].__len__() == 11
    assert [k for k in kinds if k == ["CREATE", "INDEX"]].__len__() == 6
    assert len(script.statements) == 17


@pytest.mark.parametrize("word", [r"CREATE SCHEMA", r"INSERT", r"COMMIT", r"ECHO", r"UPDATE COMMAND",
                                  r"CREATE FUNCTION", r"ADVISE_", r"DB2INST1", r"SYSTOOLS", r"SAMPLE", r"TESTDB",
                                  r"DROP", r"ALTER", r"GRANT", r"CALL"])
def test_003_has_no_out_of_scope_statement_or_reference(script, word):
    for stmt in script.statements:
        assert not re.search(rf"\b{word}", canon(stmt)), (word, canon(stmt)[:60])


def test_003_creates_objects_only_in_db2intel_and_no_name_clashes_with_001(script):
    meta = load_migrations(SQL_DIR, 768)[0]
    created = created_objects(script)
    assert created == {f"DB2INTEL.{t}" for t in EXPECTED_TABLES}
    assert not created & created_objects(meta)
    meta_indexes = {m.group(1) for s in meta.statements if (m := re.match(rf"^CREATE INDEX ({ID}\.{ID})", canon(s)))}
    assert not {f"DB2INTEL.{i}" for i in EXPECTED_INDEXES} & meta_indexes


# ---- table definitions ------------------------------------------------------------------------
def test_exactly_the_eleven_expected_tables_are_created(tables):
    assert set(tables) == EXPECTED_TABLES and len(tables) == 11
    assert all(info["suffix"] == " ORGANIZE BY ROW" for info in tables.values())


def test_primary_keys_are_exactly_as_ibm_defines_them(tables):
    assert {t: info["pk"] for t, info in tables.items() if info["pk"]} == EXPECTED_PK
    for table, pk in EXPECTED_PK.items():
        for col in pk:
            assert "NOT NULL" in tables[table]["columns"][col], (table, col)


@pytest.mark.parametrize("table,column,definition", [
    ("EXPLAIN_INSTANCE", "DB2_VERSION", "CHAR(7 OCTETS) NOT NULL"),
    ("EXPLAIN_INSTANCE", "EXECUTABLE_ID", "VARCHAR(32 OCTETS) FOR BIT DATA"),
    ("EXPLAIN_STATEMENT", "TOTAL_COST", "DOUBLE NOT NULL"),
    ("EXPLAIN_STATEMENT", "EXPLAIN_LEVEL", "CHAR(1 OCTETS) NOT NULL"),
    ("EXPLAIN_STATEMENT", "STATEMENT_TEXT", "CLOB(2M OCTETS) NOT NULL NOT LOGGED"),
    ("EXPLAIN_OPERATOR", "OPERATOR_TYPE", "CHAR(6 OCTETS) NOT NULL"),
    ("EXPLAIN_OPERATOR", "TOTAL_COST", "DOUBLE NOT NULL"),
    ("EXPLAIN_STREAM", "STREAM_COUNT", "DOUBLE NOT NULL"),
    ("EXPLAIN_PREDICATE", "FILTER_FACTOR", "DOUBLE NOT NULL"),
    ("EXPLAIN_OBJECT", "OBJECT_NAME", "VARCHAR(128 OCTETS) NOT NULL"),
])
def test_columns_used_by_the_cost_guard_and_plan_view_exist(tables, table, column, definition):
    assert tables[table]["columns"][column] == definition


def test_not_logged_is_only_used_on_lob_columns(tables):
    for table, info in tables.items():
        for col, definition in info["columns"].items():
            if "NOT LOGGED" in definition:
                assert re.match(r"^[CB]LOB\(", definition), (table, col)


# ---- foreign keys --------------------------------------------------------------------------
def test_foreign_key_graph_is_exactly_as_expected(tables):
    graph = {t: [parent for _, parent, _ in info["fks"]] for t, info in tables.items() if info["fks"]}
    assert graph == {child: [parent] for child, parent in EXPECTED_FK.items()}


def test_every_foreign_key_matches_the_parent_primary_key_and_cascades(tables):
    for child, info in tables.items():
        for fk_cols, parent, tail in info["fks"]:
            assert fk_cols == EXPECTED_PK[parent], (child, parent)
            assert tail == "ON DELETE CASCADE ENFORCED", (child, tail)
            assert all(c in info["columns"] for c in fk_cols), child


def test_foreign_keys_never_leave_db2intel(script):
    for stmt in script.statements:
        for ref in re.findall(rf"REFERENCES ({ID}(?:\.{ID})?)", canon(stmt)):
            assert ref.startswith("DB2INTEL.") and ref.split(".")[1] in EXPECTED_TABLES


def test_parents_are_created_before_children(script):
    order = [m.group(1) for s in script.statements if (m := re.match(rf"^CREATE TABLE DB2INTEL\.({ID})", canon(s)))]
    for child, parent in EXPECTED_FK.items():
        assert order.index(parent) < order.index(child), (parent, child)


# ---- indexes -------------------------------------------------------------------------------
def test_indexes_are_exactly_ibm_recommended_set(indexes, tables):
    assert indexes == EXPECTED_INDEXES
    for name, (table, columns) in indexes.items():
        assert all(c in tables[table]["columns"] for c in columns), name


def test_indexes_are_created_after_their_tables(script):
    seen = set()
    for stmt in script.statements:
        c = canon(stmt)
        if m := re.match(rf"^CREATE TABLE DB2INTEL\.({ID})", c):
            seen.add(m.group(1))
        elif m := re.match(rf"^CREATE INDEX DB2INTEL\.{ID} ON DB2INTEL\.({ID})", c):
            assert m.group(1) in seen


# ---- migration ordering --------------------------------------------------------------------
def test_003_is_registered_last_after_001_and_002():
    assert MIGRATIONS.index(NAME) == 2 and MIGRATIONS[:2] == ("001_schema_meta.sql", "002_demo_data.sql")


def runner(db, sql_dir=SQL_DIR):
    return MigrationRunner(db, sql_dir, expected_dim=768, log=lambda _m: None)


@pytest.fixture
def db_with_001_002(fake_db, monkeypatch):
    """The real current state of TESTDB: 001 and 002 applied, 003 pending."""
    monkeypatch.setattr(migrate_module, "MIGRATIONS", MIGRATIONS[:2])
    assert runner(fake_db).up() == ["001_schema_meta.sql", "002_demo_data.sql"]
    monkeypatch.setattr(migrate_module, "MIGRATIONS", MIGRATIONS)
    fake_db.calls.clear()
    fake_db.commits = fake_db.rollbacks = 0
    return fake_db


def test_up_on_current_state_applies_only_003_in_one_transaction(db_with_001_002):
    db = db_with_001_002
    protected = copy.deepcopy((db.committed["protected"], db.committed["rows"], db.committed["indexes"]))
    assert runner(db).up() == [NAME]
    assert db.commits == 1 and db.rollbacks == 0
    executed = db.executed()
    assert len(executed) == 17 + 1  # 17 DDL statements + ledger row
    assert all(s.startswith(("CREATE TABLE DB2INTEL.", "CREATE INDEX DB2INTEL.")) for s in executed[:-1])
    assert executed[-1].startswith("INSERT INTO DB2INTEL.SCHEMA_MIGRATION")
    assert {f"DB2INTEL.{t}" for t in EXPECTED_TABLES} <= db.committed["objects"]
    assert set(db.committed["ledger"]) == set(MIGRATIONS)
    assert (db.committed["protected"], db.committed["rows"], db.committed["indexes"]) == protected


def test_failure_inside_003_rolls_back_003_only(db_with_001_002):
    db = db_with_001_002
    before = copy.deepcopy(db.committed)
    db.fail_when(r"^CREATE TABLE DB2INTEL\.EXPLAIN_ACTUALS", "42704")
    with pytest.raises(MigrationError, match=r"003_explain_tables\.sql failed at statement 11 of 17"):
        runner(db).up()
    assert db.committed == before  # 001/002 objects and ledger intact, no explain table committed
    assert db.commits == 0 and db.rollbacks == 1
    db.fail_on.clear()
    assert runner(db).up() == [NAME]


def test_existing_explain_table_without_ledger_row_is_refused(db_with_001_002):
    db = db_with_001_002
    db.committed["objects"].add("DB2INTEL.EXPLAIN_INSTANCE")  # e.g. created by hand or by SYSINSTALLOBJECTS
    db.work = copy.deepcopy(db.committed)
    with pytest.raises(MigrationError, match=r"DB2INTEL\.EXPLAIN_INSTANCE already exist.*003_explain_tables\.sql"):
        runner(db).up()
    assert db.executed() == []


def test_003_cannot_run_before_001(fake_db, monkeypatch):
    monkeypatch.setattr(migrate_module, "MIGRATIONS", (NAME,))
    with pytest.raises(MigrationError):  # DB2INTEL does not exist; ledger insert fails; rolled back
        runner(fake_db).up()
    assert fake_db.committed["objects"] == set() and fake_db.committed["ledger"] == {}


def test_modified_003_after_apply_stops_the_run(db_with_001_002):
    db = db_with_001_002
    runner(db).up()
    db.committed["ledger"][NAME] = "0" * 64
    db.work = copy.deepcopy(db.committed)
    count = len(db.executed())
    with pytest.raises(MigrationError, match="modified after it was applied"):
        runner(db).up()
    assert len(db.executed()) == count


@pytest.mark.parametrize("extra", [
    "CREATE TABLE DB2INST1.EXPLAIN_INSTANCE (X INT);",
    "CREATE TABLE SYSTOOLS.EXPLAIN_INSTANCE (X INT);",
    "CREATE TABLE EXPLAIN_INSTANCE (X INT);",
    "CREATE INDEX DB2INTEL.IX_BAD ON DB2INST1.EMPLOYEE_INFO (EMP_ID);",
    "DROP TABLE DB2INTEL.EXPLAIN_INSTANCE;",
    "CALL SYSPROC.SYSINSTALLOBJECTS('EXPLAIN', 'C', NULL, 'DB2INST1');",
])
def test_tampered_003_is_rejected_before_connecting(sql_copy, fake_db, extra):
    path = sql_copy / NAME
    path.write_text(path.read_text() + "\n" + extra + "\n")
    with pytest.raises(PolicyViolation):
        runner(fake_db, sql_copy).up()
    assert fake_db.calls == []


# ---- teardown safety -----------------------------------------------------------------------
@pytest.fixture(scope="module")
def teardown_drops():
    script = load_teardown(SQL_DIR)
    return [canon(s) for s in script.statements]


def test_teardown_drops_all_eleven_explain_tables_before_the_db2intel_schema(teardown_drops):
    explain = [s for s in teardown_drops if re.match(rf"^DROP TABLE DB2INTEL\.(EXPLAIN_{ID}|OBJECT_METRICS)$", s)]
    assert {s.split(".")[1] for s in explain} == EXPECTED_TABLES
    schema_drop = teardown_drops.index("DROP SCHEMA DB2INTEL RESTRICT")
    assert all(teardown_drops.index(s) < schema_drop for s in explain)


def test_teardown_drops_explain_children_before_parents(teardown_drops):
    pos = {s.split(".")[1]: i for i, s in enumerate(teardown_drops) if s.startswith("DROP TABLE DB2INTEL.")}
    for child, parent in EXPECTED_FK.items():
        assert pos[child] < pos[parent], (child, parent)


def test_teardown_still_only_drops_project_objects_with_the_same_confirmation(teardown_drops):
    assert TEARDOWN_CONFIRMATION == "DROP DB2INTEL AND DB2INTEL_DEMO"
    for s in teardown_drops:
        assert re.match(rf"^DROP (TABLE|VIEW) DB2INTEL(_DEMO)?\.{ID}$|^DROP SCHEMA DB2INTEL(_DEMO)? RESTRICT$", s), s
        assert not re.search(r"\b(DB2INST1|SAMPLE|TESTDB|DATABASE|TABLESPACE|SYSTOOLS)\b", s), s
    assert len(teardown_drops) == 28 and len(set(teardown_drops)) == 28


def test_teardown_after_full_up_removes_everything_and_keeps_db2inst1(fake_db):
    runner(fake_db).up()
    protected = copy.deepcopy((fake_db.committed["protected"], fake_db.committed["rows"]))
    dropped = runner(fake_db).teardown(TEARDOWN_CONFIRMATION)
    assert len(dropped) == 28
    assert fake_db.committed["schemas"] == set() and fake_db.committed["objects"] == set()
    assert (fake_db.committed["protected"], fake_db.committed["rows"]) == protected


def test_teardown_still_works_when_003_was_never_applied(db_with_001_002):
    db = db_with_001_002
    dropped = runner(db).teardown(TEARDOWN_CONFIRMATION)
    assert not any("EXPLAIN" in s or "OBJECT_METRICS" in s for s in dropped)  # skipped via SQLSTATE 42704
    assert len(dropped) == 17
    assert db.committed["schemas"] == set() and db.committed["objects"] == set()


def test_teardown_refuses_when_outside_view_depends_on_an_explain_table(db_with_001_002):
    db = db_with_001_002
    runner(db).up()
    db.committed["foreign_deps"] = {"SYSCAT.TABDEP": [("DB2INST1.V_PLANS", "DB2INTEL.EXPLAIN_STATEMENT")]}
    db.work = copy.deepcopy(db.committed)
    count = len(db.executed())
    with pytest.raises(MigrationError, match=r"teardown refused.*DB2INST1\.V_PLANS"):
        runner(db).teardown(TEARDOWN_CONFIRMATION)
    assert len(db.executed()) == count
    assert "DB2INTEL.EXPLAIN_STATEMENT" in db.committed["objects"]
