"""Shared fixtures. FakeDb simulates the Db2 behaviour the runner relies on, with no real database."""
from __future__ import annotations

import copy
import re
import shutil
from pathlib import Path

import pytest

from db2intel.db.connection import DbError

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SQL_DIR = PROJECT_ROOT / "sql"


class FakeDb:
    """In-memory model of: schemas, tables, the migration ledger and the protected DB2INST1 tables.

    Semantics mirrored from Db2 with autocommit OFF:
      * all writes go to an open unit of work; commit() publishes it, rollback() discards it
      * DROP of a missing object raises SQLSTATE 42704
      * DROP SCHEMA ... RESTRICT fails (42893) while the schema still contains objects
    """

    def __init__(self, server: str = "TESTDB"):
        self.server = server
        self.committed = {
            "schemas": set(),
            "objects": set(),  # "SCHEMA.NAME" for tables and views
            "ledger": {},
            "protected": [("EMPLOYEE_INFO", "T", "2026-01-01 00:00:00"), ("EMPLOYEE_SALARY", "T", "2026-01-01 00:00:00")],
            "rows": {
                "EMPLOYEE_INFO": [(1, "Ava", "Rao", "IT", "2020-01-01"), (2, "Ben", "Das", "HR", "2021-02-02"),
                                  (3, "Cy", "Iyer", "OPS", "2022-03-03")],
                "EMPLOYEE_SALARY": [(1, "50000.00", "500.00"), (2, "60000.00", "600.00"), (3, "70000.00", "700.00")],
            },
            "indexes": [("SYSIBM", "SQL260101000000000", "EMPLOYEE_INFO", "2026-01-01 00:00:00")],
            "foreign_deps": {},  # e.g. {"SYSCAT.TABDEP": [("DB2INST1.V", "DB2INTEL_DEMO.CUSTOMER")]}
        }
        self.work = copy.deepcopy(self.committed)
        self.calls: list[tuple[str, str]] = []  # (kind, sql) in order
        self.fail_on: list[tuple[re.Pattern, str]] = []
        self.on_execute = None  # optional hook(fake_db, sql) to simulate side effects
        self.commits = 0
        self.rollbacks = 0

    # --- helpers for tests ---------------------------------------------------
    def fail_when(self, pattern: str, sqlstate: str = "42601") -> None:
        self.fail_on.append((re.compile(pattern, re.I | re.S), sqlstate))

    def executed(self) -> list[str]:
        return [sql for kind, sql in self.calls if kind == "execute"]

    # --- Database protocol ---------------------------------------------------
    def execute(self, sql, params=()):
        self.calls.append(("execute", sql))
        for pattern, state in self.fail_on:
            if pattern.search(sql):
                raise DbError(f"simulated failure SQLSTATE={state}", state)
        canon = " ".join(sql.upper().split())
        w = self.work
        if m := re.match(r"CREATE SCHEMA (\w+)$", canon):
            if m.group(1) in w["schemas"]:
                raise DbError("SQL0601N exists", "42710")
            w["schemas"].add(m.group(1))
        elif m := re.match(r"CREATE (?:TABLE|VIEW) (\w+)\.(\w+)", canon):
            if m.group(1) not in w["schemas"]:
                w["schemas"].add(m.group(1))  # Db2 creates the schema implicitly
            w["objects"].add(f"{m.group(1)}.{m.group(2)}")
        elif canon.startswith("INSERT INTO DB2INTEL.SCHEMA_MIGRATION"):
            if "DB2INTEL.SCHEMA_MIGRATION" not in w["objects"]:
                raise DbError("SQL0204N undefined name SQLSTATE=42704", "42704")
            w["ledger"][params[0]] = params[1]
        elif m := re.match(r"DROP (?:TABLE|VIEW) (\w+\.\w+)$", canon):
            if m.group(1) not in w["objects"]:
                raise DbError("SQL0204N undefined name SQLSTATE=42704", "42704")
            w["objects"].discard(m.group(1))
            if m.group(1) == "DB2INTEL.SCHEMA_MIGRATION":
                w["ledger"] = {}
        elif m := re.match(r"DROP SCHEMA (\w+) RESTRICT$", canon):
            name = m.group(1)
            if name not in w["schemas"]:
                raise DbError("SQL0204N undefined name SQLSTATE=42704", "42704")
            if any(obj.startswith(name + ".") for obj in w["objects"]):
                raise DbError("SQL0478N schema not empty SQLSTATE=42893", "42893")
            w["schemas"].discard(name)
        if self.on_execute:
            self.on_execute(self, sql)

    def query(self, sql, params=()):
        self.calls.append(("query", sql))
        canon = " ".join(sql.upper().split())
        w = self.work
        if "CURRENT SERVER" in canon:
            return [(self.server,)]
        if "FROM SYSCAT.SCHEMATA" in canon:
            return [(s,) for s in sorted(w["schemas"]) if s in params]
        if "TABNAME = 'SCHEMA_MIGRATION'" in canon:
            return [(1 if "DB2INTEL.SCHEMA_MIGRATION" in w["objects"] else 0,)]
        if canon.startswith("SELECT MIGRATION_ID"):
            return sorted(w["ledger"].items())
        if "FROM SYSCAT.TABLES WHERE TABSCHEMA = ?" in canon:
            return list(w["protected"])
        if "FROM SYSCAT.INDEXES WHERE TABSCHEMA = ?" in canon:
            return list(w["indexes"])
        if m := re.match(r"SELECT \* FROM DB2INST1\.(\w+)$", canon):
            return list(w["rows"][m.group(1)])
        for catalog in ("SYSCAT.TABDEP", "SYSCAT.TRIGDEP", "SYSCAT.ROUTINEDEP", "SYSCAT.REFERENCES"):
            if f"FROM {catalog} " in canon:
                return list(w["foreign_deps"].get(catalog, []))
        if "FROM SYSCAT.TABLES WHERE TABSCHEMA IN" in canon:
            return [tuple(o.split(".")) for o in sorted(w["objects"]) if o.split(".")[0] in params]
        raise AssertionError(f"FakeDb received an unexpected query: {sql}")

    def commit(self):
        self.commits += 1
        self.committed = copy.deepcopy(self.work)

    def rollback(self):
        self.rollbacks += 1
        self.work = copy.deepcopy(self.committed)

    def close(self):
        self.rollback()


@pytest.fixture
def fake_db():
    return FakeDb()


@pytest.fixture
def sql_copy(tmp_path):
    """A private copy of sql/ that a test may tamper with."""
    target = tmp_path / "sql"
    shutil.copytree(SQL_DIR, target)
    return target
