"""Fake Db2 responses for SQL guard tests. Nothing here talks to a database."""
from __future__ import annotations

import sys

import pytest

from db2intel.db.connection import DbError
from db2intel.guard import analysis as A
from db2intel.guard.context import GuardContext, GuardLimits

HEXID = "0100000000000000010000000000000000000000020020261106152041000000"
LIMITS = GuardLimits(max_rows=500, max_estimated_cost=50_000.0, timeout_seconds=30)
CTX = GuardContext(database="TESTDB", session_user="DB2INST1", allowed_schemas=frozenset({"DB2INTEL_DEMO"}), limits=LIMITS)
GOOD_SQL = "SELECT C.COMPANY_NAME FROM DB2INTEL_DEMO.CUSTOMER C WHERE C.CUSTOMER_ID = 42"


class ExplodingDriver:
    """Installed as ibm_db in every guard test: any driver use fails the test."""

    def __getattr__(self, name):
        raise AssertionError(f"a guard test touched the Db2 driver: ibm_db.{name}")


@pytest.fixture(autouse=True)
def no_db_driver(monkeypatch):
    monkeypatch.setitem(sys.modules, "ibm_db", ExplodingDriver())


ROW_TIME = "2026-11-06-15.30.00.123456"  # VARCHAR(EXPLAIN_TIME) of the rows EXPLAIN writes


def key(schema="DB2INTEL", **over):
    """Driver OUT values. Default time "" mirrors ibm_db, which returned None for EXPLAIN_TIME."""
    values = dict(requester="DB2INST1", time="", source_name="SYSSH200", source_schema="NULLID", source_version="")
    values.update(over)
    return A.ExplainKey(schema, values["requester"], values["time"], values["source_name"],
                        values["source_schema"], values["source_version"])


def resolved(**over):
    return key(time=over.pop("time", ROW_TIME), **over)


def _with_statement(rows, n, section=(1, 1)):
    """Allow tests to give short rows; dependent rows default to the section statement (S, STMTNO, SECTNO)."""
    return [tuple(r) + ("S", *section)[len(r) - n:] if len(r) < n + 3 else tuple(r) for r in rows]


class FakeAnalysis:
    """Models prepare-only, the package cache, EXPLAIN_FROM_SECTION and rollback.

    The package cache is a list of entries; lookups filter by the LIKE pattern exactly as Db2
    would (marker substring), so an entry with the same SQL text but no marker never matches.
    EXPLAIN writes rows keyed by (requester, ROW_TIME, source name, schema, version); reads by
    any other key find nothing, so a wrong key in the guard shows up as missing rows.
    Presence is tracked per table, so a rollback can be made to leave rows in any one table
    (rollback_keeps), and other committed rows can be placed in a table (foreign_rows) to show
    that whole-table cleanup counts see them. cleanup_error_on names a table whose post-rollback
    count fails.
    """

    TABLES = ("EXPLAIN_STATEMENT", "EXPLAIN_INSTANCE", "EXPLAIN_OBJECT", "EXPLAIN_OPERATOR")

    def __init__(self, *, columns=1, cost=177.0, executions=0, explain_cost=176.5, extra_cache=(),
                 statements=None, objects=None, operators=None, index_owners=None, explain_key=None,
                 prepare_error=None, explain_error=None, query_error_on=None, rollback_error=None,
                 rollback_keeps_rows=False, cache_text=None, evict_after_explain=False,
                 executions_after_explain=None, hexid_after_explain=None, duplicate=False, missing=False,
                 locate_rows=None, instance_count=1, explain_writes=True, explain_error_after_write=False,
                 rollback_keeps=(), foreign_rows=None, cleanup_error_on=None, cleanup_result=None,
                 section=(1, 1)):  # (STMTNO, SECTNO); real Db2 gave SECTNO 10, 22, 34, 45 (2B run)
        self.__dict__.update(locals())
        del self.__dict__["self"]
        self.calls: list[tuple] = []
        self.prepared: list[str] = []
        self.rollbacks = 0
        self.explained = False
        self.present: set[str] = set()  # tables that currently hold this request's explain rows
        self.foreign_rows = dict(foreign_rows or {})
        self.keeps = set(self.TABLES) if rollback_keeps_rows else set(rollback_keeps)

    @property
    def explain_rows_present(self) -> bool:
        return bool(self.present)

    # -- AnalysisSession --------------------------------------------------------------------
    def prepare_only(self, sql):
        self.calls.append(("prepare_only", sql))
        if self.prepare_error:
            raise self.prepare_error
        self.prepared.append(sql)
        return self.columns

    def explain_from_section(self, hexid, schema):
        self.calls.append(("explain_from_section", hexid, schema))
        if self.explain_error and not self.explain_error_after_write:
            raise self.explain_error
        self.explained = True
        self.present = set(self.TABLES) if self.explain_writes else set()
        if self.explain_error:
            raise self.explain_error
        return self.explain_key if self.explain_key is not None else key(schema)

    def rollback(self):
        self.calls.append(("rollback",))
        self.rollbacks += 1
        if self.rollback_error:
            raise self.rollback_error
        self.present &= self.keeps

    def query(self, sql, params=()):
        params = tuple(params)
        self.calls.append(("query", sql, params))
        if self.query_error_on and self.query_error_on in sql and not self.rollbacks:  # analysis reads only
            raise DbError("simulated failure SQLSTATE=40001", "40001")
        if sql == A.CACHE_LOOKUP_SQL:
            return self._cache(params[0])
        if sql == A.INDEX_TABLE_SQL:
            owners = self.index_owners or {("DB2INTEL_DEMO", "PK_CUSTOMER"): [("DB2INTEL_DEMO", "CUSTOMER")]}
            return owners.get(params, [])
        # Cleanup counts are those sent after rollback (the keyed EXPLAIN_INSTANCE count is the
        # same statement as the instance check in _locate, which runs before any rollback).
        cleanup_table = self._cleanup_table(sql) if self.rollbacks else None
        if cleanup_table and self.cleanup_error_on == cleanup_table:
            raise DbError("simulated cleanup check failure SQLSTATE=40001", "40001")
        if cleanup_table and self.cleanup_result is not None:
            return self.cleanup_result
        if sql == A.EXPLAIN_LEFTOVER_SQL:
            marker = self._marker(params[0])
            text = self.prepared[-1] if self.prepared else ""
            return [(2 if "EXPLAIN_STATEMENT" in self.present and marker in text else 0,)]
        if sql in A.LEFTOVER_ANY_SQL.values():
            table = self._cleanup_table(sql)
            return [((3 if table in self.present else 0) + self.foreign_rows.get(table, 0),)]
        if sql == A.EXPLAIN_LOCATE_SQL:
            if "EXPLAIN_STATEMENT" not in self.present:
                return []
            if self.locate_rows is not None:
                return self.locate_rows
            marker = self._marker(params[0])
            k = resolved()
            return [(k.requester, ROW_TIME, k.source_name, k.source_schema, k.source_version, *self.section)] \
                if marker in self.prepared[-1] else []
        # Remaining reads are by explain key: only the rows EXPLAIN wrote match.
        def rows_exist(table):
            return table in self.present and params == resolved().params()
        if sql == A.EXPLAIN_INSTANCE_SQL:  # also the keyed EXPLAIN_INSTANCE cleanup count
            return [(self.instance_count if rows_exist("EXPLAIN_INSTANCE") else 0,)]
        if sql == A.LEFTOVER_BY_KEY_SQL["EXPLAIN_OBJECT"]:
            return [(2 if rows_exist("EXPLAIN_OBJECT") else 0,)]
        if sql == A.LEFTOVER_BY_KEY_SQL["EXPLAIN_OPERATOR"]:
            return [(3 if rows_exist("EXPLAIN_OPERATOR") else 0,)]
        if sql == A.EXPLAIN_STATEMENT_SQL:
            if not rows_exist("EXPLAIN_STATEMENT"):
                return []
            text = self.prepared[-1]
            return self.statements if self.statements is not None else [
                ("O", *self.section, 0.0, text), ("S", *self.section, self.explain_cost, text)]
        if sql == A.EXPLAIN_OBJECT_SQL:
            if not rows_exist("EXPLAIN_OBJECT"):
                return []
            rows = self.objects if self.objects is not None else [
                ("DB2INTEL_DEMO", "CUSTOMER", "TA"), ("DB2INTEL_DEMO", "PK_CUSTOMER", "IX")]
            return _with_statement(rows, 3, self.section)
        if sql == A.EXPLAIN_OPERATOR_SQL:
            if not rows_exist("EXPLAIN_OPERATOR"):
                return []
            rows = self.operators if self.operators is not None else [
                (1, "RETURN", 7.0), (2, "FETCH", 6.9), (3, "IXSCAN", 0.1)]
            return _with_statement(rows, 3, self.section)
        raise AssertionError(f"unexpected SQL sent by the guard: {sql}")

    @staticmethod
    def _cleanup_table(sql):
        """The table a post-rollback leftover count reads, or None for any other statement."""
        if sql == A.EXPLAIN_LEFTOVER_SQL:
            return "EXPLAIN_STATEMENT"
        for table in A.LEFTOVER_TABLES:
            if sql in (A.LEFTOVER_BY_KEY_SQL[table], A.LEFTOVER_ANY_SQL[table]):
                return table
        return None

    @staticmethod
    def _marker(pattern):
        assert pattern.startswith("%") and pattern.endswith("%")
        return pattern[1:-1].replace("!_", "_").replace("!%", "%").replace("!!", "!")

    def _cache(self, pattern):
        marker = self._marker(pattern)
        after = self.explained
        if self.missing or (after and self.evict_after_explain):
            entries = []
        else:
            text = self.cache_text if self.cache_text is not None else (self.prepared[-1] if self.prepared else "")
            execs = self.executions_after_explain if (after and self.executions_after_explain is not None) else self.executions
            hexid = self.hexid_after_explain if (after and self.hexid_after_explain) else HEXID
            entries = [(hexid, self.cost, execs, text)]
            if self.duplicate:
                entries.append((HEXID[:-2] + "FF", self.cost, 0, text))
        entries += list(self.extra_cache)
        return [e for e in entries if marker in (e[3] or "")]

    # -- inspection -------------------------------------------------------------------------
    def kinds(self):
        return [c[0] for c in self.calls]


# ---- recording ibm_db stand-ins for the real session adapters ------------------------------
_UNSET = object()


class StubDriver:
    SQL_ATTR_DEFERRED_PREPARE = 1277
    SQL_ATTR_QUERY_TIMEOUT = 0

    def __init__(self, rows=(), callproc_result=None, fail=None, num_fields=2, timeout_readback=_UNSET):
        self.calls, self.rows, self.fail, self._num_fields = [], list(rows), fail or {}, num_fields
        self.callproc_result = callproc_result
        self.options: dict[str, dict] = {}  # statement handle -> options given to prepare
        self.timeout_readback = timeout_readback  # if set, get_option returns this instead

    def _maybe_fail(self, name):
        if name in self.fail:
            raise Exception(self.fail[name])

    def prepare(self, conn, sql, options=None):
        self.calls.append(("prepare", sql, options))
        self._maybe_fail("prepare")
        stmt = f"stmt{len(self.calls)}"
        self.options[stmt] = dict(options or {})
        return stmt

    def get_option(self, handle, attr, kind):
        """Statement-level read-back (kind 0) echoes what prepare set, like ibm_db 3.3.0."""
        self.calls.append(("get_option", handle, attr, kind))
        self._maybe_fail("get_option")
        if self.timeout_readback is not _UNSET:
            return self.timeout_readback
        if kind != 0:
            return False  # ibm_db cannot read SQL_ATTR_QUERY_TIMEOUT from a connection handle
        return self.options.get(handle, {}).get(attr, 0)

    def num_fields(self, stmt):
        return self._num_fields

    def field_name(self, stmt, i):
        return f"C{i}"

    def execute(self, stmt, params=None):
        self.calls.append(("execute", stmt))
        self._maybe_fail("execute")
        return True

    def fetch_tuple(self, stmt):
        return self.rows.pop(0) if self.rows else False

    def callproc(self, conn, name, params):
        self.calls.append(("callproc", name, params))
        self._maybe_fail("callproc")
        return self.callproc_result

    def free_stmt(self, stmt):
        self.calls.append(("free_stmt", stmt))

    def stmt_errormsg(self, *a):
        return ""

    def conn_errormsg(self, *a):
        return ""


class StubConnection:
    def __init__(self, driver, rollback_error=None):
        self.driver, self.handle, self.rollback_error = driver, "conn", rollback_error
        self.queries, self.rollbacks = [], 0

    def query(self, sql, params=()):
        self.queries.append((sql, params))
        return []

    def rollback(self):
        self.rollbacks += 1
        if self.rollback_error:
            raise self.rollback_error
