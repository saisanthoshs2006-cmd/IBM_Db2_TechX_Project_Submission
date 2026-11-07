"""An offline stand-in for the ibm_db module, modelling only what the G2 integration code uses.

FakeIbmDb answers the it_sql statements from an in-memory model: a package cache, explain
instances written by EXPLAIN_FROM_SECTION (kept in the open unit of work until rollback), the
migration ledger and the protected employee tables. Nothing here connects to anything.

Knobs reproduce the Db2 / ibm_db behaviours G2 is meant to discover, so the tests can show the
integration code handles every outcome:
  inherit_connection_timeout  statements inherit a connection-level timeout (fix B works)
  connection_read_back        what get_option(conn, QUERY_TIMEOUT, 1) returns (Phase 2B: False)
  statement_read_back         override what get_option(stmt, ...) returns
  prepared_call_error         the prepared CALL fails on execute
  rollback_keeps_rows         explain rows survive rollback (a cleanup failure)
  foreign_rows_after_rollback an explain instance without this run's marker is present after rollback
  vary_prepared_call_cost     the prepared CALL writes a different plan
  package_metadata            package cache entries report PACKAGE_SCHEMA/NAME/VERSION_ID and
                              SECTION_NUMBER (default False: all NULL, as Db2 does for dynamic SQL)
"""
from __future__ import annotations

import re

from integration import it_sql as Q

FAKE_ROWS = {
    "EMPLOYEE_INFO": [(1, "SENTINEL-ROW-DATA", "Rao"), (2, "Ben", "Das"), (3, "Cy", "Iyer")],
    "EMPLOYEE_SALARY": [(1, "50000.00"), (2, "60000.00"), (3, "70000.00")],
}
LEDGER = [("001_schema_meta", "4f81" + "0" * 60, "2026-11-06-10.00.00", "DB2INST1", 120),
          ("002_demo_data", "5b97" + "0" * 60, "2026-11-06-10.01.00", "DB2INST1", 300),
          ("003_explain_tables", "456d" + "0" * 60, "2026-11-06-10.02.00", "DB2INST1", 396)]


def like_to_regex(pattern: str) -> re.Pattern:
    out, i = [], 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "!" and i + 1 < len(pattern):
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(".*" if ch == "%" else "." if ch == "_" else re.escape(ch))
        i += 1
    return re.compile("".join(out) + r"\Z", re.S)


class FakeConn:
    def __init__(self):
        self.default_timeout = None
        self.autocommit = 1
        self.closed = False


class FakeStmt:
    def __init__(self, conn, sql, options):
        self.conn, self.sql, self.options = conn, sql, dict(options or {})
        self.rows, self.bound, self.freed = [], {}, False


DYNAMIC_PACKAGE = ("NULLID", "SYSSH200", "")  # the CLI package EXPLAIN reports as the source


class FakeDb2State:
    def __init__(self):
        self.cache = []  # [hexid, cost, executions, text, package schema, package name, version, section]
        self.pending = []  # explain instances in the open unit of work
        self.committed = []  # explain instances that survived (only with rollback_keeps_rows)
        self.clock = 0
        self.audit_rows = 0
        self.sections = {}  # hexid -> the section EXPLAIN writes, whatever the cache reports


class FakeIbmDb:
    SQL_ATTR_QUERY_TIMEOUT = 0
    SQL_ATTR_DEFERRED_PREPARE = 1277
    SQL_AUTOCOMMIT_OFF = 0
    SQL_AUTOCOMMIT_ON = 1
    SQL_PARAM_INPUT = 1
    SQL_PARAM_INPUT_OUTPUT = 2
    SQL_PARAM_OUTPUT = 4

    def __init__(self, **knobs):
        self.state = FakeDb2State()
        self.calls: list[tuple] = []
        self.inherit_connection_timeout = knobs.pop("inherit_connection_timeout", True)
        self.connection_read_back = knobs.pop("connection_read_back", False)
        self.statement_read_back = knobs.pop("statement_read_back", None)
        self.prepared_call_error = knobs.pop("prepared_call_error", False)
        self.rollback_keeps_rows = knobs.pop("rollback_keeps_rows", False)
        self.foreign_rows_after_rollback = knobs.pop("foreign_rows_after_rollback", False)
        self.vary_prepared_call_cost = knobs.pop("vary_prepared_call_cost", False)
        self.connect_error = knobs.pop("connect_error", None)
        self.server = knobs.pop("server", "TESTDB")
        self.limit_timeout = knobs.pop("limit_timeout", 30)
        self.limit_cost = knobs.pop("limit_cost", "50000")  # query.max_estimated_cost
        self.package_metadata = knobs.pop("package_metadata", False)
        self.call_read_back = knobs.pop("call_read_back", None)  # what the EXPLAIN CALL's timeout reads back
        assert not knobs, knobs

    # -- connection ------------------------------------------------------------------------
    def connect(self, conn_str, user, password):
        self.calls.append(("connect",))
        if self.connect_error:
            raise Exception(self.connect_error)
        return FakeConn()

    def autocommit(self, conn, value=None):
        self.calls.append(("autocommit", value))
        conn.autocommit = value

    def close(self, conn):
        self.calls.append(("close",))
        conn.closed = True

    def rollback(self, conn):
        self.calls.append(("rollback",))
        if self.rollback_keeps_rows:
            self.state.committed.extend(self.state.pending)
        if self.foreign_rows_after_rollback and self.state.pending and not self.state.committed:
            self.state.committed.append({**self.state.pending[0], "text": "SELECT 1 FROM SYSIBM.SYSDUMMY1",
                                         "time": "2026-11-07-09.00.00.000000"})
        self.state.pending = []

    def commit(self, conn):
        self.calls.append(("commit",))

    def exec_immediate(self, conn, sql):
        self.calls.append(("exec_immediate", sql))

    def conn_errormsg(self, *a):
        return ""

    def stmt_errormsg(self, *a):
        return ""

    # -- options ---------------------------------------------------------------------------
    def set_option(self, handle, options, kind):
        self.calls.append(("set_option", dict(options), kind))
        if kind == 1:
            handle.default_timeout = options[self.SQL_ATTR_QUERY_TIMEOUT]
        else:
            handle.options.update(options)
        return True

    def get_option(self, handle, attr, kind):
        if kind == 1:
            return self.connection_read_back
        if self.statement_read_back is not None:
            return self.statement_read_back
        if self.call_read_back is not None and handle.sql == Q.CALL_EXPLAIN_SQL:
            return self.call_read_back
        value = handle.options.get(attr)
        if value is None and self.inherit_connection_timeout:
            value = handle.conn.default_timeout
        return 0 if value is None else value

    # -- statements ------------------------------------------------------------------------
    def prepare(self, conn, sql, options=None):
        self.calls.append(("prepare", sql, dict(options or {})))
        if Q.is_allowed_marked(sql):
            n = len(self.state.cache) + 1
            cost = 38_149_348.0 if "CROSS JOIN" in sql else 6.8
            # [hexid, cost, executions, text, package schema, name, version, section number]
            # Db2 12.1.5 reports all four package fields as NULL for dynamic SQL (G2.4 live run).
            hexid = "%064X" % n
            self.state.sections[hexid] = 10 * n
            meta = DYNAMIC_PACKAGE + (10 * n,) if self.package_metadata else (None, None, None, None)
            self.state.cache.append([hexid, cost, 0, sql, *meta])
        return FakeStmt(conn, sql, options)

    def free_stmt(self, stmt):
        stmt.freed = True
        return True

    def num_fields(self, stmt):
        return 1

    def field_name(self, stmt, i):
        return f"C{i}"

    def bind_param(self, stmt, n, value, param_type=None, *rest):
        self.calls.append(("bind_param", n, param_type))
        stmt.bound[n] = value
        return True

    def execute(self, stmt, params=None):
        self.calls.append(("execute", stmt.sql, tuple(params or ())))
        if stmt.sql in Q.PREPARE_ONLY_SQL or Q.is_allowed_marked(stmt.sql):
            raise AssertionError("the fake must never be asked to execute a prepare-only statement")
        if stmt.sql == Q.CALL_EXPLAIN_SQL:
            if self.prepared_call_error:
                raise Exception("SQL0440N simulated failure SQLSTATE=42884")
            self._explain(bytes(stmt.bound[1]), cost=8.5 if self.vary_prepared_call_cost else None)
            return True
        stmt.rows = list(self._answer(stmt.sql, tuple(params or ())))
        return True

    def fetch_tuple(self, stmt):
        return stmt.rows.pop(0) if stmt.rows else False

    def callproc(self, conn, name, params):
        self.calls.append(("callproc", name))
        inst = self._explain(bytes(params[0]))
        stmt = FakeStmt(conn, f"CALL {name}", None)
        return (stmt, *params[:4], "DB2INTEL", inst["requester"], inst["time"], inst["source_name"],
                inst["source_schema"], inst["source_version"])

    # -- the model ---------------------------------------------------------------------------
    def _explain(self, executable_id: bytes, cost=None) -> dict:
        hexid = executable_id.hex().upper()
        entry = next(e for e in self.state.cache if e[0] == hexid)
        self.state.clock += 1
        # EXPLAIN writes the CLI package identity and the real section, whatever the cache reports.
        schema, name, version = DYNAMIC_PACKAGE if entry[4] is None else entry[4:7]
        inst = {"requester": "DB2INST1", "time": "2026-11-07-10.00.00.%06d" % self.state.clock,
                "source_name": name, "source_schema": schema, "source_version": version,
                "sectno": self.state.sections.get(hexid, entry[7]), "text": entry[3],
                "cost": cost if cost is not None else 6.9}
        self.state.pending.append(inst)
        return inst

    def _instances(self):
        return self.state.committed + self.state.pending

    def _by_key(self, key):
        req, etime, sname, sschema, sver = key
        return [i for i in self._instances() if (i["requester"], i["time"], i["source_name"], i["source_schema"],
                                                  i["source_version"]) == (req, etime, sname, sschema, sver)]

    def _answer(self, sql, params):
        insts = self._instances()
        if sql == Q.SERVER_SQL:
            return [(self.server, "DB2INST1")]
        for table, count_sql in Q.EXPLAIN_COUNT_SQL.items():
            if sql == count_sql:
                per = {"EXPLAIN_INSTANCE": 1, "EXPLAIN_STATEMENT": 2, "EXPLAIN_OBJECT": 1, "EXPLAIN_OPERATOR": 2}
                return [(per.get(table, 0) * len(insts),)]
        if sql == Q.AUDIT_COUNT_SQL:
            return [(self.state.audit_rows,)]
        if sql == Q.LEDGER_SQL:
            return list(LEDGER)
        for table, protected_sql in Q.PROTECTED_SQL.items():
            if sql == protected_sql:
                return list(FAKE_ROWS[table])
        A = Q.IT2_SELECTS
        if sql == A["CACHE_LOOKUP (by marker)"]:
            rx = like_to_regex(params[0])
            return [tuple(e) for e in self.state.cache if rx.match(e[3])]
        if sql == A["EXPLAIN_LOCATE (by marker)"]:
            rx = like_to_regex(params[0])
            return [(i["requester"], i["time"], i["source_name"], i["source_schema"], i["source_version"], 1,
                     i["sectno"], i["text"]) for i in insts if rx.match(i["text"])]
        P = Q.IT3_SELECTS
        if sql == P["preflight STMT_CONC"]:
            return [("OFF",)]
        if sql == P["preflight EXPLAIN tables"]:
            return [(t,) for t in Q.EXPLAIN_TABLE_NAMES] + [("APP_SETTING",)]
        if sql == P["preflight LIMITS"]:
            return [("query.max_rows", "500", "INTEGER"), ("query.max_estimated_cost", self.limit_cost, "DECIMAL"),
                    ("query.timeout_seconds", str(self.limit_timeout), "INTEGER")]
        if sql == P["preflight SOURCES"]:
            return [("DB2INTEL_DEMO",)]
        if sql == P["preflight UDF shadowing"]:
            return []
        if sql == P["SYSCAT.INDEXES (index owner)"]:
            return [("DB2INTEL_DEMO", "CUSTOMER")] if params == ("SYSIBM", "SQL261106") else []
        if sql == P["LEFTOVER EXPLAIN_OBJECT (by key)"]:
            return [(2 * len(self._by_key(params)),)]
        if sql == P["LEFTOVER EXPLAIN_OPERATOR (by key)"]:
            return [(2 * len(self._by_key(params)),)]
        if sql == A["LEFTOVER EXPLAIN_STATEMENT (by marker)"]:
            rx = like_to_regex(params[0])
            return [(2 * sum(1 for i in insts if rx.match(i["text"])),)]
        if sql == A["EXPLAIN_INSTANCE count (by key)"]:
            return [(len(self._by_key(params)),)]
        if sql == A["EXPLAIN_STATEMENT (by key)"]:
            return [(lvl, 1, i["sectno"], i["cost"], i["text"]) for i in self._by_key(params) for lvl in ("O", "S")]
        if sql == A["EXPLAIN_OBJECT (by key)"]:
            return [row for i in self._by_key(params)
                    for row in (("DB2INTEL_DEMO", "CUSTOMER", "TA", "O", 1, i["sectno"]),
                                ("SYSIBM", "SQL261106", "IX", "O", 1, i["sectno"]))]
        if sql == A["EXPLAIN_OPERATOR (by key)"]:
            return [row for i in self._by_key(params)
                    for row in ((1, "RETURN", i["cost"], "O", 1, i["sectno"]),
                                (2, "FETCH", i["cost"], "O", 1, i["sectno"]))]
        raise AssertionError(f"the fake has no answer for: {sql}")
