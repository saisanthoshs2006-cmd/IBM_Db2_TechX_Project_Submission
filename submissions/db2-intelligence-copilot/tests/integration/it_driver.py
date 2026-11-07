"""A stand-in for the ibm_db module that lets through only what the G2 run is approved to do.

install() replaces sys.modules["ibm_db"] in the current process, so Db2Connection and the guard
sessions (which import ibm_db lazily) get this proxy. Every refusal happens before the real
driver is called.

  prepare     only statements listed in it_sql (exact text) or the marked PK lookup; every
              prepared statement gets SQL_ATTR_QUERY_TIMEOUT, and the value must read back from
              the statement handle, otherwise the statement is freed and the call refused
  execute     only statements prepared from it_sql.EXECUTABLE_SQL (the SELECTs and the CALL);
              the marked PK lookup and the IT1 probe can be prepared, never executed
  bind_param  only on the prepared CALL; inputs must be (id, 'M', NULL, -1, 'DB2INTEL'),
              parameters 6-10 outputs
  callproc    only SYSPROC.EXPLAIN_FROM_SECTION with the same inputs
  set_option  only SQL_ATTR_QUERY_TIMEOUT, 1..120 seconds
  commit, exec_immediate, autocommit ON and every other driver function are refused
"""
from __future__ import annotations

import sys

from integration import it_sql as Q

MAX_TIMEOUT_S = 120


class DriverRefused(Exception):
    """The integration run tried something it is not approved to do."""


def _explain_inputs_ok(values) -> bool:
    if len(values) < 5:
        return False
    hexid, mode, src, level, schema = values[:5]
    return (isinstance(hexid, (bytes, bytearray)) and 1 <= len(hexid) <= 64 and mode == "M" and src is None
            and level == -1 and schema == Q.EXPLAIN_SCHEMA)


class GuardedDriver:
    _PASS = frozenset({"connect", "close", "rollback", "num_fields", "field_name", "fetch_tuple",
                       "stmt_errormsg", "conn_errormsg", "get_option"})

    def __init__(self, real, timeout_s: int):
        if not hasattr(real, "SQL_ATTR_QUERY_TIMEOUT"):
            raise DriverRefused("this ibm_db has no SQL_ATTR_QUERY_TIMEOUT")
        if type(timeout_s) is not int or not 1 <= timeout_s <= MAX_TIMEOUT_S:
            raise DriverRefused(f"query timeout must be 1..{MAX_TIMEOUT_S} seconds")
        self._real, self.timeout = real, timeout_s
        self._stmts: dict[int, tuple[object, str]] = {}  # id(stmt) -> (stmt, sql)
        self._bound: dict[int, dict[int, object]] = {}  # CALL statement -> bound input values
        self.log: list[tuple[str, str]] = []  # (operation, sql or name), for the results file

    def __getattr__(self, name):
        if name.isupper() or name in self._PASS:
            return getattr(self._real, name)
        raise DriverRefused(f"ibm_db.{name} is not allowed in the integration run")

    # -- refused outright ------------------------------------------------------------------
    def commit(self, *args):
        raise DriverRefused("commit is never allowed in the integration run")

    def exec_immediate(self, *args):
        raise DriverRefused("exec_immediate is never allowed in the integration run")

    def autocommit(self, conn, value=None):
        if value != self._real.SQL_AUTOCOMMIT_OFF:
            raise DriverRefused("autocommit may only be switched OFF")
        return self._real.autocommit(conn, value)

    def set_option(self, handle, options, kind):
        attr = self._real.SQL_ATTR_QUERY_TIMEOUT
        if not isinstance(options, dict) or set(options) != {attr}:
            raise DriverRefused("set_option may only set SQL_ATTR_QUERY_TIMEOUT")
        value = options[attr]
        if type(value) is not int or not 1 <= value <= MAX_TIMEOUT_S:
            raise DriverRefused(f"query timeout must be 1..{MAX_TIMEOUT_S} seconds")
        self.log.append(("set_option", f"QUERY_TIMEOUT={value} kind={kind}"))
        return self._real.set_option(handle, options, kind)

    # -- prepare -----------------------------------------------------------------------------
    @staticmethod
    def allowed_to_prepare(sql) -> bool:
        return isinstance(sql, str) and (sql in Q.EXECUTABLE_SQL or sql in Q.PREPARE_ONLY_SQL
                                         or Q.MARKED_PK_LOOKUP_RE.match(sql) is not None)

    def prepare(self, conn, sql, options=None):
        return self._prepare(conn, sql, options, with_timeout=True)

    def prepare_without_timeout(self, conn, sql):
        """IT1 only: prepare the IT1 probe without a statement timeout, to see whether the
        connection-level default is inherited. The statement can never be executed."""
        if sql != Q.IT1_PROBE_SQL:
            raise DriverRefused("only the IT1 probe may be prepared without a statement timeout")
        return self._prepare(conn, sql, None, with_timeout=False)

    def _prepare(self, conn, sql, options, with_timeout: bool):
        if not self.allowed_to_prepare(sql):
            raise DriverRefused("prepare refused: statement is not on the G2 allow-list")
        db = self._real
        opts = dict(options or {})
        if with_timeout:
            opts[db.SQL_ATTR_QUERY_TIMEOUT] = self.timeout
        stmt = db.prepare(conn, sql, opts) if opts else db.prepare(conn, sql)
        if not stmt:
            return stmt
        if with_timeout:
            got = db.get_option(stmt, db.SQL_ATTR_QUERY_TIMEOUT, 0)
            if isinstance(got, bool) or got != self.timeout:
                try:
                    db.free_stmt(stmt)
                finally:
                    raise DriverRefused(f"statement query timeout reads back {got!r}, expected {self.timeout}")
        self._stmts[id(stmt)] = (stmt, sql)
        self.log.append(("prepare", sql))
        return stmt

    def _sql_of(self, stmt) -> str | None:
        entry = self._stmts.get(id(stmt))
        return entry[1] if entry is not None and entry[0] is stmt else None

    # -- execution ---------------------------------------------------------------------------
    def bind_param(self, stmt, param_no, value, param_type=None, *rest):
        if self._sql_of(stmt) != Q.CALL_EXPLAIN_SQL:
            raise DriverRefused("bind_param is only allowed on the prepared EXPLAIN_FROM_SECTION CALL")
        if type(param_no) is not int or not 1 <= param_no <= 10:
            raise DriverRefused("bind_param: parameter number out of range")
        if param_no <= 4 and param_type not in (None, self._real.SQL_PARAM_INPUT):
            raise DriverRefused("bind_param: parameters 1-4 must be inputs")
        if param_no == 5 and param_type not in (None, self._real.SQL_PARAM_INPUT, self._real.SQL_PARAM_INPUT_OUTPUT):
            raise DriverRefused("bind_param: parameter 5 (explain schema) must be an input or INOUT")
        if param_no > 5 and param_type != self._real.SQL_PARAM_OUTPUT:
            raise DriverRefused("bind_param: parameters 6-10 must be outputs")
        self._bound.setdefault(id(stmt), {})[param_no] = value
        args = (stmt, param_no, value) + (() if param_type is None else (param_type,)) + rest
        return self._real.bind_param(*args)

    def execute(self, stmt, params=None):
        sql = self._sql_of(stmt)
        if sql is None or sql not in Q.EXECUTABLE_SQL:
            raise DriverRefused("execute refused: only allow-listed SELECTs and the EXPLAIN CALL may run")
        if sql == Q.CALL_EXPLAIN_SQL:
            bound = self._bound.get(id(stmt), {})
            if params is not None or sorted(bound) != list(range(1, 11)) or not _explain_inputs_ok(
                    [bound[i] for i in range(1, 6)]):
                raise DriverRefused("execute refused: the EXPLAIN CALL needs all 10 parameters bound with "
                                    "inputs (id, 'M', NULL, -1, 'DB2INTEL')")
        elif not Q.is_plain_select(sql):
            raise DriverRefused("execute refused: not a plain SELECT")
        self.log.append(("execute", sql))
        return self._real.execute(stmt) if params is None else self._real.execute(stmt, params)

    def callproc(self, conn, name, params):
        if name != Q.EXPLAIN_PROC or not isinstance(params, tuple) or len(params) != 10 or not _explain_inputs_ok(params):
            raise DriverRefused(f"callproc refused: only {Q.EXPLAIN_PROC} with inputs (id, 'M', NULL, -1, 'DB2INTEL')")
        self.log.append(("callproc", name))
        return self._real.callproc(conn, name, params)

    def free_stmt(self, stmt):
        self._stmts.pop(id(stmt), None)
        self._bound.pop(id(stmt), None)
        return self._real.free_stmt(stmt)


def install(timeout_s: int, real=None) -> GuardedDriver:
    """Replace ibm_db in this process with a GuardedDriver around the real module."""
    current = sys.modules.get("ibm_db")
    if isinstance(current, GuardedDriver):
        raise DriverRefused("the guarded driver is already installed")
    if real is None:
        import ibm_db as real  # noqa: PLC0415 - imported only when an integration run starts
    driver = GuardedDriver(real, timeout_s)
    sys.modules["ibm_db"] = driver
    return driver
