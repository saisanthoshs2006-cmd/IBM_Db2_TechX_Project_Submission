"""ibm_db implementations of the analysis and execution sessions.

Neither session has a commit method. Driver behaviour marked "Phase 2B" is verified against
TESTDB only after separate approval; until then these classes are exercised with stub drivers.
"""
from __future__ import annotations

from typing import Any, Sequence

from db2intel.db.connection import Db2Connection, DbError
from db2intel.guard.analysis import _HEX_ID_RE, ExplainKey
from db2intel.guard.execution import QueryResult

_DEFERRED_PREPARE_OFF = 0
_STATEMENT_OPTION = 0  # ibm_db.get_option type for a statement handle (1 = connection)
# Pin function resolution to the built-in schemas for the life of the connection, so no
# user-defined function created after preflight can shadow an allow-listed built-in.
# Phase 2C: written and unit-tested offline; verified against Db2 only at gate G2/G5.
SET_SYSTEM_PATH_SQL = "SET CURRENT PATH = SYSTEM PATH"
CURRENT_PATH_SQL = "SELECT CURRENT PATH FROM SYSIBM.SYSDUMMY1"
SYSTEM_PATH_SCHEMAS = frozenset({"SYSIBM", "SYSFUN", "SYSPROC", "SYSIBMADM"})
# Initial values size the OUT buffers; the timestamp placeholder matches the 2026-11-06 trial.
_EXPLAIN_OUT_PLACEHOLDERS = ("", "2000-01-01-00.00.00.000000", "", "", "")


def _driver_error(db, exc: Exception, what: str) -> DbError:
    try:
        detail = db.stmt_errormsg() or db.conn_errormsg() or ""
    except Exception:
        detail = ""
    return DbError.from_driver(exc, f"{what}: {detail or exc}")


class Db2AnalysisSession:
    """Prepares user SQL without executing it, reads the package cache and explain tables."""

    def __init__(self, connection: Db2Connection):
        self._conn = connection
        self._db = connection.driver
        self._handle = connection.handle
        self._held: list = []  # prepared statements kept open until rollback

    def prepare_only(self, sql: str) -> int:
        db = self._db
        try:
            stmt = db.prepare(self._handle, sql, {db.SQL_ATTR_DEFERRED_PREPARE: _DEFERRED_PREPARE_OFF})
            if not stmt:
                raise RuntimeError("prepare returned no statement")
            self._held.append(stmt)
            columns = db.num_fields(stmt)
        except Exception as exc:
            raise _driver_error(db, exc, "prepare failed") from None
        if columns is False or columns is None:
            raise DbError("prepare failed: the driver could not describe the result")
        return int(columns)

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[tuple]:
        return self._conn.query(sql, params)

    def pin_system_path(self) -> tuple[str, ...]:
        """SET CURRENT PATH = SYSTEM PATH (a special register; writes nothing), then read it back.

        Uses prepare/execute, never exec_immediate. Raises DbError unless every schema on the
        path is a built-in system schema.
        """
        db = self._db
        stmt = None
        try:
            stmt = db.prepare(self._handle, SET_SYSTEM_PATH_SQL)
            if not stmt:
                raise RuntimeError("prepare returned no statement")
            db.execute(stmt)
        except Exception as exc:
            raise _driver_error(db, exc, "could not set CURRENT PATH") from None
        finally:
            if stmt:
                try:
                    db.free_stmt(stmt)
                except Exception:
                    pass
        rows = self._conn.query(CURRENT_PATH_SQL)
        if len(rows) != 1 or not rows[0] or not isinstance(rows[0][0], str):
            raise DbError("could not read CURRENT PATH back")
        schemas = tuple(part.strip().strip('"').strip() for part in rows[0][0].split(","))
        if not schemas or any(s not in SYSTEM_PATH_SCHEMAS for s in schemas):
            raise DbError(f"CURRENT PATH is not the system path: {rows[0][0]!r}")
        return schemas

    def explain_from_section(self, executable_id_hex: str, explain_schema: str) -> ExplainKey:
        hexid = executable_id_hex.strip().upper()
        if not _HEX_ID_RE.match(hexid):
            raise DbError("invalid executable id")
        db = self._db
        params = (bytes.fromhex(hexid), "M", None, -1, explain_schema, *_EXPLAIN_OUT_PLACEHOLDERS)
        try:
            result = db.callproc(self._handle, "SYSPROC.EXPLAIN_FROM_SECTION", params)
        except Exception as exc:
            raise _driver_error(db, exc, "EXPLAIN_FROM_SECTION failed") from None
        if not isinstance(result, tuple) or len(result) != 1 + len(params):
            raise DbError("EXPLAIN_FROM_SECTION returned an unexpected result")
        stmt, *values = result
        try:
            db.free_stmt(stmt)
        except Exception:
            pass
        schema, requester, time, source_name, source_schema, source_version = (
            "" if v is None else str(v).rstrip() for v in values[4:10]
        )
        return ExplainKey(schema, requester, time, source_name, source_schema, source_version)

    def rollback(self) -> None:
        try:
            self._conn.rollback()
        finally:
            held, self._held = self._held, []
            for stmt in held:
                try:
                    self._db.free_stmt(stmt)
                except Exception:
                    pass


class Db2ExecutionSession:
    """Runs an approved query with a statement timeout and a hard fetch cap."""

    def __init__(self, connection: Db2Connection):
        self._conn = connection
        self._db = connection.driver
        self._handle = connection.handle

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[tuple]:
        return self._conn.query(sql, params)

    def execute_capped(self, sql: str, max_rows: int, timeout_seconds: int) -> QueryResult:
        db = self._db
        timeout_attr = getattr(db, "SQL_ATTR_QUERY_TIMEOUT", None)
        if timeout_attr is None:
            raise DbError("the Db2 driver does not support statement timeouts; refusing to execute")
        if not 1 <= timeout_seconds <= 300 or not 1 <= max_rows <= 100_000:
            raise DbError("invalid execution limits")
        stmt = None
        try:
            stmt = db.prepare(self._handle, sql, {timeout_attr: timeout_seconds})
            if not stmt:
                raise RuntimeError("prepare returned no statement")
            # Read the timeout back from the statement handle. (On a connection handle ibm_db
            # 3.3.0 cannot read it back, and set_option reports success even when the CLI
            # rejected the value, so only the statement-level read-back is trusted.)
            confirmed = db.get_option(stmt, timeout_attr, _STATEMENT_OPTION)
            if isinstance(confirmed, bool) or not isinstance(confirmed, int) or confirmed != timeout_seconds:
                raise DbError(f"the statement timeout could not be confirmed (read back {confirmed!r}); refusing to execute")
            db.execute(stmt)
            ncols = db.num_fields(stmt)
            columns = tuple(db.field_name(stmt, i) for i in range(ncols))
            rows: list[tuple] = []
            truncated = False
            row = db.fetch_tuple(stmt)
            while row:
                if len(rows) >= max_rows:
                    truncated = True
                    break
                rows.append(tuple(row))
                row = db.fetch_tuple(stmt)
            return QueryResult(columns, tuple(rows), truncated)
        except DbError:
            raise
        except Exception as exc:
            raise _driver_error(db, exc, "query failed") from None
        finally:
            if stmt:
                try:
                    db.free_stmt(stmt)
                except Exception:
                    pass

    def rollback(self) -> None:
        self._conn.rollback()
