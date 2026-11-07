"""Thin transactional wrapper around the native ibm_db driver."""
from __future__ import annotations

import re
from typing import Any, Protocol, Sequence

from db2intel.config import Db2Settings

_SQLSTATE_RE = re.compile(r"SQLSTATE=([0-9A-Z]{5})")


class DbError(Exception):
    """A Db2 error with its SQLSTATE (if the driver reported one)."""

    def __init__(self, message: str, sqlstate: str | None = None):
        super().__init__(message)
        self.sqlstate = sqlstate

    @classmethod
    def from_driver(cls, exc: Exception, detail: str = "") -> "DbError":
        text = detail or str(exc)
        match = _SQLSTATE_RE.search(text) or _SQLSTATE_RE.search(str(exc))
        return cls(text.strip(), match.group(1) if match else None)


class Database(Protocol):
    """The operations the migration runner needs. Implemented by Db2Connection and test fakes."""

    def execute(self, sql: str, params: Sequence[Any] = ()) -> None: ...
    def query(self, sql: str, params: Sequence[Any] = ()) -> list[tuple]: ...
    def commit(self) -> None: ...
    def rollback(self) -> None: ...
    def close(self) -> None: ...


_SQLCODE_RE = re.compile(r"\b(SQL\d{4,5}N)\b")
_CONNECT_HINTS = {
    "SQL30082N": "authentication failed: check DB2_USER and DB2_PASSWORD in .env",
    "SQL30081N": "communication error: check that Db2 is running and DB2_HOST / DB2_PORT are correct",
    "SQL1013N": "database not found: check DB2_DATABASE",
    "SQL1031N": "database directory not found: check DB2_DATABASE",
    "SQL1060N": "the user lacks CONNECT privilege on this database",
}


def _driver_message(exc: Exception, errormsg) -> str:
    """Best available driver message; a failing errormsg() never hides the original error."""
    try:
        detail = errormsg() or ""
    except Exception:
        detail = ""
    return detail or str(exc) or type(exc).__name__


def _redact(text: str, *secrets: str) -> str:
    # Longest first, so the full connection string is masked before the password inside it.
    for secret in sorted(filter(None, secrets), key=len, reverse=True):
        text = text.replace(secret, "***")
    return text


class Db2Connection:
    """ibm_db connection with autocommit OFF: nothing is persisted until commit()."""

    def __init__(self, settings: Db2Settings):
        # Validate configuration first: a missing or malformed setting is a ConfigError and
        # must surface as such, before the driver is imported or contacted.
        conn_str = settings.connection_string()

        import ibm_db  # imported lazily so offline commands and tests do not need the driver

        self._ibm_db = ibm_db
        try:
            self._conn = ibm_db.connect(conn_str, "", "")
        except Exception as exc:  # ibm_db raises plain Exception
            raw = _redact(_driver_message(exc, ibm_db.conn_errormsg), settings.password, conn_str)
            code = _SQLCODE_RE.search(raw)
            hint = _CONNECT_HINTS.get(code.group(1)) if code else None
            message = f"cannot connect to {settings.describe()}: {raw.strip()}"
            if hint:
                message += f" ({hint})"
            state = _SQLSTATE_RE.search(raw)
            raise DbError(message, state.group(1) if state else None) from None
        try:
            ibm_db.autocommit(self._conn, ibm_db.SQL_AUTOCOMMIT_OFF)
        except Exception as exc:
            raw = _redact(_driver_message(exc, ibm_db.conn_errormsg), settings.password, conn_str)
            try:
                ibm_db.close(self._conn)
            except Exception:
                pass
            raise DbError(f"connected to {settings.describe()} but could not disable autocommit: {raw}") from None

    @property
    def driver(self):
        """The ibm_db module, for callers that need driver features beyond this wrapper."""
        return self._ibm_db

    @property
    def handle(self):
        """The raw ibm_db connection handle (autocommit is OFF)."""
        return self._conn

    def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        db = self._ibm_db
        try:
            if params:
                stmt = db.prepare(self._conn, sql)
                db.execute(stmt, tuple(params))
            else:
                db.exec_immediate(self._conn, sql)
        except Exception as exc:
            raise DbError.from_driver(exc, db.stmt_errormsg() or db.conn_errormsg()) from None

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[tuple]:
        db = self._ibm_db
        try:
            stmt = db.prepare(self._conn, sql)
            db.execute(stmt, tuple(params))
            rows, row = [], db.fetch_tuple(stmt)
            while row:
                rows.append(tuple(row))
                row = db.fetch_tuple(stmt)
            return rows
        except Exception as exc:
            raise DbError.from_driver(exc, db.stmt_errormsg() or db.conn_errormsg()) from None

    def commit(self) -> None:
        try:
            self._ibm_db.commit(self._conn)
        except Exception as exc:
            raise DbError.from_driver(exc, self._ibm_db.conn_errormsg()) from None

    def rollback(self) -> None:
        # If the connection is already gone, Db2 has rolled the unit of work back itself.
        try:
            self._ibm_db.rollback(self._conn)
        except Exception as exc:
            raise DbError.from_driver(exc, self._ibm_db.conn_errormsg()) from None

    def close(self) -> None:
        try:
            self._ibm_db.rollback(self._conn)  # never leave an open unit of work behind
        except Exception:
            pass  # a dead connection has no open unit of work; Db2 already rolled it back
        finally:
            try:
                self._ibm_db.close(self._conn)
            except Exception:
                pass
