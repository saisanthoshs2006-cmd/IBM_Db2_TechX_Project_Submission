"""IT1 (gate G2.2): can a query timeout be set and read back, and where?

Nothing is executed apart from the read-only server identity SELECT. The probe statement
SELECT 1 FROM SYSIBM.SYSDUMMY1 is only prepared. Recorded facts:
  statement_read_back        timeout set on prepare, read back from the statement (must equal it)
  statement_default          a statement prepared without a timeout, before any connection default
  connection_set_returned    set_option on the connection handle
  connection_read_back       get_option on the connection handle (Phase 2B: not readable)
  inherited_read_back        a statement prepared without a timeout after the connection default
Only statement_read_back is asserted; the others are evidence for the fix-A/fix-B decision.
"""
from __future__ import annotations

import pytest

from integration import it_harness as H
from integration import it_sql as Q

pytestmark = pytest.mark.db2

_STATEMENT, _CONNECTION = 0, 1


def _read(fn, *args):
    try:
        return repr(fn(*args))
    except Exception as exc:
        return f"raised {type(exc).__name__}"


def test_it1_query_timeout_read_back():
    run = H.supervised_run("it1")
    connection_default = run.timeout + 7 if run.timeout <= 113 else run.timeout - 7  # distinguishable
    with H.recording(run, {"query_timeout": run.timeout, "connection_default": connection_default}) as facts:
        driver, conn = H.connect(run.timeout)
        try:
            attr = driver.SQL_ATTR_QUERY_TIMEOUT
            stmt = driver.prepare(conn.handle, Q.IT1_PROBE_SQL)  # the driver verifies the read-back
            facts["statement_read_back"] = driver.get_option(stmt, attr, _STATEMENT)
            driver.free_stmt(stmt)

            stmt = driver.prepare_without_timeout(conn.handle, Q.IT1_PROBE_SQL)
            facts["statement_default"] = _read(driver.get_option, stmt, attr, _STATEMENT)
            driver.free_stmt(stmt)

            facts["connection_set_returned"] = _read(driver.set_option, conn.handle, {attr: connection_default}, _CONNECTION)
            facts["connection_read_back"] = _read(driver.get_option, conn.handle, attr, _CONNECTION)

            stmt = driver.prepare_without_timeout(conn.handle, Q.IT1_PROBE_SQL)
            facts["inherited_read_back"] = _read(driver.get_option, stmt, attr, _STATEMENT)
            driver.free_stmt(stmt)
            facts["driver_log"] = driver.log
        finally:
            conn.close()
        assert facts["statement_read_back"] == run.timeout
        assert [op for op, _ in facts["driver_log"] if op in ("execute", "callproc")] == ["execute"]  # identity only
