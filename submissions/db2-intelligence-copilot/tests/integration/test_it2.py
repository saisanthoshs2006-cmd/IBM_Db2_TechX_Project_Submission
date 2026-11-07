"""IT2 (gate G2.3): can EXPLAIN_FROM_SECTION be bounded by a Db2-side query timeout?

One marked PK lookup is prepared (never executed) and found in the package cache by its marker.
Its section is then explained three ways, all in one unit of work that is rolled back:
  path 1  production code: Db2AnalysisSession.explain_from_section (ibm_db.callproc, no timeout)
  path 2  fix A: a prepared CALL with a statement timeout that must read back before execution.
          ibm_db 3.3.0 returns OUT values only from callproc (ibm_db.c, ibm_db_callproc); execute()
          returns True, so this path's instance is located through the marker alone.
  path 3  fix B: a connection-level timeout, then callproc; the timeout is read back from the
          statement handle callproc returns (did it inherit the connection default?)
The three explain instances are located by marker and compared (statement, object and operator
rows, everything except EXPLAIN_TIME). Then ROLLBACK; on the same connection the marker count
and all 11 explain tables must be 0. The supervisor's post-snapshot checks again from a new
connection. Nothing commits and nothing is cleaned up automatically.
"""
from __future__ import annotations

import pytest

from db2intel.guard import analysis as A
from db2intel.guard.sessions import _EXPLAIN_OUT_PLACEHOLDERS, Db2AnalysisSession
from integration import it_harness as H
from integration import it_sql as Q

pytestmark = pytest.mark.db2

_STATEMENT, _CONNECTION = 0, 1


def _key(row) -> tuple:
    req, etime, sname, sschema, sver = (str(v).strip() for v in row[:5])
    return req, etime, sname, sschema, sver


def _instance(session, key: tuple) -> dict:
    """Everything about one explain instance except its EXPLAIN_TIME."""
    norm = lambda rows: sorted(tuple(str(v).strip() for v in r) for r in rows)  # noqa: E731
    return {
        "instances": session.query(A.EXPLAIN_INSTANCE_SQL, key)[0][0],
        "statement": norm(session.query(A.EXPLAIN_STATEMENT_SQL, key)),
        "object": norm(session.query(A.EXPLAIN_OBJECT_SQL, key)),
        "operator": norm(session.query(A.EXPLAIN_OPERATOR_SQL, key)),
    }


def test_it2_explain_from_section_paths():
    run = H.supervised_run("it2")
    connection_default = run.timeout + 7 if run.timeout <= 113 else run.timeout - 7
    with H.recording(run, {"query_timeout": run.timeout, "connection_default": connection_default}) as facts:
        driver, conn = H.connect(run.timeout)
        session = Db2AnalysisSession(conn)
        attr = driver.SQL_ATTR_QUERY_TIMEOUT
        marker = A.marker_for(A.new_request_id())
        pattern = (A.like_pattern(marker),)
        try:
            text = A.with_marker(Q.PK_LOOKUP, marker)
            session.prepare_only(text)
            cache = session.query(A.CACHE_LOOKUP_SQL, pattern)
            facts["cache_entries"] = len(cache)
            assert len(cache) == 1 and cache[0][2] == 0 and cache[0][3] == text, "one unexecuted cache entry"
            hexid = str(cache[0][0]).strip().upper()
            inputs = (bytes.fromhex(hexid), "M", None, -1, Q.EXPLAIN_SCHEMA)

            # path 1: production callproc
            k1 = session.explain_from_section(hexid, Q.EXPLAIN_SCHEMA)
            facts["path1_out_time"] = k1.time

            # path 2: prepared CALL with a statement timeout
            stmt = driver.prepare(conn.handle, Q.CALL_EXPLAIN_SQL)  # timeout verified by the driver
            facts["path2_timeout_read_back"] = driver.get_option(stmt, attr, _STATEMENT)
            for n, value in enumerate(inputs, 1):  # parameter 5 (explain schema) is INOUT
                driver.bind_param(stmt, n, value, driver.SQL_PARAM_INPUT_OUTPUT if n == 5 else driver.SQL_PARAM_INPUT)
            for n, value in enumerate(_EXPLAIN_OUT_PLACEHOLDERS, 6):
                driver.bind_param(stmt, n, value, driver.SQL_PARAM_OUTPUT)
            facts["path2_execute_returned"] = repr(driver.execute(stmt))
            driver.free_stmt(stmt)

            # path 3: connection default, then callproc; read back on the returned statement
            facts["path3_connection_set_returned"] = repr(driver.set_option(conn.handle, {attr: connection_default}, _CONNECTION))
            result = driver.callproc(conn.handle, Q.EXPLAIN_PROC, inputs + _EXPLAIN_OUT_PLACEHOLDERS)
            try:
                facts["path3_statement_timeout"] = repr(driver.get_option(result[0], attr, _STATEMENT))
            except Exception as exc:
                facts["path3_statement_timeout"] = f"raised {type(exc).__name__}"
            facts["path3_out_time"] = str(result[7])
            driver.free_stmt(result[0])

            located = session.query(A.EXPLAIN_LOCATE_SQL, pattern)
            facts["instances_located"] = len(located)
            assert len(located) == 3, "three explain instances carry the marker"
            by_time = {A._timestamp_digits(row[1]): _key(row) for row in located}
            assert len(by_time) == 3, "the three instances have distinct EXPLAIN_TIMEs"
            content = {t: _instance(session, key) for t, key in by_time.items()}
            facts["instance_counts"] = sorted(c["instances"] for c in content.values())
            facts["row_counts"] = {k: [len(c[k]) for c in content.values()] for k in ("statement", "object", "operator")}
            path1 = A._timestamp_digits(k1.time)
            path3 = A._timestamp_digits(facts["path3_out_time"])
            facts["path1_located"] = path1 in by_time
            facts["path3_located"] = path3 in by_time
            facts["all_instances_identical"] = len({repr(c) for c in content.values()}) == 1
            assert facts["instance_counts"] == [1, 1, 1]
            assert facts["path1_located"] and facts["path3_located"]
            assert facts["all_instances_identical"], "the three paths produced different explain rows"
            assert facts["path2_timeout_read_back"] == run.timeout
        finally:
            session.rollback()
            facts["leftover_marker_rows"] = session.query(A.EXPLAIN_LEFTOVER_SQL, pattern)[0][0]
            facts["leftover_counts"] = H.leftover_counts(conn)
            session.rollback()
            facts["driver_log"] = driver.log
            conn.close()
        assert facts["leftover_marker_rows"] == 0
        assert all(n == 0 for n in facts["leftover_counts"].values()), "explain rows remain after rollback"
