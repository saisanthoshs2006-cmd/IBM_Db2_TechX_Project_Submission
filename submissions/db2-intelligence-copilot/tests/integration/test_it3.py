"""IT3 (gate G2.4): the production guard on Db2, end to end, with the bounded EXPLAIN.

Runs the real preflight (load_guard_context) and analyze() through Db2AnalysisSession on the
fixed queries in it_sql.IT3_QUERIES, behind the guarded driver: user statements can only be
prepared behind a guard marker; the only CALL is the prepared EXPLAIN_FROM_SECTION, whose query
timeout (query.timeout_seconds) is read back before it runs; callproc is never used by the
production path. Every analysis rolls back and verifies its own cleanup; at the end, on the same
connection, all 11 explain tables must be empty. Nothing commits and nothing is executed.
"""
from __future__ import annotations

import pytest

from db2intel.guard import analysis as A
from db2intel.guard import context as C
from db2intel.guard.sessions import Db2AnalysisSession
from integration import it_harness as H
from integration import it_sql as Q

pytestmark = pytest.mark.db2


def test_it3_production_guard_analysis():
    run = H.supervised_run("it3")
    with H.recording(run, {"query_timeout": run.timeout}) as facts:
        driver, conn = H.connect(run.timeout)
        session = Db2AnalysisSession(conn)
        try:
            ctx = C.load_guard_context(session, (Q.EXPECTED_DATABASE,))
            session.rollback()
            facts["context"] = {"database": ctx.database, "session_user": ctx.session_user,
                                "allowed_schemas": sorted(ctx.allowed_schemas),
                                "max_rows": ctx.limits.max_rows, "max_estimated_cost": ctx.limits.max_estimated_cost,
                                "explain_timeout_seconds": ctx.limits.timeout_seconds}
            assert ctx.allowed_schemas == Q.IT3_ALLOWED_SCHEMAS and ctx.limits.max_rows == Q.IT3_MAX_ROWS

            decisions = []
            for label, sql, expected in Q.IT3_QUERIES:
                start = len(driver.log)
                d = A.analyze(sql, session, ctx)
                ops = driver.log[start:]
                decisions.append({
                    "label": label, "expected": expected, "status": d.status, "code": d.code, "reason": d.reason,
                    "estimated_cost": d.estimated_cost, "explain_cost": d.explain_cost,
                    "objects": [list(o) for o in d.objects], "plan_operators": len(d.plan),
                    "bounded_calls": ops.count(("execute", Q.CALL_EXPLAIN_SQL)),
                    "callproc_calls": sum(1 for op, _ in ops if op == "callproc"),
                    "user_statements_executed": sum(1 for op, sql_ in ops if op == "execute" and Q.MARKED_RE.match(sql_)),
                })
            facts["decisions"] = decisions
        finally:
            session.rollback()
            facts["leftover_counts"] = H.leftover_counts(conn)
            session.rollback()
            facts["driver_ops"] = sorted({op for op, _ in driver.log})
            conn.close()

        for d in facts["decisions"]:
            assert d["code"] != "cleanup_failed", d
            assert d["status"] == d["expected"], d
            assert d["callproc_calls"] == 0 and d["user_statements_executed"] == 0, d
            assert d["bounded_calls"] == (0 if d["explain_cost"] is None else 1), d  # one EXPLAIN when explained
        approved = [d for d in facts["decisions"] if d["status"] == A.APPROVED]
        assert approved and all(d["bounded_calls"] == 1 and d["explain_cost"] is not None for d in approved)
        assert all(n == 0 for n in facts["leftover_counts"].values()), "explain rows remain after rollback"
        assert "commit" not in facts["driver_ops"] and "callproc" not in facts["driver_ops"]
