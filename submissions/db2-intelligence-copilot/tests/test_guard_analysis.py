"""Prepare-only cost check, package-cache matching and EXPLAIN verification, with fake Db2 responses."""
import re
import uuid

import pytest

from db2intel.db.connection import DbError
from db2intel.guard import analysis as A
from db2intel.guard.analysis import analyze, like_pattern, marker_for
from db2intel.guard.sessions import Db2AnalysisSession
import datetime

from guard_fakes import (CTX, GOOD_SQL, HEXID, LIMITS, PACKAGE, ROW_TIME, FakeAnalysis, StubConnection,  # noqa: F401
                         StubDriver, no_db_driver, resolved)
from db2intel.guard.context import GuardContext, GuardLimits

RID = "12345678-1234-5678-1234-567812345678"
MARKER = "DB2INTEL_REQ_12345678123456781234567812345678"


def run(fake=None, sql=GOOD_SQL, **kw):
    fake = fake or FakeAnalysis(**kw)
    return analyze(sql, fake, CTX, request_id=RID), fake


def assert_cleaned_up(fake):
    assert fake.kinds()[-1] == "rollback"
    assert not fake.explain_rows_present


# ---- the approved path --------------------------------------------------------------------
def test_approved_query_passes_every_check():
    d, fake = run()
    assert d.approved and d.status == "APPROVED" and d.code == "approved"
    assert d.sql == GOOD_SQL + " FETCH FIRST 500 ROWS ONLY"
    assert d.prepared_text == f"/* {MARKER} */ {d.sql}"
    assert d.estimated_cost == 177.0 and d.explain_cost == 176.5
    assert d.objects == (("DB2INTEL_DEMO", "CUSTOMER", "TA"), ("DB2INTEL_DEMO", "PK_CUSTOMER", "IX"))
    assert [op.operator_type for op in d.plan] == ["RETURN", "FETCH", "IXSCAN"]
    assert d.tables == (("DB2INTEL_DEMO", "CUSTOMER"),)
    assert_cleaned_up(fake)


def test_analysis_only_prepares_reads_explains_and_rolls_back():
    _, fake = run()
    assert set(fake.kinds()) == {"prepare_only", "query", "explain_section", "rollback"}
    assert fake.prepared == [f"/* {MARKER} */ {GOOD_SQL} FETCH FIRST 500 ROWS ONLY"]
    order = fake.kinds()
    assert order.index("prepare_only") < order.index("explain_section") < order.index("rollback")
    assert ("explain_section", HEXID, "DB2INTEL", CTX.limits.timeout_seconds) in fake.calls
    for absent in ("execute", "commit", "exec_immediate", "callproc"):
        assert not hasattr(fake, absent)


def test_explain_rows_are_checked_gone_after_rollback():
    _, fake = run()
    after = fake.calls[fake.kinds().index("rollback"):]
    assert after == [
        ("rollback",),
        ("query", A.EXPLAIN_LEFTOVER_SQL, (like_pattern(MARKER),)),
        ("query", A.LEFTOVER_BY_KEY_SQL["EXPLAIN_INSTANCE"], resolved().params()),
        ("query", A.LEFTOVER_BY_KEY_SQL["EXPLAIN_OBJECT"], resolved().params()),
        ("query", A.LEFTOVER_BY_KEY_SQL["EXPLAIN_OPERATOR"], resolved().params()),
        ("rollback",),
    ]


def test_every_request_gets_a_fresh_unique_marker():
    markers = set()
    for _ in range(50):
        d = analyze(GOOD_SQL, FakeAnalysis(), CTX)
        markers.add(re.search(r"DB2INTEL_REQ_[0-9A-F]{32}", d.prepared_text).group(0))
        uuid.UUID(d.request_id)
    assert len(markers) == 50


def test_cache_lookup_matches_on_the_marker_with_escaped_wildcards():
    _, fake = run()
    lookups = [c for c in fake.calls if c[0] == "query" and c[1] == A.CACHE_LOOKUP_SQL]
    assert len(lookups) == 2  # before EXPLAIN and again after it
    assert all(c[2] == (like_pattern(MARKER),) for c in lookups)
    assert like_pattern(MARKER) == "%DB2INTEL!_REQ!_12345678123456781234567812345678%"
    assert "ESCAPE '!'" in A.CACHE_LOOKUP_SQL
    assert marker_for(RID) == MARKER


# ---- static rejection never reaches the database ------------------------------------------
@pytest.mark.parametrize("sql", [
    "DELETE FROM DB2INTEL_DEMO.CUSTOMER",
    "SELECT * FROM DB2INST1.EMPLOYEE_INFO",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER; DROP TABLE X",
    "SELECT * FROM DB2INTEL_DEMO.CUSTOMER -- x",
])
def test_static_rejection_makes_no_database_call(sql):
    d, fake = run(sql=sql)
    assert d.status == "BLOCKED" and fake.calls == []


# ---- prepare ------------------------------------------------------------------------------
def test_prepare_error_is_error_with_sqlstate_and_rolls_back():
    d, fake = run(prepare_error=DbError("SQL0204N undefined name SQLSTATE=42704", "42704"))
    assert (d.status, d.code, d.sqlstate) == ("ERROR", "prepare_failed", "42704")
    assert "explain_section" not in fake.kinds()
    assert_cleaned_up(fake)


@pytest.mark.parametrize("columns", [0, None, -1, "3"])
def test_statement_without_result_set_is_blocked(columns):
    d, _ = run(columns=columns)
    assert (d.status, d.code) == ("BLOCKED", "no_result_set")


# ---- package cache ------------------------------------------------------------------------
def test_missing_cache_entry_is_blocked():
    d, fake = run(missing=True)
    assert (d.status, d.code) == ("BLOCKED", "cache_missing")
    assert "explain_section" not in fake.kinds()
    assert_cleaned_up(fake)


def test_entry_with_identical_text_but_no_marker_is_never_matched():
    """No fallback to text-only matching: an unmarked entry with the same SQL is ignored."""
    unmarked = (HEXID, 1.0, 0, GOOD_SQL + " FETCH FIRST 500 ROWS ONLY", *PACKAGE, 1)
    d, _ = run(missing=True, extra_cache=[unmarked])
    assert (d.status, d.code) == ("BLOCKED", "cache_missing")


def test_entry_with_another_requests_marker_is_never_matched():
    other = (HEXID, 1.0, 0, f"/* DB2INTEL_REQ_{'0' * 32} */ {GOOD_SQL} FETCH FIRST 500 ROWS ONLY", *PACKAGE, 1)
    d, _ = run(missing=True, extra_cache=[other])
    assert d.code == "cache_missing"


def test_duplicate_cache_entries_are_blocked():
    d, fake = run(duplicate=True)
    assert (d.status, d.code) == ("BLOCKED", "cache_ambiguous")
    assert "explain_section" not in fake.kinds()


def test_text_rewritten_by_statement_concentrator_is_blocked():
    d, _ = run(cache_text=f"/* {MARKER} */ SELECT C.COMPANY_NAME FROM DB2INTEL_DEMO.CUSTOMER C "
                          "WHERE C.CUSTOMER_ID = :L0 FETCH FIRST :L1 ROWS ONLY")
    assert (d.status, d.code) == ("BLOCKED", "cache_text_mismatch")


def test_entry_that_was_executed_is_blocked():
    d, _ = run(executions=1)
    assert (d.status, d.code) == ("BLOCKED", "already_executed")


@pytest.mark.parametrize("hexid", ["", None, "XYZ", "ABC", "00" * 65])
def test_invalid_executable_id_is_blocked(hexid):
    fake = FakeAnalysis()
    fake._cache = lambda pattern: [(hexid, 1.0, 0, fake.prepared[-1], *PACKAGE, 1)]
    d, _ = run(fake)
    assert (d.status, d.code) == ("BLOCKED", "cache_unexpected")


@pytest.mark.parametrize("cost", [None, "n/a", -1, float("nan"), float("inf")])
def test_unknown_cost_is_blocked(cost):
    d, _ = run(cost=cost)
    assert (d.status, d.code) == ("BLOCKED", "cost_unknown")


def test_excessive_cache_cost_is_rejected_before_explain():
    d, fake = run(cost=38_149_348)
    assert (d.status, d.code) == ("COST_REJECTED", "cost_too_high")
    assert d.estimated_cost == 38_149_348 and "38,149,348" in d.reason
    assert "explain_section" not in fake.kinds()
    assert_cleaned_up(fake)


def test_cost_exactly_at_the_limit_is_allowed():
    d, _ = run(cost=50_000, explain_cost=50_000)
    assert d.approved


def test_entry_evicted_between_explain_and_recheck_is_blocked():
    d, fake = run(evict_after_explain=True)
    assert (d.status, d.code) == ("BLOCKED", "cache_missing")
    assert_cleaned_up(fake)


def test_entry_replaced_during_analysis_is_blocked():
    d, _ = run(hexid_after_explain=HEXID[:-2] + "EE")
    assert (d.status, d.code) == ("BLOCKED", "cache_unexpected")


def test_explain_that_executed_the_statement_is_blocked():
    d, _ = run(executions_after_explain=1)
    assert (d.status, d.code) == ("BLOCKED", "already_executed")


# ---- EXPLAIN ------------------------------------------------------------------------------
def test_explain_failure_is_blocked_and_rolled_back():
    d, fake = run(explain_error=DbError("SQL20503N section not found SQLSTATE=5UA0K", "5UA0K"))
    assert (d.status, d.code, d.sqlstate) == ("BLOCKED", "explain_failed", "5UA0K")
    assert_cleaned_up(fake)


@pytest.mark.parametrize("package,section", [
    (("", "SYSSH200", ""), 1), ((None, "SYSSH200", ""), 1), (("NULLID", " ", ""), 1), (("NULLID", None, ""), 1),
    (("NULLID", "SYSSH200", 5), 1), (PACKAGE, None), (PACKAGE, -1), (PACKAGE, True), (PACKAGE, "x"), (PACKAGE, 1.5),
])
def test_cache_entry_without_a_usable_package_identity_is_blocked_before_explain(package, section):
    d, fake = run(package=package, cache_section=section)
    assert (d.status, d.code) == ("BLOCKED", "cache_unexpected")
    assert "explain_section" not in fake.kinds() and fake.kinds()[-1] == "rollback"


def test_dynamic_cache_entry_with_documented_null_metadata_uses_marker_identity():
    assert "MON_GET_PKG_CACHE_STMT('D'" in A.CACHE_LOOKUP_SQL
    d, fake = run(package=(None, None, None), cache_section=None)
    assert d.approved, d.reason
    assert d.prepared_text in fake.prepared
    assert_cleaned_up(fake)


# ---- dynamic SQL: all-NULL package metadata (what Db2 12.1.5 reports, G2.4 live run) -----------
DYNAMIC = dict(package=(None, None, None), cache_section=None)


def run_dynamic(fake_cls=FakeAnalysis, ctx=CTX, **kw):
    fake = fake_cls(**{**DYNAMIC, **kw})
    return analyze(GOOD_SQL, fake, ctx, request_id=RID), fake


def test_dynamic_metadata_still_explains_once_with_the_bounded_call_and_cleans_up():
    d, fake = run_dynamic()
    assert d.approved and fake.kinds().count("explain_section") == 1
    assert ("explain_section", HEXID, "DB2INTEL", 30) in fake.calls
    assert_cleaned_up(fake)


@pytest.mark.parametrize("meta", [
    (None, None, None, 5), (None, None, "", None), (None, None, "V1", None), ("NULLID", None, None, None),
    (None, "SYSSH200", None, None), ("", "", "", None), ("", None, None, None), (None, None, None, 0),
    (None, None, None, "x"), (None, None, None, True), ("NULLID", "SYSSH200", None, None),
    ("NULLID", "SYSSH200", "", -1), ("NULLID", "SYSSH200", 7, 1), (" ", "SYSSH200", "", 1),
])
def test_partial_or_malformed_package_metadata_is_blocked_before_explain(meta):
    d, fake = run(package=meta[:3], cache_section=meta[3])
    assert (d.status, d.code) == ("BLOCKED", "cache_unexpected"), d.reason
    assert "explain_section" not in fake.kinds() and fake.kinds()[-1] == "rollback"
    assert not fake.explain_rows_present


def test_dynamic_metadata_requester_must_be_the_session_user():
    ctx = GuardContext(database="TESTDB", session_user="GUARDUSR", allowed_schemas=CTX.allowed_schemas, limits=LIMITS)
    d, fake = run_dynamic(ctx=ctx)
    assert (d.status, d.code) == ("BLOCKED", "explain_key_mismatch") and "requester" in d.reason
    assert_cleaned_up(fake)


@pytest.mark.parametrize("requester", ["", "   ", None, 5])
def test_dynamic_metadata_empty_or_unreadable_requester_is_blocked(requester):
    d, fake = run_dynamic(locate_over={"requester": requester})
    assert (d.status, d.code) == ("BLOCKED", "explain_key_mismatch") and "requester" in d.reason
    assert_cleaned_up(fake)


@pytest.mark.parametrize("text", [GOOD_SQL, f"/* {MARKER} */ SELECT * FROM DB2INST1.EMPLOYEE_INFO", None, "",
                                  "PREPARED+SPACE"])
def test_dynamic_metadata_statement_text_must_be_exact(text):
    class Text(FakeAnalysis):
        def query(self, sql, params=()):
            rows = super().query(sql, params)
            if sql == A.EXPLAIN_LOCATE_SQL and rows and text == "PREPARED+SPACE":
                rows = [rows[0][:7] + (rows[0][7] + " ",)]
            return rows
    over = {} if text == "PREPARED+SPACE" else {"text": text}
    d, fake = run_dynamic(Text, locate_over=over)
    assert (d.status, d.code) == ("BLOCKED", "explain_text_mismatch")
    assert_cleaned_up(fake)


def test_dynamic_metadata_duplicate_marked_rows_are_blocked():
    class Duplicate(FakeAnalysis):
        def query(self, sql, params=()):
            rows = super().query(sql, params)
            if sql == A.EXPLAIN_LOCATE_SQL and rows:
                rows = rows + [rows[0][:1] + ("2026-11-06-15.30.00.999999",) + rows[0][2:]]
            return rows
    d, fake = run_dynamic(Duplicate)
    assert (d.status, d.code) == ("BLOCKED", "explain_ambiguous")
    assert_cleaned_up(fake)


def test_dynamic_metadata_missing_marked_row_is_blocked():
    d, fake = run_dynamic(locate_rows=[])
    assert (d.status, d.code) == ("BLOCKED", "explain_rows_missing")
    assert fake.kinds()[-1] == "rollback"


def test_dynamic_metadata_marked_rows_before_explain_are_blocked():
    d, fake = run_dynamic(marked_rows_before=1)
    assert (d.status, d.code) == ("BLOCKED", "explain_preexisting")
    assert "explain_section" not in fake.kinds() and fake.kinds()[-1] == "rollback"


@pytest.mark.parametrize("field", ["source_schema", "source_name"])
@pytest.mark.parametrize("value", ["", "   ", None, 7])
def test_dynamic_metadata_empty_source_schema_or_name_is_blocked(field, value):
    d, fake = run_dynamic(locate_over={field: value})
    assert (d.status, d.code) == ("BLOCKED", "explain_key_mismatch")
    assert field.replace("_", " ") in d.reason
    assert_cleaned_up(fake)


@pytest.mark.parametrize("sectno", [None, -1, True, "x", 1.5, ""])
def test_dynamic_metadata_unreadable_section_number_is_blocked(sectno):
    d, fake = run_dynamic(locate_over={"sectno": sectno})
    assert (d.status, d.code) == ("BLOCKED", "explain_key_mismatch") and "section number" in d.reason
    assert_cleaned_up(fake)


def test_dynamic_metadata_unreadable_source_version_or_time_is_blocked():
    for over, word in (({"source_version": 5}, "source version"), ({"time": None}, "explain time")):
        d, fake = run_dynamic(locate_over=over)
        assert (d.status, d.code) == ("BLOCKED", "explain_key_mismatch") and word in d.reason
        assert_cleaned_up(fake)


def test_dynamic_metadata_requires_exactly_one_instance():
    for count in (0, 2):
        d, fake = run_dynamic(instance_count=count)
        assert (d.status, d.code) == ("BLOCKED", "explain_instance_mismatch")
        assert fake.kinds()[-1] == "rollback"


def test_dynamic_metadata_that_appears_during_analysis_is_blocked():
    d, fake = run_dynamic(package_after_explain=PACKAGE)  # the section stays NULL: partial, so malformed
    assert (d.status, d.code) == ("BLOCKED", "cache_unexpected")
    assert_cleaned_up(fake)


def test_dynamic_metadata_executable_id_change_is_blocked():
    d, fake = run_dynamic(hexid_after_explain=HEXID[:-2] + "EE")
    assert (d.status, d.code) == ("BLOCKED", "cache_unexpected")
    assert_cleaned_up(fake)


def test_dynamic_metadata_plan_checks_still_apply():
    d, fake = run_dynamic(objects=[("DB2INST1", "EMPLOYEE_INFO", "TA")])
    assert (d.status, d.code) == ("BLOCKED", "forbidden_object")
    assert_cleaned_up(fake)


def test_dynamic_metadata_rows_left_after_rollback_are_cleanup_failed():
    d, fake = run_dynamic(rollback_keeps=("EXPLAIN_OBJECT",))
    assert (d.status, d.code) == ("ERROR", "cleanup_failed")
    assert fake.kinds()[-1] != "explain_section"


@pytest.mark.parametrize("row", [(HEXID, 1.0, 0), (HEXID, 1.0, 0, "x", "NULLID", "SYSSH200", "", 1, "extra")])
def test_cache_entry_of_an_unexpected_shape_is_blocked(row):
    fake = FakeAnalysis()
    fake._cache = lambda pattern: [row]
    d, _ = run(fake)
    assert (d.status, d.code) == ("BLOCKED", "cache_unexpected")


def test_null_package_version_is_the_empty_version_of_dynamic_sql():
    d, _ = run(package=("NULLID", "SYSSH200", None))
    assert d.approved, d.reason


def test_package_identity_changed_during_analysis_is_blocked():
    d, fake = run(package_after_explain=("NULLID", "SYSSH201", ""))
    assert (d.status, d.code) == ("BLOCKED", "cache_unexpected")
    assert_cleaned_up(fake)


# ---- the bounded EXPLAIN call ---------------------------------------------------------------
def test_explain_timeout_comes_from_the_configured_guard_limit():
    ctx = GuardContext(database="TESTDB", session_user="DB2INST1", allowed_schemas=CTX.allowed_schemas,
                       limits=GuardLimits(LIMITS.max_rows, LIMITS.max_estimated_cost, 45))
    fake = FakeAnalysis()
    d = analyze(GOOD_SQL, fake, ctx, request_id=RID)
    assert d.approved and ("explain_section", HEXID, "DB2INTEL", 45) in fake.calls


def test_unconfirmed_explain_timeout_is_blocked_without_explaining():
    d, fake = run(explain_error=A.ExplainTimeoutUnconfirmed("the query timeout reads back False, expected 30"))
    assert (d.status, d.code) == ("BLOCKED", "explain_timeout_unconfirmed") and "reads back False" in d.reason
    assert_cleaned_up(fake)


def test_explain_that_hits_the_query_timeout_is_blocked_and_cleaned_up():
    d, fake = run(explain_error=DbError("SQL0952N Processing was cancelled due to an interrupt. SQLSTATE=57014",
                                        "57014"), explain_error_after_write=True)
    assert (d.status, d.code, d.sqlstate) == ("BLOCKED", "explain_timeout", "57014") and "30 s" in d.reason
    assert_cleaned_up(fake)


# ---- no explain row may carry the marker before EXPLAIN ------------------------------------
def test_marker_is_checked_absent_before_explain():
    _, fake = run()
    pre = fake.calls.index(("query", A.EXPLAIN_LEFTOVER_SQL, (like_pattern(MARKER),)))
    assert pre < fake.kinds().index("explain_section")


def test_preexisting_marked_rows_block_before_explain():
    d, fake = run(marked_rows_before=2)
    assert (d.status, d.code) == ("BLOCKED", "explain_preexisting")
    assert "explain_section" not in fake.kinds() and fake.kinds()[-1] == "rollback"


@pytest.mark.parametrize("result", [[], [(None,)], [("0",)], [(True,)], [(0, 0)], [(-1,)]])
def test_unreadable_marker_precheck_is_blocked(result):
    class Precheck(FakeAnalysis):
        def query(self, sql, params=()):
            if sql == A.EXPLAIN_LEFTOVER_SQL and not self.explained:
                self.calls.append(("query", sql, tuple(params)))
                return result
            return super().query(sql, params)
    d, fake = run(Precheck())
    assert (d.status, d.code) == ("BLOCKED", "explain_unexpected")
    assert "explain_section" not in fake.kinds()


@pytest.mark.parametrize("levels", [[], ["O"], ["S"], ["O", "S", "S"], ["O", "P"]])
def test_unexpected_explain_statement_rows_are_blocked(levels):
    fake = FakeAnalysis()
    fake.statements = [(lvl, 1, 1, 1.0, "") for lvl in levels]
    d, _ = run(fake)
    assert (d.status, d.code) == ("BLOCKED", "explain_unexpected")


def test_explained_text_must_be_the_prepared_text():
    fake = FakeAnalysis(statements=[("O", 1, 1, 0.0, "SELECT * FROM DB2INST1.EMPLOYEE_INFO"), ("S", 1, 1, 1.0, "x")])
    d, _ = run(fake)
    assert (d.status, d.code) == ("BLOCKED", "explain_text_mismatch")


def test_excessive_explain_cost_is_rejected_even_if_cache_cost_was_low():
    d, fake = run(cost=10, explain_cost=60_000)
    assert (d.status, d.code) == ("COST_REJECTED", "cost_too_high")
    assert d.explain_cost == 60_000
    assert_cleaned_up(fake)


@pytest.mark.parametrize("cost", [None, -5, "x"])
def test_unknown_explain_cost_is_blocked(cost):
    d, _ = run(explain_cost=cost)
    assert (d.status, d.code) == ("BLOCKED", "cost_unknown")


@pytest.mark.parametrize("objects,reason", [
    ([("DB2INST1", "EMPLOYEE_INFO", "TA")], "DB2INST1.EMPLOYEE_INFO"),
    ([("DB2INTEL_DEMO", "CUSTOMER", "TA"), ("DB2INST1", "EMPLOYEE_SALARY", "TA")], "EMPLOYEE_SALARY"),
    ([("DB2INTEL", "QUERY_AUDIT", "TA")], "DB2INTEL.QUERY_AUDIT"),
    ([("SYSIBM", "SYSTABLES", "TA")], "SYSIBM.SYSTABLES"),
    ([("OTHER", "T", "TA")], "OTHER.T"),
    ([("DB2INTEL_DEMO", "CUSTOMER", "TA"), ("DB2INTEL_DEMO", "F", "TF")], "unsupported type"),
    ([("DB2INTEL_DEMO", "CUSTOMER", "TA"), ("DB2INTEL_DEMO", "N", "NK")], "unsupported type"),
])
def test_forbidden_objects_in_the_plan_are_blocked(objects, reason):
    """A view in an allowed schema that reads a protected table is caught here, after view expansion."""
    d, fake = run(objects=objects)
    assert (d.status, d.code) == ("BLOCKED", "forbidden_object") and reason in d.reason
    assert_cleaned_up(fake)


def test_index_on_a_forbidden_table_is_blocked():
    fake = FakeAnalysis(objects=[("DB2INTEL_DEMO", "CUSTOMER", "TA"), ("SYSIBM", "SQL261106", "IX")],
                        index_owners={("SYSIBM", "SQL261106"): [("DB2INST1", "EMPLOYEE_INFO")]})
    d, _ = run(fake)
    assert d.code == "forbidden_object" and "DB2INST1.EMPLOYEE_INFO" in d.reason


@pytest.mark.parametrize("owners", [[], [("DB2INTEL_DEMO", "A"), ("DB2INTEL_DEMO", "B")]])
def test_unresolvable_index_is_blocked(owners):
    fake = FakeAnalysis(objects=[("DB2INTEL_DEMO", "CUSTOMER", "TA"), ("DB2INTEL_DEMO", "IX1", "IX")],
                        index_owners={("DB2INTEL_DEMO", "IX1"): owners})
    d, _ = run(fake)
    assert d.code == "forbidden_object"


def test_system_pk_index_on_allowed_table_is_accepted():
    fake = FakeAnalysis(objects=[("DB2INTEL_DEMO", "CUSTOMER", "TA"), ("SYSIBM", "SQL261106", "IX")],
                        index_owners={("SYSIBM", "SQL261106"): [("DB2INTEL_DEMO", "CUSTOMER")]})
    d, _ = run(fake)
    assert d.approved


def test_sysdummy1_is_an_allowed_object():
    d, _ = run(sql="SELECT 1 FROM SYSIBM.SYSDUMMY1", objects=[("SYSIBM", "SYSDUMMY1", "TA")])
    assert d.approved


def test_plan_with_only_indexes_is_blocked():
    d, _ = run(objects=[("DB2INTEL_DEMO", "PK_CUSTOMER", "IX")])
    assert (d.status, d.code) == ("BLOCKED", "explain_unexpected")


# ---- cleanup is mandatory -----------------------------------------------------------------
def test_failed_rollback_turns_any_result_into_error():
    d, _ = run(rollback_error=DbError("SQL30081N communication error SQLSTATE=08001", "08001"))
    assert (d.status, d.code) == ("ERROR", "cleanup_failed") and not d.approved


def test_explain_rows_left_after_rollback_is_error():
    d, _ = run(rollback_keeps_rows=True)
    assert (d.status, d.code) == ("ERROR", "cleanup_failed")
    assert "still present" in d.reason


def test_database_error_mid_analysis_is_error_and_rolls_back():
    d, fake = run(query_error_on="EXPLAIN_OBJECT")
    assert (d.status, d.code, d.sqlstate) == ("ERROR", "db_error", "40001")
    assert_cleaned_up(fake)


def test_cleanup_failure_after_blocked_result_is_still_not_approved():
    d, _ = run(missing=True, rollback_error=DbError("gone"))
    assert d.status == "ERROR" and not d.approved


# ---- cleanup verification counts every explain table directly ------------------------------
@pytest.mark.parametrize("table,count", [("EXPLAIN_STATEMENT", 2), ("EXPLAIN_INSTANCE", 1),
                                         ("EXPLAIN_OBJECT", 2), ("EXPLAIN_OPERATOR", 3)])
def test_rows_left_in_any_one_explain_table_is_cleanup_failure(table, count):
    d, fake = run(rollback_keeps={table})
    assert (d.status, d.code) == ("ERROR", "cleanup_failed") and not d.approved
    assert d.reason == f"explain rows are still present after rollback: {table}={count}"
    assert fake.present == {table} and fake.kinds()[-1] == "rollback"


def test_leftover_object_rows_alone_are_detected_without_relying_on_cascade():
    """Statement and instance rows gone, object rows left: only the direct object count sees it."""
    d, _ = run(rollback_keeps={"EXPLAIN_OBJECT"})
    assert d.code == "cleanup_failed" and "EXPLAIN_OBJECT=2" in d.reason and "EXPLAIN_STATEMENT" not in d.reason


def test_leftover_operator_rows_alone_are_detected_without_relying_on_cascade():
    d, _ = run(rollback_keeps={"EXPLAIN_OPERATOR"})
    assert d.code == "cleanup_failed" and "EXPLAIN_OPERATOR=3" in d.reason and "EXPLAIN_INSTANCE" not in d.reason


@pytest.mark.parametrize("over", [
    dict(objects=[("DB2INST1", "EMPLOYEE_SALARY", "TA")]),          # BLOCKED forbidden_object
    dict(explain_cost=10**9),                                       # COST_REJECTED from explain
    dict(operators=[(1, "RETURN", "abc")]),                         # ERROR internal_error
    dict(query_error_on="SYSCAT.INDEXES"),                          # ERROR db_error
    dict(locate_over={"source_name": "OTHER"}),                     # BLOCKED explain_key_mismatch
    dict(),                                                         # would be APPROVED
])
def test_leftover_rows_override_every_other_result(over):
    d, _ = run(rollback_keeps={"EXPLAIN_OPERATOR"}, **over)
    assert (d.status, d.code) == ("ERROR", "cleanup_failed") and not d.approved


@pytest.mark.parametrize("table", ["EXPLAIN_STATEMENT", "EXPLAIN_INSTANCE", "EXPLAIN_OBJECT", "EXPLAIN_OPERATOR"])
@pytest.mark.parametrize("over", [dict(), dict(objects=[("DB2INST1", "EMPLOYEE_SALARY", "TA")]),
                                  dict(explain_error=DbError("x"), explain_error_after_write=True)])
def test_failed_cleanup_check_on_any_table_is_cleanup_failure(table, over):
    d, fake = run(cleanup_error_on=table, **over)
    assert (d.status, d.code) == ("ERROR", "cleanup_failed") and not d.approved
    assert d.reason.startswith("rollback after analysis failed")
    assert fake.kinds()[-1] == "rollback" and fake.rollbacks == 2


@pytest.mark.parametrize("result", [[], [(None,)], [("0",)], [(0.0,)], [(True,)], [(0, 0)], [(0,), (0,)], [(-1,)]])
def test_unreadable_cleanup_count_is_cleanup_failure(result):
    d, _ = run(cleanup_result=result)
    assert (d.status, d.code) == ("ERROR", "cleanup_failed") and not d.approved
    assert d.reason == "explain rows are still present after rollback: " + ", ".join(
        f"{t}=unknown" for t in ("EXPLAIN_STATEMENT",) + A.LEFTOVER_TABLES)


def test_unresolved_key_counts_whole_explain_tables():
    d, fake = run(explain_error=DbError("x SQLSTATE=58004", "58004"), explain_error_after_write=True)
    assert (d.status, d.code) == ("BLOCKED", "explain_failed")
    after = fake.calls[fake.kinds().index("rollback"):]
    for table in A.LEFTOVER_TABLES:
        assert ("query", A.LEFTOVER_ANY_SQL[table], ()) in after
        assert all(c[1] != A.LEFTOVER_BY_KEY_SQL[table] for c in after if c[0] == "query")


@pytest.mark.parametrize("table", A.LEFTOVER_TABLES)
def test_unresolved_key_with_any_row_in_a_table_is_cleanup_failure(table):
    d, _ = run(explain_error=DbError("x"), explain_error_after_write=True, foreign_rows={table: 1})
    assert (d.status, d.code) == ("ERROR", "cleanup_failed") and f"{table}=1" in d.reason


def test_resolved_key_counts_only_this_requests_rows():
    d, _ = run(foreign_rows={"EXPLAIN_OBJECT": 5, "EXPLAIN_OPERATOR": 5, "EXPLAIN_INSTANCE": 5})
    assert d.approved


def test_no_cleanup_counts_when_explain_was_never_attempted():
    _, fake = run(cost=10**9)
    assert fake.kinds()[-1] == "rollback" and fake.kinds().count("rollback") == 1
    cleanup_sql = {A.EXPLAIN_LEFTOVER_SQL, *A.LEFTOVER_BY_KEY_SQL.values(), *A.LEFTOVER_ANY_SQL.values()}
    assert not any(c[0] == "query" and c[1] in cleanup_sql for c in fake.calls)


# ---- locating explain rows through the request marker (the prepared CALL returns no OUT keys) ----
def reads_by_key(fake):
    return {c[2] for c in fake.calls if c[0] == "query" and c[1] in (
        A.EXPLAIN_STATEMENT_SQL, A.EXPLAIN_OBJECT_SQL, A.EXPLAIN_OPERATOR_SQL)}


def test_explain_rows_are_resolved_from_the_marked_row():
    d, fake = run()
    assert d.approved
    assert ("query", A.EXPLAIN_LOCATE_SQL, (like_pattern(MARKER),)) in fake.calls
    assert reads_by_key(fake) == {resolved().params()}
    assert resolved().params()[1] == ROW_TIME


def test_locate_sql_matches_original_level_by_marker_only():
    assert "EXPLAIN_LEVEL = 'O'" in A.EXPLAIN_LOCATE_SQL
    assert "STATEMENT_TEXT LIKE ? ESCAPE '!'" in A.EXPLAIN_LOCATE_SQL
    assert "SECTNO, STATEMENT_TEXT FROM" in A.EXPLAIN_LOCATE_SQL
    assert "EXPLAIN_TIME =" not in A.EXPLAIN_LOCATE_SQL


def test_no_marked_explain_row_is_blocked():
    d, fake = run(explain_writes=False)
    assert (d.status, d.code) == ("BLOCKED", "explain_rows_missing")
    assert fake.kinds()[-1] == "rollback"


def test_duplicate_marked_explain_rows_are_blocked():
    class Duplicate(FakeAnalysis):
        def query(self, sql, params=()):
            rows = super().query(sql, params)
            if sql == A.EXPLAIN_LOCATE_SQL and rows:
                rows = rows + [rows[0][:1] + ("2026-11-06-15.30.00.999999",) + rows[0][2:]]
            return rows
    d, fake = run(Duplicate())
    assert (d.status, d.code) == ("BLOCKED", "explain_ambiguous")
    assert_cleaned_up(fake)


@pytest.mark.parametrize("over,field", [
    (dict(requester="OTHERUSER"), "requester"), (dict(requester=""), "requester"), (dict(requester=None), "requester"),
    (dict(source_name="SYSSH100"), "source name"), (dict(source_name=None), "source name"),
    (dict(source_schema="DB2INST1"), "source schema"), (dict(source_version="V2"), "source version"),
    (dict(sectno=2), "section number"), (dict(sectno=None), "section number"), (dict(sectno="1x"), "section number"),
])
def test_marked_row_that_does_not_match_the_explained_entry_is_blocked(over, field):
    d, fake = run(locate_over=over)
    assert (d.status, d.code) == ("BLOCKED", "explain_key_mismatch") and field in d.reason
    assert_cleaned_up(fake)


@pytest.mark.parametrize("package,field", [
    (("NULLID", "SYSSH100", ""), "source name"), (("DB2INST1", "SYSSH200", ""), "source schema"),
    (("NULLID", "SYSSH200", "V1"), "source version"),
])
def test_package_cache_identity_that_differs_from_the_marked_row_is_blocked(package, field):
    d, _ = run(package=package)
    assert (d.status, d.code) == ("BLOCKED", "explain_key_mismatch") and field in d.reason


def test_cache_section_that_differs_from_the_marked_row_is_blocked():
    d, _ = run(cache_section=2)
    assert (d.status, d.code) == ("BLOCKED", "explain_key_mismatch") and "section number" in d.reason


def test_requester_must_be_the_session_user():
    ctx = GuardContext(database="TESTDB", session_user="GUARDUSR", allowed_schemas=CTX.allowed_schemas, limits=LIMITS)
    d = analyze(GOOD_SQL, FakeAnalysis(), ctx, request_id=RID)
    assert (d.status, d.code) == ("BLOCKED", "explain_key_mismatch") and "requester" in d.reason


@pytest.mark.parametrize("user", ["", "   "])
def test_empty_requester_is_blocked_even_if_the_session_user_is_empty(user):
    ctx = GuardContext(database="TESTDB", session_user=user, allowed_schemas=CTX.allowed_schemas, limits=LIMITS)
    d = analyze(GOOD_SQL, FakeAnalysis(locate_over={"requester": ""}), ctx, request_id=RID)
    assert (d.status, d.code) == ("BLOCKED", "explain_key_mismatch") and "requester (empty)" in d.reason


@pytest.mark.parametrize("text", [GOOD_SQL, f"/* {MARKER} */ SELECT * FROM DB2INST1.EMPLOYEE_INFO", None, ""])
def test_marked_row_text_must_be_the_exact_prepared_text(text):
    d, fake = run(locate_over={"text": text})
    assert (d.status, d.code) == ("BLOCKED", "explain_text_mismatch")
    assert_cleaned_up(fake)


def test_timestamp_normaliser_accepts_datetime_objects():
    assert A._timestamp_digits(datetime.datetime(2026, 11, 6, 15, 30, 0, 123456)) == "20261106153000123456000000"


@pytest.mark.parametrize("row_time", [None, "", "not a time"])
def test_marked_row_without_usable_time_is_blocked(row_time):
    d, _ = run(locate_over={"time": row_time})
    assert (d.status, d.code) == ("BLOCKED", "explain_key_mismatch") and "explain time" in d.reason


@pytest.mark.parametrize("row", [("DB2INST1", ROW_TIME, "SYSSH200", "NULLID", "", 1, 1),
                                 ("DB2INST1", ROW_TIME, "SYSSH200", "NULLID", "", 1, 1, "t", "extra")])
def test_marked_row_of_an_unexpected_shape_is_blocked(row):
    d, _ = run(locate_rows=[row])
    assert (d.status, d.code) == ("BLOCKED", "explain_unexpected")


class SessionCallAnalysis(FakeAnalysis):
    """Fake Db2 for every read, but EXPLAIN goes through the real Db2AnalysisSession.explain_section
    with a stub driver, so the prepared CALL, its timeout read-back and its bindings are exercised."""

    def __init__(self, driver=None, **kw):
        super().__init__(**kw)
        self.driver = driver or StubDriver()
        self.adapter = Db2AnalysisSession(StubConnection(self.driver))

    def explain_section(self, hexid, schema, timeout_seconds):
        self.adapter.explain_section(hexid, schema, timeout_seconds)  # raises before any rows are written
        super().explain_section(hexid, schema, timeout_seconds)


def test_end_to_end_prepared_call_with_confirmed_timeout_is_approved():
    fake = SessionCallAnalysis()
    d, _ = run(fake)
    assert d.approved, d.reason
    calls = fake.driver.calls
    assert calls[0] == ("prepare", A.EXPLAIN_CALL_SQL, {StubDriver.SQL_ATTR_QUERY_TIMEOUT: 30})
    assert calls[1][0] == "get_option" and calls.index(calls[1]) < [c[0] for c in calls].index("execute")
    assert not any(c[0] == "callproc" for c in calls)
    assert_cleaned_up(fake)


@pytest.mark.parametrize("readback", [False, 0, 29, True, "30", None])
def test_end_to_end_unconfirmed_timeout_never_runs_the_call(readback):
    fake = SessionCallAnalysis(StubDriver(timeout_readback=readback))
    d, _ = run(fake)
    assert (d.status, d.code) == ("BLOCKED", "explain_timeout_unconfirmed")
    kinds = [c[0] for c in fake.driver.calls]
    assert "execute" not in kinds and "bind_param" not in kinds and kinds[-1] == "free_stmt"
    assert_cleaned_up(fake)


def test_end_to_end_driver_timeout_error_is_explain_timeout():
    drv = StubDriver(fail={"execute": "[IBM][CLI Driver][DB2/LINUXX8664] SQL0952N Processing was cancelled "
                                      "due to an interrupt.  SQLSTATE=57014"})
    fake = SessionCallAnalysis(drv)
    d, _ = run(fake)
    assert (d.status, d.code, d.sqlstate) == ("BLOCKED", "explain_timeout", "57014")
    assert fake.driver.calls[-1][0] == "free_stmt"
    assert_cleaned_up(fake)


@pytest.mark.parametrize("count", [0, 2])
def test_explain_instance_must_be_exactly_one(count):
    d, _ = run(instance_count=count)
    assert (d.status, d.code) == ("BLOCKED", "explain_instance_mismatch")


def test_statement_rows_of_another_statement_are_blocked():
    d, _ = run(FakeAnalysis(statements=[("O", 1, 1, 0.0, "x"), ("S", 2, 1, 1.0, "x")]))
    assert (d.status, d.code) == ("BLOCKED", "explain_instance_mismatch")


@pytest.mark.parametrize("which", ["objects", "operators"])
def test_dependent_rows_of_another_statement_are_blocked(which):
    rows = {"objects": [("DB2INTEL_DEMO", "CUSTOMER", "TA", "S", 2, 1)],
            "operators": [(1, "RETURN", 7.0, "S", 1, 2)]}
    d, fake = run(**{which: rows[which]})
    assert (d.status, d.code) == ("BLOCKED", "explain_instance_mismatch")
    assert fake.kinds()[-1] == "rollback"


@pytest.mark.parametrize("which", ["objects", "operators"])
def test_missing_dependent_rows_are_blocked(which):
    d, fake = run(**{which: []})
    assert (d.status, d.code) == ("BLOCKED", "explain_rows_missing")
    assert fake.kinds()[-1] == "rollback"


def test_missing_statement_rows_for_the_resolved_key_are_blocked():
    d, _ = run(statements=[])
    assert (d.status, d.code) == ("BLOCKED", "explain_unexpected")


# ---- driver errors: rollback on every path ------------------------------------------------
def test_explain_error_after_writing_rows_is_blocked_and_rows_are_rolled_back():
    d, fake = run(explain_error=DbError("SQL0901N SQLSTATE=58004", "58004"), explain_error_after_write=True)
    assert (d.status, d.code) == ("BLOCKED", "explain_failed")
    assert ("query", A.EXPLAIN_LEFTOVER_SQL, (like_pattern(MARKER),)) in fake.calls
    assert not fake.explain_rows_present


def test_explain_error_with_rows_surviving_rollback_is_error():
    d, _ = run(explain_error=DbError("x SQLSTATE=58004", "58004"), explain_error_after_write=True,
               rollback_keeps_rows=True)
    assert (d.status, d.code) == ("ERROR", "cleanup_failed")


@pytest.mark.parametrize("failing", ["STATEMENT_TEXT LIKE ? ESCAPE '!'\"", "EXPLAIN_INSTANCE", "EXPLAIN_OPERATOR"])
def test_db_errors_while_reading_explain_rows_are_errors_with_rollback(failing):
    sql_part = {"STATEMENT_TEXT LIKE ? ESCAPE '!'\"": "EXPLAIN_LEVEL = 'O'"}.get(failing, failing)
    d, fake = run(query_error_on=sql_part)
    assert d.status == "ERROR" and not d.approved
    assert "rollback" in fake.kinds() and not fake.explain_rows_present


def test_error_during_leftover_check_is_cleanup_failure_and_rolls_back_again():
    class LeftoverFails(FakeAnalysis):
        def query(self, sql, params=()):
            if sql == A.EXPLAIN_LEFTOVER_SQL and self.rollbacks:  # the post-rollback check, not the pre-check
                self.calls.append(("query", sql, tuple(params)))
                raise DbError("SQL30081N SQLSTATE=08001", "08001")
            return super().query(sql, params)
    fake = LeftoverFails()
    d, _ = run(fake)
    assert (d.status, d.code) == ("ERROR", "cleanup_failed")
    assert fake.kinds()[-1] == "rollback" and fake.rollbacks == 2


@pytest.mark.parametrize("over", [dict(operators=[("x", "RETURN", 1.0)]), dict(operators=[(1, "RETURN", "abc")])])
def test_malformed_driver_data_is_internal_error_with_rollback(over):
    d, fake = run(**over)
    assert (d.status, d.code) == ("ERROR", "internal_error") and not d.approved
    assert fake.kinds()[-1] == "rollback" and not fake.explain_rows_present


@pytest.mark.parametrize("over", [
    dict(), dict(missing=True), dict(cost=10**9), dict(explain_writes=False), dict(instance_count=2),
    dict(locate_over={"source_name": "X"}), dict(objects=[("DB2INST1", "EMPLOYEE_INFO", "TA")]),
    dict(marked_rows_before=1), dict(explain_error=A.ExplainTimeoutUnconfirmed("x")),
    dict(operators=[]), dict(query_error_on="EXPLAIN_OBJECT"), dict(explain_error=DbError("x")),
    dict(prepare_error=DbError("x")),
])
def test_every_path_ends_with_rollback_and_no_explain_rows(over):
    _, fake = run(**over)
    assert fake.kinds()[-1] == "rollback" and not fake.explain_rows_present
