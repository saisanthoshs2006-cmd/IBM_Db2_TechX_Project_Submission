"""Prepare-only cost check, package-cache matching and EXPLAIN verification, with fake Db2 responses."""
import re
import uuid

import pytest

from db2intel.db.connection import DbError
from db2intel.guard import analysis as A
from db2intel.guard.analysis import analyze, like_pattern, marker_for
from db2intel.guard.sessions import Db2AnalysisSession
import datetime

from guard_fakes import (CTX, GOOD_SQL, HEXID, ROW_TIME, FakeAnalysis, StubConnection, StubDriver,  # noqa: F401
                         key, no_db_driver, resolved)

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
    assert set(fake.kinds()) == {"prepare_only", "query", "explain_from_section", "rollback"}
    assert fake.prepared == [f"/* {MARKER} */ {GOOD_SQL} FETCH FIRST 500 ROWS ONLY"]
    order = fake.kinds()
    assert order.index("prepare_only") < order.index("explain_from_section") < order.index("rollback")
    assert ("explain_from_section", HEXID, "DB2INTEL") in fake.calls
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
    assert "explain_from_section" not in fake.kinds()
    assert_cleaned_up(fake)


@pytest.mark.parametrize("columns", [0, None, -1, "3"])
def test_statement_without_result_set_is_blocked(columns):
    d, _ = run(columns=columns)
    assert (d.status, d.code) == ("BLOCKED", "no_result_set")


# ---- package cache ------------------------------------------------------------------------
def test_missing_cache_entry_is_blocked():
    d, fake = run(missing=True)
    assert (d.status, d.code) == ("BLOCKED", "cache_missing")
    assert "explain_from_section" not in fake.kinds()
    assert_cleaned_up(fake)


def test_entry_with_identical_text_but_no_marker_is_never_matched():
    """No fallback to text-only matching: an unmarked entry with the same SQL is ignored."""
    unmarked = (HEXID, 1.0, 0, GOOD_SQL + " FETCH FIRST 500 ROWS ONLY")
    d, _ = run(missing=True, extra_cache=[unmarked])
    assert (d.status, d.code) == ("BLOCKED", "cache_missing")


def test_entry_with_another_requests_marker_is_never_matched():
    other = (HEXID, 1.0, 0, f"/* DB2INTEL_REQ_{'0' * 32} */ {GOOD_SQL} FETCH FIRST 500 ROWS ONLY")
    d, _ = run(missing=True, extra_cache=[other])
    assert d.code == "cache_missing"


def test_duplicate_cache_entries_are_blocked():
    d, fake = run(duplicate=True)
    assert (d.status, d.code) == ("BLOCKED", "cache_ambiguous")
    assert "explain_from_section" not in fake.kinds()


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
    fake._cache = lambda pattern: [(hexid, 1.0, 0, fake.prepared[-1])]
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
    assert "explain_from_section" not in fake.kinds()
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


@pytest.mark.parametrize("bad_key", [
    key("SYSTOOLS"), key("DB2INST1"), key(requester=""), key(time=None), key(source_name=" "),
    key(source_schema=""), key(source_version=None), "not a key",
])
def test_unexpected_explain_keys_are_blocked(bad_key):
    d, fake = run(explain_key=bad_key)
    assert (d.status, d.code) == ("BLOCKED", "explain_unexpected")
    assert fake.kinds()[-1] == "rollback"


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
    dict(explain_key=key(source_name="OTHER")),                     # BLOCKED explain_key_mismatch
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


# ---- locating explain rows through the request marker (EXPLAIN_TIME OUT is not returned) ----
def reads_by_key(fake):
    return {c[2] for c in fake.calls if c[0] == "query" and c[1] in (
        A.EXPLAIN_STATEMENT_SQL, A.EXPLAIN_OBJECT_SQL, A.EXPLAIN_OPERATOR_SQL)}


def test_missing_out_timestamp_is_resolved_from_the_marked_row():
    d, fake = run()  # driver OUT time is "" as observed on Db2 12.1.5
    assert d.approved
    assert ("query", A.EXPLAIN_LOCATE_SQL, (like_pattern(MARKER),)) in fake.calls
    assert reads_by_key(fake) == {resolved().params()}
    assert resolved().params()[1] == ROW_TIME


def test_locate_sql_matches_original_level_by_marker_only():
    assert "EXPLAIN_LEVEL = 'O'" in A.EXPLAIN_LOCATE_SQL
    assert "STATEMENT_TEXT LIKE ? ESCAPE '!'" in A.EXPLAIN_LOCATE_SQL
    assert "EXPLAIN_TIME =" not in A.EXPLAIN_LOCATE_SQL


@pytest.mark.parametrize("out_time", [ROW_TIME, "2026-11-06 15:30:00.123456", "2026-11-06-15.30.00.123456000"])
def test_returned_timestamp_that_matches_is_accepted(out_time):
    d, _ = run(explain_key=key(time=out_time))
    assert d.approved


class DriverKeyAnalysis(FakeAnalysis):
    """Fake Db2 for every read, but the explain key comes from the real Db2AnalysisSession
    adapter decoding a stub ibm_db callproc result, so the driver's OUT value type is exercised."""

    def __init__(self, out_time, **kw):
        super().__init__(**kw)
        out = ("stmt", bytes.fromhex(HEXID), "M", None, -1, "DB2INTEL  ", "DB2INST1", out_time,
               "SYSSH200", "NULLID  ", "")
        self.driver = StubDriver(callproc_result=out)
        self.adapter = Db2AnalysisSession(StubConnection(self.driver))

    def explain_from_section(self, hexid, schema):
        super().explain_from_section(hexid, schema)  # records the call and writes the fake rows
        return self.adapter.explain_from_section(hexid, schema)


@pytest.mark.parametrize("out_time", [datetime.datetime(2026, 11, 6, 15, 30, 0, 123456), None, ROW_TIME])
def test_end_to_end_driver_timestamp_that_matches_is_approved(out_time):
    fake = DriverKeyAnalysis(out_time)
    d, _ = run(fake)
    assert d.approved, d.reason
    (call,) = [c for c in fake.driver.calls if c[0] == "callproc"]
    assert call[1] == "SYSPROC.EXPLAIN_FROM_SECTION" and call[2][0] == bytes.fromhex(HEXID)
    assert ("query", A.EXPLAIN_STATEMENT_SQL, resolved().params()) in fake.calls
    assert_cleaned_up(fake)


@pytest.mark.parametrize("out_time", [
    datetime.datetime(2026, 11, 6, 15, 30, 0, 123457),  # 1 microsecond later
    datetime.datetime(2026, 11, 6, 15, 30, 0),          # no fraction (str() drops it)
    datetime.datetime(2026, 11, 7, 15, 30, 0, 123456),
])
def test_end_to_end_driver_timestamp_that_differs_is_blocked(out_time):
    fake = DriverKeyAnalysis(out_time)
    d, _ = run(fake)
    assert (d.status, d.code) == ("BLOCKED", "explain_key_mismatch") and "explain time" in d.reason
    assert_cleaned_up(fake)


def test_timestamp_normaliser_accepts_datetime_objects():
    assert A._timestamp_digits(datetime.datetime(2026, 11, 6, 15, 30, 0, 123456)) == "20261106153000123456000000"


@pytest.mark.parametrize("out_time", ["2026-11-06-15.30.00.123457", "2026-11-06-15.30.01.123456", "garbage", "2026"])
def test_returned_timestamp_that_differs_is_blocked(out_time):
    d, fake = run(explain_key=key(time=out_time))
    assert (d.status, d.code) == ("BLOCKED", "explain_key_mismatch") and "explain time" in d.reason
    assert fake.kinds()[-1] == "rollback" and not fake.explain_rows_present


def test_no_marked_explain_row_is_blocked():
    d, fake = run(explain_writes=False)
    assert (d.status, d.code) == ("BLOCKED", "explain_rows_missing")
    assert fake.kinds()[-1] == "rollback"


def test_duplicate_marked_explain_rows_are_blocked():
    row = ("DB2INST1", ROW_TIME, "SYSSH200", "NULLID", "", 1, 1)
    d, _ = run(locate_rows=[row, row[:1] + ("2026-11-06-15.30.00.999999",) + row[2:]])
    assert (d.status, d.code) == ("BLOCKED", "explain_ambiguous")


@pytest.mark.parametrize("over,field", [
    (dict(requester="OTHERUSER"), "requester"), (dict(source_name="SYSSH100"), "source name"),
    (dict(source_schema="DB2INST1"), "source schema"), (dict(source_version="V2"), "source version"),
])
def test_metadata_mismatch_between_out_values_and_row_is_blocked(over, field):
    d, _ = run(explain_key=key(**over))
    assert (d.status, d.code) == ("BLOCKED", "explain_key_mismatch") and field in d.reason


@pytest.mark.parametrize("row_time", [None, "", "not a time"])
def test_marked_row_without_usable_time_is_blocked(row_time):
    d, _ = run(locate_rows=[("DB2INST1", row_time, "SYSSH200", "NULLID", "", 1, 1)])
    assert (d.status, d.code) == ("BLOCKED", "explain_key_mismatch")


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
            if sql == A.EXPLAIN_LEFTOVER_SQL:
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
    dict(explain_key=key(time="2000-01-01-00.00.00.000000")), dict(objects=[("DB2INST1", "EMPLOYEE_INFO", "TA")]),
    dict(operators=[]), dict(query_error_on="EXPLAIN_OBJECT"), dict(explain_error=DbError("x")),
    dict(prepare_error=DbError("x")),
])
def test_every_path_ends_with_rollback_and_no_explain_rows(over):
    _, fake = run(**over)
    assert fake.kinds()[-1] == "rollback" and not fake.explain_rows_present
