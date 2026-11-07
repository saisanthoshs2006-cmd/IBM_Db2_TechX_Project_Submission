"""Row cap applied to the outermost query. Offline."""
import pytest

from db2intel.guard.lexer import GuardViolation
from db2intel.guard.parser import guard_sql
from guard_fakes import no_db_driver  # noqa: F401

A = {"DB2INTEL_DEMO"}
CAP = " FETCH FIRST 500 ROWS ONLY"


def cap(sql, max_rows=500):
    return guard_sql(sql, A, max_rows)


def test_cap_is_appended_when_absent():
    g = cap("SELECT * FROM DB2INTEL_DEMO.CUSTOMER")
    assert g.text == "SELECT * FROM DB2INTEL_DEMO.CUSTOMER" + CAP
    assert (g.cap_action, g.original_fetch, g.row_cap) == ("appended", None, 500)


def test_larger_fetch_is_lowered():
    g = cap("SELECT * FROM DB2INTEL_DEMO.CUSTOMER FETCH FIRST 100000 ROWS ONLY")
    assert g.text.endswith(CAP) and g.text.count("FETCH") == 1
    assert (g.cap_action, g.original_fetch) == ("lowered", 100000)


@pytest.mark.parametrize("clause,expected", [
    ("FETCH FIRST 10 ROWS ONLY", 10), ("FETCH NEXT 5 ROW ONLY", 5), ("FETCH FIRST ROW ONLY", 1),
    ("FETCH FIRST 500 ROWS ONLY", 500), ("FETCH FIRST 0 ROWS ONLY", 0),
])
def test_smaller_fetch_is_kept(clause, expected):
    g = cap(f"SELECT * FROM DB2INTEL_DEMO.CUSTOMER {clause}")
    assert g.cap_action == "kept" and g.original_fetch == expected and g.text.endswith(clause)


def test_order_by_and_offset_are_kept_before_the_cap():
    g = cap("SELECT * FROM DB2INTEL_DEMO.CUSTOMER ORDER BY CUSTOMER_ID DESC OFFSET 20 ROWS")
    assert g.text.endswith("ORDER BY CUSTOMER_ID DESC OFFSET 20 ROWS" + CAP)


def test_cap_applies_to_the_whole_union_not_the_last_branch():
    g = cap("SELECT REGION_NAME FROM DB2INTEL_DEMO.REGION UNION SELECT SEGMENT FROM DB2INTEL_DEMO.CUSTOMER ORDER BY 1")
    assert g.text.endswith("ORDER BY 1" + CAP) and g.cap_action == "appended"


def test_inner_fetch_clauses_do_not_satisfy_the_outer_cap():
    g = cap("SELECT * FROM (SELECT * FROM DB2INTEL_DEMO.CUSTOMER FETCH FIRST 10 ROWS ONLY) T")
    assert g.cap_action == "appended" and g.text.endswith(") T" + CAP)
    g = cap("WITH A AS (SELECT * FROM DB2INTEL_DEMO.CUSTOMER FETCH FIRST 9 ROWS ONLY) SELECT * FROM A")
    assert g.cap_action == "appended" and g.text.endswith("FROM A" + CAP)
    g = cap("SELECT * FROM DB2INTEL_DEMO.CUSTOMER WHERE CUSTOMER_ID IN "
            "(SELECT CUSTOMER_ID FROM DB2INTEL_DEMO.SALES_ORDER FETCH FIRST 3 ROWS ONLY)")
    assert g.cap_action == "appended"


def test_inner_fetch_larger_than_cap_is_left_alone_outer_is_capped():
    g = cap("SELECT * FROM (SELECT * FROM DB2INTEL_DEMO.CUSTOMER FETCH FIRST 999999 ROWS ONLY) T")
    assert "FETCH FIRST 999999 ROWS ONLY) T" + CAP in g.text


def test_parenthesized_top_level_query_gets_an_outer_cap():
    g = cap("(SELECT * FROM DB2INTEL_DEMO.CUSTOMER FETCH FIRST 1000 ROWS ONLY)")
    assert g.text == "(SELECT * FROM DB2INTEL_DEMO.CUSTOMER FETCH FIRST 1000 ROWS ONLY)" + CAP


def test_semicolon_is_dropped_before_the_cap():
    assert cap("SELECT * FROM DB2INTEL_DEMO.CUSTOMER;").text == "SELECT * FROM DB2INTEL_DEMO.CUSTOMER" + CAP


@pytest.mark.parametrize("clause", [
    "FETCH FIRST 1.5 ROWS ONLY", "FETCH FIRST 1E3 ROWS ONLY", "FETCH FIRST -1 ROWS ONLY",
    "FETCH FIRST 9999999999 ROWS ONLY", "FETCH FIRST 10 ROWS", "FETCH 10 ROWS ONLY",
    "FETCH FIRST (10) ROWS ONLY", "OFFSET 1.5 ROWS", "FETCH FIRST 10 ROWS ONLY FETCH FIRST 5 ROWS ONLY",
    "FETCH FIRST 5 ROWS ONLY ORDER BY 1",
])
def test_malformed_fetch_clauses_are_rejected(clause):
    with pytest.raises(GuardViolation):
        cap(f"SELECT * FROM DB2INTEL_DEMO.CUSTOMER {clause}")


@pytest.mark.parametrize("bad", [0, -1, 100_001, True, 1.5, "500", None])
def test_invalid_row_cap_setting_is_refused(bad):
    with pytest.raises(ValueError):
        guard_sql("SELECT * FROM DB2INTEL_DEMO.CUSTOMER", A, bad)


def test_cap_of_one_row():
    g = cap("SELECT * FROM DB2INTEL_DEMO.CUSTOMER FETCH FIRST 2 ROWS ONLY", max_rows=1)
    assert g.text.endswith("FETCH FIRST 1 ROWS ONLY") and g.cap_action == "lowered"
