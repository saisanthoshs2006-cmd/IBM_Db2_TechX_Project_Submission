"""Offline model of the 002_demo_data.sql generators.

The SQL runs inside Db2, so these tests re-implement its formulas in Python
(Db2 integer division truncates, like //, for the non-negative values used here)
and read reference data straight from the SQL file. Formula 'anchors' assert the
SQL still contains the exact expressions modelled here, so the two cannot drift.
After migration, the same facts are re-checked with SQL against Db2.
"""
import datetime as dt
import math
import re
from collections import Counter
from decimal import ROUND_DOWN, Decimal

import pytest

from conftest import SQL_DIR

SQL = (SQL_DIR / "002_demo_data.sql").read_text()
CUTOFF = dt.date(2026, 10, 31)

ANCHORS = [
    "WHERE N < 240",
    "WHERE N < 3000",
    "JOIN PREFIX P ON P.IDX = MOD(S.N - 1, 30)",
    "JOIN IND    I ON I.IDX = (S.N - 1) / 30",
    "JOIN LOC    L ON L.IDX = MOD(S.N * 7, 12)",
    "DATE('2025-01-01') + INTEGER(669 * SQRT(DOUBLE(MOD(N * 37, 669)) / 669)) DAYS",
    "THEN 10 * ((MOD((N / 4) * 7, 48) + 1) / 2) + MOD(MOD((N / 4) * 7, 48) + 1, 2)",
    "ELSE 1 + MOD((N - N / 4) * 97, 240) END",
    "ORDER_DATE + (1 + MOD(N, 9)) DAYS",
    "JOIN LINES L ON L.LINE_NO <= 1 + MOD(O.ORDER_ID * 13, 4)",
    "CASE WHEN 1 + MOD(O.ORDER_ID * 31 + L.LINE_NO * 17, 23) = 23 THEN 24",
    "CASE WHEN P.UNIT_PRICE >= 20000 THEN 1 + MOD(K.ORDER_ID + K.LINE_NO * 3, 3)",
    "WHEN K.SEGMENT = 'ENTERPRISE' THEN 5 + MOD(K.ORDER_ID * 7 + K.LINE_NO, 26)",
    "ELSE 1 + MOD(K.ORDER_ID * 7 + K.LINE_NO, 10) END",
    "CASE WHEN K.SEGMENT = 'ENTERPRISE' AND MOD(K.ORDER_ID + K.LINE_NO, 3) = 0 THEN 15.00",
    "WHEN MOD(K.ORDER_ID + K.LINE_NO, 10) = 1 THEN 10.00",
    "WHEN MOD(K.ORDER_ID + K.LINE_NO, 10) = 2 THEN 5.00",
    "ELSE 0.00 END",
    "CASE WHEN MOD(S.N, 10) < 2 THEN 'ENTERPRISE'",
    "WHEN MOD(S.N, 10) < 5 THEN 'MID_MARKET'",
    "CASE WHEN MOD(N, 20) = 0 THEN 'CANCELLED'",
    "WHEN MOD(N, 20) = 1 THEN 'RETURNED'",
    "WHEN MOD(N, 20) IN (2, 3) THEN 'PENDING'",
    "WHEN MOD(N, 20) BETWEEN 4 AND 7 THEN 'SHIPPED'",
    "WHEN ORDER_DATE + (1 + MOD(N, 9)) DAYS > DATE('2026-10-31') THEN 'PENDING'",
    "WHEN RAW_STATUS = 'PENDING' AND ORDER_DATE >= DATE('2026-10-01') THEN 'PENDING'",
    "WHEN RAW_STATUS = 'SHIPPED' AND ORDER_DATE < DATE('2026-09-01') THEN 'DELIVERED'",
    "(DECIMAL(QUANTITY * UNIT_PRICE * (100 - DISCOUNT_PCT) / 100, 14, 2))",
]


def test_every_discount_in_sql_gives_exact_cent_amounts_for_every_price_and_quantity():
    """Independent of the model: any (discount literal, catalog price, quantity 1..30) is exact to the cent."""
    item_insert = SQL.split("INSERT INTO DB2INTEL_DEMO.ORDER_ITEM")[1]
    discounts = {Decimal(d) for d in re.findall(r"THEN (\d+\.\d\d)\b", item_insert)} | {Decimal("0.00")}
    assert discounts == {Decimal("0.00"), Decimal("5.00"), Decimal("10.00"), Decimal("15.00")}
    for d in discounts:
        for p in PRODUCTS.values():
            for q in range(1, 31):
                exact = Decimal(q) * p["price"] * (100 - d) / 100
                assert exact == exact.quantize(Decimal("0.01")), (d, p["sku"], q)


@pytest.mark.parametrize("anchor", ANCHORS)
def test_sql_still_contains_modelled_formula(anchor):
    assert anchor in SQL


# ---- reference data parsed from the SQL ------------------------------------------------
PRODUCTS = {
    int(m[0]): {"sku": m[1], "name": m[2], "category": m[3], "price": Decimal(m[4]), "cost": Decimal(m[5]),
                "launch": dt.date.fromisoformat(m[6]), "active": int(m[7])}
    for m in re.findall(r"\(\s*(\d+), '([^']+)', +'([^']+)', +'([^']+)', +([\d.]+), +([\d.]+), '([\d-]+)', ([01])\)", SQL)
}
PREFIXES = dict((int(i), w) for i, w in re.findall(r"\((\d+), '([A-Z][a-z]+)'\)", SQL.split("PREFIX (IDX, WORD)")[1].split("IND (")[0]))
INDUSTRIES = {int(i): (n, s) for i, n, s in re.findall(r"\((\d+), '([^']+)', '([^']+)'\)", SQL.split("IND (IDX, NAME, SUFFIX)")[1].split("LOC (")[0])}
LOCATIONS = {int(i): int(r) for i, r, _c, _t in re.findall(r"\((\d+), (\d), '([^']+)', '([^']+)'\)", SQL.split("LOC (IDX")[1].split("SELECT")[0])}


def segment(n):
    return "ENTERPRISE" if n % 10 < 2 else "MID_MARKET" if n % 10 < 5 else "SMB"


def build():
    customers = {n: {"name": f"{PREFIXES[(n - 1) % 30]} {INDUSTRIES[(n - 1) // 30][1]}", "segment": segment(n),
                     "region": LOCATIONS[n * 7 % 12]} for n in range(1, 241)}
    orders = {}
    for n in range(1, 3001):
        od = dt.date(2025, 1, 1) + dt.timedelta(days=int(669 * math.sqrt((n * 37 % 669) / 669)))
        raw = ("CANCELLED" if n % 20 == 0 else "RETURNED" if n % 20 == 1 else "PENDING" if n % 20 in (2, 3)
               else "SHIPPED" if 4 <= n % 20 <= 7 else "DELIVERED")
        sc = od + dt.timedelta(days=1 + n % 9)
        status = ("CANCELLED" if raw == "CANCELLED" else "PENDING" if sc > CUTOFF
                  else "PENDING" if raw == "PENDING" and od >= dt.date(2026, 10, 1)
                  else "DELIVERED" if raw == "PENDING"
                  else "DELIVERED" if raw == "SHIPPED" and od < dt.date(2026, 9, 1) else raw)
        if n % 4 == 0:
            k = ((n // 4) * 7) % 48
            cid = 10 * ((k + 1) // 2) + (k + 1) % 2
        else:
            cid = 1 + ((n - n // 4) * 97) % 240
        orders[n] = {"date": od, "status": status, "customer": cid,
                     "ship": None if status in ("PENDING", "CANCELLED") else sc}
    lines = []
    for oid, o in orders.items():
        seg = customers[o["customer"]]["segment"]
        for ln in range(1, 2 + (oid * 13) % 4):
            raw = 1 + (oid * 31 + ln * 17) % 23
            pid = 24 if raw == 23 else raw
            price = PRODUCTS[pid]["price"]
            qty = (1 + (oid + ln * 3) % 3 if price >= 20000 else 5 + (oid * 7 + ln) % 26
                   if seg == "ENTERPRISE" else 1 + (oid * 7 + ln) % 10)
            disc = (Decimal("15.00") if seg == "ENTERPRISE" and (oid + ln) % 3 == 0 else Decimal("10.00")
                    if (oid + ln) % 10 == 1 else Decimal("5.00") if (oid + ln) % 10 == 2 else Decimal("0.00"))
            exact = Decimal(qty) * price * (100 - disc) / 100
            amount = exact.quantize(Decimal("0.01"), rounding=ROUND_DOWN)  # DECIMAL(...,14,2) truncates
            lines.append({"order": oid, "line": ln, "product": pid, "qty": qty, "price": price,
                          "disc": disc, "amount": amount, "exact": exact})
    return customers, orders, lines


CUSTOMERS, ORDERS, LINES = build()


# ---- fictional data ---------------------------------------------------------------------
def test_reference_data_parsed_completely():
    assert len(PRODUCTS) == 24 and len(PREFIXES) == 30 and len(INDUSTRIES) == 8 and len(LOCATIONS) == 12


def test_company_names_are_unique_invented_brands():
    names = [c["name"] for c in CUSTOMERS.values()]
    assert len(set(names)) == 240
    assert all(re.fullmatch(r"[A-Z][a-z]{5,8}", w) for w in PREFIXES.values())
    assert len(set(PREFIXES.values())) == 30


def test_no_personal_data_columns_exist():
    ddl = SQL.upper()
    for column in ["EMAIL", "PHONE", "FIRST_NAME", "LAST_NAME", "ADDRESS", "BIRTH", "SSN", "PAN", "AADHAAR"]:
        assert not re.search(rf"\b{column}\w*\s+(VAR)?CHAR", ddl), column


# ---- constraint emulation ------------------------------------------------------------------
def test_every_customer_has_orders_and_every_enterprise_account_is_boosted():
    counts = Counter(o["customer"] for o in ORDERS.values())
    assert len(counts) == 240 and min(counts.values()) >= 9
    boosted = {o["customer"] for n, o in ORDERS.items() if n % 4 == 0}
    assert len(boosted) == 48 and all(CUSTOMERS[c]["segment"] == "ENTERPRISE" for c in boosted)


def test_order_dates_and_ship_status_rules():
    for o in ORDERS.values():
        assert dt.date(2025, 1, 1) <= o["date"] <= CUTOFF
        if o["status"] in ("PENDING", "CANCELLED"):
            assert o["ship"] is None
        else:
            assert o["date"] <= o["ship"] <= CUTOFF
        if o["status"] == "PENDING":
            assert o["date"] >= dt.date(2026, 10, 1)


def test_lines_respect_check_constraints_and_catalog():
    assert len(LINES) == 7500
    assert len({(l["order"], l["line"]) for l in LINES}) == 7500  # primary key
    for l in LINES:
        p = PRODUCTS[l["product"]]
        assert l["qty"] > 0 and 0 <= l["disc"] <= 100
        assert p["active"] == 1, "discontinued product sold"
        assert p["launch"] <= ORDERS[l["order"]]["date"], "sold before launch"
        assert l["price"] == p["price"]


# ---- revenue consistency -------------------------------------------------------------------
def test_line_amount_is_exact_to_the_cent():
    """No truncation happens: every line's exact value already has at most 2 decimals."""
    assert all(l["amount"] == l["exact"] for l in LINES)


def test_net_equals_gross_minus_discount_and_margin_is_positive():
    for l in LINES:
        gross = l["qty"] * l["price"]
        assert l["amount"] == gross - gross * l["disc"] / 100
        assert l["amount"] <= gross
        assert l["amount"] > l["qty"] * PRODUCTS[l["product"]]["cost"], "negative margin line"


def test_order_and_total_revenue_add_up():
    by_order = Counter()
    for l in LINES:
        by_order[l["order"]] += l["amount"]
    assert sum(by_order.values()) == sum(l["amount"] for l in LINES)
    assert len(by_order) == 3000
    assert max(l["amount"] for l in LINES) < Decimal("1e12")  # fits DECIMAL(14,2)


def test_products_cost_never_exceeds_price():
    assert all(Decimal(0) <= p["cost"] <= p["price"] for p in PRODUCTS.values())
    assert {pid for pid, p in PRODUCTS.items() if not p["active"]} == {23}
