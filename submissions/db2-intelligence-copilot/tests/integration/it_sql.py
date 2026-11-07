"""Every SQL statement the G2 integration run may send to Db2, in one place.

Nothing here connects to anything. The guarded driver (it_driver.py) refuses any statement
that is not listed here, and `python -m integration.it_sql` prints the complete list for review.

Kinds:
  SELECT      read-only; prepared and executed
  PREPARE     prepared (compiled) but never executed: the marked guard statements, the IT1 probe
  CALL        SYSPROC.EXPLAIN_FROM_SECTION: writes EXPLAIN rows into DB2INTEL inside the open
              unit of work; they are rolled back and the rollback is verified by counts
Nothing in G2 commits. There is no INSERT, UPDATE, DELETE, MERGE, DDL, GRANT or SET statement.
"""
from __future__ import annotations

import re

from db2intel.guard import analysis as A
from db2intel.guard import context as C
from db2intel.guard import rules
from db2intel.guard.parser import guard_sql

EXPLAIN_SCHEMA = "DB2INTEL"
EXPECTED_DATABASE = "TESTDB"
EXPLAIN_TABLE_NAMES = tuple(sorted(C.EXPLAIN_TABLES))  # the 11 tables created by migration 003
PROTECTED_TABLES = ("EMPLOYEE_INFO", "EMPLOYEE_SALARY")
# (row count, first 16 hex digits of the sha256 fingerprint) recorded before Phase 2B.
EXPECTED_FINGERPRINTS = {"EMPLOYEE_INFO": (3, "c6e96adb4bcfc5d5"), "EMPLOYEE_SALARY": (3, "9f9edd2017255f98")}
EXPECTED_MIGRATIONS = ("001", "002", "003")

# ---- snapshots (G2.1 and before/after every G2 step) ------------------------------------------
SERVER_SQL = C.SERVER_SQL  # SELECT CURRENT SERVER, SESSION_USER FROM SYSIBM.SYSDUMMY1
EXPLAIN_COUNT_SQL = {t: f"SELECT COUNT(*) FROM {EXPLAIN_SCHEMA}.{t}" for t in EXPLAIN_TABLE_NAMES}
AUDIT_COUNT_SQL = "SELECT COUNT(*) FROM DB2INTEL.QUERY_AUDIT"
LEDGER_SQL = ("SELECT MIGRATION_ID, CHECKSUM_SHA256, APPLIED_AT, APPLIED_BY, EXECUTION_MS "
              "FROM DB2INTEL.SCHEMA_MIGRATION ORDER BY 1")
PROTECTED_SQL = {t: f"SELECT * FROM DB2INST1.{t}" for t in PROTECTED_TABLES}

# ---- IT1: query timeout read-back, no execution ------------------------------------------------
IT1_PROBE_SQL = "SELECT 1 FROM SYSIBM.SYSDUMMY1"  # prepared only

# ---- IT2: EXPLAIN_FROM_SECTION through callproc and through a prepared CALL ------------------
PK_LOOKUP = "SELECT C.COMPANY_NAME FROM DB2INTEL_DEMO.CUSTOMER C WHERE C.CUSTOMER_ID = 42"  # prepared only
MARKED_PK_LOOKUP_RE = re.compile(r"\A/\* " + re.escape(rules.MARKER_PREFIX) + r"[0-9A-F]{32} \*/ "
                                 + re.escape(PK_LOOKUP) + r"\Z")
EXPLAIN_PROC = "SYSPROC.EXPLAIN_FROM_SECTION"
CALL_EXPLAIN_SQL = A.EXPLAIN_CALL_SQL  # the production guard's bounded CALL (G2.4)
assert CALL_EXPLAIN_SQL == f"CALL {EXPLAIN_PROC}(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
IT2_SELECTS = {
    "CACHE_LOOKUP (by marker)": A.CACHE_LOOKUP_SQL,
    "EXPLAIN_LOCATE (by marker)": A.EXPLAIN_LOCATE_SQL,
    "EXPLAIN_INSTANCE count (by key)": A.EXPLAIN_INSTANCE_SQL,
    "EXPLAIN_STATEMENT (by key)": A.EXPLAIN_STATEMENT_SQL,
    "EXPLAIN_OBJECT (by key)": A.EXPLAIN_OBJECT_SQL,
    "EXPLAIN_OPERATOR (by key)": A.EXPLAIN_OPERATOR_SQL,
    "LEFTOVER EXPLAIN_STATEMENT (by marker)": A.EXPLAIN_LEFTOVER_SQL,
}

# ---- IT3: the production guard (preflight + analyze) on fixed queries ------------------------
IT3_ALLOWED_SCHEMAS = frozenset({"DB2INTEL_DEMO"})
IT3_MAX_ROWS = 500  # query.max_rows seeded by migration 001; preflight must report the same
IT3_QUERIES = (  # (label, user SQL, expected status) -- the Phase 2B end-to-end set
    ("pk lookup", PK_LOOKUP, A.APPROVED),
    ("regional report",
     "SELECT R.REGION_NAME, SUM(I.LINE_AMOUNT) AS NET FROM DB2INTEL_DEMO.ORDER_ITEM I "
     "JOIN DB2INTEL_DEMO.SALES_ORDER O ON O.ORDER_ID = I.ORDER_ID "
     "JOIN DB2INTEL_DEMO.CUSTOMER C ON C.CUSTOMER_ID = O.CUSTOMER_ID "
     "JOIN DB2INTEL_DEMO.REGION R ON R.REGION_ID = C.REGION_ID GROUP BY R.REGION_NAME ORDER BY NET DESC",
     A.APPROVED),
    ("view (expanded)", "SELECT SEGMENT, SUM(NET_AMOUNT) FROM DB2INTEL_DEMO.V_ORDER_SUMMARY GROUP BY SEGMENT", A.APPROVED),
    ("runaway cross join",
     "SELECT COUNT(*) FROM DB2INTEL_DEMO.ORDER_ITEM A CROSS JOIN DB2INTEL_DEMO.ORDER_ITEM B "
     "CROSS JOIN DB2INTEL_DEMO.SALES_ORDER S", A.COST_REJECTED),
    ("protected table", "SELECT * FROM DB2INST1.EMPLOYEE_INFO", A.BLOCKED),  # static: never reaches Db2
)
IT3_GUARDED = {label: guard_sql(sql, IT3_ALLOWED_SCHEMAS, IT3_MAX_ROWS).text
               for label, sql, status in IT3_QUERIES if status != A.BLOCKED}
IT3_SELECTS = {
    "preflight STMT_CONC": C.STMT_CONC_SQL,
    "preflight EXPLAIN tables": C.EXPLAIN_TABLES_SQL,
    "preflight LIMITS": C.LIMITS_SQL,
    "preflight SOURCES": C.SOURCES_SQL,
    "preflight UDF shadowing": C.udf_shadow_sql(len(rules.ALLOWED_FUNCTIONS)),
    "SYSCAT.INDEXES (index owner)": A.INDEX_TABLE_SQL,
    "LEFTOVER EXPLAIN_OBJECT (by key)": A.LEFTOVER_BY_KEY_SQL["EXPLAIN_OBJECT"],
    "LEFTOVER EXPLAIN_OPERATOR (by key)": A.LEFTOVER_BY_KEY_SQL["EXPLAIN_OPERATOR"],
}
# Statements that may be prepared (never executed) behind a guard marker.
MARKED_RE = re.compile(r"\A/\* " + re.escape(rules.MARKER_PREFIX) + r"[0-9A-F]{32} \*/ (?P<body>[^\r\n]+)\Z")
MARKED_BODIES = frozenset({PK_LOOKUP, *IT3_GUARDED.values()})


def is_allowed_marked(sql) -> bool:
    match = MARKED_RE.match(sql) if isinstance(sql, str) else None
    return match is not None and match.group("body") in MARKED_BODIES


SELECT_SQL: dict[str, str] = {
    "server identity": SERVER_SQL,
    **{f"count DB2INTEL.{t}": sql for t, sql in EXPLAIN_COUNT_SQL.items()},
    "count DB2INTEL.QUERY_AUDIT": AUDIT_COUNT_SQL,
    "migration ledger": LEDGER_SQL,
    **{f"fingerprint DB2INST1.{t}": sql for t, sql in PROTECTED_SQL.items()},
    **IT2_SELECTS,
    **IT3_SELECTS,
}
EXECUTABLE_SQL = frozenset(SELECT_SQL.values()) | {CALL_EXPLAIN_SQL}
PREPARE_ONLY_SQL = frozenset({IT1_PROBE_SQL})  # plus marked statements (is_allowed_marked)

_WRITE_WORD = re.compile(r"\b(INSERT|UPDATE|DELETE|MERGE|DROP|CREATE|ALTER|GRANT|REVOKE|COMMIT|SET|"
                         r"TRUNCATE|CALL|RUNSTATS|REORG|LOAD|IMPORT|EXPORT)\b", re.I)


def is_plain_select(sql: str) -> bool:
    return sql.startswith("SELECT ") and not _WRITE_WORD.search(sql) and ";" not in sql


def listing() -> list[tuple[str, str, str]]:
    """(kind, label, sql) for every statement, in review order."""
    rows = [("SELECT", label, sql) for label, sql in SELECT_SQL.items()]
    rows.append(("PREPARE", "IT1 timeout probe (never executed)", IT1_PROBE_SQL))
    rows.append(("PREPARE", "IT2 marked PK lookup (never executed)",
                 f"/* {rules.MARKER_PREFIX}<32 hex digits> */ {PK_LOOKUP}"))
    for label, text in IT3_GUARDED.items():
        rows.append(("PREPARE", f"IT3 marked guard statement: {label} (never executed)",
                     f"/* {rules.MARKER_PREFIX}<32 hex digits> */ {text}"))
    rows.append(("CALL", "IT2/IT3 prepared CALL, statement timeout read back first (writes EXPLAIN rows, rolled back)",
                 CALL_EXPLAIN_SQL))
    rows.append(("CALL", "IT2 ibm_db.callproc (writes EXPLAIN rows, rolled back)",
                 f"ibm_db.callproc(conn, '{EXPLAIN_PROC}', (<executable id>, 'M', NULL, -1, '{EXPLAIN_SCHEMA}' INOUT, 5 OUT))"))
    rows.append(("ATTR", "statement query timeout (every prepare; read back from the statement)",
                 "ibm_db.prepare(conn, sql, {SQL_ATTR_QUERY_TIMEOUT: n}); ibm_db.get_option(stmt, SQL_ATTR_QUERY_TIMEOUT, 0)"))
    rows.append(("ATTR", "IT1/IT2 connection default timeout (client attribute, not SQL)",
                 "ibm_db.set_option(conn, {SQL_ATTR_QUERY_TIMEOUT: n}, 1); ibm_db.get_option(conn, SQL_ATTR_QUERY_TIMEOUT, 1)"))
    return rows


if __name__ == "__main__":
    for kind, label, sql in listing():
        print(f"{kind:8} {label}\n         {sql}")
