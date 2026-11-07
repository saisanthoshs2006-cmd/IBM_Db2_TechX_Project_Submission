"""Read-only database snapshot for the G2 integration run (promoted from the Phase 2B probe).

A snapshot holds:
  server     CURRENT SERVER and SESSION_USER
  explain    row counts of the 11 DB2INTEL explain tables
  audit_rows row count of DB2INTEL.QUERY_AUDIT
  ledger     the migration ledger rows (DB2INTEL.SCHEMA_MIGRATION)
  protected  DB2INST1.EMPLOYEE_INFO / EMPLOYEE_SALARY: row count and sha256 of all rows (the
             MigrationRunner method). Only the count and the hash are kept, never the rows.

Every statement is a SELECT from it_sql. The snapshot runs on its own new connection with
autocommit OFF, rolls back and closes. `python -m integration.snapshot OUT.json` takes one
snapshot through the guarded driver and writes it atomically; exit 0 only if it is complete.
The pure functions (snapshot_problems, baseline_problems, compare) need no database.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

from integration import it_sql as Q

PARTS = ("server", "explain", "audit_rows", "ledger", "protected")


def fingerprint(rows) -> list:
    digest = hashlib.sha256("\n".join(sorted(repr(tuple(r)) for r in rows)).encode()).hexdigest()
    return [len(rows), digest]


def take_snapshot(conn) -> dict:
    """`conn` has query(sql) and rollback(). Returns a JSON-ready dict."""
    try:
        server = conn.query(Q.SERVER_SQL)
        snap = {
            "server": [str(v).strip() for v in server[0]] if len(server) == 1 else None,
            "explain": {t: conn.query(sql)[0][0] for t, sql in Q.EXPLAIN_COUNT_SQL.items()},
            "audit_rows": conn.query(Q.AUDIT_COUNT_SQL)[0][0],
            "ledger": [[str(v) for v in row] for row in conn.query(Q.LEDGER_SQL)],
            "protected": {t: fingerprint(conn.query(sql)) for t, sql in Q.PROTECTED_SQL.items()},
        }
    finally:
        conn.rollback()
    return snap


# ---- pure checks --------------------------------------------------------------------------
def snapshot_problems(snap) -> list[str]:
    """Structure check: a snapshot the comparison can trust."""
    if not isinstance(snap, dict) or set(snap) != set(PARTS):
        return ["snapshot does not have exactly the parts " + ", ".join(PARTS)]
    problems = []
    server = snap["server"]
    if not isinstance(server, list) or len(server) != 2 or not all(isinstance(v, str) and v for v in server):
        problems.append("server identity is malformed")
    explain = snap["explain"]
    if not isinstance(explain, dict) or tuple(sorted(explain)) != Q.EXPLAIN_TABLE_NAMES:
        problems.append("snapshot does not list exactly the 11 explain tables")
    elif not all(type(n) is int and n >= 0 for n in explain.values()):
        problems.append("explain table counts are not non-negative integers")
    if type(snap["audit_rows"]) is not int or snap["audit_rows"] < 0:
        problems.append("QUERY_AUDIT count is not a non-negative integer")
    if not isinstance(snap["ledger"], list) or not all(isinstance(r, list) and len(r) == 5 for r in snap["ledger"]):
        problems.append("ledger rows are malformed")
    protected = snap["protected"]
    if not isinstance(protected, dict) or set(protected) != set(Q.EXPECTED_FINGERPRINTS) or not all(
            isinstance(v, list) and len(v) == 2 and type(v[0]) is int and isinstance(v[1], str) and len(v[1]) == 64
            for v in protected.values()):
        problems.append("employee fingerprints are malformed")
    return problems


def baseline_problems(snap) -> list[str]:
    """The state every G2 step must start from (and, being read-only or rolled back, end in)."""
    problems = snapshot_problems(snap)
    if problems:
        return problems
    if snap["server"][0] != Q.EXPECTED_DATABASE:
        problems.append(f"connected to {snap['server'][0]}, expected {Q.EXPECTED_DATABASE}")
    nonzero = {t: n for t, n in snap["explain"].items() if n != 0}
    if nonzero:
        problems.append(f"explain tables are not empty: {nonzero}")
    if snap["audit_rows"] != 0:
        problems.append(f"QUERY_AUDIT has {snap['audit_rows']} rows, expected 0")
    ids = [str(r[0])[:3] for r in snap["ledger"]]
    if ids != list(Q.EXPECTED_MIGRATIONS):
        problems.append(f"migration ledger is {ids}, expected {list(Q.EXPECTED_MIGRATIONS)}")
    for table, (count, prefix) in Q.EXPECTED_FINGERPRINTS.items():
        n, digest = snap["protected"][table]
        if (n, digest[:16]) != (count, prefix):
            problems.append(f"DB2INST1.{table} fingerprint is ({n}, {digest[:16]}), expected ({count}, {prefix})")
    return problems


def compare(pre, post) -> dict:
    """Per-part equality; explain counts table by table. {} if either snapshot is malformed."""
    if snapshot_problems(pre) or snapshot_problems(post):
        return {}
    tables = {t: [pre["explain"][t], post["explain"][t]] for t in Q.EXPLAIN_TABLE_NAMES}
    return {
        "server": pre["server"] == post["server"],
        "explain": all(before == after for before, after in tables.values()),
        "explain_tables": tables,
        "audit_rows": pre["audit_rows"] == post["audit_rows"],
        "ledger": pre["ledger"] == post["ledger"],
        "protected": pre["protected"] == post["protected"],
    }


def summary(snap: dict) -> list[str]:
    """Printable lines. Never includes row data: counts, ledger ids and hash prefixes only."""
    lines = [f"server {snap['server'][0]} as {snap['server'][1]}"]
    lines.append("explain tables: " + ", ".join(f"{t}={n}" for t, n in snap["explain"].items()))
    lines.append(f"DB2INTEL.QUERY_AUDIT: {snap['audit_rows']} rows")
    for row in snap["ledger"]:
        lines.append(f"ledger {row[0]} sha256={row[1][:16]}... applied {row[2]} by {row[3]}")
    for t, (n, digest) in snap["protected"].items():
        lines.append(f"DB2INST1.{t}: {n} rows, sha256 {digest[:16]}")
    return lines


# ---- CLI (one snapshot, through the guarded driver) -----------------------------------------
def write_snapshot(out: Path, timeout_s: int = 30) -> int:
    from db2intel.config import load_settings
    from db2intel.db.connection import Db2Connection
    from db2intel.db.migrate import check_migration_host
    from integration import it_driver

    try:
        it_driver.install(timeout_s)
        settings = load_settings()
        check_migration_host(settings.db2, settings.migration.allowed_hosts)
        conn = Db2Connection(settings.db2)
        try:
            snap = take_snapshot(conn)
        finally:
            conn.close()
    except Exception as exc:
        print(f"SNAPSHOT FAILED: {type(exc).__name__}: {exc}")
        return 1
    problems = snapshot_problems(snap)
    if problems:
        print(f"SNAPSHOT MALFORMED: {problems}")
        return 1
    for line in summary(snap):
        print(f"  {line}")
    tmp = out.with_name(out.name + ".partial")
    tmp.write_text(json.dumps(snap, sort_keys=True))
    os.replace(tmp, out)  # the supervisor only ever sees a complete file
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python -m integration.snapshot OUT.json")
        sys.exit(2)
    sys.exit(write_snapshot(Path(sys.argv[1])))
