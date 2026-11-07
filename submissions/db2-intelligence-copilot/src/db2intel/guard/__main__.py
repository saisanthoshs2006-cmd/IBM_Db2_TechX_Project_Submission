"""SQL guard command line.

    python -m db2intel.guard lint  "<sql>"   offline static check and row cap; no database
    python -m db2intel.guard check "<sql>"   prepare-only cost + EXPLAIN analysis; never executes
                                             the query, never commits (Phase 2B, needs approval)

There is deliberately no command that executes a query: execution needs a dedicated restricted
Db2 user and audit persistence, neither of which exists yet.
"""
from __future__ import annotations

import argparse
import sys

from db2intel.guard.lexer import GuardViolation
from db2intel.guard.parser import guard_sql

DEFAULT_LINT_SCHEMAS = ("DB2INTEL_DEMO",)
DEFAULT_LINT_MAX_ROWS = 500


def _read_sql(value: str) -> str:
    return sys.stdin.read() if value == "-" else value


def _lint(sql: str, schemas, max_rows: int) -> int:
    try:
        guarded = guard_sql(sql, schemas, max_rows)
    except GuardViolation as exc:
        print(f"BLOCKED [{exc.code}] {exc}", file=sys.stderr)
        return 1
    print(f"OK  tables: {', '.join(f'{s}.{n}' for s, n in guarded.tables)}")
    print(f"    row cap {guarded.row_cap} ({guarded.cap_action}); functions: {', '.join(guarded.functions) or '-'}")
    print(guarded.text)
    return 0


def _open_analysis():  # separated so tests can replace it
    from db2intel.config import load_settings
    from db2intel.db.connection import Db2Connection
    from db2intel.db.migrate import check_migration_host
    from db2intel.guard.sessions import Db2AnalysisSession

    settings = load_settings()
    check_migration_host(settings.db2, settings.migration.allowed_hosts)
    conn = Db2Connection(settings.db2)
    return conn, Db2AnalysisSession(conn), settings.migration.allowed_databases


def _check(sql: str) -> int:
    from db2intel.guard.analysis import analyze
    from db2intel.guard.context import load_guard_context

    conn, session, databases = _open_analysis()
    try:
        try:
            ctx = load_guard_context(session, databases)
        finally:
            session.rollback()
        decision = analyze(sql, session, ctx)
    finally:
        conn.close()
    print(f"{decision.status} [{decision.code}] {decision.reason}")
    if decision.estimated_cost is not None:
        print(f"    estimated cost {decision.estimated_cost:,.0f} timerons (limit {ctx.limits.max_estimated_cost:,.0f})")
    for schema, name, kind in decision.objects:
        print(f"    reads {kind} {schema}.{name}")
    for op in decision.plan:
        print(f"    plan  #{op.operator_id} {op.operator_type} cost {op.total_cost:,.1f}")
    if decision.sql:
        print(decision.sql)
    return 0 if decision.approved else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m db2intel.guard", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    lint = sub.add_parser("lint", help="offline static check; no database connection")
    lint.add_argument("sql", help='SQL text, or "-" to read from stdin')
    lint.add_argument("--schema", action="append", help="allowed schema (default DB2INTEL_DEMO)")
    lint.add_argument("--max-rows", type=int, default=DEFAULT_LINT_MAX_ROWS)
    check = sub.add_parser("check", help="prepare-only analysis against Db2 (never executes the query)")
    check.add_argument("sql", help='SQL text, or "-" to read from stdin')
    args = parser.parse_args(argv)

    from db2intel.config import ConfigError
    from db2intel.db.connection import DbError
    from db2intel.db.migrate import MigrationError
    from db2intel.guard.context import PreflightError

    try:
        if args.command == "lint":
            return _lint(_read_sql(args.sql), tuple(args.schema or DEFAULT_LINT_SCHEMAS), args.max_rows)
        return _check(_read_sql(args.sql))
    except (ValueError, PreflightError, DbError, ConfigError, MigrationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
