"""Safe, repeatable migration runner for the Db2 Intelligence schemas.

Commands (run from the project directory with PYTHONPATH=src):
  plan      offline: parse and policy-check the scripts. Never connects to Db2.
  status    read-only: show which migrations are applied.
  up        apply 001_schema_meta.sql, 002_demo_data.sql, 003_explain_tables.sql in that
            order (each in one transaction); already applied scripts are skipped.
  analyze   RUNSTATS on DB2INTEL / DB2INTEL_DEMO tables only (optional, not a migration).
  teardown  drop DB2INTEL_DEMO and DB2INTEL. Requires --confirm "DROP DB2INTEL AND DB2INTEL_DEMO".

Guarantees:
  * Only the scripts in MIGRATIONS run during `up`, in that order. Teardown is a
    separate command and is never reachable from `up`.
  * Every statement passes the static policy in sql_policy before Db2 is contacted.
  * Each script plus its ledger row is one unit of work: success commits both,
    any failure rolls back both, so a partially applied script cannot exist.
  * Applied scripts are skipped. A script edited after it was applied stops the run.
  * A pending script whose schema or tables already exist (without a ledger row) stops
    the run before anything is executed: the runner never guesses about unknown state.
  * The host must be local (default localhost / 127.0.0.1 / ::1) and the connected
    database (CURRENT SERVER, the real name, never an alias) must be allowed
    (default TESTDB). SAMPLE is always refused.
  * DB2INST1 is snapshotted (tables and views with ALTER_TIME, indexes on its tables,
    and a SHA-256 of every row of the protected EMPLOYEE tables) before and after each
    script and teardown, inside the same transaction. Any difference rolls back.
  * Teardown refuses to start if any view, trigger, routine or foreign key OUTSIDE the
    project schemas depends on a project object, because Db2 would make such objects
    inoperative or drop their constraints when the project tables are dropped.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from db2intel.config import PROJECT_ROOT, ConfigError, Db2Settings, load_settings
from db2intel.db.connection import Database, DbError
from db2intel.db.sql_policy import (
    PROJECT_SCHEMAS,
    PolicyViolation,
    check_migration_script,
    check_teardown_script,
    check_vector_dimensions,
    classify_migration_statement,
)
from db2intel.db.sql_script import SqlScript, load_script

SQL_DIR = PROJECT_ROOT / "sql"
MIGRATIONS: tuple[str, ...] = ("001_schema_meta.sql", "002_demo_data.sql", "003_explain_tables.sql")
# Schema each migration creates (003 creates tables in DB2INTEL, which 001 created).
SCHEMA_CREATED_BY = {"001_schema_meta.sql": "DB2INTEL", "002_demo_data.sql": "DB2INTEL_DEMO"}
TEARDOWN_SCRIPT = "900_teardown.sql"
TEARDOWN_CONFIRMATION = "DROP DB2INTEL AND DB2INTEL_DEMO"

PROTECTED_SCHEMA = "DB2INST1"
PROTECTED_TABLES: tuple[str, ...] = ("EMPLOYEE_INFO", "EMPLOYEE_SALARY")
ALWAYS_FORBIDDEN_DATABASES = frozenset({"SAMPLE"})
UNDEFINED_OBJECT_SQLSTATE = "42704"

_IDENT_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


class MigrationError(RuntimeError):
    """The migration could not be applied; the database was left unchanged by the failing step."""


@dataclass(frozen=True)
class MigrationStatus:
    name: str
    state: str  # "applied", "pending" or "modified"
    checksum: str


def load_migrations(sql_dir: Path = SQL_DIR, expected_dim: int | None = None) -> list[SqlScript]:
    scripts = []
    for name in MIGRATIONS:
        script = load_script(sql_dir / name)
        check_migration_script(script)
        if expected_dim is not None:
            check_vector_dimensions(script, expected_dim)
        scripts.append(script)
    return scripts


def created_objects(script: SqlScript) -> set[str]:
    """Qualified names of the tables and views a migration script creates."""
    return {
        info.targets[0]
        for info in (classify_migration_statement(stmt) for stmt in script.statements)
        if info.kind in ("CREATE TABLE", "CREATE VIEW")
    }


def load_teardown(sql_dir: Path = SQL_DIR) -> SqlScript:
    script = load_script(sql_dir / TEARDOWN_SCRIPT)
    check_teardown_script(script)
    return script


def check_migration_host(db2: Db2Settings, allowed_hosts: tuple[str, ...]) -> None:
    """Refuse to connect for write operations unless DB2_HOST is an allowed (local) host."""
    host = db2.host.strip().lower()
    if host not in allowed_hosts:
        raise MigrationError(
            f"refusing to run migrations against host {db2.host!r}: allowed hosts are {list(allowed_hosts)} "
            "(set DB2INTEL_MIGRATION_HOSTS to change)"
        )


# Objects outside the project schemas that depend on project objects. Dropping the
# project tables would make these inoperative (views, triggers), invalidate them
# (routines) or drop their foreign keys, so teardown refuses while any exist.
_FOREIGN_DEPENDENCY_QUERIES: tuple[tuple[str, str], ...] = (
    ("view or MQT",
     "SELECT RTRIM(TABSCHEMA) || '.' || RTRIM(TABNAME), RTRIM(BSCHEMA) || '.' || RTRIM(BNAME) "
     "FROM SYSCAT.TABDEP WHERE BSCHEMA IN (?, ?) AND TABSCHEMA NOT IN (?, ?)"),
    ("trigger",
     "SELECT RTRIM(TRIGSCHEMA) || '.' || RTRIM(TRIGNAME), RTRIM(BSCHEMA) || '.' || RTRIM(BNAME) "
     "FROM SYSCAT.TRIGDEP WHERE BSCHEMA IN (?, ?) AND TRIGSCHEMA NOT IN (?, ?)"),
    ("routine",
     "SELECT RTRIM(ROUTINESCHEMA) || '.' || RTRIM(SPECIFICNAME), RTRIM(BSCHEMA) || '.' || RTRIM(BNAME) "
     "FROM SYSCAT.ROUTINEDEP WHERE BSCHEMA IN (?, ?) AND ROUTINESCHEMA NOT IN (?, ?)"),
    ("foreign key",
     "SELECT RTRIM(TABSCHEMA) || '.' || RTRIM(TABNAME), RTRIM(REFTABSCHEMA) || '.' || RTRIM(REFTABNAME) "
     "FROM SYSCAT.REFERENCES WHERE REFTABSCHEMA IN (?, ?) AND TABSCHEMA NOT IN (?, ?)"),
)


class MigrationRunner:
    def __init__(
        self,
        db: Database,
        sql_dir: Path = SQL_DIR,
        allowed_databases: tuple[str, ...] = ("TESTDB",),
        expected_dim: int | None = None,
        log: Callable[[str], None] = print,
    ):
        self.db = db
        self.sql_dir = sql_dir
        self.allowed_databases = tuple(name.upper() for name in allowed_databases)
        self.expected_dim = expected_dim
        self.log = log

    # ---- read-only inspection -------------------------------------------------
    def current_database(self) -> str:
        return str(self.db.query("SELECT CURRENT SERVER FROM SYSIBM.SYSDUMMY1")[0][0]).strip().upper()

    def check_target(self) -> str:
        name = self.current_database()
        if name in ALWAYS_FORBIDDEN_DATABASES:
            raise MigrationError(f"refusing to run against {name}: it is read-only for this project")
        if name not in self.allowed_databases:
            raise MigrationError(f"refusing to run against {name}: allowed targets are {list(self.allowed_databases)}")
        return name

    def existing_project_schemas(self) -> set[str]:
        rows = self.db.query(
            "SELECT RTRIM(SCHEMANAME) FROM SYSCAT.SCHEMATA WHERE SCHEMANAME IN (?, ?)",
            tuple(sorted(PROJECT_SCHEMAS)),
        )
        return {str(row[0]).strip() for row in rows}

    def existing_project_objects(self) -> set[str]:
        """Tables and views that currently exist in DB2INTEL / DB2INTEL_DEMO, as SCHEMA.NAME."""
        rows = self.db.query(
            "SELECT RTRIM(TABSCHEMA), RTRIM(TABNAME) FROM SYSCAT.TABLES WHERE TABSCHEMA IN (?, ?)",
            tuple(sorted(PROJECT_SCHEMAS)),
        )
        return {f"{str(schema).strip()}.{str(name).strip()}" for schema, name in rows}

    def ledger_exists(self) -> bool:
        rows = self.db.query(
            "SELECT COUNT(*) FROM SYSCAT.TABLES WHERE TABSCHEMA = 'DB2INTEL' AND TABNAME = 'SCHEMA_MIGRATION'"
        )
        return int(rows[0][0]) > 0

    def applied(self) -> dict[str, str]:
        if not self.ledger_exists():
            return {}
        rows = self.db.query("SELECT MIGRATION_ID, CHECKSUM_SHA256 FROM DB2INTEL.SCHEMA_MIGRATION")
        return {str(name).strip(): str(digest).strip() for name, digest in rows}

    def protected_snapshot(self) -> tuple:
        """Fingerprint of DB2INST1: tables/views, indexes on its tables, and protected table contents."""
        tables = tuple(
            (str(name).strip(), str(kind).strip(), str(altered))
            for name, kind, altered in self.db.query(
                "SELECT TABNAME, TYPE, ALTER_TIME FROM SYSCAT.TABLES WHERE TABSCHEMA = ? ORDER BY TABNAME",
                (PROTECTED_SCHEMA,),
            )
        )
        indexes = tuple(
            (str(schema).strip(), str(name).strip(), str(table).strip(), str(created))
            for schema, name, table, created in self.db.query(
                "SELECT INDSCHEMA, INDNAME, TABNAME, CREATE_TIME FROM SYSCAT.INDEXES "
                "WHERE TABSCHEMA = ? ORDER BY INDSCHEMA, INDNAME",
                (PROTECTED_SCHEMA,),
            )
        )
        present = {name for name, _, _ in tables}
        contents = []
        for table in PROTECTED_TABLES:
            if table in present:  # names come from a fixed tuple, never from user input
                rows = self.db.query(f"SELECT * FROM {PROTECTED_SCHEMA}.{table}")
                digest = hashlib.sha256("\n".join(sorted(repr(tuple(r)) for r in rows)).encode()).hexdigest()
                contents.append((table, len(rows), digest))
        return tables, indexes, tuple(contents)

    def foreign_dependents(self) -> list[str]:
        params = tuple(sorted(PROJECT_SCHEMAS)) * 2
        found = []
        for kind, sql in _FOREIGN_DEPENDENCY_QUERIES:
            for dependent, base in self.db.query(sql, params):
                found.append(f"{kind} {str(dependent).strip()} depends on {str(base).strip()}")
        return found

    def status(self) -> list[MigrationStatus]:
        scripts = load_migrations(self.sql_dir, self.expected_dim)
        self.check_target()
        applied = self.applied()
        result = []
        for script in scripts:
            if script.name not in applied:
                state = "pending"
            elif applied[script.name] != script.checksum:
                state = "modified"
            else:
                state = "applied"
            result.append(MigrationStatus(script.name, state, script.checksum))
        return result

    # ---- write operations -----------------------------------------------------
    def up(self) -> list[str]:
        scripts = load_migrations(self.sql_dir, self.expected_dim)  # static checks before any write
        target = self.check_target()
        applied = self.applied()
        existing = self.existing_project_schemas()

        for name, digest in applied.items():
            if name not in MIGRATIONS:
                raise MigrationError(f"ledger contains unknown migration {name!r}; refusing to continue")
        for script in scripts:
            if script.name in applied and applied[script.name] != script.checksum:
                raise MigrationError(
                    f"{script.name} was modified after it was applied (ledger checksum differs). "
                    "Create a new migration instead of editing an applied one."
                )
        for script in scripts:
            schema = SCHEMA_CREATED_BY.get(script.name)
            if script.name not in applied and schema in existing:
                raise MigrationError(
                    f"schema {schema} already exists but {script.name} is not in the ledger. "
                    "Refusing to guess; inspect the database manually."
                )
        pending = [script for script in scripts if script.name not in applied]
        if pending:
            existing_objects = self.existing_project_objects()
            for script in pending:
                clash = sorted(created_objects(script) & existing_objects)
                if clash:
                    raise MigrationError(
                        f"{', '.join(clash)} already exist(s) but {script.name} is not in the ledger. "
                        "Refusing to guess; inspect the database manually."
                    )

        ran: list[str] = []
        for position, script in enumerate(scripts):
            if script.name in applied:
                self.log(f"skip   {script.name} (already applied)")
                continue
            missing = [s.name for s in scripts[:position] if s.name not in applied and s.name not in ran]
            if missing:
                raise MigrationError(f"{script.name} requires {missing} first")
            self._apply(script, target)
            ran.append(script.name)
        if not ran:
            self.log("nothing to do: all migrations are applied")
        return ran

    def _apply(self, script: SqlScript, target: str) -> None:
        self.log(f"apply  {script.name} -> {target} ({len(script.statements)} statements, one transaction)")
        before = self.protected_snapshot()
        started = time.perf_counter()
        index = 0
        try:
            for index, stmt in enumerate(script.statements, start=1):
                self.db.execute(stmt)
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            self.db.execute(
                "INSERT INTO DB2INTEL.SCHEMA_MIGRATION (MIGRATION_ID, CHECKSUM_SHA256, EXECUTION_MS) VALUES (?, ?, ?)",
                (script.name, script.checksum, elapsed_ms),
            )
            if self.protected_snapshot() != before:
                raise MigrationError(f"{PROTECTED_SCHEMA} objects changed during {script.name}")
            self.db.commit()
        except (DbError, MigrationError) as exc:
            self.db.rollback()
            where = f"statement {index} of {len(script.statements)}" if index else "start"
            state = f" SQLSTATE={exc.sqlstate}" if isinstance(exc, DbError) and exc.sqlstate else ""
            raise MigrationError(f"{script.name} failed at {where}{state}: {exc}. Rolled back; nothing was applied.") from None
        except BaseException:
            self.db.rollback()
            raise
        self.log(f"done   {script.name} in {elapsed_ms} ms (committed with ledger row)")

    def analyze(self) -> list[str]:
        """Collect optimizer statistics for project tables. Optional; not a migration."""
        self.check_target()
        rows = self.db.query(
            "SELECT RTRIM(TABSCHEMA), RTRIM(TABNAME) FROM SYSCAT.TABLES "
            "WHERE TABSCHEMA IN (?, ?) AND TYPE = 'T' ORDER BY 1, 2",
            tuple(sorted(PROJECT_SCHEMAS)),
        )
        done = []
        for schema, table in rows:
            schema, table = str(schema), str(table)
            if schema not in PROJECT_SCHEMAS or not _IDENT_RE.match(table):
                raise MigrationError(f"unexpected table name {schema}.{table}")
            command = f"RUNSTATS ON TABLE {schema}.{table} WITH DISTRIBUTION AND INDEXES ALL"
            self.db.execute("CALL SYSPROC.ADMIN_CMD(?)", (command,))
            self.db.commit()
            done.append(f"{schema}.{table}")
            self.log(f"runstats {schema}.{table}")
        return done

    def teardown(self, confirm: str) -> list[str]:
        if confirm != TEARDOWN_CONFIRMATION:
            raise MigrationError(f'teardown requires --confirm "{TEARDOWN_CONFIRMATION}"')
        script = load_teardown(self.sql_dir)
        target = self.check_target()
        dependents = self.foreign_dependents()
        if dependents:
            self.db.rollback()
            raise MigrationError(
                "teardown refused: objects outside DB2INTEL/DB2INTEL_DEMO depend on project objects "
                "and would be made inoperative or altered: " + "; ".join(dependents)
            )
        self.log(f"teardown on {target}: {len(script.statements)} DROP statements, one transaction")
        before = self.protected_snapshot()
        dropped: list[str] = []
        try:
            for stmt in script.statements:
                try:
                    self.db.execute(stmt)
                    dropped.append(" ".join(stmt.split()))
                except DbError as exc:
                    if exc.sqlstate == UNDEFINED_OBJECT_SQLSTATE:
                        self.log(f"skip   {' '.join(stmt.split())} (does not exist)")
                        continue
                    raise
            if self.protected_snapshot() != before:
                raise MigrationError(f"{PROTECTED_SCHEMA} objects changed during teardown")
            self.db.commit()
        except (DbError, MigrationError) as exc:
            self.db.rollback()
            raise MigrationError(f"teardown failed: {exc}. Rolled back; nothing was dropped.") from None
        except BaseException:
            self.db.rollback()
            raise
        return dropped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m db2intel.db.migrate", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", help="offline policy check; no database connection")
    sub.add_parser("status", help="show applied / pending migrations (read-only)")
    sub.add_parser(
        "up",
        help="apply pending migrations in order: 001_schema_meta.sql, 002_demo_data.sql, "
        "003_explain_tables.sql (applied scripts are skipped)",
    )
    sub.add_parser("analyze", help="RUNSTATS on project tables")
    td = sub.add_parser("teardown", help="drop DB2INTEL_DEMO and DB2INTEL")
    td.add_argument("--confirm", default="", help=f'must equal "{TEARDOWN_CONFIRMATION}"')
    args = parser.parse_args(argv)

    try:
        settings = load_settings()
        dim = settings.embedding.dimension
        if args.command == "plan":
            for script in load_migrations(SQL_DIR, dim):
                print(f"ok  {script.name:22} {len(script.statements):3} statements  sha256={script.checksum[:16]}")
            teardown = load_teardown(SQL_DIR)
            print(f"ok  {teardown.name:22} {len(teardown.statements):3} statements  (teardown, separate command)")
            print(f"order: {' -> '.join(MIGRATIONS)}; VECTOR dimension {dim}; no database contacted")
            return 0

        from db2intel.db import connection  # only now is a connection needed

        check_migration_host(settings.db2, settings.migration.allowed_hosts)
        db = connection.Db2Connection(settings.db2)
        try:
            runner = MigrationRunner(db, SQL_DIR, settings.migration.allowed_databases, dim)
            if args.command == "status":
                for item in runner.status():
                    print(f"{item.state:9} {item.name}")
            elif args.command == "up":
                runner.up()
            elif args.command == "analyze":
                runner.analyze()
            elif args.command == "teardown":
                for stmt in runner.teardown(args.confirm):
                    print(f"dropped: {stmt}")
        finally:
            db.close()
    except (MigrationError, PolicyViolation, DbError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
