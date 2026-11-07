# Db2 Intelligence — Enterprise AI Data Copilot

> **One-Line Pitch:** Ask business questions in plain English and get back IBM Db2 SQL that has been
> checked by a strict, Db2-aware SQL guard (static analysis, prepare-only cost estimation and
> `EXPLAIN` plan inspection) before anyone runs it. Generated SQL is never executed automatically.

---

## Table of Contents
- [Problem Statement](#problem-statement)
- [Solution Overview](#solution-overview)
- [Project Status](#project-status)
- [IBM Db2 Integration](#ibm-db2-integration)
- [AI / LLM Architecture](#ai--llm-architecture)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Setup & Installation](#setup--installation)
- [Configuration](#configuration)
- [Running the Project](#running-the-project)
- [Testing & Verification](#testing--verification)
- [Screenshots & Demo](#screenshots--demo)
- [Known Limitations & Future Roadmap](#known-limitations--future-roadmap)
- [Team Members & Credits](#team-members--credits)

---

## Problem Statement
- Business users need answers held in enterprise Db2 databases but cannot write SQL; data teams
  become a bottleneck for routine questions.
- Large language models can write SQL, but generated SQL is untrusted text. It can modify data,
  read tables it should not see, take locks, or run queries that are far too expensive.
- Common text-to-SQL tools rely on prompts ("only write SELECT") or on read-only connection flags.
  Neither is a security boundary.
- **Target users:** enterprise analysts (ask questions), DBAs and platform owners (keep control over
  what can reach the database), and developers building governed AI access to Db2.

---

## Solution Overview
Db2 Intelligence separates *generating* SQL from *trusting* it:

1. **Schema retrieval (RAG):** the question is matched against *schema cards* — table and column
   names, declared types, keys and catalog remarks. Cards never contain row values.
2. **SQL generation:** a local model (Ollama, no paid API) writes one SQL statement from the cards.
   The provider is pluggable; with no model configured the system answers `NO_SQL`.
3. **Static SQL guard:** an allow-list parser accepts exactly one read-only `SELECT`/`WITH` over
   allowed schemas, rejects comments, data-change table references, locking clauses, parameter
   markers, recursive CTEs, table functions and non-allow-listed functions, and enforces a row cap
   (`FETCH FIRST n ROWS ONLY`).
4. **Db2 analysis without execution (human-written SQL only, for now):** Db2 *prepares* the
   statement, the guard reads its cost estimate from the package cache, runs
   `SYSPROC.EXPLAIN_FROM_SECTION`, checks every table and index in the plan, rolls back, and proves
   the explain rows are gone. This runs in a separate worker process with a hard deadline.
5. **No automatic execution.** No API route or CLI command executes SQL. Execution code exists but is
   blocked until a restricted Db2 user and audit persistence are approved.

---

## Project Status

This is a work in progress built in reviewed, gated phases. The table separates what has been
verified against a real Db2 database from what is so far tested only with fakes.

| Capability | Status |
|---|---|
| Migrations 001–003 (metadata schema, demo data, 11 explain tables) | **Verified on Db2** (TESTDB, Db2 12.1.5) |
| Static SQL guard (`lint`) | Offline by design; decisions matched the Db2 probe |
| Prepare-only analysis: package-cache cost, `EXPLAIN_FROM_SECTION`, plan object checks, rollback and leftover verification | **Verified on Db2** (controlled probe, see [Testing](#testing--verification)) |
| Statement-level query timeout read-back | **Verified on Db2** |
| HTTP API (`/health`, `/guard/status`, `/guard/lint`, `/guard/check`, `/ask`) | Tested offline only (FastAPI test client) |
| Guard worker subprocess (deadline, SIGKILL, bounded pool, degraded latch, allow-listed environment, redacted stderr log, explain-tables-empty startup check) | Tested offline with real subprocesses and fake backends; **not yet run against Db2** |
| NL-to-SQL pipeline, schema cards, in-memory semantic index | Tested offline only (static LLM, deterministic embeddings) |
| Ollama LLM / Ollama embeddings | Implemented; **not yet run against a live Ollama** |
| Db2 `VECTOR` search (`VECTOR_DISTANCE`) | Columns created on Db2; **search not implemented yet** |
| Executing approved SQL | **Disabled** (no route; needs a restricted Db2 user and audit persistence) |
| Audit inserts into `DB2INTEL.QUERY_AUDIT` | **Disabled** |

---

## IBM Db2 Integration
- **Db2 Edition & Environment:** Db2 Community Edition 12.1.5 on Docker (`db2server`, port 50000),
  database `TESTDB`. The IBM `SAMPLE` database is never written to and the migration runner refuses it.
- **Connector / Driver Used:** `ibm_db` 3.3.0 (bundles the Db2 CLI driver). Connections run with
  autocommit **off**.
- **Database Schema / Data Models:** everything lives in two project schemas; existing objects
  (for example `DB2INST1.EMPLOYEE_INFO` and `DB2INST1.EMPLOYEE_SALARY`) are never modified, and the
  guard refuses to read them.
  - `DB2INTEL` — application metadata: `SCHEMA_MIGRATION` (checksummed migration ledger),
    `APP_SETTING` (row cap, cost limit, timeout), `DATA_SOURCE` (read-only data sources, enforced by
    `CHECK` constraints), `SCHEMA_OBJECT` and `SCHEMA_EMBEDDING` (`VECTOR(768, FLOAT32)`),
    `VERIFIED_QUERY` and `VERIFIED_QUERY_EMBEDDING` (`VECTOR(768, FLOAT32)`), `QUERY_AUDIT`,
    `QUERY_FEEDBACK`, and the 11 Db2 explain tables (from IBM's `EXPLAIN.DDL` for 12.1.5).
  - `DB2INTEL_DEMO` — synthetic, deterministic sales data: `REGION` (6 rows), `PRODUCT` (24),
    `CUSTOMER` (240), `SALES_ORDER` (3,000), `ORDER_ITEM` (7,500) and the view `V_ORDER_SUMMARY`,
    with primary/foreign keys, check constraints, indexes, a generated column and catalog remarks
    written for semantic search. No personal data.
- **Key Queries & Operations:**
  - `PREPARE` with deferred prepare off, so Db2 compiles the statement without executing it.
  - `MON_GET_PKG_CACHE_STMT`: find exactly one cache entry carrying the request's marker, with the
    exact prepared text and zero executions; read `QUERY_COST_ESTIMATE` (timerons).
  - `SYSPROC.EXPLAIN_FROM_SECTION` into the `DB2INTEL` explain tables; read `EXPLAIN_STATEMENT`,
    `EXPLAIN_OBJECT` and `EXPLAIN_OPERATOR` to check every table/index the plan touches
    (indexes resolved to their tables through `SYSCAT.INDEXES`).
  - `ROLLBACK`, then count leftover explain rows in four tables; any leftover or failed count makes
    the result `cleanup_failed`, overriding every other outcome.
  - Read-only preflight: `CURRENT SERVER`, statement concentrator must be `OFF`, explain tables
    present, limits from `APP_SETTING`, enabled `DATA_SOURCE` schemas, no user-defined function
    shadowing an allow-listed built-in.
  - Migration runner: one transaction per script, SHA-256 checksums in the ledger, refuses
    `SAMPLE`, non-allow-listed databases and remote hosts; teardown is a separate command with a
    typed confirmation and dependency checks.

---

## AI / LLM Architecture
- **Framework:** custom, dependency-light Python pipeline (no agent framework).
- **Model Provider & Model:** local [Ollama](https://ollama.com) — chat model configurable
  (`LLM_MODEL`, default `qwen2.5-coder:7b`) and `nomic-embed-text` (768 dimensions) for embeddings.
  `LLM_PROVIDER=none` disables generation. A deterministic, offline embedder is used by the tests.
  OpenAI and watsonx.ai are planned, not implemented.
- **RAG / Tool Calling Workflow:**
  1. Schema metadata is read from the demo DDL (offline) into *schema cards*; a `SYSCAT`-based
     loader exists for live catalogs but is not wired in yet.
  2. Cards are embedded and ranked by cosine similarity in memory, filtered to the schemas of the
     requested data source. (Storing them in the `DB2INTEL.SCHEMA_EMBEDDING` VECTOR column and
     searching with `VECTOR_DISTANCE` is planned.)
  3. The prompt fences cards and question as data, lists the guard's allowed functions, and asks
     for one fenced SQL block. Prompt delimiters and control characters are stripped from all free
     text.
  4. Exactly one statement is extracted (prose around it, two blocks, or a non-`SELECT` answer is
     `NO_SQL`), then the static guard decides: `LINT_APPROVED`, `BLOCKED` or `NO_SQL`.
  5. AI-generated SQL is **not** prepared, explained or executed in the current phase; the API
     refuses to send it to the Db2 guard check.

---

## Tech Stack
- **Backend / Core:** Python 3.11, FastAPI 0.115, Uvicorn
- **Database:** IBM Db2 Community Edition 12.1.5 (Docker), `ibm_db` 3.3.0
- **Frontend / UI:** HTTP JSON API and command-line tools (no web UI yet)
- **Libraries & Tools:** Pydantic 2, pytest, uv, Ollama (optional, local)

---

## Prerequisites
- Docker with a running Db2 Community Edition container (see `docs/db2-setup-guide.md` in the
  repository root) and a database named `TESTDB`
- Python 3.11 (pinned in `.python-version`)
- [uv](https://docs.astral.sh/uv/) (or `pip`)
- Optional: Ollama with a code model and `nomic-embed-text`, for natural-language questions

---

## Setup & Installation

The Python virtual environment lives **outside the Git repository** so that third-party
files inside it (for example the `.pem` CA bundle shipped with `ibm_db`) are never scanned
by `scripts/validate_submission.py` or accidentally committed.

```bash
# 1. Navigate to the submission directory
cd submissions/db2-intelligence-copilot

# 2. Create a Python 3.11 environment outside the repo with uv (https://docs.astral.sh/uv/)
#    (.python-version pins 3.11; uv downloads it if it is not installed)
uv venv --python 3.11 ~/.venvs/db2-intelligence-copilot
source ~/.venvs/db2-intelligence-copilot/bin/activate

# 3. Install pinned dependencies (ibm_db bundles the Db2 CLI driver; no separate client needed)
uv pip install -r requirements.txt

# 4. Verify the driver
python -c "import ibm_db; print(ibm_db.__version__)"
```

Without uv: `python3.11 -m venv ~/.venvs/db2-intelligence-copilot` and `pip install -r requirements.txt`.

---

## Configuration

Copy `.env.example` to `.env` and fill in your local or test credentials:

```bash
cp .env.example .env
```

`.env` is git-ignored. Every setting has a safe default; the important ones are:

| Setting | Purpose |
|---|---|
| `DB2_HOST`, `DB2_PORT`, `DB2_DATABASE`, `DB2_USER`, `DB2_PASSWORD`, `DB2_SECURITY` | Db2 connection (password only in `.env`) |
| `DB2INTEL_MIGRATION_DATABASES`, `DB2INTEL_MIGRATION_HOSTS` | Where migrations and guard checks may connect (local `TESTDB` by default) |
| `EMBEDDING_PROVIDER`, `EMBEDDING_MODEL`, `EMBEDDING_DIM`, `OLLAMA_BASE_URL` | Embeddings (`ollama` or `deterministic`); dimension must be 768 |
| `LLM_PROVIDER`, `LLM_MODEL`, `LLM_BASE_URL`, `LLM_TIMEOUT_SECONDS` | SQL generation (`none` or `ollama`); the model server must be local unless `DB2INTEL_LLM_ALLOW_REMOTE=true` |
| `DB2INTEL_API_HOST`, `APP_PORT`, `DB2INTEL_API_TOKEN` | API bind address (loopback only) and bearer token (16+ characters). Without a token the API runs, but the guard pool is not started and `/api/v1/guard/check` answers 503 `guard_disabled` |
| `DB2INTEL_WORKER_LOG` | Redacted, size-bounded guard worker stderr log (default `logs/guard-worker.log`, git-ignored; must end in `.log`; `off` discards it) |
| `DB2INTEL_GUARD_WORKERS`, `DB2INTEL_CHECK_DEADLINE_SECONDS`, `DB2INTEL_WORKER_STARTUP_SECONDS`, `DB2INTEL_QUEUE_WAIT_SECONDS` | Guard worker pool size (1–4) and deadlines |
| `DB2INTEL_MAX_BODY_BYTES`, `DB2INTEL_API_MAX_ROWS` | Request size limit and row cap for API lint and `/ask` |

> **Security Warning:** Never commit `.env` or any real API keys or database passwords to Git!

---

## Running the Project

All commands run from `submissions/db2-intelligence-copilot` with the virtual environment active
and `export PYTHONPATH=src`.

### Database initialization

Initialization applies exactly `sql/001_schema_meta.sql`, `sql/002_demo_data.sql` and
`sql/003_explain_tables.sql`, in that order, each in a single Db2 transaction recorded in the
`DB2INTEL.SCHEMA_MIGRATION` ledger. It only creates objects in the schemas `DB2INTEL` and
`DB2INTEL_DEMO`, and it refuses to run against any database except `TESTDB` (configurable) and
always refuses `SAMPLE`.

Migration 003 creates the 11 Db2 explain tables in `DB2INTEL`, copied from IBM's `EXPLAIN.DDL`
for Db2 12.1.5. The SQL guard fills them with `SYSPROC.EXPLAIN_FROM_SECTION` (explain schema
`DB2INTEL`) to show query plans; the cost check itself reads `QUERY_COST_ESTIMATE` from
`MON_GET_PKG_CACHE_STMT` after a prepare, without executing the generated SQL.

```bash
python -m db2intel.db.migrate plan      # offline policy check, no database connection
python -m db2intel.db.migrate status    # read-only: applied / pending
python -m db2intel.db.migrate up        # apply pending migrations in order (safe to re-run)
python -m db2intel.db.migrate analyze   # optional: RUNSTATS on project tables only
```

Removing the project objects is a separate, explicit command (never part of `up`):

```bash
python -m db2intel.db.migrate teardown --confirm "DROP DB2INTEL AND DB2INTEL_DEMO"
```

### SQL guard (command line)

```bash
# Offline static check and row cap; no database connection
python -m db2intel.guard lint "select company_name from db2intel_demo.customer"

# Prepare-only cost and EXPLAIN analysis against Db2; never executes the query, never commits
python -m db2intel.guard check "SELECT C.COMPANY_NAME FROM DB2INTEL_DEMO.CUSTOMER C WHERE C.CUSTOMER_ID = 42"
```

There is deliberately no command that executes a query.

### HTTP API

```bash
python -m db2intel.api        # binds to 127.0.0.1:${APP_PORT:-8000}
```

Starting the server does not connect to Db2. A guard worker process (which connects, prepares only
and never commits) starts on the first `/api/v1/guard/check` request. That route needs
`DB2INTEL_API_TOKEN`: without a token the guard pool is not created, the server says so on startup,
and the route answers 503 `guard_disabled` (lint, status and `/ask` still work).

Guard workers get an allow-listed environment (Db2 connection settings, locale, `PATH`, driver
library paths); the API token, LLM settings and API keys are never passed to them, and they read
only allow-listed keys from `.env`. Before a worker accepts checks it counts the rows in all 11
explain tables (read-only `COUNT(*)`); if any table is not empty it refuses to start, the pool
becomes degraded, and nothing is deleted automatically. Worker stderr is redacted (known secret
values, `key=value` credentials, `Authorization` headers, API and private keys), truncated per line
and written to `DB2INTEL_WORKER_LOG`, which is rotated once at 1 MB.

| Route | What it does | Touches Db2 |
|---|---|---|
| `GET /health` | Liveness | No |
| `GET /api/v1/guard/status` | Pool state, degraded flag, feature flags | No |
| `POST /api/v1/guard/lint` `{"sql": "..."}` | Static guard and row cap | No |
| `POST /api/v1/guard/check` `{"sql": "..."}` | Lint, then prepare-only analysis of **human-written** SQL in a worker with a deadline | Prepare + EXPLAIN, rolled back |
| `POST /api/v1/ask` `{"question": "...", "source": "demo"}` | Schema cards → LLM → one statement → static guard | No |

```bash
curl -s localhost:8000/api/v1/guard/lint -H 'content-type: application/json' \
     -d '{"sql": "select * from db2intel_demo.customer"}'
```

Every response, including errors, contains `"executed": false` and the header
`X-Db2Intel-Executed: false`. Interactive API docs are disabled. If a check cannot prove its
explain rows were cleaned up (or a worker is killed at its deadline), the guard switches to a
*degraded* state and refuses further checks until the process is restarted.

Stopping the server (Ctrl+C or SIGTERM) shuts the guard pool down exactly once from the application
shutdown hook: idle workers are asked to exit and reaped; a worker still inside a check is killed
with its whole process group and reaped, so no worker process outlives the server.

---

## Testing & Verification

The unit tests need no database, Ollama or API keys:

```bash
uv pip install -r requirements-dev.txt
python -m pytest
```

`tests/integration/` is reserved for tests against a real Db2 database. They must carry the `db2`
marker and are skipped unless `DB2INTEL_IT=1`; none is approved yet, so the only test there is a
placeholder that always skips.

1,300 offline tests cover the parser, analysis and cleanup logic (with fake Db2 responses), the
migration runner, the API, the worker pool (real subprocesses with fake backends: deadlines,
SIGKILL of the whole process group, bounded pool, degraded latch, environment allow-list,
redacted stderr log, explain-tables-empty startup check, shutdown on SIGTERM), the NL-to-SQL pipeline, schema
cards and a security suite (no route can reach execution, AI-generated SQL is never prepared, a
corpus of 64 hostile statements never reaches the database). Mutation testing (deliberately
breaking one safety check at a time) confirmed that the tests catch every mutation tried.

**Real Db2 verification (controlled probe, 2026-11-07, TESTDB):** a supervised probe ran only the
guard's internal read-only SQL plus prepare/EXPLAIN of five test queries, with snapshots before and
after proving the explain tables were empty again, `QUERY_AUDIT` unchanged, the migration ledger
unchanged and the protected `DB2INST1` tables unchanged.

| Test query | Guard decision | Estimated cost (timerons) |
|---|---|---:|
| Primary-key lookup | APPROVED | 7 |
| Regional revenue report | APPROVED | 177 |
| Query over `V_ORDER_SUMMARY` | APPROVED | 172 |
| Cross join | COST_REJECTED (limit 50,000) | 38,149,348 |
| `DB2INST1` protected table | BLOCKED (`forbidden_schema`) | — |

---

## Screenshots & Demo
- **Live Demo Link:** not available yet (the API binds to localhost only).
- **Demo Video Link:** not recorded yet.
- No screenshots yet; they will be added to `docs/screenshots/`.

---

## Known Limitations & Future Roadmap
- **Current Limitations:**
  - No SQL is executed. Execution requires a dedicated Db2 user with `CONNECT` and `SELECT` on the
    demo schema only, plus audit persistence; neither exists yet. Until then the guard connects as
    the instance owner, so the guard's checks are the only barrier, which is why execution is off.
  - AI-generated SQL is only statically checked; Db2 prepare/EXPLAIN of AI SQL is not yet enabled.
  - The `EXPLAIN_FROM_SECTION` call has no Db2-side timeout that the driver can confirm (`ibm_db`
    cannot read a connection-level timeout back); it is bounded by the worker deadline instead.
  - The degraded state is held in memory and cleared by a restart. A new worker then refuses to
    start if any explain table still holds rows, but that check has so far been tested only with
    fakes.
  - Schema cards omit `CHECK` constraint values (they can repeat data values), so the model learns
    allowed codes only from catalog remarks.
  - Ollama integration and the HTTP server have not yet been run end to end; Db2 `VECTOR` search
    is not implemented yet.
  - Single Db2 data source (`DB2INTEL_DEMO` in `TESTDB`); `SAMPLE` is registered but disabled.
- **Next Steps:** Db2-side timeout for EXPLAIN, restricted execution user and audit persistence,
  schema embeddings in `DB2INTEL.SCHEMA_EMBEDDING` with `VECTOR_DISTANCE` search, verified-query
  reuse, Db2 integration tests, a web UI, and watsonx.ai as an LLM provider.

---

## Team Members & Credits
| Name | GitHub Handle | Role / Contribution |
|---|---|---|
| Full Name | [@saisanthoshs2006-cmd](https://github.com/saisanthoshs2006-cmd) | Backend, Db2 integration, SQL guard and AI workflow |

Credits: Db2 explain table DDL adapted from IBM's `EXPLAIN.DDL` (Db2 12.1.5); the `ibm_db` driver
by IBM.
