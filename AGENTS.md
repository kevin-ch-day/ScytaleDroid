# AGENTS.md

Guide for humans and coding agents working **in this CLI / analysis repo**. Prefer small, reviewable changes and the maintenance maps below for anything non-obvious.

## Project summary

ScytaleDroid is an Android security research framework (not a single-purpose scanner): device and APK collection, static analysis, dynamic/runtime measurement, database-backed evidence, and reporting/publication workflows.

## Operator quick start (this repo)

| Step | Notes |
| --- | --- |
| Config | Copy **`.env.example`** → **`.env`** at repo root (`SCYTALEDROID_DB_*`, runtime preset, etc.). |
| Run CLI | **`./run.sh`** — primary entry (menus, device workflows, static/dynamic hooks). |
| MariaDB helper | **`./run_mariadb.sh`** — sets `SCYTALEDROID_DB_URL` from `.env` parts or first argument, then `exec ./run.sh …`. **`./run_mariadb.sh --help`** for resolution order. |

Inventory snapshots live under **`data/state/`**; DB mirror writes depend on `.env`. JSON can exist without a DB snapshot row until connectivity/schema allows — see workflow map inventory section.

## Operating principles

1. **Small and bounded** — One concern per change set. Do not refactor unrelated areas or “clean up while you’re here” without an explicit ask.
2. **Behavior by default** — Preserve observable behavior unless the task says otherwise (CLI wording, artifact layout, SQL/view semantics, schema).
3. **Code over docs when they disagree** — Runtime Python is authoritative; then the maintenance maps; then other docs.

## Domain routing (start here)

| Area | Primary package | Typical tests |
| --- | --- | --- |
| Device, inventory, APK harvest, device menus | `scytaledroid/DeviceAnalysis/` | `tests/device_analysis/`, `tests/inventory/`, `tests/harvest/` |
| Static analysis & static persistence | `scytaledroid/StaticAnalysis/` | `tests/static_analysis/`, `tests/persistence/` |
| Dynamic analysis | `scytaledroid/DynamicAnalysis/` | `tests/dynamic/` |
| DB, schema, read-model, DB tools | `scytaledroid/Database/` | `tests/database/`, `tests/db/`, `tests/db_utils/` |
| Reporting & publication | `scytaledroid/Reporting/`, `scytaledroid/Publication/` | `tests/analysis/`, gates/docs as noted in maps |

Additional rules:

- **Web UI** lives in a **separate** repo — do not patch this Python tree for analyst Web issues.
- **`scripts/`** are wrappers and automation — business logic belongs in `scytaledroid/` modules unless the script is explicitly the supported surface (see `docs/supported_entrypoints.md`).

## High-risk seams (extra review, narrow diffs)

These areas have wide fan-out; prefer extraction helpers and targeted tests over rewrites.

- **Static** — CLI dispatch, persistence, results: `StaticAnalysis/cli/flows`, `cli/persistence`, `cli/execution`.
- **Database** — Read-model / view façades: `Database/db_queries/views*.py`, `schema_manifest.py`; DB menus/controllers: `Database/db_utils/menu_actions.py`, `db_utils/menus/`.
- **DeviceAnalysis** — Large orchestration + operator UX intertwined: `DeviceAnalysis/harvest/runner.py`, `harvest/summary.py`, `harvest/scope.py`, `DeviceAnalysis/apk/workflow.py`, `device_menu/dashboard.py`, `device_menu/inventory_guard/ensure_recent_inventory.py`.

## Source-of-truth, local state, and legacy

- **Maintenance maps** (routing and ownership — read before cross-cutting work):

  - `docs/maintenance/repo_ownership_map.md`
  - `docs/maintenance/workflow_entrypoint_map.md`
  - `docs/maintenance/documentation_authority_index.md`

- **Not architecture truth**: generated or machine-local trees (`output/`, `evidence/`, `logs/`, `data/`, local DB snapshots, scratch paths). Use them as evidence of runs, not as the contract.

- **Legacy / bridge paths** — Do not widen them. Keep thin forwarding wrappers while tests or callers still import or monkeypatch legacy entrypoints.

## Refactor guardrails

- Preserve **public imports and package facades** unless migration is explicitly in scope.
- Prefer **extracting** a helper next to the call site over rewriting a large module.
- Do not change **schema, SQL/view semantics**, or **generated artifact layout** unless the task requires it.
- Do not change **CLI output wording or section ordering** in drive-by cleanup unless explicitly requested (inventory/static menus are sensitive to operator habit).
- If work **spills across domains**, stop and say why scope grew before continuing.

## Validation (targeted first)

Match tests to what you touched, then widen.

| Slice | Command |
| --- | --- |
| Device / inventory / harvest touchpoints | `pytest tests/device_analysis tests/inventory tests/harvest -q` |
| Static | `pytest tests/static_analysis -q` and `pytest tests/persistence -q` |
| Database | `pytest tests/database tests/db tests/db_utils -q` |
| Dynamic | `pytest tests/dynamic -q` |
| Gates / scripts contracts | `pytest tests/gates -q` |

Always compile touched modules:

```bash
python -m py_compile path/to/file1.py path/to/file2.py
```

Run **broader or full-suite** checks only after the relevant slices pass, or when you change shared contracts (models, schema, façade imports).

## Common pitfalls

- Fixing **inventory or harvest** problems starting in StaticAnalysis or the Web repo.
- Assuming **filesystem inventory JSON alone** means DB-backed inventory is healthy — verify snapshot/table behavior when DB is enabled (see workflow map inventory section).
- **Duplicating operator prompts** (e.g. harvest pre-check vs inventory guard) without a deliberate UX pass.
- Passing **`--help`** as the “URL” argument to `run_mariadb.sh` — use **`./run_mariadb.sh --help`** (first token) for launcher help.
- Expecting the long **`[COPY] harvest`** line on-screen by default — it is **log-only** unless **`SCYTALEDROID_HARVEST_COPY_LINE=1`** is set (see `.env.example`).
- **`OperationResult` partial** (`apk_harvest_summary_failed`): pull finished but `render_harvest_summary` blew up — artifacts/receipt paths in `context` are still valid; inspect **logs**.

## Completion checklist (for agents and PR authors)

- List **files changed** and whether behavior is preserved or intentionally changed.
- Note **tests run** (commands above) and any **skipped** areas with reason.
- Call out **follow-ups / risks** (especially DB, static dispatch, harvest runner).
- **Pre-existing failures**: say so explicitly; avoid unrelated fixes in the same commit.

## Cursor / automation

Workspace rules load this file. When adding **new persistent** agent guidance (domains, forbidden refactors), update **AGENTS.md** and, if editor-specific, **`.cursor/rules/`** — avoid duplicating long prose in both.

