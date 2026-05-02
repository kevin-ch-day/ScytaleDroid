# AGENTS.md

Guide for humans and coding agents working **in this CLI / analysis repo**. Prefer small, reviewable changes and the maintenance maps below for anything non-obvious.

## Project summary

ScytaleDroid is an Android security research framework (not a single-purpose scanner): device and APK collection, static analysis, dynamic/runtime measurement, database-backed evidence, and reporting/publication workflows.

## Operator quick start (this repo)

| Step | Notes |
| --- | --- |
| Config | Repo-root **`.env`** from **`.env.example`** — see **Configuration and environment** below. |
| Run CLI | **`./run.sh`** — primary entry (menus, device workflows, static/dynamic hooks). |
| MariaDB helper | **`./run_mariadb.sh`** — sets `SCYTALEDROID_DB_URL` from `.env` parts or first argument, then `exec ./run.sh …`. **`./run_mariadb.sh --help`** for resolution order. |

Inventory snapshots live under **`data/state/`**; DB mirror writes depend on `.env`. JSON can exist without a DB snapshot row until connectivity/schema allows — see workflow map inventory section.

## Configuration and environment

**Canonical vs legacy names**

| Variable | Role |
| --- | --- |
| `SCYTALEDROID_DB_PASSWD` | **Canonical** DB password for split-host DSN usage. |
| `SCYTALEDROID_DB_PASS` | **Legacy** — do not use in new setup unless a script explicitly documents support. |
| `SCYTALEDROID_PERMISSION_INTEL_DB_PASSWD` | **Canonical** Permission Intel DB password. |
| `SCYTALEDROID_PERMISSION_INTEL_DB_PASS` | **Not** a supported canonical name. |

If **`SCYTALEDROID_*_DB_URL`** (or equivalent full URL vars) is set, it **overrides** split host/name/user/passwd composition.

**Dotenv / files**

- **Repo-root `.env`** is the recommended local developer source.
- **`.env.example`** is the setup contract — keep it aligned when adding env knobs.
- **`SCYTALEDROID_NO_DOTENV=1`** disables dotenv loading.
- **`SCYTALEDROID_ENV_FILE`** can point at an alternate env file.

## Permission Intel model

**`android_permission_intel`** is a shared permission **dictionary and governance** database. It is **not** where static analysis **results** live.

- Static findings and runs belong in the analyst **core / results** catalog (e.g. **`scytaledroid_core_prod`** in typical installs — match your DSN).
- Erebus / VirusTotal enrichment should use the same Permission Intel dictionary/governance source where applicable.

**Operational checks**

- Before paper-grade static work, run:  
  `PYTHONPATH=. python scripts/db/check_permission_intel.py`
- **Paper-grade governance** expects governance snapshot signals such as **`permission_governance_snapshots > 0`** and **`permission_governance_snapshot_rows > 0`** (see doctor/governance checks — runtime code is authoritative).

Do not treat “permission intel DB reachable” as “governance ready” without the snapshot checks above.

## Database governance

- Names **`v_*`** and **`vw_*`** are reserved for **SQL VIEW** objects. **Do not** create physical **BASE TABLE** objects named like views.
- **Schema/view DDL** lives in **this Python repo**. The Web repo **consumes** views; **this repo owns** DB/view contracts.
- Prefer **posture / semantic / smoke** workflows before large DDL or consumer repairs:

```bash
PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py posture
PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py semantic
SCYTALEDROID_WEB_ROOT=/var/www/html/ScytaleDroid-Web ./scripts/db/smoke_web_db.sh
```

Adjust `SCYTALEDROID_WEB_ROOT` to your deployed Web tree.

## Canonical static persistence and legacy bridge

**Canonical surfaces** (static analysis writes here):

- `static_analysis_runs`, `static_analysis_findings`
- `static_permission_matrix`, `static_string_summary`, `static_string_samples`
- `static_session_run_links`, `static_session_rollups`
- Static handoff via views such as **`v_static_handoff_v1`**

**Legacy tables** (`runs`, `metrics`, `buckets`, legacy `findings`, etc.) may still hold **historical** rows from older pipelines; static analysis **no longer writes** a compatibility mirror there—persistence is **`static_analysis_*` only**. **Do not** reintroduce or widen legacy write paths without an explicit product decision and dependency map. Session audits and diagnostics must treat **empty or stale legacy tables as normal** when only canonical writers are in use.

## Static run-health and operator UX (high-ROI)

Prioritize: **preflight clarity**, **Permission Intel status before scan**, **run-health reason lines**, **stable post-run diagnostics**, **DB queryability** (copy/paste SQL where offered), **clear split-APK wording**.

**Labeling rules**

- Do **not** imply **execution crashes** when **`detector_errors=0`**. Use **`detector_pipeline`** / pipeline rollup vocabulary: distinguish **policy/gate failures** and **warnings** from **execution errors**.
- Separate **workflow execution** (scan finished, artifacts, DB persist) from **governance / paper-grade** and from **overall partial** when only detector policy stages fired.
- Do not treat **permission audit snapshot prevalence counts** as MariaDB **`permission_matrix`** row counts — different artifacts.

## Profile, capture, and APK terminology (CLI)

Use consistently:

| Term | Meaning |
| --- | --- |
| **Profile** | Group of packages in scope for a workflow. |
| **Harvest capture** | One captured install/version for a package. |
| **APK files** | Base APK + split APKs inside a **selected** capture. |
| **Run** | Analysis over **selected** captures / APK files. |

Prefer operator-facing phrases like **newest harvest capture per package**, **selected APK files**, **older captures excluded from this run**. Avoid vague **“artifact sets”** unless defined in-context.

## Static-to-dynamic handoff

Dynamic analysis depends on **`static_run_id`**, **handoff hashes**, **plan/baseline artifacts**, and views such as **`v_static_handoff_v1`**. Do not change **`v_static_handoff_v1`**, **`v_run_identity`**, cohort/runtime identity views, or handoff hash contracts without **targeted** dynamic-readiness coverage.

**Sanity targets**

- `v_static_handoff_v1` returns a row for the target **`static_run_id`** when the run completed with required hashes.
- Baseline/plan artifacts exist where the loader expects them.
- Dynamic plan loader accepts the linked static run.

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

**Operator / DB smoke** (when changing views, Permission Intel, or Web consumers):

```bash
PYTHONPATH=. python scripts/db/check_permission_intel.py
PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py posture
PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py semantic
SCYTALEDROID_WEB_ROOT=/var/www/html/ScytaleDroid-Web ./scripts/db/smoke_web_db.sh
```

Always compile touched modules (including CLI menus and DB helpers when edited):

```bash
python -m py_compile path/to/file1.py path/to/file2.py
```

Run **broader or full-suite** checks only after the relevant slices pass, or when you change shared contracts (models, schema, façade imports).

## Direction (north star)

- **Canonical static tables first**; legacy bridge is optional and **not** widened casually.
- **Permission Intel** = shared dictionary/governance — not static results storage.
- **DB posture / semantic / smoke** before aggressive DDL or “repair” churn.
- **`v_*` / `vw_*`** are **views**, not physical tables.
- **Run-health** and CLI copy must **explain reasons** (pipeline vs execution vs persistence).
- **Operator language**: profiles, captures, APK files — not vague “artifact sets.”

## Common pitfalls

- Using **`SCYTALEDROID_DB_PASS`** instead of **`SCYTALEDROID_DB_PASSWD`**, or **`SCYTALEDROID_PERMISSION_INTEL_DB_PASS`** instead of **`…_PASSWD`**.
- Setting **`SCYTALEDROID_PERMISSION_INTEL_DB_URL`** (or full URL vars) with a **placeholder** password — URL **wins** over split host/user/passwd.
- Assuming **`permission_intel_db_available()`** proves login + governance — it only proves DSN resolution; use **`check_permission_intel.py`** for query/governance reality.
- Treating Permission Intel as a **static results** database.
- Creating **`v_*` / `vw_*` physical tables** instead of views.
- Calling a scan **“failed”** when only **detector policy / warning stages** fired but execution and persistence succeeded.
- Confusing **permission parity / audit snapshot JSON** with **`static_permission_matrix`** row counts.
- Fixing **inventory or harvest** problems starting in StaticAnalysis or the Web repo.
- Assuming **filesystem inventory JSON alone** means DB-backed inventory is healthy — verify snapshot/table behavior when DB is enabled (see workflow map inventory section).
- **Duplicating operator prompts** without a deliberate UX pass.
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
