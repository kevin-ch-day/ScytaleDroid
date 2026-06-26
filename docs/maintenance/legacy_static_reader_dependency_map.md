# Legacy static reader dependency map (planning)

**Status:** planning / inventory — **not** runtime architecture truth.  
**Audience:** maintainers executing Phase 2+ of `legacy_static_deprecation_playbook.md`.  
**Constraint:** this document was produced by repo-wide search and manual classification; re-run greps when merging reader-retirement PRs.

---

## 1. Scope and method

### In scope

- Physical legacy static tables (the “legacy five”):
  - `runs`
  - `findings` (legacy base table — **not** `static_analysis_findings`)
  - `metrics`
  - `buckets`
  - `contributors`
- **This Python repo only** (`scytaledroid/`, `scripts/`, `tests/`, `docs/` where they cite SQL). The Web repo is out of scope here.

### Method

- Pattern searches for SQL identifiers: `FROM`, `JOIN`, `INSERT INTO`, `DELETE FROM` (and dynamic `FROM {table}` / `` `table` `` where the bound name is one of the five).
- Include **`scripts/`** for operator/audit CLIs; **`tests/`** for assertions that pin SQL text (retirement must update tests in the same PRs as readers).
- Cross-check: `rg 'INSERT INTO (runs|findings|metrics|buckets|contributors)\\b'` over `scytaledroid/**/*.py` (see §2).
- **False positives** (JSON keys, Python attribute names, prose, unrelated “metrics”) are listed in §4 and must not drive retirement work.
- **Follow-up pass:** §8 lists **gaps** found after the first inventory (missed call sites, indirect readers, doc drift, audit-json quirks).

### Out of scope for this file

- Canonical writers (`static_analysis_runs`, `static_analysis_findings`, etc.) except where they interact with legacy reads.
- Permission Intel, Erebus, and Web SQL (see separate audits / playbook).

---

## 2. INSERT confirmation (current Python runtime)

**Claim:** Current Python runtime paths do **not** normally **`INSERT INTO`** the legacy five.

**Evidence:** Repository scan:

```bash
rg 'INSERT INTO (runs|findings|metrics|buckets|contributors)\b' scytaledroid --glob '*.py'
```

**Result:** **No matches** in `scytaledroid/**/*.py` for:

- `runs`
- `findings`
- `metrics`
- `buckets`
- `contributors`

**Interpretation:** Static persistence in current sources does not insert into these tables. Rows may still exist from **older binaries**, **external tools**, or **historical** pipelines. **Admin/reset** paths may **DELETE** or **TRUNCATE** these tables (see playbook Phase 4); that is not an `INSERT` and is documented separately.

---

## 2.1 Shared diagnostic helpers (bounded)

- **`scytaledroid/Database/db_utils/legacy_static_mirror_diagnostics.py`** — read-only presence + legacy ``findings`` / ``runs`` count helpers used by ``scripts/db/audit_static_session.py`` and ``scripts/db/session_static_health.py``. **Not** canonical truth; do not call from writers. **Call-site guardrails:** see **§2.1.1** (merged from the former `legacy_mirror_helper_wiring_report.md`, documentation Wave W1).

### 2.1.1 Legacy mirror helper wiring (merged report)

*Source: former `docs/maintenance/legacy_mirror_helper_wiring_report.md` (2026-05-09). Lane 2 planning — which call sites can share helpers **without** changing semantics. **Do not** use for `metrics.run_id` ambiguity zones without per-query review.*

#### Helpers today

| Helper | SQL / role |
| --- | --- |
| `legacy_mirror_table_presence_audit()` | `runs`, `metrics`, `buckets`, `findings` presence |
| `legacy_mirror_runs_findings_presence()` | `runs` + `findings` presence |
| `legacy_runs_count_by_session_stamp()` | `SELECT COUNT(*) FROM runs WHERE session_stamp=%s` |
| `legacy_findings_count_via_runs_session_stamp()` | Legacy `findings` ⋈ `runs` on `session_stamp` |
| `legacy_findings_count_via_static_run_id()` | Legacy `findings.static_run_id` ∈ SAR ids for `session_stamp` |

#### Wired in this repo

- `scripts/db/audit_static_session.py` — presence + all three count shapes where applicable (`runs` row uses `legacy_runs_count_by_session_stamp`).
- `scripts/db/session_static_health.py` — runs/findings presence + runs-join findings count.

#### `scripts/db/audit_static_session.py` — metrics / buckets

**Stay local:** joined queries `metrics` ⋈ `runs`, `buckets` ⋈ `runs` differ from helper SQL; no shared helper until a parameterized `legacy_mirror_count_via_runs(table, ...)` is designed and tested.

#### `scytaledroid/StaticAnalysis/cli/execution/db_verification.py`

**Stay local:**

- Legacy totals use `_legacy_mirror_catalog_total` + `SELECT COUNT(*) FROM \`table\`` (full catalog), **not** session-scoped mirror counts.
- Session-scoped legacy row counts use `_count_by_run("findings"|"metrics"|…)` with **dynamic** table/column choice (`static_run_id` vs legacy `run_id`) — different semantics from both findings helpers.
- **Do not** route `metrics` through new helpers without classifying **`metrics.run_id`** space per **this doc §6**.

#### `scytaledroid/Database/db_utils/menus/query_runner.py`

**Stay local (for now):**

- `_session_downstream_counts` uses `_run_read_only(...)` with a different call signature than `core_q.run_sql`; SQL for `runs` matches **`legacy_runs_count_by_session_stamp`** text but wiring would need a thin adapter (`lambda sql, params, **_: _run_read_only(sql, params, fetch="one")`) — **defer** to avoid coupling scripts helpers to menu DB session layer in the same batch.
- Digest SQL for legacy **`findings`** (if any) uses **session-scoped keys** tied to digest contract — compare line-by-line before deduping.

#### Safe future additions (bounded)

- `legacy_metrics_count_via_runs_session_stamp` **only** if the SQL is **identical** to audit’s metrics block and call sites agree on **`runs.run_id`** join semantics (not `metrics.run_id` = SAR id paths).

#### Related (planning)

- [fast_implementation_backlog_lanes.md](fast_implementation_backlog_lanes.md) — Lane 2 batch notes.

---

## 3. Per-table dependency map

Legend for **Class**:

| Class | Meaning |
| --- | --- |
| `read` | SELECT / JOIN / subquery against the physical table |
| `write_admin` | DELETE / TRUNCATE as part of reset or session cleanup |
| `diagnostic` | Operator or developer visibility only |
| `reconcile` | Parity / drift semantics vs canonical |
| `compat` | Optional linkage or fallback (e.g. legacy `run_id`) |
| `schema_ddl` | View or DDL string in repo (not a runtime “reader” but blocks DROP) |

Legend for **Suggested handling** (Phase 2 planning — **not** a commitment to edit in this doc):

| Handling | Meaning |
| --- | --- |
| keep | Still required for behavior or explicit policy |
| relabel | Operator text / keys only |
| helper | Consolidate under an explicit “legacy diagnostics” module later |
| replace | Move to `static_analysis_runs` / `static_analysis_findings` / canonical views when ready |
| ddl_later | Requires coordinated view or migration work |

---

### 3.1 `runs` (legacy mirror)

| Location (representative) | Function / context | Class | Suggested handling | Notes |
| --- | --- | --- | --- | --- |
| `scytaledroid/Database/db_scripts/static_run_audit.py` | `_resolve_run`, `_count_for_table` | read / diagnostic | keep / helper | Legacy `run_id` for session+package; orphan detection |
| `scytaledroid/StaticAnalysis/cli/execution/db_verification.py` | `_render_persistence_footer`, `_count_by_run` | read / diagnostic | keep / helper | Session `run_id` list; totals; footer labels |
| `scytaledroid/Database/db_utils/menus/query_runner.py` | `_session_downstream_counts` (`legacy_runs`) | read / diagnostic | **skip when absent** | Count by `session_stamp`; **skips** legacy ``runs`` / other optional tables when ``check_required_tables`` reports missing (canonical-only catalogs). |
| `scytaledroid/Database/db_utils/health_checks/queries.py` | `fetch_latest_run` | read / compat | keep | Subquery for `legacy_run_id` |
| `scytaledroid/Database/db_utils/health_checks/analysis_integrity.py` | `completed_static_runs_missing_legacy_runs` | read / diagnostic | keep | SAR completed but no legacy row |
| `scytaledroid/Database/db_utils/menu_actions.py` | `backfill_app_version_target_sdks` | read | keep | Historical `target_sdk` from legacy rows |
| `scytaledroid/StaticAnalysis/modules/permissions/audit.py` | legacy `run_id` lookup | read / compat | keep | Optional column population |
| `scytaledroid/StaticAnalysis/cli/execution/permission_flow.py` | same pattern | read / compat | keep | Same |
| `scytaledroid/Database/db_queries/views_bridge.py` | `CREATE_V_RUN_OVERVIEW` | schema_ddl | ddl_later | `FROM runs` + `buckets` |
| `scytaledroid/Database/db_utils/static_reconcile.py` | `reconcile_static_session` | reconcile | keep | `SELECT package FROM runs …` |
| `scytaledroid/StaticAnalysis/cli/flows/run_persistence_queries.py` | `_bridge_direct_counts`, `_secondary_compat_package_rows` | read / diagnostic | keep | Audit / persistence summary |
| `scripts/db/audit_static_session.py` | legacy mirror section + copyable SQL | diagnostic | relabel / keep | |
| `scripts/db/session_static_health.py` | legacy findings join uses `runs` | diagnostic | keep | |
| `scytaledroid/StaticAnalysis/cli/persistence/reports/masvs_summary_report.py` | `MAX(run_id)` fallback | read / compat | keep | Gated legacy MASVS path |
| `scytaledroid/Database/db_utils/reset_static.py`, `Workspace/reset_full.py` | table lists, `DELETE FROM runs` | write_admin | keep | Do not narrow before reader exit |
| `scytaledroid/Database/tools/db_schema_snapshot.py` | `_LEGACY_MIRROR_TABLES`, snapshot `required_tables` | diagnostic | relabel | Presence vs “truth” |
| `tests/integration/test_persist_run_summary.py` | assertions on `runs` | test | replace later | Out of scope for this doc’s edits |
| `tests/ui/test_database_menu_rollout.py`, `tests/static_analysis/test_missing_run_ids_artifact.py` | SQL substring assertions | test | replace later | |

---

### 3.2 `findings` (legacy base table)

| Location (representative) | Function / context | Class | Suggested handling | Notes |
| --- | --- | --- | --- | --- |
| `scytaledroid/Database/db_scripts/static_run_audit.py` | `collect_static_run_counts`, severity fallback | read / diagnostic | keep / helper | May use `static_run_id` on legacy table when present |
| `scytaledroid/StaticAnalysis/cli/execution/db_verification.py` | `_count_by_run`, totals | read / diagnostic | keep | |
| `scytaledroid/StaticAnalysis/cli/flows/run_persistence_queries.py` | `_secondary_compat_package_rows` | read | keep | Join `runs` |
| `scytaledroid/Database/db_utils/static_reconcile.py` | package query | reconcile | keep | |
| `scripts/db/audit_static_session.py` | count via `static_run_id IN (SELECT id FROM static_analysis_runs …)` | read / diagnostic | keep | **Join key is canonical static id**, not `runs.run_id` |
| `scripts/db/session_static_health.py` | `findings` + `runs` join | diagnostic | keep | |
| `scytaledroid/StaticAnalysis/cli/persistence/reports/masvs_summary_report.py` | `fetch_db_masvs_summary` | read / compat | env-gated legacy | Canonical by default; legacy `findings`/`runs` only with **`SCYTALEDROID_ALLOW_LEGACY_MASVS_FALLBACK`** |
| `scytaledroid/Database/db_utils/menus/query_runner.py` | digest `legacy_mirror_spec` (display); **`SESSION_DIGEST_REQUIRED_SINGLE_TABLES`** gates on **`static_analysis_findings`** | diagnostic / policy | **Digest gate updated:** canonical findings required for single-scope “missing” | Legacy `findings` optional in mirror table only | Canonical-only DB without legacy `findings` table |
| `scytaledroid/Database/db_utils/reset_static.py` | reset list | write_admin | keep | |
| `scytaledroid/Database/db_utils/action_groups/status_actions.py` | `check_required_tables` includes `findings` | diagnostic | replace | Schema **presence** gate — consider `static_analysis_findings` |
| `scytaledroid/StaticAnalysis/cli/persistence/contracts.py` | comments | doc | relabel | |
| `tests/...` | various | test | replace later | |
| `scytaledroid/Database/db_func/evidence_json.py` | log `extra={"table": "findings",…}` | false positive | — | Not SQL |

---

### 3.3 `metrics`

| Location (representative) | Function / context | Class | Suggested handling | Notes |
| --- | --- | --- | --- | --- |
| `scytaledroid/Database/db_utils/action_groups/risk_actions.py` | backfill `JOIN metrics … ON ms.run_id = sar.id` | read | keep | See **§6** — `run_id` = **`static_analysis_runs.id`** here |
| `scytaledroid/Database/db_utils/action_groups/risk_actions.py` | `runs_missing_metric` audit | read / diagnostic | keep | Same semantic |
| `scytaledroid/StaticAnalysis/cli/execution/db_verification.py` | counts, `SUM(… ) FROM metrics` with legacy `run_id` list | read / diagnostic | keep | See **§6** — legacy **`runs.run_id`** |
| `scytaledroid/Database/db_scripts/static_run_audit.py` | `collect_static_run_counts` | read / diagnostic | keep | `_count_for_table` chooses column by schema |
| `scytaledroid/StaticAnalysis/cli/flows/run_persistence_queries.py` | `_secondary_compat_package_rows` | read | keep | Join via **`runs.run_id`** |
| `scytaledroid/Database/db_utils/static_reconcile.py` | package query | reconcile | keep | |
| `scytaledroid/StaticAnalysis/cli/persistence/dep_view.py` | `_metrics_join` | read / compat | replace later | Optional dep view |
| `scripts/db/audit_static_session.py` | `metrics` + `runs` | diagnostic | keep | |
| `scytaledroid/Database/db_utils/reset_static.py` | reset list | write_admin | keep | |
| `scytaledroid/Database/tools/db_schema_snapshot.py` | optional column `metrics.static_run_id` | diagnostic | keep | Schema drift signal |
| `tests/...` | assertions | test | replace later | |

---

### 3.4 `buckets`

| Location (representative) | Function / context | Class | Suggested handling | Notes |
| --- | --- | --- | --- | --- |
| `scytaledroid/Database/db_queries/views_bridge.py` | `CREATE_V_RUN_OVERVIEW` | schema_ddl | ddl_later | |
| `scytaledroid/StaticAnalysis/cli/execution/db_verification.py` | counts, `_count_by_run` | diagnostic | keep | |
| `scytaledroid/Database/db_scripts/static_run_audit.py` | `collect_static_run_counts` | diagnostic | keep | |
| `scytaledroid/StaticAnalysis/cli/flows/run_persistence_queries.py` | `_secondary_compat_package_rows` | read | keep | |
| `scytaledroid/Database/db_utils/static_reconcile.py` | package query | reconcile | keep | |
| `scripts/db/audit_static_session.py` | counts + printed SQL | diagnostic | keep | |
| `scytaledroid/Database/db_utils/reset_static.py` | reset list | write_admin | keep | |
| `tests/...` | assertions | test | replace later | |

---

### 3.5 `contributors`

| Location (representative) | Function / context | Class | Suggested handling | Notes |
| --- | --- | --- | --- | --- |
| `scytaledroid/StaticAnalysis/cli/flows/run_persistence_queries.py` | `_secondary_compat_package_rows` | read | keep | |
| `scytaledroid/Database/db_utils/static_reconcile.py` | package query | reconcile | keep | |
| `scytaledroid/Database/db_utils/reset_static.py`, `Workspace/reset_full.py` | lists | write_admin | keep | |
| `scytaledroid/Database/db_scripts/static_run_audit.py` | **not** in default `tables` list for `collect_static_run_counts` | gap | optional | Central counts omit `contributors`; reconcile still reads |
| `scytaledroid/Database/db_utils/menus/health_checks_permission.py` | `render_scoring_checks` — `scalar(f"SELECT COUNT(*) FROM {table}")` for `contributors` in `optional_tables` | read / diagnostic | keep | **Real** legacy table read (was misclassified as label-only in an earlier pass) |
| `tests/...` | assertions / SQL substring | test | replace later | |
| `scytaledroid/StaticAnalysis/cli/persistence/metrics_writer.py` | in-memory `contributors` list | false positive | — | Not the DB table |

---

## 4. False positives (do not treat as legacy table dependencies)

| Pattern | Example | Why it is not a legacy table read |
| --- | --- | --- |
| JSON / artifact keys | `run_persistence_audit.py` — `bridge` dict keys `"runs"`, `"metrics_packages"`, canonical section key `"findings"` | Audit **shape**; canonical `"findings"` count is not the legacy `findings` table |
| JSON ingestion | `Database/tools/analysis_ingest.py` — `inclusion.runs` | Unrelated domain “runs” |
| Python variables | `risk_score_audit.py` — dict named `metrics` | Not SQL |
| In-memory structures | `metrics_writer.py` — `contributors=` tuples | Not `INSERT INTO contributors` |
| Logging metadata | `db_func/evidence_json.py` — `extra={"table": "findings"}` | Log field string |
| `bridge_posture.py` | `table="findings"` metadata | Registry; `current_readers` may lag grep — prefer this map + fresh grep |
| Docs under `docs/**` | Prose and grep checkpoints | Documentation unless embedded SQL is executed by tooling you own |

---

## 5. Phase 2 reader-retirement order (planning)

Order is **for planning PRs**; each step needs its own tests and grep verification. Align with `legacy_static_deprecation_playbook.md` Phase 2–3.

### 5.1 Safest replacements

- Tighten **schema presence** checks that still require legacy `findings` where every deployed catalog already has **`static_analysis_findings`** (e.g. `status_actions.py` static bundle — **plan** only until inventory confirms).
- Optionally drop **redundant** script sections that duplicate canonical counts when product agrees legacy empty is always acceptable (e.g. overlapping blocks in `session_static_health.py` vs canonical joins).

### 5.2 Label-only changes

- Menus / footers / audit banners: ensure strings read as **legacy mirror / compatibility**, not “missing static” (continues Phase 1).
- Refresh **`bridge_posture.py`** `current_readers` when implementing — keep in sync with this map.

### 5.3 Must keep temporarily

- **`collect_static_run_counts`** / orphan and group-scope behavior tied to legacy `runs`.
- **Permission** paths resolving optional legacy `run_id` (`permission_flow.py`, `permissions/audit.py`).
- **`risk_actions`** backfill and audits reading **`metrics` keyed by `static_analysis_runs.id`** (§6).
- **`masvs_summary_report`** legacy **`findings`** fallback when enabled.
- **`menu_actions.backfill_app_version_target_sdks`** reading **`runs`** for historical SDKs.
- **`health_checks/queries.fetch_latest_run`** legacy id column.
- **`static_reconcile.py`** and **`run_persistence_queries.py`** parity logic.

### 5.4 Web blockers

- **None tracked in this Python repo** for the legacy five; Web consumption is covered separately (`legacy_static_tables_web_deep_dive.md`). Treat Web as a **parallel** exit criterion before DDL.

### 5.5 Schema / DDL blockers

- **`views_bridge.CREATE_V_RUN_OVERVIEW`** — references `runs` and `buckets`.
- Migration artifacts under `scytaledroid/Database/db_scripts/` (and similar) that reference these names — constrain **drop order** and recreation smoke.

### 5.6 Do not touch yet

- **`reset_static` / `reset_full`** delete ordering and table lists until reader exit criteria are met for each table.
- **Integration tests** asserting legacy row counts until a written “canonical-only” contract and migration period exist.
- **`v_static_handoff_v1`** and handoff contracts — orthogonal; high risk per `AGENTS.md`.

---

## 6. Special warning: ambiguous `metrics.run_id`

Legacy table **`metrics`** uses column name **`run_id`**, but **two different semantics** appear in this codebase:

| Semantic | Typical join | Example locations |
| --- | --- | --- |
| **`run_id` = `static_analysis_runs.id`** (canonical static run id) | `JOIN metrics ms ON ms.run_id = sar.id` | `risk_actions.py` backfill and “missing metric” audit |
| **`run_id` = legacy `runs.run_id`** | `JOIN metrics m JOIN runs r ON r.run_id = m.run_id` | `run_persistence_queries.py`, `audit_static_session.py`, `db_verification.py` footer tail using legacy id list |

**Consequence:** reader retirement and “bulk migrate metrics queries” **must not** be done mechanically by string replace. Each call site must be classified against **which id space** the row keys use, then migrated to the appropriate canonical surface (or removed).

---

## 7. Decision statement (normative for this cleanup lane)

1. **Legacy static tables** (`runs`, legacy `findings`, `metrics`, `buckets`, `contributors`) are **not** canonical static truth.
2. **Current static truth** for run and finding persistence is **`static_analysis_runs`** and **`static_analysis_findings`**, plus the baseline / string / permission surfaces described in `AGENTS.md` and `persistence.md`.
3. **Legacy mirrors** may still be used for:
   - **compatibility diagnostics** (counts, footers, session scripts),
   - **reset/admin cleanup** (truncate/delete lists),
   - **historical fallback** (e.g. MASVS, SDK backfill),
   - **bridge parity** (`static_reconcile`, persistence audit summaries),
   until explicit **exit criteria** per table are met and **DDL** is last (`legacy_static_deprecation_playbook.md`).

---

## 8. Follow-up audit — gaps, edge cases, and doc drift

Second-pass checks against greps, `static_database_schema_audit_plan.md`, `legacy_static_deprecation_playbook.md`, `phase5c_task_list.md`, and `ownership_matrix_v1_3.csv`. Use this section when **hardening** the map or before mechanical refactors.

### 8.1 Missed or easy-to-miss readers (corrected / added)

| Item | Detail |
| --- | --- |
| **`health_checks_permission.py`** | `render_scoring_checks` loops `optional_tables` and runs `SELECT COUNT(*) FROM contributors` (and other non–legacy-five tables). This is a **literal** legacy `contributors` read, not a UI-only string. |
| **Full-catalog row counts** | `status_actions` **DB schema snapshot** (`write_db_schema_snapshot_audit`) uses **`diagnostics.approximate_table_row_counts()`** by default (**one** `information_schema.tables` read; InnoDB `TABLE_ROWS` is an **estimate**). Opt-in exact mode: **`SCYTALEDROID_DB_SCHEMA_SNAPSHOT_EXACT_TABLE_COUNTS=1`** restores per-table `SELECT COUNT(*)`. Other menus that still call **`table_counts`** directly remain potentially expensive. |
| **Bootstrap schema diff snapshots** | `menu_actions._schema_snapshot` (before/after **canonical schema bootstrap**) uses **bulk** `information_schema.COLUMNS` + `information_schema.STATISTICS` + one `SHOW TABLES` on **MySQL/MariaDB** (single session), instead of per-table column + `SHOW INDEX` probes. Falls back to the legacy per-table path if bulk reads fail. |
| **Generic snapshot helpers** | `diagnostics.build_table_snapshot(table_name)` / `table_counts` accept **any** name a caller passes; future menus must not treat this as endorsement to depend on legacy tables for new features. |

### 8.2 Dynamic SQL and audit centralization

| Item | Detail |
| --- | --- |
| **`static_run_audit._count_for_table`** | Executes `SELECT COUNT(*) FROM {table} WHERE …` for names in the configured list (`findings`, `metrics`, `buckets`, …). Any **expansion** of that list (e.g. adding `contributors`) immediately creates a new reader — track list edits in PR review. |
| **`db_verification._count_by_run`** | Same pattern: `{table}` can be legacy five; branch choice depends on `_table_has_column` for `static_run_id` vs legacy `run_id`. |

### 8.3 View and smoke dependencies (not only `views_bridge.py`)

| Item | Detail |
| --- | --- |
| **`v_run_overview`** | DDL in `views_bridge.py` (`runs` + `buckets`). Also referenced from **`schema_manifest.py`** (ordered apply), **`scripts/db/recreate_web_consumer_views.py`** (smoke `SELECT COUNT(*) FROM v_run_overview`), **`scripts/db/check_schema_posture.sql`**, **`view_repair_support.py`**. Retiring base tables requires **view replacement first** or coordinated consumer removal. |
| **`CREATE_V_RUN_IDENTITY`** | Uses **`static_analysis_runs`** + dynamic — not legacy five; do not conflate with `v_run_overview`. |

### 8.4 Documentation and matrix drift (planning risk, not SQL)

| Item | Detail |
| --- | --- |
| **`ownership_matrix_v1_3.csv`** | **Phase 2A+ hygiene:** legacy-five **`write_owner`** / **notes** rows were refreshed to match the no-`INSERT` baseline in current Python (see **`legacy_static_phase2a_policy_alignment_plan.md`**). If a row drifts again (e.g. new script claims a writer without grep proof), fix the CSV in the same PR as the code or revert the doc claim. |
| **`bridge_posture.py` `current_readers`** | Tuple lists are **partial**; prefer this map + fresh `rg` when arguing “no readers.” |

### 8.5 Policy / contract contradictions (operator confusion)

| Item | Detail |
| --- | --- |
| **`schema_gate.static_schema_gate`** | **Does not** require legacy `findings` (canonical tables + `v_static_handoff_v1`, etc.). |
| **`status_actions` DB snapshot** | **Resolved (Phase 2A):** legacy `findings` removed from `required_tables["static"]`; optional **`legacy_mirror_table_presence`** + **`legacy_mirror_table_presence_meta`** cover the legacy five with explicit “missing is normal” wording. |

### 8.6 Persistence audit JSON shape (reconcile bridge)

| Item | Detail |
| --- | --- |
| **`run_persistence_queries._apply_reconcile_summary`** | **Fixed:** `metrics_packages` / `buckets_packages` / `contributors_packages` now use **`StaticSessionReconcileSummary.legacy_*_mirror_packages`** (distinct package counts per legacy mirror table). **`secondary_compat_mirror_packages`** remains the union cardinality. See `tests/persistence/test_run_persistence_reconcile_bridge_json.py`. |

### 8.7 Naming and alias false trails

| Item | Detail |
| --- | --- |
| **`static_findings` vs `findings`** | Baseline tables are **not** the legacy `findings` mirror; greps on `findings` must distinguish `static_findings`, JSON keys, and legacy SQL. |
| **`scripts/operator/diagnose_static_pipeline.py`** | Uses SQL `SELECT COUNT(*) AS runs … FROM static_analysis_runs` — column **alias** `runs` is **not** the legacy `runs` table. |
| **Filesystem paths** | Harvest / evidence paths named `runs/` are unrelated to the DB table. |

### 8.8 Engine and portability edges

| Item | Detail |
| --- | --- |
| **MariaDB vs SQLite** | Audit code paths use `SHOW COLUMNS` / `information_schema` depending on engine; `_count_for_table` branch logic differs when `static_run_id` exists on a legacy-named table. Mixed dev DBs can **skip** or **error** counts — treat odd `SKIP`/`ERROR` statuses as environment signals, not always “missing data.” |

### 8.9 Scripts and SQL files outside `scytaledroid/**/*.py`

| Item | Detail |
| --- | --- |
| **`scytaledroid/Database/db_scripts/run_id_migration.sql`** | References `buckets`, `metrics` in **DDL** — migration artifact; affects upgrade ordering, not weekly runtime. |
| **`scripts/db/*.sql`** | Posture lists may name **`v_run_overview`**; smoke queries do not add new readers but **prove** view existence. |

---

## Related documents

- [legacy_static_deprecation_playbook.md](legacy_static_deprecation_playbook.md) — phased exit; this map feeds **Phase 2–3**.
- [legacy_static_phase2a_policy_alignment_plan.md](legacy_static_phase2a_policy_alignment_plan.md) — **completed** policy record + verification commands (stub).
- [legacy_static_tables_consumer_audit.md](legacy_static_tables_consumer_audit.md) — **index page** (baseline grep + pointers); per-table matrices live in **this doc §3**.
- [static_database_schema_audit_plan.md](static_database_schema_audit_plan.md) — schema inventory semantics.
- [legacy_static_deprecation_playbook.md](legacy_static_deprecation_playbook.md#legacy-static-table-compatibility-appendix) — relabel vs migrate buckets (**Appendix A**, merged from the former reduction plan doc).

**Re-verify command (legacy SQL in Python):**

```bash
rg -n '\b(FROM|JOIN|INSERT INTO|DELETE FROM)\s+`?(runs|findings|metrics|buckets|contributors)`?\b' scytaledroid scripts tests --glob '*.py'
```

Adjust for false positives per §4 after each change.
