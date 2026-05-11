# ScytaleDroid — Database and schema audit plan (read-only phase)

This document defines **what to audit**, **how to classify objects**, and **how the read-only script** (`scripts/db/static_schema_audit.py`) fits. **No schema changes** in this phase — no drops, migrations, or destructive cleanup.

**Context:** `docs/maintenance/static_run_artifact_lifecycle.md` maps the static **evidence** chain (inventory → harvest → receipts → canonical store → selection → archive JSON → DB → audits → run health → artifact map). The **core DB** does not yet persist every edge of that graph; this audit classifies what **is** in the catalog vs what is still **inferred** from paths, receipts, logs, and JSON.

Runtime Python and `AGENTS.md` canonical lists override this plan when they disagree; update this file when classification changes.

---

## Questions 1–9 (read-only audit — concise answers)

1. **Canonical current truth for static analysis** — `static_analysis_runs`, `static_analysis_findings`, `static_permission_matrix`, `static_permission_risk_vnext`, `static_string_summary`, `static_string_samples`, `static_session_run_links`, `static_session_rollups`, `static_persistence_failures`, plus permission cohort `permission_audit_snapshots`, `permission_audit_apps`, `permission_signal_observations` (see §1 and `schema_gate.py`).

2. **Derived or bridge surfaces** — `static_findings`, `static_findings_summary`, `artifact_registry`, consumer **`v_*` / `vw_*`** views; **`risk_scores`** acts as a **bridge/reconcile** surface vs matrix (§2).

3. **Legacy / stale / compatibility-only** — `runs`, `findings`, `metrics`, `buckets`, `contributors`: **legacy_freeze**; empty is normal; non-empty is **stale_review** territory (§3, §8). The legacy base name **`correlations`** is **optional**: many catalogs never created it; canonical correlation payloads use **`static_correlation_results`** instead (§3, script `AUDIT_OPTIONAL_LEGACY`).

4. **Active writers** — Canonical and permission tables: `StaticAnalysis/cli/persistence/*`, permission audit pipeline, `permission_risk.py` / `risk_scores` upsert, `artifact_registry.record_artifacts`, `static_findings` DB func (§4). Not legacy `runs` / old `findings` for new static.

5. **Active readers** — DB menus, `db_verification`, run health projection, `views_web` / `views_permission`, reporting services, audit scripts (§5).

6. **Views on legacy** — Use `static_schema_audit.py`: **`VIEW_TABLE_USAGE`** when supported, else **`VIEW_DEFINITION`** parse; any dependency in the legacy set is flagged (§6).

7. **Empty but expected** — Legacy tables at **zero rows** when only canonical static writers run; script adds **`empty_expected`** `status_tag` (§7).

8. **Populated but likely stale** — Legacy tables with **rows > 0** without current writers; script adds **`stale_review`** tag; **`risk_scores`** rows that fail matrix reconcile are data-level stale (menus) (§8).

9. **Inferred vs persisted** — Session↔harvest receipt dir, run↔archive JSON path, run↔perm-audit JSON file, full evidence graph: still **filesystem + logs + receipts + selection + artifact map** in part; see §9 and §10 for additive RFC ideas (**no migrations in this phase**).

**Additive schema (assessment only — §10):** optional `static_analysis_sessions` / cohort table, `static_session_artifacts`, stronger harvest/receipt linkage columns, explicit archive path / perm-audit JSON keys, richer **`artifact_registry`** — all **later RFC**, nullable-first.

---

## 0. Lifecycle vs database (gap summary)

| Lifecycle stage | Typical persistence today |
| --- | --- |
| Inventory / harvest | DB: inventory/harvest tables (see `inventory_schema_gate`); also `data/state/`, `device_apks/`, receipts JSON. |
| Canonical APK store | Filesystem + optional DB APK tables; selection manifest may list store paths. |
| Selection manifest | **Filesystem** (`output/audit/selection/…`); digest not always duplicated on DB rollups. |
| Archive JSON | **Filesystem** + log `report.saved`; `artifact_registry` may list paths. |
| Per-app DB static | **`static_analysis_runs`** and children (canonical). |
| Persistence audit | **Filesystem** JSON + summary in post-run flow. |
| Permission audit | DB: `permission_audit_*` + **filesystem** `data/audit/perm-audit_app_…`. |
| Run health | **Filesystem** JSON (+ DB projection in tooling). |
| Artifact map | **Read-only script** — reconstructs receipt ↔ store ↔ pull. |

**Implication:** additive DB work (later RFC) should target the highest-friction inferred links (session ↔ harvest receipt session, run ↔ archive path, run ↔ perm-audit file key) without breaking writers — see §10.

---

## 1. Canonical static tables (today)

Authoritative **static analysis results and session linkage** (writes from current static persistence; readers across CLI, DB menus, reporting):

| Table | Role |
| --- | --- |
| `static_analysis_runs` | One row per persisted static run (identity, status, handoff hashes/paths, session keys). |
| `static_analysis_findings` | Normalized findings linked to `static_analysis_runs.id`. |
| `static_permission_matrix` | Permission matrix rows per run. |
| `static_permission_risk_vnext` | Permission risk / vnext rows per run. |
| `static_string_summary` | String index summary per run/session scope. |
| `static_string_samples` | String samples linked to summary / run. |
| `static_string_sample_sets` | String sample **set** headers (pipeline sibling to summary/samples). |
| `static_string_selected_samples` | Rows linking selected samples to sets / runs. |
| `static_fileproviders` | File-provider / authority detector persistence (harvest storage surface + ingest). |
| `static_provider_acl` | Provider ACL rows (same write paths as `static_fileproviders`). |
| `static_dynload_events` | Dynamic-loading detector events (`DynamicLoadingDetector` / `db_func/harvest/dynamic_loading`). |
| `static_reflection_calls` | Reflection-call rows from the same detector pipeline. |
| `static_session_run_links` | Links session stamp + package to `static_run_id`. |
| `static_session_rollups` | Session-level rollups (counts by status). |
| `static_persistence_failures` | Failure diagnostics for persistence pipeline. |

**Derived static adjunct (persisted, not in `static_schema_gate` required_tables):**

| Table | Role |
| --- | --- |
| `static_correlation_results` | Correlation-stage rows written from `run_summary.py`; replaces the inactive legacy **`correlations`** bridge target (`bridge_posture.py`). |

**Permission cohort (static-adjacent, canonical in core DB):**

| Table | Role |
| --- | --- |
| `permission_audit_snapshots` | Cohort snapshot header. |
| `permission_audit_apps` | Per-app permission audit payload linkage. |
| `permission_signal_observations` | Normalized permission signals (see schema gate `permissions_schema_gate`). |

These align with `scytaledroid/Database/db_utils/schema_gate.py` (`static_schema_gate`, `permissions_schema_gate`) and `AGENTS.md` **Canonical static persistence**.

---

## 2. Derived / bridge / compatibility

| Object | Classification | Notes |
| --- | --- | --- |
| `static_findings_summary` | `derived_keep` | Baseline / summary table used by verification, menus, Web-oriented views; distinct from `static_analysis_findings`. |
| `static_findings` | `derived_keep` | Baseline detail rows tied to `static_findings_summary`; still written on some paths (see `db_func/static_analysis/static_findings.py`). |
| `static_correlation_results` | `derived_keep` | Persisted correlation output (`run_summary.py`); not listed in `static_schema_gate`; covered by persistence tests. |
| `risk_scores` | `bridge_compat` | Auxiliary score row reconciled vs matrix; writers `permission_risk.py`; readers `views_permission.py`, `run_persistence_queries` reconcile. |
| `artifact_registry` | `derived_keep` | Cross-run artifact paths / hashes; writers `record_artifacts` from manifest, dep export, permission audit; not a “finding” table. |
| `v_*` / `vw_*` consumer views | `derived_keep` | Read models; DDL owned by this repo (`recreate_web_consumer_views.py`, `db_queries/views*.py`). |

**Bridge / compat (legacy read or reconcile, not primary static write target):**

- Code that **reconciles** or **compares** legacy `risk_scores` vs matrix (e.g. `run_persistence_queries.py` “missing_legacy_risk”) treats some surfaces as **compatibility**, not new source of truth.

---

## 3. Legacy or freeze candidates

Per `AGENTS.md` and `scripts/db/audit_static_session.py` commentary:

| Table | Classification | Notes |
| --- | --- | --- |
| `runs` | `legacy_freeze` | Historical; static no longer mirrors here. |
| `findings` (legacy) | `legacy_freeze` | Same. |
| `metrics` | `legacy_freeze` | Same. |
| `buckets` | `legacy_freeze` | Same. |
| `contributors` | `legacy_freeze` | Typical legacy lineage; verify in your catalog with `information_schema`. |
| `correlations` (if present) | `legacy_freeze` | **Optional** legacy base name; superseded by `static_correlation_results`. Absence is normal — the audit script does **not** warn when missing. |

**Freeze policy:** do **not** drop or rename without inventory, consumer grep, and Web smoke. Empty counts are **expected** when only canonical writers run.

---

## 4. Active code writers (detectable)

| Object | Writer domains (indicative) |
| --- | --- |
| `static_analysis_runs`, `static_analysis_findings`, matrix, risk, strings (summary, samples, sample_sets, selected_samples), links, rollups, `static_persistence_failures`, fileproviders/ACL, dynload/reflection | `StaticAnalysis/cli/persistence/*`, `run_writers.py`, `run_summary.py`, `string_analysis` DB func/queries, `storage_surface` / `ingest`, `modules/dynamic_loading.py` + `db_func/harvest/dynamic_loading`. |
| `static_correlation_results` | `run_summary.py` correlation persistence stage. |
| `permission_audit_*`, `permission_signal_observations` | `StaticAnalysis/modules/permissions/audit.py`, persistence paths. |
| `static_findings`, `static_findings_summary` | `Database/db_func/static_analysis/static_findings.py`, related query modules. |
| `risk_scores` | `StaticAnalysis/cli/persistence/permission_risk.py`, `db_queries/static_analysis/risk_scores.py`. |
| `artifact_registry` | `Database/db_utils/artifact_registry.py`, manifest writer, dep export, permission audit. |

**No active static writers (grep baseline):** legacy `runs`, `metrics`, `buckets`, legacy `findings` — inserts not expected in `scytaledroid/` for new static flows.

---

## 5. Active code readers (detectable)

- **Menus / dashboards:** `Database/db_utils/menus/*`, `query_runner.py`, `runs_dashboard.py`.
- **Run health / verification:** `StaticAnalysis/cli/execution/db_verification.py`, `run_health/*`, `post_run_session_summary.py`.
- **Reporting / Web facades:** `Database/db_queries/views_web.py`, `views_permission.py`, `Reporting/services/*`.
- **Audits:** `scripts/db/audit_static_session.py`, `run_artifact_map.py` (DB section), `Database/db_scripts/static_run_audit.py`.
- **Indirect / full-catalog diagnostics:** `Database/db_utils/diagnostics.table_counts` after `SHOW TABLES` (used from DB schema snapshot flows) issues `COUNT(*)` for **every** table name returned by the server, including legacy five when present — not a targeted “static reader” but still observable SQL. Optional-table menus such as **`health_checks_permission.render_scoring_checks`** issue `SELECT COUNT(*) FROM contributors`. Dual meaning of **`metrics.run_id`** (canonical `static_analysis_runs.id` vs legacy `runs.run_id`) must be classified per call site before refactors. See [legacy_static_reader_dependency_map.md](legacy_static_reader_dependency_map.md) §6 and **§8**.
- **DB schema snapshot (`status_actions.write_db_schema_snapshot_audit`):** `required_tables.static` excludes legacy `findings`; **`legacy_mirror_table_presence`** + **`legacy_mirror_table_presence_meta`** document optional legacy-five presence (Phase 2A).
- **Session digest (`query_runner.render_session_digest`):** “required for OK” single-scope checks use **`static_analysis_findings`** counts, not legacy **`findings`** (`SESSION_DIGEST_REQUIRED_SINGLE_TABLES`).

The audit script carries **static string hints** for “known readers/writers”; expand via repo grep when an object is `unknown_needs_review`.

---

## 6. Views depending on legacy or compatibility tables

**Automated (best-effort) in `static_schema_audit.py`:**

1. Prefer **`information_schema.VIEW_TABLE_USAGE`** when the server exposes it (MySQL 8+; some MariaDB builds). Returns **base tables/views** referenced by each catalogued view.
2. Else fallback: parse **`information_schema.VIEWS.VIEW_DEFINITION`** for **backtick-quoted** identifiers, intersected with object names in `TABLE_SCHEMA = DATABASE()`. **Imprecise** (aliases / subqueries); use for triage only.
3. If neither works: `view_dependency_engine: unavailable` and rely on repo DDL review.

Any dependency whose name is in the **legacy set** (`runs`, `findings`, `metrics`, `buckets`, `contributors`, `correlations`) is flagged in **`view_dependency_legacy_hits`** on that view’s row and in top-level **`warnings`**.

**Manual follow-up:** high-risk views (`v_static_handoff_v1`, `v_run_identity`, Web `vw_*`) — confirm consumers before DDL changes.

---

## 7. Empty but expected

- Legacy **`runs`**, **`metrics`**, **`buckets`**, legacy **`findings`**, **`contributors`** — **empty_expected** when only canonical static writers are deployed.
- Optional legacy **`correlations`** (if the table exists) — same legacy tags; absence of the object is **not** a schema problem.
- **`static_dynload_events`** / **`static_reflection_calls`** — script may add **`sparse_zero_table_ok`** when the whole table has zero approximate rows (detector-specific; unused cohorts are common).

**Not** “empty_expected” globally: other canonical tables at zero rows still deserve operator review (fresh DB vs broken writers).

---

## 8. Populated but probably stale

- Legacy tables with **non-zero** rows but **no writers** in current code → **stale_review** (historical cohorts).
- **`risk_scores`** rows that **fail reconcile** against matrix (menus / `run_persistence_queries` already surface “missing” / “bridge_only”) → **stale_review** at data level, not schema level.

---

## 9. Relationships inferred outside the DB

| Link | Inferred via |
| --- | --- |
| Static session ↔ harvest run | `session_stamp`, `capture_id`, filesystem `device_apks`, `data/receipts/harvest/...`, `run_artifact_map.py` receipt linkage. |
| Static run ↔ on-disk JSON | `report.saved` logs, archive paths, `artifact_registry.host_path`, selection manifest. |
| Cohort ↔ permission audit files | `data/audit/perm-audit_app_<session>/` + `permission_audit_snapshots.snapshot_key`. |
| Dynamic ↔ static | `static_run_id`, `v_static_handoff_v1`, handoff hashes, evidence under `evidence/static_runs/`. |

---

## 10. Additive schema changes (later — **not** in this phase)

Assess whether each is **worth the migration cost** vs continuing to infer from artifacts + `run_artifact_map.py`. All are **RFC-only** here.

| Idea | Reduces inference for… | Notes |
| --- | --- | --- |
| **`static_analysis_sessions`** or **`static_session_cohorts`** | One DB row = one operator “static session” (stamp + scope + digest) | Today: `static_session_rollups` + links approximate this; cohort identity still crosses filesystem. |
| **`static_session_artifacts`** | Selected APK path / SHA / capture_id per session | Today: selection JSON + receipts + optional `artifact_registry`. |
| **Stronger static session → harvest receipt / capture** | Which `data/receipts/harvest/<label>/` produced the cohort | Today: `capture_id` on selection + receipt linkage script; not a single FK. |
| **Selected artifact → canonical SHA** | Dedup identity without path parsing | Partially: `static_analysis_runs.base_apk_sha256` etc.; per-split rows hold run-level identity. |
| **Static run → archive JSON path** | Which file on disk is the scanner JSON for `static_run_id` | Today: logs + `artifact_registry` + conventions under `data/static_analysis/reports/archive/<stamp>/`. |
| **Static run → permission audit app JSON** | Which `perm-audit_app_…/apps/*.json` row | Today: snapshot_key + filesystem layout + DB snapshot rows. |
| **Clearer evidence artifact registry** | Typed links run ↔ handoff ↔ plan ↔ HTML | `artifact_registry` exists but is not a full evidence graph. |

**Principles:** nullable columns first; no drops; Web/view smoke after any additive column; keep **`v_static_handoff_v1`** contracts stable.

---

## Per-object classification tags (script output)

| Tag | Meaning |
| --- | --- |
| `canonical_keep` | Primary static or permission persistence; do not drop. |
| `derived_keep` | Summaries, registries, scores, or views built from canonical data. |
| `bridge_compat` | Reconcile / legacy joins; minimize new dependencies. |
| `legacy_freeze` | Historical; no new writes; empty often OK. |
| `empty_expected` | Zero rows normal under current writers. |
| `stale_review` | Non-zero but likely historical or inconsistent with canonical. |
| `sparse_zero_table_ok` | Whole-table zero rows may be normal for optional detector persistence (`static_dynload_events`, `static_reflection_calls`). |
| `drop_later_candidate` | Only after explicit product deprecation + consumer removal (none listed by default). |
| `unknown_needs_review` | Object in DB but not in catalogue; grep + classify. |

### Catalogue (initial rows for named objects)

Primary **`classification`** (always one). **`status_tags`** (optional, data-dependent) are added by the script for legacy base tables: `empty_expected` when `TABLE_ROWS==0`, `stale_review` when rows &gt; 0 under no writers.

| Object | classification | owner_domain | status_tags (typical) |
| --- | --- | --- | --- |
| `static_analysis_runs` | `canonical_keep` | StaticAnalysis | — |
| `static_analysis_findings` | `canonical_keep` | StaticAnalysis | — |
| `static_permission_matrix` | `canonical_keep` | StaticAnalysis | — |
| `static_permission_risk_vnext` | `canonical_keep` | StaticAnalysis | — |
| `static_string_summary` | `canonical_keep` | StaticAnalysis | — |
| `static_string_samples` | `canonical_keep` | StaticAnalysis | — |
| `static_string_sample_sets` | `canonical_keep` | StaticAnalysis | — |
| `static_string_selected_samples` | `canonical_keep` | StaticAnalysis | — |
| `static_fileproviders` | `canonical_keep` | StaticAnalysis | — |
| `static_provider_acl` | `canonical_keep` | StaticAnalysis | — |
| `static_dynload_events` | `canonical_keep` | StaticAnalysis | `sparse_zero_table_ok` when `TABLE_ROWS==0` |
| `static_reflection_calls` | `canonical_keep` | StaticAnalysis | `sparse_zero_table_ok` when `TABLE_ROWS==0` |
| `static_correlation_results` | `derived_keep` | StaticAnalysis | — |
| `static_session_run_links` | `canonical_keep` | StaticAnalysis | — |
| `static_session_rollups` | `canonical_keep` | StaticAnalysis | — |
| `static_persistence_failures` | `canonical_keep` | StaticAnalysis | — |
| `permission_audit_apps` | `canonical_keep` | Permissions | — |
| `permission_audit_snapshots` | `canonical_keep` | Permissions | — |
| `permission_signal_observations` | `canonical_keep` | Permissions | — |
| `artifact_registry` | `derived_keep` | Cross-cutting | — |
| `risk_scores` | `bridge_compat` | Permissions / rollup | reconcile may flag data-level `stale_review` (manual / queries) |
| `static_findings_summary` | `derived_keep` | StaticAnalysis | — |
| `static_findings` | `derived_keep` | StaticAnalysis | — |
| `runs` | `legacy_freeze` | Legacy | `empty_expected` or `stale_review` |
| `findings` | `legacy_freeze` | Legacy | `empty_expected` or `stale_review` |
| `metrics` | `legacy_freeze` | Legacy | `empty_expected` or `stale_review` |
| `buckets` | `legacy_freeze` | Legacy | `empty_expected` or `stale_review` |
| `contributors` | `legacy_freeze` | Legacy | `empty_expected` or `stale_review`; `drop_later_candidate` only after grep + Web sign-off |
| `correlations` | `legacy_freeze` | Legacy | Only if table exists; `empty_expected` or `stale_review`; **no warning when absent** |
| `v_static_handoff_v1` | `derived_keep` | StaticAnalysis/Dynamic | — |
| `v_run_identity` | `derived_keep` | StaticAnalysis/Dynamic | — |

**Schema gates vs catalogue:** `static_schema_gate()` requires the §1 “core” static tables + `v_static_handoff_v1` only. The string set tables, fileprovider tables, dynload/reflection tables, and `static_correlation_results` are **not** gate-required but are **first-class writers** in repo code — classify in catalogue; validate with targeted tests (`tests/persistence`, `tests/static_analysis`, `tests/database`, UI/menu SQL contract tests where applicable).

**High-risk — do not alter casually**

- `static_schema_gate` required tables/columns and **`v_static_handoff_v1`**.
- **`v_run_identity`**, cohort / handoff views consumed by dynamic planning.
- **`recreate_web_consumer_views.py`** outputs and **`db_queries/views_web.py`** contracts.
- **Permission Intel** DSN surfaces (`check_permission_intel.py`, `MANAGED_TABLES`) — separate catalog from core.

---

## Script: `scripts/db/static_schema_audit.py`

**Command:**

```bash
PYTHONPATH=. python scripts/db/static_schema_audit.py
PYTHONPATH=. python scripts/db/static_schema_audit.py --json
```

**Behaviour (read-only):**

- Requires core DB (`SCYTALEDROID_DB_*` / URL) enabled and reachable.
- Lists curated objects + optional legacy **`correlations`** (row emitted only if the table exists) + any `static_%` / `permission_%` tables/views in current schema not in catalogue → `unknown_needs_review`.
- Emits: **name**, **object_type** (`BASE TABLE` / `VIEW` / `MISSING`), **row_count** (approximate `TABLE_ROWS` for base tables; `null` for views in v1), **owner_domain**, **classification**, **`status_tags`** (legacy empty/stale heuristics; **`sparse_zero_table_ok`** for dynload/reflection when empty), **writers_hint**, **readers_hint**, **notes**.
- For **catalogued views**: **`view_dependencies`** (resolved table/view names), **`view_dependency_legacy_hits`** (subset in legacy set), top-level **`view_dependency_engine`** (`VIEW_TABLE_USAGE` | `VIEW_DEFINITION` | `unavailable`).
- Top-level **`warnings`**: missing **mandatory** catalogue objects only, unsupported dependency engine, “view references legacy table …”. Optional legacy names absent from schema do **not** warn.

**Explicit non-goals:** no DDL, no `DROP`, no `ALTER`, no Permission Intel DSN queries in this script (core catalog only; use `check_permission_intel.py` for Intel).

**Legacy five — code consumers:** authoritative per-table map in `docs/maintenance/legacy_static_reader_dependency_map.md` §3; short index + baseline grep in `docs/maintenance/legacy_static_tables_consumer_audit.md`. Web impact: `docs/maintenance/legacy_static_tables_web_deep_dive.md`. **Reduction plan (labels / gating / migration sequencing, still no DDL):** `docs/maintenance/legacy_static_table_compatibility_reduction_plan.md`.

---

## Source-aware classification (formerly `unknown_needs_review`)

Concise answers aligned with repo code (writers/readers/gates/tests):

| Object | Writes (primary) | Reads (primary) | Canonical? | Derived / bridge? | Legacy? | Zero rows OK? | In `AUDIT_PROFILES`? | `static_schema_gate` | Tests / gates |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `static_correlation_results` | `StaticAnalysis/cli/persistence/run_summary.py` | session diagnostics, menu SQL | No (adjunct) | Yes — persisted correlation stage | No | Only per-run / not “must be non-empty globally” | Yes (`derived_keep`) | Not required | `test_persist_run_summary_atomicity.py`, `test_permission_intel_freeze.py` (FK note), UI menu rollout tests |
| `static_fileproviders` / `static_provider_acl` | `db_queries/harvest/storage_surface.py`, `StaticAnalysis/persistence/ingest.py` | `views_web.py`, health checks, session diagnostics | Yes (detector persistence) | No | No | Empty possible if no provider hits | Yes | Not required | `test_ingest_provider_compat.py`, `test_persist_run_summary.py` |
| `static_string_sample_sets` / `static_string_selected_samples` | `db_func` + `db_queries` `static_analysis/string_analysis.py` | verification, menus, health summary | Yes (string pipeline) | No | No | Empty if no string sampling | Yes | Not required | `test_health_family.py`, `test_diagnostic_output_helpers.py` |
| `static_dynload_events` / `static_reflection_calls` | `StaticAnalysis/modules/dynamic_loading.py` → `db_func/harvest/dynamic_loading.py` | `views_static.py`, `views_dynamic.py` | Yes (detector DB) | No | No | **Whole table zero** often normal if dynload detector unused | Yes + `sparse_zero_table_ok` tag | Not required | Detector module + schema_manifest DDL registration |

---

## Next steps after first report

1. Attach JSON output to run folder / CI artifact for cohort sessions.
2. Grep-driven expansion of `writers_hint` / `readers_hint` for `unknown_needs_review` rows.
3. Manual view lineage pass for `v_*` joining legacy tables.
4. Only then: RFC for additive columns (§10).
