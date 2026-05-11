# Static run artifact lifecycle (inside-out)

This document answers operator and analyst questions about **what ScytaleDroid writes**, **how it is produced**, and **where it lands** — especially under **`data/`** and **`output/`** — from **device inventory and harvest** through **static analysis**, **optional permission audit**, and **database persistence**. It also separates durable evidence from mirrors and logs. **Runtime Python is authoritative**; this file is a map of that behavior as of the repo that contains it.

**Operator shortcut:** from repo root,

`PYTHONPATH=. python scripts/static_analysis/run_artifact_map.py --session <session_stamp> [--json] [--write-report] [--no-db] [--strict] [--strict-log-duplicates] [--include-harvest-linkage] [--include-harvest-receipt-linkage]`

Legacy flags `--compare-log` and `--db` are no-ops (the script always runs the full audit; use `--no-db` to skip SQL).

**Defaults:** `DATA_DIR` → `data/`, `OUTPUT_DIR` → `output/`, `LOGS_DIR` → `logs/` (`scytaledroid/Config/app_config.py`). Paths below are relative to the **repository working directory** unless noted.

---

## Top-down audit: what happens, in order

This section is the **narrative** version of the rest of the doc. Use it when you want a single pass from “we touched a device” to “we have DB rows and reports.”

### A. Device inventory (before harvest)

1. The CLI talks to ADB and records what is installed. Snapshots live under **`data/state/<serial>/inventory/`** (see `DEVICE_STATE_DIR` + `snapshot_io.py`).
2. Typical artifacts include timestamped **`inventory_YYYYMMDD-HHMMSS*.json`** files, scoped lists, and “latest” pointer files. Retention prunes old history files (keep last N snapshots per device).
3. **Optional DB sync** may mirror inventory into analyst tables when the database is configured; **disk can exist without DB** rows (see project inventory rules in `AGENTS.md`).

**What you are auditing:** “Do we have a coherent picture of the device?” — filesystem under `data/state/`, not `output/`.

### B. Harvest (pull APKs from device)

1. **Plan:** `resolve_harvest_plan` uses inventory rows, root/non-root policy, and operator scope.
2. **Run destination:** Each harvest run gets a directory  
   **`data/device_apks/<serial>/runs/<harvest_label>/`**  
   where `harvest_label` is derived from a unique `run_id` (`compose_harvest_run_destination` in `artifact_store.py`). The label is filesystem-safe and truncated for long IDs.
3. **Pull:** For each planned artifact, the runner **adb-pulls** to something like  
   `package_dir / artifact.file_name` under that run tree (`harvest/runner.py` → `_pull_and_record`).
4. **Hashes:** After pull, SHA-256 (and related) are computed. Duplicates may be deduped and the spare file removed (`DedupeTracker`).
5. **Canonical store (optional materialization):** Content-addressed copies can live under  
   **`data/store/apk/sha256/<first2>/<fullsha>.apk`** (`canonical_apk_path`, `materialize_apk`). This is the **deduplicated APK library**, not the same folder as the per-run pull tree.
6. **Receipts:** Per package, a JSON receipt is written under  
   **`data/receipts/harvest/<session_label>/<package>.json`** (`write_harvest_receipt`, `harvest_receipt_path`). These receipts are how static analysis and dashboards **rediscover** harvest metadata (paths, versions, capture identity) without re-querying the device.
7. **Database:** When enabled, harvest upserts **`android_apk_repository`**, **`harvest_artifact_paths`**, etc. (see `reset_static.HARVEST_TABLES` for the table family).

**What you are auditing:** Under `data/device_apks/` you should see **physical APKs** for the run; under `data/receipts/harvest/` you should see **JSON receipts** keyed by harvest session label; under `data/store/apk/sha256/` you may see **canonical** copies if your workflow materializes them.

**Naming pitfall:** In `apk/workflow.py`, the variable `session_stamp` passed into harvest is actually **`filesystem_harvest_run_label(run_id)`** from `compose_harvest_run_destination` — it identifies **that pull run’s folder and receipt subdirectory**, not your later **static analysis** `session_stamp` unless you deliberately reuse the same string. When auditing, compare **harvest receipt directory name** under `data/receipts/harvest/` to **`capture_id` / path metadata** inside receipts and selection JSON, not only to the static session label you typed in the scanner.

### C. Upload path (alternative to device harvest)

APKs can land via **`data/inbox/uploads/`** and receipts under **`data/receipts/upload/`** (`upload_inbox_root`, `write_upload_receipt`). The API and upload flows call `materialize_apk` into the canonical store. Treat this as **the same conceptual artifact** as harvest: a byte-identical APK with provenance in receipts/DB.

### D. Static analysis session (selection → scan → disk → DB)

1. **Scope:** The operator chooses profile/scope; the engine builds **`ScopeSelection`** (groups of **`ArtifactGroup`**, each with one or more APK paths — base + splits).
2. **Selection audit:** Right after scope is fixed, **`_emit_selection_manifest`** writes  
   **`output/audit/selection/<session_stamp>_selected_artifacts.json`**.  
   This file lists every **filesystem path** that will be scanned, per package, plus **`artifact_manifest_sha256`** over those paths. It is the best answer to “what did we *think* we were scanning?”
3. **Analysis working directory:** The static pipeline uses **`base_dir = artifact_store.analysis_apk_root()`**, which resolves to **`data/store/apk/`** (parent of the `sha256/` tree). This is passed into `execute_scan` / `generate_report` as **`storage_root`**: it anchors **relative paths** inside reports (`pipeline.py` / `context_builders.py`), not necessarily where every APK byte lives.
4. **Per-artifact scan:** For each APK in scope, `generate_report` runs `analyze_apk` then, when allowed, **`save_report`**:
   - **JSON:** `data/static_analysis/reports/archive/<session>/<report_sha>.json` and/or `data/static_analysis/reports/latest/<report_sha>.json` (`reports.py`).
   - **HTML:** `output/reports/static/latest/<package>/<artifact>.html` and optionally `output/reports/static/archive/<session>/...` (`html.py`).
5. **Per-app persistence:** After all artifacts for a package are scanned, post-processing calls **`persist_run_summary` once per app** using **`AppRunResult.base_report()`** (the **base** split’s report, or first artifact if no “base” role). That creates/updates **`static_analysis_runs`** and child tables. **Splits** still have their own JSON on disk if `save_report` ran for them; they do **not** each get their own `static_analysis_runs` row.
6. **Handoff / evidence (repo root):** Static handoff and related files go under **`evidence/static_runs/<static_run_id>/`** (relative to **current working directory** when the CLI runs — usually repo root). See `static_handoff.py`. This is **not** under `data/` or `output/` by default.
7. **Baselines and dynamic plans (data):** Successful publication-style steps can write:
   - **`data/static_analysis/baseline/<package>-<profile>-<scope>-<timestamp>.json`** (`write_baseline_json`),
   - **`data/static_analysis/dynamic_plan/...`** (`write_dynamic_plan_json`).
   Aliases like `latest_baseline.json` may be updated beside specific saves (`artifacts.update_static_aliases`).
8. **Session finalization:** **`emit_persistence_audit_artifact`** → `output/audit/persistence/...`; **`run_health`** JSON is written under **`base_dir`** (i.e. typically **`data/store/apk/<session_sanitized>_run_health.json`** pattern — exact name from `sanitize_session_stamp_for_filename`). **Important:** many operators look under `output/` for health files; the code writes next to **`analysis_apk_root`**, so audit both if you do not see the file under `output/`.
9. **Permission audit (optional workflow):** **`execute_permission_scan`** builds reports (or reloads saved JSON), accumulates cohort stats, and writes  
   **`data/audit/<filesystem_safe_slug(perm-audit:app:<session>)>/snapshot.json`** plus per-app JSON under `apps/` (`audit.py`). The same workflow can persist **`permission_audit_snapshots`** in DB.
10. **Logs:** **`logs/static_analysis.log`** / **`.jsonl`** receive human and structured events (`REPORT_SAVED`, persistence, etc.). **`logs/db.log`** is a **separate** logger channel for database operations — useful when separating “scanner said X” from “MariaDB did Y.”

**What you are auditing:** Trace one **`session_stamp`**: selection JSON → count of archive JSON files for that session → count of `static_analysis_runs` rows for that session (≈ apps, not splits) → persistence audit → optional permission snapshot dir.

---

## Reference: `data/` directory (what appears here)

| Path | Produced by | Contents / role |
| --- | --- | --- |
| **`data/state/<serial>/inventory/`** | Device inventory / snapshot I/O | `inventory_*.json` history, scoped snapshots, metadata. **Device truth** on disk. |
| **`data/device_apks/<serial>/runs/<harvest_label>/`** | Harvest runner | **Pulled APK files** (and related layout) for one harvest run. Ephemeral-by-policy; can be large. |
| **`data/store/apk/sha256/xx/...`** | `materialize_apk`, canonical store | **Content-addressed** APK library (dedupe). |
| **`data/store/apk/`** | Config + static CLI | **`analysis_apk_root()`** — static pipeline **storage_root** for relative paths; run health JSON often lands **here**. |
| **`data/receipts/harvest/<session>/<package>.json`** | Harvest receipt writer | Machine-readable **harvest receipt** linking package, paths, hashes, capture metadata. |
| **`data/receipts/upload/<id>.json`** | Upload flow | Upload receipt. |
| **`data/inbox/uploads/`** | Upload / API | Staging before materialize. |
| **`data/static_analysis/reports/archive/<session>/`** | `save_report` | **Session-scoped** full report JSON (SHA-named files). |
| **`data/static_analysis/reports/latest/`** | `save_report` | **Global** report JSON keyed by content hash. |
| **`data/static_analysis/baseline/`** | `write_baseline_json` | Timestamped baseline JSON exports. |
| **`data/static_analysis/dynamic_plan/`** | `write_dynamic_plan_json` | Dynamic handoff plan artifacts. |
| **`data/audit/<perm-audit_slug>/`** | Permission audit accumulator | `snapshot.json`, `apps/*.json`, `correlation.csv`. |
| **`data/sessions/<session_label>/`** | Various session helpers | Session-scoped metadata (see purge tools in `reset_static.py`). |
| **`data/locks/static_analysis.lock`** | Static run coordination | Lock file when enabled. |
| **`data/archive/`** | Dynamic / dataset tooling | Freeze and archive payloads (e.g. canonical freeze); overlaps **research** workflows more than day-to-day static. |

Not every tree exists on every machine; missing dirs usually mean that workflow has not run yet.

---

## Reference: `output/` directory (what appears here)

| Path | Produced by | Contents / role |
| --- | --- | --- |
| **`output/audit/selection/`** | Selection manifest | `<session>_selected_artifacts.json` — **scope proof**. |
| **`output/audit/persistence/`** | Session finalizer | `<session>_persistence_audit.json`, `_missing_run_ids.json`, optional `_db_lock_health.json`. |
| **`output/audit/dynamic/`** | `run_freeze_readiness_audit` | `paper_readiness_audit_<timestamp>.json` — **dynamic** freeze readiness, not static scan output. |
| **`output/reports/static/latest/<package>/`** | `save_html_report` | **Overwriting** HTML mirror per package + artifact slug. |
| **`output/reports/static/archive/<session>/<package>/`** | `save_html_report` (archive/both mode) | Session-scoped HTML. |
| **`output/evidence/dynamic/<run_id>/`** | Dynamic analysis orchestrator | Runtime/dynamic evidence packs (PCAP, manifests, etc.). Separate domain from static JSON reports. |
| **`output/evidence/...`** (other) | Reporting / exports | Publication or experimental exports depending on menu/script (see `Reporting/` services). |

Static **JSON reports are not stored under `output/`** by default — they go under **`data/static_analysis/reports/`**.

---

## Reference: `evidence/` at repository root

When you run the CLI from the repo root, paths like **`evidence/static_runs/<id>/`** hold **handoff JSON**, **`manifest_evidence.json`**, correlation exports, and other **run-scoped evidence** tied to `static_run_id`. These paths are **cwd-relative** in code (`Path("evidence") / ...`). If you run ScytaleDroid from another working directory, the same relative segment is created **there**, not necessarily under the git tree.

---

## Harvest → static: how receipts and scans connect

1. **Harvest** writes APK bytes under **`data/device_apks/...`** and metadata under **`data/receipts/harvest/...`**.
2. **Repository discovery** (`StaticAnalysis/core/repository.py`) walks receipt trees and canonical locations to build **`RepositoryArtifact`** objects (path, package metadata, capture/session hints).
3. **Static scope** groups those artifacts into **`ArtifactGroup`** entries (base + splits share a group key).
4. **Selection manifest** freezes the **exact list of paths** used for that static `session_stamp`.
5. **Reports** record `file_path`, `hashes`, and enriched `metadata` (including harvest fields when present), so each JSON report is **self-describing** about which APK file was analyzed.

If receipts are missing or stale, static analysis can still point at APK files, but you lose **provenance** linking scan results back to a specific harvest run.

---

## Static scan internals (what “generates” a report file)

For one APK path:

1. **`analyze_apk`** runs the detector pipeline (`pipeline.py`): manifest parse, permissions, strings, optional detectors, MASVS hooks, etc.
2. The pipeline builds **`StaticAnalysisReport`**: structured fields (`manifest`, `findings`, `detector_metrics`, `detector_results`, …).
3. **`save_report`** serializes `report.to_dict()`, adds **`view`** (`build_report_view`) and enriched **`metadata`**, then writes JSON. **HTML** is rendered from **`view`**, not by re-parsing detectors.
4. **Logging** emits **`REPORT_SAVED`** with `json_path`, `archive_path`, `html_path`, `report_sha256`, `session_stamp`, and package identity metadata (`reports.py`).

So: **the report JSON is the full machine artifact**; **HTML is a derived view**; **DB rows are a third projection** focused on queryable outcomes per app.

---

## 1. Authoritative source of truth for a static run

There is **no single file** that is “the” run. For paper-grade and cross-session work, treat truth as **layered**:

| Layer | Role |
| --- | --- |
| **DB (`static_analysis_runs` + canonical child tables)** | Durable, queryable **per-package** outcome for a session: status, `static_run_id`, linkage to `app_versions` / `apps`, persisted findings, permission matrix/risk, strings, handoff hashes, session rollups, etc. |
| **Session-scoped JSON under `data/static_analysis/reports/archive/<session>/`** | **Immutable-by-convention** per-report snapshot on disk (filename stem = report content SHA-256). Best filesystem anchor for “what the scanner emitted” when DB is unavailable or disputed. |
| **Selection manifest `output/audit/selection/<session>_selected_artifacts.json`** | Authoritative for **what was in scope** (paths, counts, `artifact_manifest_sha256`). Does not prove scan or DB success. |
| **Archived HTML** (`output/reports/static/archive/...` when enabled) | Human-readable mirror for that session; optional. |
| **Run health JSON** (`*_run_health.json`) | **Diagnostics**: aggregates execution + persistence signals; not a substitute for DB or archive JSON. |
| **Persistence audit JSON** | **Diagnostics**: per-app persistence classification, paths, stages; use to explain gaps, not as primary evidence. |
| **`data/static_analysis/reports/latest/<sha>.json`** | **Content-addressed mirror**: one file per distinct report **content** hash; **not session-scoped**; older hashes remain until manually pruned. |
| **`output/reports/static/latest/<package>/...html`** | **Latest mirror** per package + artifact slug; **overwrites** across runs. |

**Practical rule:** For reproducibility, pair **`static_analysis_runs.id` + session_stamp** with **archive JSON** for the same session; use **selection manifest** to prove scope.

---

## 2. What is generated at each phase

| Phase | What is produced |
| --- | --- |
| **Harvest / scope / selection** | `ScopeSelection` drives the run. **`_emit_selection_manifest`** writes `output/audit/selection/<session_stamp>_selected_artifacts.json` (apps, artifact paths, counts, digest). |
| **Per-APK / per-split scan** | For each artifact: `analyze_apk` → `StaticAnalysisReport`. If not dry-run and `persistence_ready`, **`save_report`** writes JSON (and renders HTML). Each successful artifact gets its own report JSON (base + each split). |
| **Latest JSON mirror** | `data/static_analysis/reports/latest/<report_sha256>.json` when `STATIC_REPORT_JSON_MODE` is `latest` or `both` (default **both**). Stem is **`report.hashes["sha256"]`** (content hash), not session. |
| **Archive JSON** | `data/static_analysis/reports/archive/<session_stamp>/<sha256>.json` when mode is `archive` or `both`. |
| **HTML** | `save_html_report`: default **`output/reports/static/latest/<package>/<artifact>.html`** (`STATIC_HTML_MODE` default **latest**). Optional **`output/reports/static/archive/<session>/<package>/...`** when mode is `archive` or `both`. |
| **DB persistence** | After the scan, **`persist_run_summary`** runs **once per app** using the **base** artifact’s report (`AppRunResult.base_report()`), creating/updating **`static_analysis_runs`** and related tables. **`ingest_baseline_payload`** then attaches provider ACL snapshots from `detector_metrics` when a matching run row exists. |
| **Persistence audit** | **`emit_persistence_audit_artifact`** → `output/audit/persistence/<session>_persistence_audit.json` (or `_missing_run_ids.json` when appropriate). May also emit **`_db_lock_health.json`**. |
| **Permission snapshot / parity** | Permission audit accumulator writes **`data/audit/<slug(snapshot_id)>/snapshot.json`** with `snapshot_id = perm-audit:app:<session>` → directory `perm-audit_app_<session>/` (colon → `_`). Also persists **`permission_audit_snapshots` / `permission_audit_apps`** when configured. |
| **Run health** | **`build_run_health_document` + `write_run_health_json`** → `<sanitized_session>_run_health.json` under **`RunOutcome.base_dir`** (typically the static analysis APK workspace root), not under `output/`. The artifact-map script **searches under `output/`** for matches; if your runs use another cwd layout, health JSON may live next to the analysis root. |
| **DB verification digest** | **Printed** by `db_verification` / results footer (counts, status). There is **no separate mandatory “verification JSON”** artifact in the static path; capture logs if you need a durable audit trail. |
| **Logs** | `logs/static_analysis.log` (+ `.jsonl`): scanner, `REPORT_SAVED`, persistence events. `logs/db.log` (+ `.jsonl`): **`database`** logger channel (SQL / DB tooling), not the same stream as static. |

Environment knobs (see `scytaledroid/Config/app_config.py`): **`SCYTALEDROID_STATIC_REPORT_JSON_MODE`**, **`SCYTALEDROID_STATIC_HTML_MODE`** (`latest` \| `archive` \| `both`).

---

## 3. Run-scoped vs latest mirror (path classification)

| Path | Classification |
| --- | --- |
| `data/static_analysis/reports/archive/<session>/*.json` | **Run-scoped** evidence (session in path). |
| `data/static_analysis/reports/latest/*.json` | **Global content-addressed mirror** (not session-scoped). |
| `output/reports/static/latest/<package>/*.html` | **Latest mirror** (package + artifact slug). |
| `output/reports/static/archive/<session>/<package>/*.html` | **Run-scoped** when HTML mode includes archive. |
| `output/audit/selection/<session>_selected_artifacts.json` | **Run-scoped** scope manifest. |
| `output/audit/persistence/<session>_persistence_audit.json` | **Run-scoped** diagnostics summary. |
| `data/audit/perm-audit_app_<session>/snapshot.json` | **Run-scoped** permission audit snapshot (slug of `perm-audit:app:<session>`). |
| `*_run_health.json` | **Run-scoped** diagnostics; location is under `base_dir` (see §2). |
| `logs/static_analysis.log`, `logs/static_analysis.jsonl` | **Session-agnostic** files (append); filter by `session_stamp` in message / structured fields. |
| `logs/db.log`, `logs/db.jsonl` | **Session-agnostic** DB channel logs. |

---

## 4. Artifact family taxonomy

Use these labels when building retention policy or UX:

| Family | Suggested label |
| --- | --- |
| Archive JSON reports; selection manifest; permission snapshot files; handoff/evidence under `evidence/static_runs/<id>/` | **evidence_required** (for research reproducibility) |
| Persistence audit, run health, DB verification printouts, lock health JSON | **diagnostics_required** (explain failures; keep for incident review) |
| Verbose logs, optional SQL snippets | **diagnostics_optional** |
| `data/.../latest/*.json`, `output/.../static/latest/*.html` | **latest_mirror** (never sole evidence) |
| Session rollups in DB, aliases like `latest_baseline.json` | **operator_state** / convenience |
| Dynamic freeze readiness under `output/audit/dynamic` | **separate_workflow** (dynamic readiness, not static scan output) |
| Legacy DB tables cleared by `reset_static` (`metrics`, `runs`, old mirrors) | **legacy_or_compat** |
| Lock files, temp extraction dirs | **temporary** |
| Orphan `latest/` files for deleted code paths | **stale_or_orphaned** (needs manual review) |
| Anything not referenced in code paths you use | **unknown_needs_review** |

---

## 5. Is `output/reports/static/latest` intentionally not session-scoped?

**Yes.** HTML is written to **`output/reports/static/latest/<package>/<artifact>.html`** by design so operators can open the **current** HTML for a package without knowing `session_stamp`. Session-scoped HTML exists only when **`SCYTALEDROID_STATIC_HTML_MODE`** is **`archive`** or **`both`**.

---

## 6. Is `data/static_analysis/reports/latest` a mirror of archive JSON?

**Partially.** Both (when mode is `both`) write the **same payload** for a given report hash. The **`latest`** tree is keyed only by **`report_sha256`**, so:

- It is **not** partitioned by session.
- **Retention:** There is **no automatic pruning** in the save path; old hashes **remain** until you delete them. Duplicate content across runs reuses the same file.
- A **new** run with **new** report bytes adds a **new** `latest/<newhash>.json`; it does not delete older hashes.

---

## 7. Why can unique HTML paths be fewer than archived JSON reports?

Common reasons (all consistent with code):

1. **HTML path is keyed by `(package, artifact_slug)`**, where `artifact_slug` comes from `metadata["artifact"]` or `report.file_name` stem — **not** report SHA-256. Many distinct JSON hashes can map to the **same** HTML path; **later writes overwrite** earlier ones in `latest/`.
2. **`REPORT_SAVED` logs** can list the **same** `html_path` for multiple reports → counting **unique** `html_path` values understates report count.
3. **HTML write failures** (`OSError`) log a warning and set `html_path` to `None` while JSON may still exist.
4. **Mode:** If HTML mode is `latest` only, you only have one mirror slot per package/artifact.

JSON archive files are **one per distinct report content hash** (`_report_file_stem` prefers `sha256`).

---

## 8. Expected count relationships (successful full run)

| Quantity | Expected relation |
| --- | --- |
| **Selection `artifact_count`** | Should match **planned** APK/split paths for the run (before skips). |
| **Archived JSON reports** | One per **successfully saved** artifact report (base + splits), minus dry-run / `persistence_ready=False` / save failures. Often tracks **completed artifacts** more closely than app count. |
| **`report.saved` log events** | Should align with **`save_report`** calls (same caveats as JSON). |
| **`static_analysis_runs` rows for session** | **One row per app (package)** that completed persistence, **not** one per split. Expect row count ≈ **app count**, not artifact count. |
| **HTML files** | **Not** necessarily equal to JSON count: latest HTML **collapses** to one path per package/artifact slug; use archive HTML or JSON for per-artifact proof. |

---

## 9. Does every archived report JSON have a corresponding DB row?

**No.** Persistence is **`persist_run_summary` per app** using the **base** report. **Split** reports are still written to disk (when save succeeds) but **do not** each get their own `static_analysis_runs` row.

**Join paths (conceptual):**

- **Report file:** `hashes.sha256` in JSON = **report content hash** (filename stem).
- **DB identity:** `static_analysis_runs.app_version_id` → `app_versions` → **`apps.package_name`**.
- **APK hash:** `static_analysis_runs.base_apk_sha256` and `static_analysis_runs.sha256` (populated as **`base_apk_sha256` or manifest SHA fallback**, not report JSON SHA) — see `run_summary._bootstrap_persistence_transaction`.
- **Session:** `static_analysis_runs.session_stamp` / `session_label` (creation uses the stamp as label in the main path).
- **Package from report:** `manifest.package_name` (+ metadata fallbacks); must match linkage in DB via `apps`.

**`static_session_run_links`** maps `session_stamp` + `package_name` → `static_run_id` for session dashboards.

---

## 10. Where does package identity come from?

`static_analysis_runs` has **no `package_name` column** by design; package is always via **`app_version_id`**:

```text
static_analysis_runs.app_version_id
  → app_versions.id
    → app_versions.app_id
      → apps.package_name
```

**`static_permission_matrix.package_name`** is denormalized on each row for query convenience; it should agree with **`apps.package_name`** for that run’s `app_version_id`.

**Report JSON:** `manifest.package_name` is primary; `metadata.package_name` can appear; **`build_report_view`** also falls back to metadata when rendering.

---

## 11. Top-level keys in report JSON

Serialized from `StaticAnalysisReport.to_dict()`, plus **`save_report`** adds **`view`** and enriches **`metadata`** (`resolve_package_identity`).

| Key | Meaning (short) |
| --- | --- |
| `file_path`, `relative_path`, `file_name`, `file_size`, `hashes` | Provenance for the **analyzed APK** (path + content hashes). |
| `manifest` | Parsed manifest summary (package, versions, components headline, etc.). |
| `manifest_flags` | Derived manifest risk / config flags. |
| `permissions` | Declared/dangerous/custom + catalog snapshot blocks. |
| `components` / `exported_components` | Component inventories. |
| `features`, `libraries`, `signatures` | Manifest / signing extras. |
| `metadata` | Run/session/APK context (session_stamp, harvest fields, toolchain, repro bundle, …). |
| `scan_profile`, `analysis_version`, `generated_at` | Run labeling and time. |
| `findings` | Flat list of `Finding` objects (cross-detector). |
| `detector_metrics` | Structured metrics buckets (permissions_profile, network_surface, provider_acl, …). |
| `detector_results` | Per-detector results, timings, nested findings, policy gates. |
| `analysis_matrices` / `analysis_indicators` | Aggregated analytics (e.g. finding matrices, numeric indicators). |
| `workload_profile` | Workload / cost-style rollup from pipeline artifacts. |
| **`view`** | **Presentation model** from `build_report_view` (HTML + tools); not a second scan — a projection of the same report. |

---

## 12. Which sections are persisted to DB?

| Report section | Primary DB destination (canonical path) |
| --- | --- |
| Findings (via `detector_results` / baseline) | **`static_analysis_findings`** (canonical rows); **`static_findings` / summary** via `persist_static_findings`; rollup counts on **`static_analysis_runs`** (`findings_total`, caps). |
| `detector_metrics.permissions_profile` | **`static_permission_matrix`**, **`static_permission_risk_vnext`** (staged writers). Other metric keys may feed **`static_provider_acl`**, **`static_fileproviders`**, correlation/network storage, **static handoff** JSON, etc., depending on detectors. |
| `detector_metrics` (provider ACL snapshot) | **`ingest_baseline_payload` → `_persist_provider_acl`** → provider / ACL tables. |
| Strings (baseline string analysis) | **`static_string_summary`**, **`static_string_samples`** (and related sample set tables). |
| MASVS / control coverage | **`masvs_control_coverage`** when derived. |
| Handoff / identity | **`static_analysis_runs`** handoff hash/path fields; files under **`evidence/static_runs/<id>/`**. |
| `metadata` / repro | Partially mirrored into run metadata JSON columns where populated; **full repro bundle** remains in JSON + evidence files. |

Schema columns **`detector_metrics`**, **`analysis_matrices`**, **`analysis_indicators`**, **`workload_profile`** on **`static_analysis_runs`** exist for snapshot/compat; the **full structured metrics** should still be read from **report JSON** when columns are null.

---

## 13. Sections that are report-only (or mostly so)

| Area | Why mostly JSON |
| --- | --- |
| **`view`** | Derived for rendering; redundant with report + `build_report_view`. |
| **Full `detector_results` timeline** | DB stores **extracted findings** and some correlation rows, not necessarily the full per-detector envelope. |
| **Raw `components` lists** | Partially reflected in specialized tables/surfaces; full structure is in JSON. |
| **Signing / library lists** | Primarily in JSON unless a specific detector persists slices. |

---

## 14. Duplication by design

| Pair | Reason |
| --- | --- |
| Archive JSON vs `latest` JSON | **Archive** = session audit trail; **latest** = content-addressed dedup and quick lookup by hash without knowing session. |
| JSON vs HTML | **JSON** = machine evidence; **HTML** = human-readable **view** of the same logical report. |
| JSON findings vs DB findings | DB enables **SQL**, dashboards, and stable IDs across tools; JSON is the **verbatim** scanner export. |
| Permission data in JSON vs `static_permission_matrix` | JSON keeps **detector-native** structure; DB normalizes for **cohort queries** and joins. |
| Log `REPORT_SAVED` vs audit JSON | Logs are **append-only telemetry**; audits are **structured post-run** summaries (persistence health). |

---

## 15. Cleanup / retention policy (practical)

| Keep for research | Regenerate | Safe to delete (when you accept loss) | Never use as sole evidence |
| --- | --- | --- | --- |
| Archive JSON; selection manifest; `evidence/static_runs/<id>/`; permission snapshot dir; DB rows | HTML from JSON (re-render); some DB-derived summaries | **`latest` HTML**; old **`latest` JSON** hashes you no longer need; compact logs | **`output/reports/static/latest/**`**; **`data/.../reports/latest/**`** without session context |

**`purge_static_session_artifacts(session_label)`** (see `reset_static.py`) removes session archive JSON, selection/persistence audit files, and `evidence/static_runs/<id>` for runs tied to that **session_label** — it does **not** clear global `latest` JSON or `latest` HTML.

**Prune helpers** exist for old session labels (`keep_latest` pattern in `reset_static.py`) — use with care.

---

## 16. Stale / legacy surfaces

- **`reset_static.STATIC_ANALYSIS_TABLES`** still lists **legacy** tables (`metrics`, `buckets`, `runs`, old `findings`, …) for cleanup; canonical static results are under `static_analysis_*`.
- **Legacy findings mirror** is documented as historical in `bridge_posture.py`.
- **`latest`** trees accumulate **orphan** hashes if you delete sessions but never prune `latest/`.
- **Baseline/plan aliases** (`update_static_aliases`) write `*_baseline.json` / `latest_baseline.json` next to saved paths — treat as **convenience**, not archival evidence.

---

## 17. Dynamic artifacts next to static under `output/audit/`

**Intended.** `run_freeze_readiness_audit` defaults to **`Path(OUTPUT_DIR) / "audit" / "dynamic"`** for `paper_readiness_audit_*.json` while static audits use **`output/audit/selection`** and **`output/audit/persistence`**. Shared **`output/audit/`** root; different subfolders by workflow. If you want stricter separation, use **separate parent directories** via tooling/wrapper scripts (not required by core code).

---

## 18. ML confusion matrices / paper figures

This repo’s “matrix” language is overwhelmingly **permission / analysis matrices** (`analysis_matrices`, static permission matrix DB, etc.), not sklearn-style confusion matrices. **Dynamic** ML orchestration may emit pack metadata under evidence roots; **publication-grade figures** (CSV/TeX/PDF exports) are centered in **`scytaledroid/Reporting/`** and external publication/Obsidian flows — not a large pile of auto-generated confusion heatmaps in the static scanner.

---

## 19. Ambiguous names

| Term | Confusion |
| --- | --- |
| **matrix** | Permission / analysis matrix vs ML confusion matrix. |
| **latest** | Sounds like “best” or “official”; actually **overwrite mirror** or **global hash store**. |
| **skipped** | Scan skip vs persistence skip vs detector policy skip. |
| **partial** | `AppRunResult.final_status` pipeline partial vs execution failure vs paper-grade partial. |
| **`persistence_ready`** | Gates **disk `save_report`** in `generate_report`; name is easy to misread as “DB only”. |
| **`sha256` on `static_analysis_runs`** | **APK / manifest identity**, not report JSON SHA. |
| **`session_stamp` vs `session_label`** | Often the same string in CLI paths; `session_label` is the DB grouping key for purge/canonical logic. |
| **artifact** | Harvest file vs DB artifact registry vs JSON “artifact” slug for HTML. |

---

## 20. Operator-facing artifact map (recommended)

The supported read-only entry point is **`scripts/static_analysis/run_artifact_map.py`**. It correlates selection JSON, session archive JSON, log `report.saved` lines (unique `archive_path` vs raw line count), DB projection when enabled, permission-audit directories, and optional **harvest** checks.

**Flags (high signal):**

| Flag | Role |
| --- | --- |
| `--include-harvest-linkage` | Resolve selection artifact paths: APK on disk, adjacent `*.apk.meta.json` (expect **0** beside **canonical store** paths — sidecars sit under **`data/device_apks/...`**), `harvest_package_manifest.json` hints. |
| `--include-harvest-receipt-linkage` | Same as above, plus index **`data/receipts/harvest/...`** `observed_artifacts` to map **`canonical_store_path` → `local_artifact_path`** and report pull-path APK / meta / manifest counts (use when selection lists **`data/store/apk/sha256/...`**). |
| `--strict` / `--strict-log-duplicates` | Exit non-zero on configured invariant violations (see script header). |
| `--write-report` | Persist JSON under **`output/audit/run_artifacts/<session>_artifact_map.json`** (path under `OUTPUT_DIR`). |

**Semantics:** Selection manifests often list **content-addressed** APK paths; harvest writes **`*.apk.meta.json`** next to the **pull** path. Receipt linkage closes that gap without changing on-disk artifacts.

### 20.1 Harvest receipt linkage (deep dive)

When you pass **`--include-harvest-receipt-linkage`**, the script builds an in-memory index from harvest receipts:

- **Source:** `execution.observed_artifacts[]` with non-empty **`canonical_store_path`** and **`local_artifact_path`**.
- **Key:** resolved absolute path of the canonical APK (must end with `.apk`).
- **Value:** resolved absolute path of the pull under **`device_apks`** (relative `local_artifact_path` is joined to `device_apks_root()`).

**Which receipt folders are read?** In order:

1. `data/receipts/harvest/<safe(selection.session_stamp)>/` if that directory exists (filesystem-safe segment matches harvest receipt writer).
2. Else every `data/receipts/harvest/<safe(capture_id)>/` for `capture_id` values on selection app rows (deduped).
3. Else **all** immediate subdirectories under `data/receipts/harvest/` (widest net; can be slower on busy trees).

The JSON and human report include **`receipt_session_resolution`** (which rule applied) and a **sample of directory names** scanned.

**Counts:**

- **`indexed_canonical_to_pull_rows`** — rows consumed from receipts (can exceed unique keys if duplicates exist).
- **`indexed_unique_canonical_paths`** — distinct canonical keys in the index.
- **`canonical_pull_path_collisions`** — same canonical key mapped to **different** pull paths across receipt rows; the **last** row wins; a **warning** is emitted.

**Gaps:** Selection paths under `…/apk/sha256/…` with **no** receipt row appear in **`unmapped_content_store_path_samples`** (capped). If many store paths are unmapped, **`harvest_receipt_linkage_incomplete`** is set and **evidence** may show **WARN** (see script).

Remaining backlog ideas: surface `STATIC_HTML_MODE` / `STATIC_REPORT_JSON_MODE` and **`base_dir`** for run health; optionally count **`output/reports/static/archive/<session>/**/*.html`** when present.

---

## Top-down audit checklist (filesystem)

Use one **`session_stamp`** (static session) and, if relevant, one **harvest `session_label`** (often aligned with the harvest run label embedded in `data/device_apks/.../runs/<label>/`).

1. **Inventory present?** `data/state/<serial>/inventory/` — recent `inventory_*.json`, scoped files if you use scoped pulls.
2. **Harvest bytes present?** `data/device_apks/<serial>/runs/<harvest_label>/` — APK filenames match what you expect (base + splits).
3. **Harvest receipts present?** `data/receipts/harvest/<harvest_run_label>/` — one JSON per package. The folder name is the **harvest run label** (derived from pull `run_id`), which may differ from the **static** `session_stamp`; reconcile via receipt `paths` / artifact paths inside JSON.
4. **Canonical store (optional)?** `data/store/apk/sha256/` — deduped APKs; size grows with unique content.
5. **Static scope frozen?** `output/audit/selection/<session_stamp>_selected_artifacts.json` — `artifact_count`, path list, digest.
6. **Reports on disk?** `data/static_analysis/reports/archive/<session_stamp>/` — file count ≈ successful **artifact** saves (base + splits); compare to selection count minus skips/failures.
7. **Global mirror growth?** `data/static_analysis/reports/latest/` — many hashes accumulate across sessions; not session-partitioned.
8. **HTML mirrors?** `output/reports/static/latest/<package>/` — convenient; **do not** count unique files as “number of reports” (overwrites).
9. **Run health location?** Check **`data/store/apk/`** for `<sanitized_session>_run_health.json` (same directory as `analysis_apk_root()`), not only `output/`.
10. **Handoff evidence?** `evidence/static_runs/<static_run_id>/` from repo **cwd** when CLI ran — `static_handoff.json`, `manifest_evidence.json`, etc.
11. **Persistence story?** `output/audit/persistence/<session_stamp>_persistence_audit.json` — per-app rows, stages, `base_report_path`.
12. **Permission cohort snapshot?** `data/audit/perm-audit_app_<session_stamp>/snapshot.json` (slug may differ if session was normalized).
13. **Telemetry?** `logs/static_analysis.log` — grep `session_stamp=` and `report.saved`; `logs/db.log` for DB-side errors.

---

## Code anchors (for maintainers)

- APK / harvest layout: `scytaledroid/DeviceAnalysis/services/artifact_store.py` (`device_apks_root`, `compose_harvest_run_destination`, `harvest_receipt_path`, `analysis_apk_root`, `materialize_apk`)
- Harvest pull: `scytaledroid/DeviceAnalysis/harvest/runner.py` (`_pull_and_record`)
- Inventory snapshots: `scytaledroid/DeviceAnalysis/inventory/snapshot_io.py`
- Static artifact discovery: `scytaledroid/StaticAnalysis/core/repository.py`
- Report save: `scytaledroid/StaticAnalysis/persistence/reports.py` (`save_report`, `_resolve_report_paths`)
- HTML: `scytaledroid/StaticAnalysis/reporting/html.py` (`save_html_report`, `_resolve_output_paths`)
- Scan + save: `scytaledroid/StaticAnalysis/cli/execution/scan_report.py` (`generate_report`)
- Per-app DB persistence: `scytaledroid/StaticAnalysis/cli/persistence/run_summary.py` (`persist_run_summary`)
- Selection manifest: `scytaledroid/StaticAnalysis/cli/flows/run_selection_manifest.py`
- Persistence audit: `scytaledroid/StaticAnalysis/cli/flows/session_finalizer.py` (`emit_persistence_audit_artifact`)
- Permission snapshot: `scytaledroid/StaticAnalysis/modules/permissions/audit.py` (`PermissionAuditAccumulator.finalize`)
- Dynamic readiness: `scytaledroid/DynamicAnalysis/tools/evidence/freeze_readiness_audit.py` (`run_freeze_readiness_audit`)
- Session purge: `scytaledroid/Database/db_utils/reset_static.py` (`purge_static_session_artifacts`)
