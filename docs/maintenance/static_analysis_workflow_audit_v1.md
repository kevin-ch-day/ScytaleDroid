# Static analysis workflow audit (v1 design note)

**Status:** AUDIT — design / routing for implementation tickets. Not architecture authority
(see `documentation_authority_index.md` for contracts). Grounded in the current repo tree.

**Related operator tools:** `docs/maintenance/static_analysis_audit_runbook.md`,
`python -m scytaledroid.StaticAnalysis.audit`,
`python -m scytaledroid.Database.db_scripts.static_run_audit`.

---

## 1. Main goal (operator visibility)

For a profile run such as **Research Dataset Alpha → Full analysis**, operators need a
**single post-run health surface** answering:

| Question | Today (approx.) | Gap |
|----------|-----------------|-----|
| Which apps completed? | Per-app completion lines; `AppRunResult.artifacts` | No explicit `complete` / `partial` / `failed` label |
| Partial vs failed | `failed_artifacts`, pipeline OK/WARN counts | Partial not defined when some splits fail but base succeeds |
| APK parse failures | `StaticAnalysisError` → skipped artifact; metadata fallbacks (`label_fallback`, `resource_fallback`) | Fallbacks may not downgrade final “success” semantics |
| Detector stage failures | `pipeline_summary.error_detectors`; CLI card lines | App-level rollup omits **`skipped_detectors`** list merge (see §5) |
| Intentional skips | `Badge.SKIPPED` + reasons in **`pipeline_summary.skipped_detectors`** (per artifact) | Not aggregated in **`_summarize_app_pipeline`** into one list |
| String analysis health | **`base_string_data`** on `AppRunResult`; failures → `warnings` + `empty_string_analysis_payload` | No dedicated string stats block on run summary / JSON artifact |
| Split handling | **`scan_splits`**; outlier UX in **`scan_view`** | Base-only string pass; batch+quiet can force base-only scan (see §7) |
| Reports / DB | `save_report`; `persist_run_summary`; persistence audit JSON | Governance/paper-grade paths separate from “core persisted” |

---

## 2. Pipeline spine (where it starts / ends)

| Phase | Primary modules |
|-------|----------------|
| Menu / scope | `StaticAnalysis/cli/menus/static_analysis_menu.py`, `menus/static_analysis_menu_helpers.py`, `flows/selection.py` |
| Run lock + params | `StaticAnalysis/cli/flows/run_dispatch.py`, `flows/run_locking.py` |
| Scan execution | `StaticAnalysis/cli/execution/scan_flow.py` **`execute_scan`** |
| Single APK | **`scan_report.generate_report`** → `core.pipeline` **`analyze_apk`** |
| Detectors | `StaticAnalysis/core/detector_runner.py` **`PIPELINE_STAGES`**, **`run_detector_pipeline`** |
| Stage summary | `StaticAnalysis/core/pipeline_artifacts.py` **`build_pipeline_summary`** attached to **`report.metadata["pipeline_summary"]`** |
| String pass (post-artifacts) | `scan_flow.py` calls **`string_analysis_payload.analyse_string_payload`** on **`base_report`** only |
| Result render + persist | `StaticAnalysis/cli/execution/results.py` **`render_run_results`**; `persist_run_summary` in `cli/persistence/run_summary.py` |
| Evidence / audits | `output/audit/persistence/<session>_persistence_audit.json`; `logging` category **`static`** → `logs/static_analysis.log` |

**End boundary:** Interactive flow returns to menu after **`render_run_results`** and post-processing (`cli/flows/postprocessing.py`). Non-interactive callers use **`execute_run_spec`** in **`run_dispatch.py`**.

---

## 3. Detector registration and failures

**Registration:** Fixed tuple **`PIPELINE_STAGES`** in `detector_runner.py` (ordering is the contract).

**Profile gating:**

- `AnalysisConfig.profile` maps quick/full (`scan_report.build_analysis_config`).
- Per-stage **`include_in_quick`**, **`applies_to_profile`**, **`enabled_detectors`** may skip stages with **`Badge.SKIPPED`** and documented reasons (`run_detector_pipeline`).

**Exceptions:**

- **`run_detector_pipeline`:** broad **`except Exception`** wraps each detector → **`_build_error_result`** (`Badge.ERROR`), continues pipeline (**no abort**).
- **`scan_report.generate_report`:** **`StaticAnalysisError`** from **`analyze_apk`** → artifact marked skipped / error message (heartbeat `error:analyze_apk`).
- **`db_masvs_summary.render_db_masvs_summary`:** **`except Exception: pass`** swallows failures for MASVS terminal block (known visibility hole).

Operator implication: detector failures usually **appear in per-report `pipeline_summary`** and often in CLI cards IF **`verbose_output`** or error lines are printed; aggregated app summary relies on **`_summarize_app_pipeline`** (see gaps below).

---

## 4. String analysis path (full run)

**Entry for “full static” UX:**

1. **`build_analysis_config`:** **`enable_string_index`** is **False** only for **`metadata`** and **`permissions`** profiles; **Full** enables index path in core pipeline.
2. Engine: `StaticAnalysis/engine/strings.py` **`analyse_strings`** uses **`modules/string_analysis`** (index, aggregates, detectors for endpoints/cloud/tokens, noise policy, selection).
3. **Post-scan:** **`analyse_string_payload`** runs once per app on **`base_report.file_path`** after all artifact loops (`scan_flow.py`). Failures → **`logging_engine.get_error_logger().exception`** + **`empty_string_analysis_payload`** with **`warnings`** list — **easy to miss** if operator only scans stdout cards.

**Implications for audit fields:**

- **Splits:** string “intelligence” for the aggregated app row is tied to **base APK path**, not each split APK separately (unless extended by design).
- **Metrics:** `empty_string_analysis_payload` / richer maps can feed **counts, noise_counts, structured** buckets — surfaced today mainly through **`render_run_results`** string sections / DB persistence, **not** a compact run-health JSON.

---

## 5. Pipeline summary aggregation gaps (cross-artifact apps)

Per-artifact **`metadata["pipeline_summary"]`** may include **`skipped_detectors`** (explicit reasons).

**`scan_report._summarize_app_pipeline`** aggregates **counts** (`detector_total`, `detector_executed`, `detector_skipped`) and errors/fails/slow lists, but **does not** merge **`skipped_detectors`** from each artifact into a single deduped list for the CLI **app_summary**.

**Ticket-shaped fix:** Extend `_summarize_app_pipeline` (and persistence mirror in `results._summarize_app_pipeline_for_results` if still used) to carry **`skipped_stages`** / **`intentional_skips`** vs **`unexpected_skips`** if we classify reasons.

---

## 6. Split APK behavior (incl. TikTok-scale)

**Selection:**

- **`ArtifactGroup`** from `StaticAnalysis/core/repository.py` (grouping by capture / session); **`scan_flow._dedupe_artifacts`** per group.

**Scanning:**

- Default **`RunParameters.scan_splits`** (`SCYTALEDROID_STATIC_SCAN_SPLITS`, default **True**): interactive **Full** analyzes **multiple artifacts** when present.
- **Exception:** **`run_ctx.batch` and `run_ctx.quiet` and not `scan_splits`:** **`scan_flow`** reduces to **`base_artifact` or first artifact** (“predictable dataset” behavior).

**Identity / integrity:**

- **`AppRunResult.base_artifact_outcome()`** prefers **`integrity` profile `role==base`** from report metadata.

**Operator warnings:**

- **`scan_view`** outlier messaging when **`artifact_count > 20`** (card path).

**Gaps:**

- No single field **`artifacts_failed` vs `artifacts_partial`** driving **`final_status`**.
- **`create_static_run_ledger` failure** logged as **`log.warning`** only — app may proceed with **`static_run_id=None`** downstream (risk of orphaned UX).

---

## 7. Reports and DB persistence

| Concern | Location |
|---------|----------|
| Report JSON on disk | `StaticAnalysis/persistence/reports.py` **`save_report`** (raises **`ReportStorageError`** → surfaced to `generate_report`) |
| Findings/session DB | **`persist_run_summary`** (`cli/persistence/run_summary.py`), transaction wrapper **`transaction_flow.py`** |
| Run outcome flags | **`RunOutcome.persistence_failed`**, **`failures`**, **`audit_notes`** (`cli/core/models.py`) |
| Paper-grade / governance | **`artifact_publication.publish_persisted_artifacts`** (`cli/execution/artifact_publication.py`) |

**Silent-ish paths to audit:**

- **`ReportStorageError`:** logged + returned to caller; menu may still “feel OK” until footer / audit JSON.
- **Governance / intel DB:** downgrade to EXPERIMENTAL; must **not** be treated as core persistence failure (recent fix: warnings not folded into **`persistence_errors`**).

---

## 8. Proposed run-health summary (schema sketch)

Emit one **JSON artifact** under `output/audit/static/` (name TBD), written at end of **`render_run_results`** or **`postprocessing`**, plus optional CLI headline.

### Run-level

| Field | Source today | Notes |
|-------|---------------|-------|
| `session_stamp`, `session_label` | `RunParameters` | |
| `profile`, `preset` | `profile` + `profile_label` / menu command title | Normalize naming |
| `package_count`, `artifact_count_plan` | `ScopeSelection`; `scan_flow` totals | |
| `apps_completed` | Loop counter vs `total_apps` | |
| `apps_partial` / `apps_failed` | **New derivation** from `AppRunResult` + pipeline | Define rules |
| `detector_stages_total` | `len(PIPELINE_STAGES)` × artifacts or aggregated `pipeline_summary` | Document definition |
| `detector_errors` | Sum `error_count` / `error_detectors` | |
| `skipped_stages_intentional` | Merge **`skipped_detectors`** with reason classes | Requires §5 fix |
| `parse_fallback_count` | Count metadata `resource_fallback`, `label_fallback`, bounds warnings | Heuristic |
| `string_analysis` | Snapshot from **`base_string_data`** + warnings | Extend payload |
| `persistence_failed` | `RunOutcome` | |
| `report_paths` | From `ArtifactOutcome.saved_path` / audit path | |
| `db_static_run_ids` | `AppRunResult.static_run_id` list | |

### App-level

| Field | Source today |
|-------|----------------|
| `package_name`, `app_label` | `AppRunResult` |
| `capture_id` / group | `ArtifactGroup.capture_id`, `RepositoryArtifact` metadata |
| `artifact_roles` base/split counts | Integrity metadata per `ArtifactOutcome.report` |
| `discovered` / `executed` / `failed` | `AppRunResult` counters |
| Pipeline | Merge per-artifact **`pipeline_summary`** |
| `string_summary` | Derive from **`base_string_data`** maps |
| `report_saved` | Any `ArtifactOutcome.saved_path` |
| `db_persisted` | `static_run_id` + txn success markers |
| `final_status` | **New**: `complete` / `partial` / `failed` / `skipped` |

---

## 9. Proposed status semantics

| Status | Definition (draft) |
|--------|---------------------|
| **complete** | Identity valid; expected artifacts scanned; zero artifact-level hard errors; pipeline ERROR count == 0; persistence OK when enabled; (optional) harvest contract satisfied |
| **partial** | Trustworthy report emitted but ≥1 artifact failed OR detector ERROR OR resource fallback affecting strings OR incomplete split observation |
| **failed** | No trustworthy combined report OR identity invalid OR persistence aborted run |
| **skipped** | Profile/menu excluded (dry-run drilldown, identity skip, exploratory-only blocked under paper-grade) |

---

## 10. Logging and “find failures fast”

| Signal | Where |
|--------|-------|
| Static pipeline | **`logs/static_analysis.log`**, **`logs/static_analysis.jsonl`** |
| Hard errors mirrored | **`logs/error.log`** |
| Third-party parsers | **`logs/third_party/`** |
| Lock stuck | **`data/locks/static_analysis.lock`** (stale PID reclaim on Unix in `run_locking.py`) |
| Scripted tail | **`python -m scytaledroid.StaticAnalysis.audit --session …`** |

**Code audit targets for broad handlers** (prefer tightening in small tickets):

| Area | Pattern | Risk |
|------|---------|------|
| `detector_runner` | `except Exception` on observer emit | Drops telemetry only |
| `detector_runner` | `except Exception` around detector **run** | Becomes **`Badge.ERROR`** — visible if summary wired |
| `core/pipeline.py` | `_safe_get_app_label`, tuple helpers | Swallows parser noise into **metadata** — **needs surfacing** in health JSON |
| `string_analysis_payload` | `except Exception` | Falls back to empty payload — OK if **surfaced** in summary |
| `db_masvs_summary` | swallow all on render | Terminal MASVS can disappear silently |

---

## 11. Implementation plan (phased — smallest safe first)

1. **Done / adjacent:** stale lock reclaim; persistence audit JSON; **`StaticAnalysis.audit`** log tail CLI; governance warning not marking **`persistence_failed`**.
2. **Quick wins (low risk):** Extend **`_summarize_app_pipeline`** to aggregate **`skipped_detectors`** + counts of resource fallbacks per app; print one **RUN_HEALTH** stdout line when `SCYTALEDROID_STATIC_RUN_HEALTH_SUMMARY=1`.
3. **Artifact:** Emit **`output/audit/static/<session>_run_health.json`** from **`RunOutcome` + merged pipeline summaries + string snippet stats** (no schema migration).
4. **Status field:** Add **`final_status`** on `AppRunResult` (computed in **`scan_flow`** end-of-app block) + persist into static run manifest or JSON sidecar only (DB column = later ADR).
5. **String intelligence block:** Dedicated reducer over **`base_string_data`** keys (`counts`, `noise_counts`, `structured`, warnings) documented in **`docs/static_analysis/string_intelligence_explore.md`** alignment.
6. **Split transparency:** When **`discovered_artifacts > N`**, require explicit CLI banner “scanning **K** APKs incl. splits; strings from **base** only” unless future multi-APK strings.

---

## 12. Checklist for Cursor follow-ups

Use this doc to open tickets with **file:function** anchors:

- [ ] **`scan_report._summarize_app_pipeline`** — merge `skipped_deticators`, fallback flags.
- [ ] **`scan_flow.execute_scan`** — compute **`final_status`**, propagate to **`RunOutcome.deferred_diagnostics`**.
- [ ] **`string_analysis_payload` / results render** — surface string failure + counts in compact summary.
- [ ] **`core/pipeline.py` / `pipeline_artifacts`** — ensure parse fallback counts hit **`pipeline_summary`** or sibling metadata field.
- [ ] **`db_masvs_summary.render_db_masvs_summary`** — replace bare **`except`** with logged one-liner + optional CLI warn.
- [ ] **Persisted JSON artifact** — `run_health.json` schema v1 aligned with §8.

---

## Document control

| Version | Date | Note |
|---------|------|------|
| v1 | 2026-05-01 | Initial workflow audit from source trace |
