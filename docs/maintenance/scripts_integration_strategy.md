# `scripts/` lifecycle inventory and integration plan

This document is the **first-pass script lifecycle inventory** for everything under `scripts/`. `scripts/db/` is inventoried only in [`db_scripts_inventory.md`](db_scripts_inventory.md).

**Goals:** reduce mystery scripts and manual operator burden **without** breaking stable paths, docs, CI, or personal workflows.

**Current cleanup posture:** inventory / classification / archive candidates /
integration targets first. Generated caches may be removed immediately. Tracked
script paths should be deleted or moved only after replacement paths, docs,
tests, and operator habits are covered.

---

## Classification enum

Each script (or shell/SQL artifact) gets one primary class:

| Class | Meaning |
| --- | --- |
| `supported_operator` | Documented operator or deploy/readiness path; keep stable argv. |
| `ci_or_gate` | Invoked from tests, compileall gate, or repo policy checks. |
| `workflow_helper` | Read-mostly audits, smoke bundles, or thin CLI over `scytaledroid/` services. |
| `migration_historical` | One-time or rare backfill / DDL companion; not weekly operations. |
| `demo_transitional` | Demo, profile export smoke, or transitional wrapper per `supported_entrypoints.md`. |
| `candidate_archive` | Likely safe to **move** to `scripts/archive/...` after confirming no CI/docs depend on path (separate PR). |
| `candidate_delete_later` | After menu/`python -m` parity and doc migration; **no path delete** in wave 1. |
| `unknown_needs_owner` | No clear in-repo references; assign an owner or confirm external use. |

**R/W:** `RO` = read-only default; `W` = writes DB/DDL/files by design; `MIX` = read default with explicit write flags.

**DB:** `core` = analyst MariaDB; `intel` = Permission Intel DSN; `opt` = optional flags; `none` = no DB.

**`--help`:** `yes` = argparse or `-h`/`--help` supported; `partial` = thin wrapper with manual `-h` only; `n/a` = shell/SQL/library.

**Refs (compact):** `AGENTS` · `db/README` · `supported_entrypoints` · `tests/*` path · `menu:` hint · `code:` importing module.

---

## Explicit keep list (no archive/delete without separate discussion)

These stay in place as **active operator, readiness, posture, catalog hygiene, or shared library** surfaces:

| Path |
| --- |
| `scripts/db/check_permission_intel.py` |
| `scripts/db/recreate_web_consumer_views.py` |
| `scripts/db/refresh_static_analysis_sessions.py` |
| `scripts/db/verify_static_session_id_rollout.py` |
| `scripts/db/prune_artifact_registry_dangling.py` |
| `scripts/db/view_repair_support.py` |
| `scripts/db/report_app_label_hygiene.py` |
| `scripts/db/apply_app_display_name_overrides.py` |
| `scripts/db/audit_static_session.py` |
| `scripts/db/report_static_session_grain_integrity.py` |
| `scripts/db/report_package_lineage_workbench.py` |
| `scripts/db/report_static_analysis_targets.py` |
| `scripts/db/report_dynamic_static_recovery_plan.py` |
| `scripts/db/smoke_web_db.sh` |

**Note:** `scytaledroid_doctor` lives at **`scripts/db/scytaledroid_doctor.sh`** (not repo root). Treat it as part of the same keep contract as `smoke_web_db.sh` and `check_permission_intel.py`.

---

## Long-term integration direction

**Target:** scripts remain **backend helpers** and stable argv; operators see work through **menus, static preflight/post-run audit, deploy checks**, and documented smoke paths.

| Direction | Example |
| --- | --- |
| Preflight | Static preflight shows catalog display-label hygiene summary (partially done). |
| Post-run | Optional “audit card” runs or links read-only checks: `session_static_health`, grain integrity, artifact registry. |
| Governance / DB | Permission Intel readiness (DB Tools), view posture (`recreate_web_consumer_views` posture/semantic), catalog hygiene submenu. |
| Writes | Any DB write remains behind **explicit confirmation** in menus or deliberate CLI flags (`--apply`, `--confirm`). |

## Current refinement pass

Do not add another DB script until its family and replacement status are clear in
[`db_scripts_inventory.md`](db_scripts_inventory.md). The current direction is:

- keep existing paths stable;
- move reusable report/check logic into `scytaledroid/Database/db_utils/` or
  narrowly scoped `scytaledroid/Database/db_scripts/` modules;
- for package lineage / exact recovery, use
  `scytaledroid/Database/db_scripts/package_lineage_read_model.py` as the
  shared read-model seed;
- let menu code call app modules in-process when practical;
- keep DDL, prune, and one-time migration flows as explicit operator commands;
- archive only after a separate grep/docs/tests/external-use check.

Current combine-later families: package lineage / exact recovery, evidence
storage, dynamic/static alignment, static sessions, artifact registry,
Permission Intel, and catalog hygiene.

### 2026-07-09 prune checkpoint

The active script tree has already had several stale wrappers removed (see
**First Removed Historical Helpers** below). The next safe cleanup wave is
archive-oriented, not delete-first:

| Bucket | Candidate paths | Replacement / reason to preserve for now |
| --- | --- | --- |
| Legacy dynamic shell helpers | `scripts/dynamic/run_idle.sh`, `scripts/dynamic/run_scripted_interaction.sh` | Superseded by TUI dynamic capture flows, but may still be used by external operator aliases. Archive only after external-use check. |
| Historical DB backfills | `scripts/db/backfill_*` | One-time or rare migrations. Keep while rollout/repair receipts are still being reconciled; archive after stable DB posture. |
| Historical normalization helpers | `scripts/db/normalize_*`, `scripts/db/phase_b1_*`, `scripts/db/schema_version_width_hotfix.py` | Maintenance helpers with explicit dry-run/apply behavior. Archive only after schema posture proves no active need. |
| Dynamic repair tools with no current in-repo caller | `scripts/db/repair_dynamic_*` | Keep while Paper 3 evidence repair remains active. These are operator-triggered recovery tools, not dead code. |
| Static report repair tools | `scripts/static_analysis/repair_*`, `scripts/static_analysis/quarantine_unreferenced_static_archive_reports.py` | Keep through Paper 3 static/report stabilization. |

The current active Paper 3 / APK-storage additions are not archive candidates:

| Path | Reason |
| --- | --- |
| `scripts/db/report_dynamic_paper_freeze_readiness.py` | Generates cutoff evidence tiers and paper-readiness framing. |
| `scripts/db/report_paper3_writing_package.py` | Generates the Paper 3 writing bridge/workspace. |
| `scripts/device_analysis/check_external_apk_store_mount.py` | Mercury/APK-store guard and operator check. |
| `scripts/device_analysis/audit_apk_cold_promotion.py` | Read-only hot/cold candidate classification. |
| `scripts/device_analysis/promote_apk_blobs_to_cold_store.py` | Dry-run default cold-promotion apply tool. |
| `scripts/device_analysis/report_apk_inventory_model.py` | APK identity transition and run-retirement analysis. |
| `scripts/device_analysis/report_apk_release_variants.py` | Read-only same-package/version byte and signer comparison. |
| `scripts/device_analysis/report_legacy_harvest_run_retirement.py` | Legacy harvest folder retirement safety checks. |
| `scripts/device_analysis/verify_apk_library_integrity.py` | APK library/storage integrity verification. |

---

## Suggested archive layout (future PR only)

When inventory and grep confirm **no path-dependent CI**, move candidates under:

```text
scripts/archive/db/2026_static_session_rollout/
```

### `README.md` template (place inside archive folder when moving)

```markdown
# Archived: static session ID rollout helpers

## Why archived

One-time or completed rollout of `static_analysis_runs.static_session_id` linkage to
`static_analysis_sessions`. Normal operations use `refresh_static_analysis_sessions.py`
and canonical static menus; operators should not run these weekly.

## What replaced normal usage

- Session rollups: `scripts/db/refresh_static_analysis_sessions.py` (still active; not archived).
- Verification: `scripts/db/verify_static_session_id_rollout.py` (read-only counts; optional `--explain` for artifact_registry legend on stderr).
- Grain integrity: `scripts/db/report_static_session_grain_integrity.py`.

## Safe to re-run?

Document per script: idempotent yes/no, and whether a second run is a no-op or could
duplicate work. Operators must read each script's docstring before re-run.

## References at archive time

(List grep hits from docs/CI at the time of the move.)
```

**Do not move files until:** a follow-up PR greps for the basename/path across `docs/`, `tests/`, `.github/`, and shell wrappers; updates references; then moves with this README.

---

## First Removed Historical Helpers

| Path | Basis |
| --- | --- |
| `scripts/db/backfill_static_session_id_on_runs.py` | Removed from active scripts after reference check; historical one-time rollout helper. Use `refresh_static_analysis_sessions.py` and `verify_static_session_id_rollout.py` for maintained session repair/verification. |
| `scripts/db/sql/backfill_static_analysis_runs_static_session_id.sql` | Removed with the Python backfill companion; no active code/test imports. |
| `scripts/db/report_dynamic_baseline_sufficiency_audit.py` | Removed unreferenced standalone audit wrapper; historical outputs remain under `output/audit/dynamic_baseline_sufficiency/`. |
| `scripts/db/report_dynamic_collection_queue_alignment.py` | Removed unreferenced standalone audit wrapper; queue/read-model checks should be routed through maintained dynamic reports or menus. |
| `scripts/db/report_dynamic_db_truth_audit.py` | Removed unreferenced standalone audit wrapper; superseded by maintained dynamic deep/readiness reports for active workflows. |
| `scripts/db/report_dynamic_evidence_scope_audit.py` | Removed unreferenced standalone audit wrapper; historical outputs remain under `output/audit/dynamic_evidence_scope/`. |
| `scripts/db/report_dynamic_sql_audit.py` | Removed unreferenced standalone SQL audit wrapper; no code/test/menu references. |
| `scripts/db/report_storage_pressure.py` | Removed misplaced DB wrapper around DeviceAnalysis storage-pressure logic; active storage tooling lives under `scytaledroid/DeviceAnalysis/services/storage_pressure.py` and `scripts/device_analysis/`. |
| `scripts/db/report_phase_b1_join_key_normalization.py` | Removed compatibility wrapper; use `scripts/db/phase_b1_join_key_normalization.py report`. |
| `scripts/db/apply_phase_b1_join_key_normalization.py` | Removed compatibility wrapper; use `scripts/db/phase_b1_join_key_normalization.py apply`. |
| `scripts/db/report_phase_b1_session_stamp_backlog.py` | Removed compatibility wrapper; use `scripts/db/phase_b1_session_stamp_backlog.py report`. |
| `scripts/db/apply_phase_b1_session_stamp_backlog.py` | Removed compatibility wrapper; use `scripts/db/phase_b1_session_stamp_backlog.py apply`. |
| `scripts/db/report_schema_version_width_hotfix.py` | Removed compatibility wrapper; use `scripts/db/schema_version_width_hotfix.py report`. |
| `scripts/db/apply_schema_version_width_hotfix.py` | Removed compatibility wrapper; use `scripts/db/schema_version_width_hotfix.py apply`. |
| `scripts/db/report_package_lineage_coverage.py` | Removed compatibility wrapper; use `scripts/db/report_apk_lineage_availability.py` with the same flags. |
| `scripts/static_analysis/headless_all_apps.py` | Removed unreferenced headless static wrapper; use maintained static CLI/menu flows for all-app runs. |
| `scripts/operator/measure_inventory_latency.py` | Removed unreferenced inventory timing helper; use inventory logs and maintained device inventory workflows. |
| `scripts/operator/backfill_dynamic_pcap_identity.py` | Removed unreferenced historical dynamic PCAP identity backfill helper; current dynamic writers populate capture identity. |
| `scripts/device_analysis/audit_apk_storage_retention.py` | Removed stale retention-audit wrapper; current storage checks use storage-pressure, thin-session, and APK transition reports. |
| `scripts/device_analysis/migrate_legacy_harvest_storage.py` | Removed unreferenced legacy harvest migration wrapper after APK-library/storage transition tooling superseded it. |
| `scytaledroid/DeviceAnalysis/services/legacy_harvest_migration.py` | Removed dead backing service for the deleted legacy harvest migration wrapper; no active imports remained. |
| `scripts/db/sql/deep_db_exploration_20260614.sql` | Removed dated one-off read-only exploration workbench; maintained posture/audit SQL companions remain. |
| `scripts/device_analysis/audit_apk_library_migration.py` | Removed stale first-pass APK-library migration audit; use current APK inventory, transition-debt, retirement, and integrity reports. |
| `scripts/static_analysis/refresh_persistence_audit_summary.py` | Removed unreferenced static persistence-audit artifact refresher; maintained persistence-audit logic remains in `scytaledroid/StaticAnalysis/cli/flows/run_persistence_audit.py`. |
| `scripts/db/report_research_cohorts.py` | Removed redundant standalone cohort report; research cohort selection/readout is exposed through dynamic/static/reporting flows and `scytaledroid.Database.db_func.research_cohorts`. |
| `scripts/operator/diagnose_scope.py` | Removed unreferenced harvest-scope diagnostic helper; current inventory/harvest menus show scoped counts and exclusion state. |
| `scripts/operator/backfill_dynamic_network_features.py` | Removed unreferenced one-off dynamic feature backfill wrapper. Current dynamic evidence DB indexing owns feature-row persistence. |
| `scytaledroid/DynamicAnalysis/storage/feature_backfill.py` | Removed dead backing service for the deleted dynamic feature backfill wrapper; no active imports remained. |
| `scripts/db/report_dynamic_draft_package.py` | Removed superseded Paper 3 draft-package exporter; current cutoff/writeup workflow uses `scripts/db/report_dynamic_paper_freeze_readiness.py` and `scripts/db/report_paper3_writing_package.py`. |
| `tests/database/test_report_dynamic_draft_package.py` | Removed with the superseded exporter; its private-helper assertions only protected the deleted script. |

All other paths still need a **per-environment** decision before removal.

---

## Inventory: `scripts/db/` (Python)

Kept in one place: **[`db_scripts_inventory.md`](db_scripts_inventory.md)** — class, purpose, read/write posture, menu owner and lifecycle status for every script, plus a list of scripts not yet classified. The duplicate table that lived here was merged into it in 2026-10.

---

## Inventory: `scripts/db/sql/` (SQL packs)

| Path | Class | R/W | DB | `--help` | Key references | Owner / integration | Action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `verify_static_session_id_rollout.sql` | workflow_helper | RO | core | n/a | optional manual verify | ops SQL pack | keep |
| `session_summary_from_static_analysis_runs.sql` | workflow_helper | RO | core | n/a | database_target_schema_v2.md; static_child_table_join_map | analyst SQL | keep |
| `report_static_session_stamp_cohort_rollups.sql` | workflow_helper | RO | core | n/a | golden session / supersession rollups; child join map | analyst SQL | keep |
| `audit_information_schema_static_relationships.sql` | workflow_helper | RO | core | n/a | database_static_child_table_join_map.md | schema audit | keep |
| `smoke_canonical_web_views.sql` | ci_or_gate | RO | core | n/a | Web consumer posture | smoke | keep |
| `check_schema_posture.sql` | workflow_helper | RO | core | n/a | db README; `test_web_db_scripts.py` | posture | keep |

---

## Inventory: repo root and `scripts/` top level

| Path | Class | R/W | DB | `--help` | Key references | Owner / integration | Action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `scripts/__init__.py` | workflow_helper | RO | none | yes | compileall gate | n/a | keep |
| `clean_project.sh` | workflow_helper | MIX | none | n/a | touches `scripts/db` tree per script | dev hygiene | keep |
| `install_wireshark_cli.sh` | supported_operator | W | none | n/a | `menu_reports.py` suggests sudo path | Dynamic capture deps | keep |
| `stress_static_postcheck.py` | ci_or_gate | RO | none | yes | `tests/static_analysis/test_batch_log_semantics.py` docstring | static batch QA | keep |
| `static_analysis_audit_logs.sh` | workflow_helper | RO | none | n/a | static_analysis_audit_runbook.md | ops | keep |

---

## Inventory: `scripts/static_analysis/`

| Path | Class | R/W | DB | `--help` | Key references | Owner / integration | Action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `run_artifact_map.py` | supported_operator | RO | opt | yes | supported_entrypoints; `test_run_artifact_map_script.py` | Static diagnostics | keep |
| `determinism_gate.py` | ci_or_gate | RO | opt | yes | README determinism; `test_determinism_gate_schema.py` | CI static | keep |
| `validate_report_permission_risk.py` | ci_or_gate | RO | none | yes | `test_scripts_help_contract.py` | CI safety | keep |
| `verify_persistence_audit.py` | workflow_helper | RO | none | yes | persistence QA | post-run | **expose_menu** candidate |
| `post_run_session_summary.py` | workflow_helper | RO | opt | yes | permission_intelligence_pipeline.md; wraps `cli.audit.post_run_session_summary` | Static post-run | keep · **deprecate_cli** when menu parity |
| `permission_session_insights.py` | workflow_helper | RO | opt | yes | same | Static audit | keep · deprecate_cli later |
| `permission_app_drilldown.py` | workflow_helper | RO | opt | yes | same | Static audit | keep · deprecate_cli later |
| `replay_persist_run_summary.py` | workflow_helper | MIX | opt | yes | permission_intelligence_pipeline.md | persistence QA | keep |
| `static_baseline_tables.py` | workflow_helper | RO | opt | partial | README baseline | research corpus | keep · fix import path doc if needed |
| `static_baseline_tables_impl.py` | workflow_helper | RO | opt | yes | imported by static_baseline_tables | research corpus | keep |

---

## Inventory: `scripts/publication/`

| Path | Class | R/W | DB | `--help` | Key references | Owner / integration | Action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `export_profile.py` | supported_operator | MIX | opt | yes | supported_entrypoints | Publication entry | keep |
| `export_manifest_gate.py` | ci_or_gate | RO | none | yes | export_manifest_contract.md; legacy term gate | publication CI | keep |
| `generate_paper2_results_v2.py` | supported_operator | RO | none | yes | supported_entrypoints | Paper 2 v2 results package | keep |
| `validate_paper2_results_v2.py` | supported_operator | RO | none | yes | supported_entrypoints | independent Paper 2 v2 validation | keep |
| `ingest_publication_bundle.py` | retired | MIX | core | n/a | retired v1 publication bundle ingest | DB maintenance (legacy ingest) | remove |
| `publication_exports.py` | demo_transitional | RO | none | partial | supported_entrypoints | thin service wrapper | keep |
| `publication_results_numbers.py` | demo_transitional | RO | none | partial | supported_entrypoints | thin wrapper | keep |
| `publication_scientific_qa.py` | demo_transitional | RO | none | partial | supported_entrypoints | thin wrapper | keep |
| `publication_pipeline_audit.py` | retired | RO | none | n/a | retired v1 36-run audit contract | thin wrapper | remove |
| `publication_ml_audit_report.py` | demo_transitional | RO | none | partial | supported_entrypoints; legacy term gate | thin wrapper | keep |
| `profile_v3_exports.py` | demo_transitional | RO | none | partial | supported_entrypoints | thin wrapper | keep |

---

## Inventory: `scripts/profile_tools/`

| Path | Class | R/W | DB | `--help` | Key references | Owner / integration | Action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `profile_v3_integrity_gates.py` | supported_operator | RO | opt | partial | supported_entrypoints; `tests/dynamic/test_profile_v3_*` | Profile v3 paper gate | keep |
| `profile_v3_catalog_validate.py` | workflow_helper | RO | none | yes | repo_ownership_map | profile QA | keep |
| `profile_v3_catalog_suggest_missing.py` | workflow_helper | RO | core | yes | freeze_check hints | catalog ops | keep |
| `profile_v3_catalog_freeze_check.py` | workflow_helper | RO | none | yes | freeze policy tests | profile gate | keep |
| `profile_v3_apk_freshness_check.py` | workflow_helper | RO | none | yes | profile tests | harvest freshness | keep |
| `profile_v3_static_ready_check.py` | workflow_helper | RO | core | yes | profile pipeline | static readiness | keep |
| `profile_v3_scripted_coverage_audit.py` | workflow_helper | RO | none | yes | profile pipeline | coverage | keep |
| `profile_v3_manifest_build.py` | workflow_helper | RO | opt | partial | service `main` | dynamic profile | keep |
| `profile_v3_capture_status.py` | workflow_helper | RO | opt | partial | service `main` | dynamic profile | keep |

---

## Inventory: `scripts/operator/`

| Path | Class | R/W | DB | `--help` | Key references | Owner / integration | Action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `run_profile_v2_demo.sh` | demo_transitional | RO | none | n/a | supported_entrypoints | v2 demo | keep until v2 retired |
| `run_profile_v3_demo.sh` | demo_transitional | RO | none | n/a | supported_entrypoints; repo_ownership_map | v3 demo | keep |
| `provenance_stamp.py` | demo_transitional | MIX | none | yes | demo sh wrappers | demo | keep |
| `diagnose_static_pipeline.py` | workflow_helper | RO | core | yes | legacy_static_reader map | static health | **expose_menu** candidate |
| `env_check.py` | workflow_helper | RO | none | yes | `lib/android_tools.sh` | env | keep |
| `ensure_permission_matrix.py` | workflow_helper | MIX | core | yes | matrix QA | static DB | keep |
| `log_run_timeline.py` | workflow_helper | RO | none | yes | housekeeping.md | ops logs | keep |
| `log_error_summary.py` | workflow_helper | RO | none | yes | housekeeping.md | ops logs | keep |
| `profile_v3_freeze_bundle.py` | workflow_helper | RO | none | yes | freeze workflow | publication | keep |
| `audit_dynamic_network_consistency.py` | workflow_helper | RO | core | yes | dynamic QA | dynamic menu candidate | keep |

---

## Inventory: `scripts/operational/`

| Path | Class | R/W | DB | `--help` | Key references | Owner / integration | Action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `query_mode_smoke_gate.py` | ci_or_gate | RO | opt | yes | internal gates | CI | keep |
| `semantic_lint_operational.py` | ci_or_gate | RO | none | yes | internal gates | CI | keep |
| `write_snapshot_bundle.py` | workflow_helper | MIX | none | yes | governance inputs | ops bundles | keep |
| `phase_f3_acceptance_gate.py` | ci_or_gate | RO | none | yes | phase gates | CI | keep |

---

## Inventory: `scripts/device_analysis/`

| Path | Class | R/W | DB | `--help` | Key references | Owner / integration | Action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `inventory_determinism_gate.py` | ci_or_gate | RO | none | yes | repo_ownership_map | harvest CI | keep |
| `replay_harvest_db_mirror.py` | workflow_helper | MIX | core | yes | harvest replay service | device ops | keep |
| `check_external_apk_store_mount.py` | supported_operator | RO | none | yes | Mercury/APK storage guard | Evidence & Workspace / main menu | keep |
| `audit_apk_cold_promotion.py` | workflow_helper | RO | opt | yes | hot/cold storage transition | APK storage maintenance | keep |
| `promote_apk_blobs_to_cold_store.py` | workflow_helper | MIX | none | yes | hot/cold storage transition | APK storage maintenance | keep |
| `seed_apk_library_from_receipts.py` | migration_historical | MIX | none | yes | APK library transition | APK storage maintenance | keep · archive_later after rollout |
| `repair_apk_library_logical_paths.py` | migration_historical | MIX | none | yes | APK library logical-path repair | APK storage maintenance | keep through rollout |
| `repair_regular_legacy_apks.py` | workflow_helper | MIX | none | yes | legacy regular APK repair | APK storage maintenance | keep through rollout |
| `report_apk_inventory_model.py` | workflow_helper | RO | none | yes | APK inventory transition | APK storage maintenance | keep |
| `report_apk_release_variants.py` | workflow_helper | RO | none | yes | repeated release signer comparison | APK storage maintenance | keep |
| `report_apk_transition_debt.py` | workflow_helper | RO | none | yes | APK transition debt report | APK storage maintenance | keep |
| `report_legacy_harvest_run_retirement.py` | workflow_helper | RO | opt | yes | legacy harvest retirement | APK storage maintenance | keep |
| `thin_harvest_session_apks.py` | workflow_helper | MIX | none | yes | storage thinning receipts | APK storage maintenance | keep |
| `verify_apk_library_integrity.py` | workflow_helper | RO | none | yes | APK library integrity | APK storage maintenance | keep |

---

## Inventory: `scripts/dynamic/`

| Path | Class | R/W | DB | `--help` | Key references | Owner / integration | Action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `evidence_hunt.py` | workflow_helper | MIX | opt | yes | legacy term gate | dynamic evidence | keep |
| `refresh_analysis_summaries.py` | workflow_helper | MIX | opt | yes | dynamic summary refresh | dynamic maintenance | keep |
| `run_idle.sh` | candidate_archive | RO | none | n/a | comment usage | dynamic shell | archive_later after external-use check |
| `run_scripted_interaction.sh` | candidate_archive | RO | none | n/a | comment usage | dynamic shell | archive_later after external-use check |

---

## Inventory: `scripts/dev/`

| Path | Class | R/W | DB | `--help` | Key references | Owner / integration | Action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get_latest_run.py` | workflow_helper | RO | opt | yes | `docs/runbook.md` | dev helper | keep |
| `check_dataset_ready.sh` | workflow_helper | RO | none | n/a | references install_wireshark | dataset dev | keep |

---

## Inventory: `scripts/lib/`

| Path | Class | R/W | DB | `--help` | Key references | Owner / integration | Action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `android_tools.sh` | workflow_helper | RO | none | n/a | env_check / tooling | bootstrap | keep |

---

## Non-script artifacts

| Path | Notes |
| --- | --- |
| `scripts/db/README.md` | Operator contract for DB scripts; **keep** and update when inventory changes. |

---

## Summary counts (approximate)

| Class | Count (approx.) |
| --- | ---: |
| supported_operator | 18 |
| ci_or_gate | 12 |
| workflow_helper | 45+ |
| migration_historical | 4 |
| demo_transitional | 12 |
| candidate_archive | 2–4 (pending org + grep) |
| unknown_needs_owner | 2 |

---

## Next steps (outside this doc-only PR)

1. Pick **post-run audit bundle** orchestration module; wire read-only calls to `session_static_health`, `report_static_session_grain_integrity`, `report_artifact_registry_integrity` (subprocess or imports).
2. Resolve **unknown_needs_owner** rows with team (external CI, personal aliases).
3. Optionally add **`python -m`** entrypoints for thin duplicates (`permission_intel_readiness`, static audit CLIs) before deprecating argv paths.

When adding a new script, add a row to this file, or to [`db_scripts_inventory.md`](db_scripts_inventory.md) instead if it lives under `scripts/db/`.
