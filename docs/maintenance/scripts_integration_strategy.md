# `scripts/` lifecycle inventory and integration plan

This document is the **first-pass script lifecycle inventory** for everything under `scripts/`. It complements [`db_scripts_inventory.md`](db_scripts_inventory.md) (DB Python scripts in more detail).

**Goals:** reduce mystery scripts and manual operator burden **without** breaking stable paths, docs, CI, or personal workflows.

**First PR scope (this document only):** inventory / classification / archive candidates / integration targets. **No deletions, no file moves, no behavior changes** beyond documentation.

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
| `scripts/db/view_repair_support.py` |
| `scripts/db/report_app_label_hygiene.py` |
| `scripts/db/apply_app_display_name_overrides.py` |
| `scripts/db/audit_static_session.py` |
| `scripts/db/report_static_session_grain_integrity.py` |
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
- Verification: `scripts/db/verify_static_session_id_rollout.py` (read-only counts).
- Grain integrity: `scripts/db/report_static_session_grain_integrity.py`.

## Safe to re-run?

Document per script: idempotent yes/no, and whether a second run is a no-op or could
duplicate work. Operators must read each script's docstring before re-run.

## References at archive time

(List grep hits from docs/CI at the time of the move.)
```

**Do not move files until:** a follow-up PR greps for the basename/path across `docs/`, `tests/`, `.github/`, and shell wrappers; updates references; then moves with this README.

---

## First archive candidates (reference check done for this pass)

| Path | Basis |
| --- | --- |
| `scripts/db/backfill_static_session_id_on_runs.py` | **Writes** `static_session_id` on historical runs; **only** referenced from maintenance docs (`db_scripts_inventory.md`, this file), not from `scytaledroid/` or tests. Strong **migration_historical** → **candidate_archive** after org confirmation. |
| `scripts/db/sql/backfill_static_analysis_runs_static_session_id.sql` | Companion SQL for the same rollout; archive **with** the Python backfill in the same folder. |

All other paths need a **per-environment** decision (e.g. whether every deployed DB has been backfilled) before a move.

---

## Inventory: `scripts/db/` (Python)

| Path | Class | R/W | DB | `--help` | Key references | Owner / integration | Action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `check_permission_intel.py` | supported_operator | RO | intel | yes | AGENTS; db README; gates | DB Tools · deploy smoke | **keep** (explicit list) |
| `recreate_web_consumer_views.py` | supported_operator | W | core | yes | AGENTS; db README; `tests/database/test_web_db_scripts.py` | DB maintenance · Web DDL | **keep** (explicit list) |
| `refresh_static_analysis_sessions.py` | supported_operator | W | core | yes | AGENTS; db README | DB maintenance menu · post-run job (future) | **keep** (explicit list) |
| `verify_static_session_id_rollout.py` | supported_operator | RO | core | yes | AGENTS; db README | **DB Tools → 12 (4)**; post-run → 11 | **keep** (explicit list) |
| `view_repair_support.py` | workflow_helper | RO | none | yes | imported by `recreate_web_consumer_views.py` | View repair library | **keep** (explicit list) |
| `report_app_label_hygiene.py` | supported_operator | RO | core | yes | menu Catalog hygiene; `tests/gates/test_app_display_name_catalog_scripts.py` | DB Tools → 11 | **keep** (explicit list) |
| `apply_app_display_name_overrides.py` | supported_operator | MIX | core | yes | menu Catalog hygiene (confirm); gate tests load module | DB Tools → 11 | **keep** (explicit list) |
| `audit_static_session.py` | supported_operator | RO | core | yes | selection/scan_formatters copy-paste SQL; maintenance maps | Static diagnostics · post-run | **keep** (explicit list) |
| `report_static_session_grain_integrity.py` | supported_operator | RO | core | yes | scan_formatters hints | **DB Tools → 12**; post-run diagnostics → 11 | **keep** (explicit list) |
| `smoke_web_db.sh` | supported_operator | RO | core | n/a | AGENTS; `test_web_db_scripts.py` | Deploy with Web tree | **keep** (explicit list) |
| `scytaledroid_doctor.sh` | supported_operator | RO | core/intel | n/a | db README | Operator doctor bundle | **keep** (same contract as doctor path above) |
| `permission_intel_readiness.py` | workflow_helper | RO | intel | yes | permission_intelligence_pipeline.md; mirrors `db_utils.permission_intel_readiness` | DB Tools → 9 | keep · **deprecate_cli** later if `python -m` parity |
| `session_static_health.py` | workflow_helper | RO | core | yes | bridge_posture; legacy_static_reader map | **DB Tools → 12**; static post-run diagnostics → 11 | keep |
| `audit_static_permission_observation_linkage.py` | ci_or_gate | RO | core+intel | yes | PI readiness bundle sh; docs | Governance CI | keep |
| `audit_permission_intel_queue_compatibility.py` | workflow_helper | RO | core+intel | yes | PI docs; `run_permission_intel_scytale_s2_readiness_audit.sh` | Governance | keep |
| `audit_permission_name_casing.py` | workflow_helper | RO | core+intel | yes | permission_intelligence_pipeline.md | Governance | keep |
| `static_schema_audit.py` | workflow_helper | RO | core | yes | static_database_schema_audit_plan.md | Schema audit / gates | keep |
| `validate_canonical_masvs_session.py` | ci_or_gate | RO | core | yes | canonical_masvs_risk_views.md | Static research gates | keep |
| `verify_evidence_manifest.py` | workflow_helper | MIX | opt | yes | evidence_run_manifest_spec.md | Post-run / deploy | keep |
| `report_artifact_registry_integrity.py` | workflow_helper | RO | core | yes | AGENTS artifact registry note | **DB Tools → 12**; post-run diagnostics → 11 | keep |
| `run_permission_intel_scytale_s2_readiness_audit.sh` | workflow_helper | RO | core+intel | n/a | PI readiness docs | Bundle smoke | keep |
| `backfill_static_session_id_on_runs.py` | migration_historical | W | core | yes | db_scripts_inventory; **no code imports** | superseded by normal rollup + verify | **archive_later** (see template) |
| `__init__.py` | workflow_helper | RO | none | yes | package marker | n/a | keep |

---

## Inventory: `scripts/db/sql/` (SQL packs)

| Path | Class | R/W | DB | `--help` | Key references | Owner / integration | Action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `backfill_static_analysis_runs_static_session_id.sql` | migration_historical | W | core | n/a | paired with Python backfill | archive with backfill py | **archive_later** |
| `verify_static_session_id_rollout.sql` | workflow_helper | RO | core | n/a | optional manual verify | ops SQL pack | keep |
| `session_summary_from_static_analysis_runs.sql` | workflow_helper | RO | core | n/a | database_target_schema_v2.md; static_child_table_join_map | analyst SQL | keep |
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
| `stress_static_postcheck.py` | ci_or_gate | RO | none | yes | `tests/static/test_static_batch_summary.py` docstring | static batch QA | keep |
| `static_analysis_audit_logs.sh` | workflow_helper | RO | none | n/a | static_analysis_audit_runbook.md | ops | keep |

---

## Inventory: `scripts/static_analysis/`

| Path | Class | R/W | DB | `--help` | Key references | Owner / integration | Action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `run_artifact_map.py` | supported_operator | RO | opt | yes | supported_entrypoints; `test_run_artifact_map_script.py` | Static diagnostics | keep |
| `determinism_gate.py` | ci_or_gate | RO | opt | yes | README determinism; `test_determinism_gate_schema.py` | CI static | keep |
| `validate_report_permission_risk.py` | ci_or_gate | RO | none | yes | `test_validate_report_permission_risk_safety.py` | CI safety | keep |
| `verify_persistence_audit.py` | workflow_helper | RO | none | yes | persistence QA | post-run | **expose_menu** candidate |
| `post_run_session_summary.py` | workflow_helper | RO | opt | yes | permission_intelligence_pipeline.md; wraps `cli.audit.post_run_session_summary` | Static post-run | keep · **deprecate_cli** when menu parity |
| `permission_session_insights.py` | workflow_helper | RO | opt | yes | same | Static audit | keep · deprecate_cli later |
| `permission_app_drilldown.py` | workflow_helper | RO | opt | yes | same | Static audit | keep · deprecate_cli later |
| `replay_persist_run_summary.py` | workflow_helper | MIX | opt | yes | permission_intelligence_pipeline.md | persistence QA | keep |
| `headless_all_apps.py` | workflow_helper | RO | none | yes | **no in-repo refs** beyond file | overlaps `headless_run` / `main.py` | **investigate** · **candidate_archive** if unused externally |
| `static_baseline_tables.py` | workflow_helper | RO | opt | partial | README baseline | research corpus | keep · fix import path doc if needed |
| `static_baseline_tables_impl.py` | workflow_helper | RO | opt | yes | imported by static_baseline_tables | research corpus | keep |

---

## Inventory: `scripts/publication/`

| Path | Class | R/W | DB | `--help` | Key references | Owner / integration | Action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `export_profile.py` | supported_operator | MIX | opt | yes | supported_entrypoints | Publication entry | keep |
| `export_manifest_gate.py` | ci_or_gate | RO | none | yes | export_manifest_contract.md; legacy term gate | publication CI | keep |
| `ingest_publication_bundle.py` | demo_transitional | MIX | core | yes | supported_entrypoints; legacy term gate | DB maintenance (ingest) | keep |
| `publication_exports.py` | demo_transitional | RO | none | partial | supported_entrypoints | thin service wrapper | keep |
| `publication_results_numbers.py` | demo_transitional | RO | none | partial | supported_entrypoints | thin wrapper | keep |
| `publication_scientific_qa.py` | demo_transitional | RO | none | partial | supported_entrypoints | thin wrapper | keep |
| `publication_pipeline_audit.py` | demo_transitional | RO | none | partial | supported_entrypoints | thin wrapper | keep |
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
| `diagnose_scope.py` | workflow_helper | RO | none | yes | docstring only | harvest scope | keep |
| `env_check.py` | workflow_helper | RO | none | yes | `lib/android_tools.sh` | env | keep |
| `ensure_permission_matrix.py` | workflow_helper | MIX | core | yes | matrix QA | static DB | keep |
| `measure_inventory_latency.py` | unknown_needs_owner | RO | none | yes | low grep | inventory perf | **investigate** |
| `log_run_timeline.py` | workflow_helper | RO | none | yes | logs_operator_hygiene_plan.md | ops logs | keep |
| `log_error_summary.py` | workflow_helper | RO | none | yes | logs_operator_hygiene_plan.md | ops logs | keep |
| `profile_v3_freeze_bundle.py` | workflow_helper | RO | none | yes | freeze workflow | publication | keep |
| `backfill_dynamic_network_features.py` | migration_historical | W | core | yes | dynamic network | one-off backfill | keep · **archive_later** if completed |
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
| `migrate_legacy_harvest_storage.py` | migration_historical | MIX | none | yes | legacy_harvest_migration | one-off migration | **archive_later** when FS fully migrated |
| `audit_apk_storage_retention.py` | unknown_needs_owner | RO | none | yes | low grep | retention audit | **investigate** |

---

## Inventory: `scripts/dynamic/`

| Path | Class | R/W | DB | `--help` | Key references | Owner / integration | Action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `evidence_hunt.py` | workflow_helper | MIX | opt | yes | legacy term gate | dynamic evidence | keep |
| `run_idle.sh` | workflow_helper | RO | none | n/a | comment usage | dynamic shell | keep |
| `run_scripted_interaction.sh` | workflow_helper | RO | none | n/a | comment usage | dynamic shell | keep |

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

1. Grep org-wide for `backfill_static_session_id_on_runs` / SQL twin; open archive PR with README template.
2. Pick **post-run audit bundle** orchestration module; wire read-only calls to `session_static_health`, `report_static_session_grain_integrity`, `report_artifact_registry_integrity` (subprocess or imports).
3. Resolve **unknown_needs_owner** rows with team (external CI, personal aliases).
4. Optionally add **`python -m`** entrypoints for thin duplicates (`permission_intel_readiness`, static audit CLIs) before deprecating argv paths.

When adding a new script, add a row to this file **and** a row to [`db_scripts_inventory.md`](db_scripts_inventory.md) if it lives under `scripts/db/`.
