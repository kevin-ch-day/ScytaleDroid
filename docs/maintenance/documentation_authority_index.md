# Documentation Authority Index

This is a routing index for the current `docs/` tree.

Use it to answer:

- which document is the primary authority for a topic
- which documents are support/reference material
- which documents are historical or maintenance-only
- which documents should not be treated as architecture truth

This is not a merge plan and not a deletion list. It exists so later cleanup
can reduce sprawl without breaking topic ownership.

## Status labels

- `authority`: primary source of truth for the topic
- `support`: useful companion doc, workflow note, or reference
- `maintenance`: current-state planning, cleanup, or operator-maintenance note
- `historical`: older phase plan or migration note retained for context
- `generated-spec`: contract/spec artifact; authoritative for a narrow format only

## Core workflow and operator routing

### Operator entrypoints and menu routing

- `authority`
  - [runbook.md](../runbook.md)
  - [supported_entrypoints.md](../supported_entrypoints.md)
- `support`
  - [workflow_entrypoint_map.md](../maintenance/workflow_entrypoint_map.md)
  - [repo_ownership_map.md](../maintenance/repo_ownership_map.md)
  - [cli_web_db_filesystem_boundary.md](../maintenance/cli_web_db_filesystem_boundary.md) — CLI vs Web vs DB vs filesystem roles (V1 posture)
  - active flag guidance is folded into `runbook.md`

Notes:
- start here when routing operator-flow or menu-entry work
- do not start in generated `output/` or `logs/` for workflow ownership questions

### Device inventory and harvest

- `authority`
  - [device_analysis/README.md](../device_analysis/README.md)
- `support`
  - [adb_contract.md](../adb_contract.md)
  - [workflow_entrypoint_map.md](../maintenance/workflow_entrypoint_map.md)
  - [v1_evidence_catalog_verification.md](../design/v1_evidence_catalog_verification.md) — ACK-pending V1 schema/verify semantics (**do not reopen without blocker**)
  - [apk_lineage_redesign_assessment.md](../maintenance/apk_lineage_redesign_assessment.md) — current exact-hash/static-dynamic availability findings; package/version/hash lineage redesign assessment
  - [apk_inventory_model_transition.md](../maintenance/apk_inventory_model_transition.md) — active package/version APK inventory transition, hot/cold byte-store reports, and legacy run-retirement model
- `historical`
  - none currently separated

Notes:
- use this cluster for device/app acquisition issues
- do not start in `StaticAnalysis` or Web-facing docs for harvest problems
- inventory rerun/failure semantics are now folded into
  `docs/device_analysis/README.md`
- inventory guard determinism notes are folded into
  `docs/device_analysis/README.md`

### Static analysis workflow and persistence

- `authority`
  - [static_analysis_contract.md](../static_analysis_contract.md)
  - [persistence.md](../persistence.md)
- `support`
  - [static_analysis/static_analysis_data_model.md](../static_analysis/static_analysis_data_model.md)
  - [permission_intelligence_pipeline.md](../maintenance/permission_intelligence_pipeline.md) — core DB vs Permission Intel, matrix vs vnext, operator commands
  - [workflow_entrypoint_map.md](../maintenance/workflow_entrypoint_map.md)
  - [static_analysis_audit_runbook.md](../maintenance/static_analysis_audit_runbook.md)
  - [static_analysis_workflow_audit_v1.md](../maintenance/static_analysis_workflow_audit_v1.md) — pipeline / string / split / persistence audit routing (AUDIT note; ticket driver)
- `maintenance`
  - [legacy_bridge_cleanup_backlog.md](../maintenance/legacy_bridge_cleanup_backlog.md)
  - [legacy_static_deprecation_playbook.md](../maintenance/legacy_static_deprecation_playbook.md) — phased legacy-five retirement; **Appendix A** = relabel/migrate/Web-grep buckets (merged Wave W1)
  - [legacy_static_reader_dependency_map.md](../maintenance/legacy_static_reader_dependency_map.md) — **file/function-level** map of legacy-five readers; Phase 2 retirement ordering; `metrics.run_id` ambiguity; **§2.1.1** mirror-helper wiring (merged Wave W1); **§8** follow-up (planning; not runtime truth)
  - [legacy_static_tables_consumer_audit.md](../maintenance/legacy_static_tables_consumer_audit.md) — **index**: legacy five scope, INSERT grep baseline, classification legend; per-table detail → dependency map §3
  - [session_identity_contract.md](../maintenance/session_identity_contract.md) — `session_stamp` vs `session_label`, `static_run_id` vs legacy `runs.run_id`, canonical join rules, forbidden SQL patterns
  - [session_static_health_hygiene_plan.md](../maintenance/session_static_health_hygiene_plan.md) — align `session_static_health.py` with canonical-first / legacy-optional (planned; script not changed in slice)
  - [evidence_run_manifest_spec.md](../maintenance/evidence_run_manifest_spec.md) — design-only run-root evidence manifest (no writer yet)
  - [pi_erebus_operational_boundary.md](../maintenance/pi_erebus_operational_boundary.md) — PI vs Erebus ownership and pre-`obs_sample` blockers
- `historical`
  - [archive/next_pass_docs_policy_implementation_plan.md](../maintenance/archive/next_pass_docs_policy_implementation_plan.md) — **completed** 2026-05-09 docs/policy slice checklist (archived; see [archive/README.md](../maintenance/archive/README.md))
  - [archive/completed-plans/legacy_static_phase2a_policy_alignment_plan.md](../maintenance/archive/completed-plans/legacy_static_phase2a_policy_alignment_plan.md) — completed Phase 2A record + verification commands
  - [archive/completed-plans/fast_implementation_backlog_lanes.md](../maintenance/archive/completed-plans/fast_implementation_backlog_lanes.md) — historical Lane 1/2/3 batch tracker

Notes:
- use this cluster for static pipeline semantics, persistence flow, and data-shape questions
- generated reports and audits validate behavior but are not the authority for workflow design
- static operator workflow notes are now folded into `workflow_entrypoint_map.md`

### Dynamic analysis, evidence, and freeze

- `authority`
  - [dynamic_analysis_contract.md](../dynamic_analysis_contract.md)
  - [storage_contract_v2.md](../storage_contract_v2.md)
- `support`
  - [contracts/freeze_capture_policy_v1.md](../contracts/freeze_capture_policy_v1.md)
  - [contracts/profile_v3_execution_contract.md](../contracts/profile_v3_execution_contract.md) — Profile v3 structural cohort execution protocol and reproducibility minima.
  - profile v3 minima and frozen-input notes are folded into `dynamic_analysis_contract.md`
- `generated-spec`
  - [contracts/export_manifest_contract.md](../contracts/export_manifest_contract.md)

Notes:
- use this cluster for runtime evidence, freeze/readiness, and dynamic storage questions
- do not treat evidence-pack outputs themselves as architecture truth

## Database and schema authority

### Database ownership, boundaries, and current shape

- `authority`
  - [database/contract_audit_v1_3.md](../database/contract_audit_v1_3.md)
  - [database/ownership_matrix_v1_3.csv](../database/ownership_matrix_v1_3.csv)
  - [maintenance/database_governance_runbook.md](../maintenance/database_governance_runbook.md) — operational recovery, **`v_*`/`vw_*` naming contract**, repeatability, security posture
- `support`
  - [database/schema_domain_inventory.md](../database/schema_domain_inventory.md)
  - [database/derived_index.md](../database/derived_index.md)
  - [maintenance/database_cleanup_audit_plan.md](../maintenance/database_cleanup_audit_plan.md) — read-only audit SQL pack; interrupted-session drill queries
  - [maintenance/database_schema_cleanup_design.md](../maintenance/database_schema_cleanup_design.md) — phased schema cleanup, `static_analysis_sessions`, Web SOT, prune/collation strategy
  - [maintenance/database_target_schema_v2.md](../maintenance/database_target_schema_v2.md) — **target** domain model, sessions center, run identity v2, permission observations/rollup, v2 Web views, migration phases 0–7
  - [maintenance/apk_lineage_redesign_assessment.md](../maintenance/apk_lineage_redesign_assessment.md) — APK content identity vs harvest observation gap; install-set schema and reset guidance
  - [maintenance/database_static_child_table_join_map.md](../maintenance/database_static_child_table_join_map.md) — canonical vs legacy FK patterns (`run_id` vs `static_run_id`), COALESCE trap, session-scoped SQL audit pack pointers
  - [maintenance/repo_ownership_map.md](../maintenance/repo_ownership_map.md)

Notes:
- start here for schema ownership, table-role confusion, and DB cleanup routing
- this is the primary authority cluster for current database/read-model cleanup

### Permission-intel split, bridge cleanup, and migration history

- `authority`
  - [database/permission_intel_contract.md](../database/permission_intel_contract.md) — active ScytaleDroid Permission Intel boundary, static writer vocabulary, and pre-observation-write contract
- `support`
  - [maintenance/legacy_bridge_cleanup_backlog.md](../maintenance/legacy_bridge_cleanup_backlog.md) — current bridge-debt and trust-stability backlog
  - [database/framework_permissions_catalog.md](../database/framework_permissions_catalog.md) — framework permission catalog feed/parser notes and offline YAML fallback behavior.
  - [database/permission_intel_schema_drift_erebus_vs_scytaledroid.md](../database/permission_intel_schema_drift_erebus_vs_scytaledroid.md) — Erebus vs Scytale PI drift; **§0** Permission Intel vs Erebus **catalog / DSN** mental model
  - [database/permission_intel_observation_readiness.md](../database/permission_intel_observation_readiness.md) — read-only PI queue/static observation readiness bundle
- `historical`
  - [database/permission_split_migration_history.md](../database/permission_split_migration_history.md) — completed split sequence and contemporary checkpoints; not the current roadmap
  - [archive/2026-06-checkpoints/](archive/2026-06-checkpoints/) — historical June 2026 schema/inventory/dynamic checkpoint notes; use active schema/governance docs first.
  - [database/archive/permission-intel-phase-notes/](../database/archive/permission-intel-phase-notes/) — archived S1/S2 Permission Intel phase notes superseded by the active contract/readiness docs.

Notes:
- use this cluster for the active Permission Intel boundary, bridge posture, and migration history
- do not spread live ownership decisions across maintenance notes without updating the authority doc

### Database read models and view contracts

- `authority`
  - [database/view_contract_v_web_static_dynamic_app_summary.md](../database/view_contract_v_web_static_dynamic_app_summary.md)
- `support`
  - package/artifact lineage notes are covered in the active audit and workflow docs
- `maintenance`
  - [maintenance/repo_ownership_map.md](../maintenance/repo_ownership_map.md)

Notes:
- use this when deciding whether a page/query should consume a DB read model
- this area likely needs expansion later, but it is the closest current read-model authority

## Scoring, findings, and analysis contracts

### Score semantics and risk display

- `authority`
  - [risk_scoring_contract.md](../risk_scoring_contract.md)
  - [operational_risk_scoring.md](../operational_risk_scoring.md)
- `support`
  - static and paper scoring definitions are folded into the active scoring contract set

Notes:
- use this cluster for score meaning and audit questions
- maintenance audits explain current problems but should not become the normative scoring contract

### Determinism and execution invariants

- `authority`
  - [engineering_invariants.md](../engineering_invariants.md)
- `support`
  - [contracts/determinism_comparator.md](../contracts/determinism_comparator.md)
  - [contracts/determinism_keys.md](../contracts/determinism_keys.md)
  - atomic-write coverage notes are folded into `engineering_invariants.md`
- `generated-spec`
  - [contracts/determinism_static_rules.json](../contracts/determinism_static_rules.json)
  - [contracts/determinism_waiver_template.json](../contracts/determinism_waiver_template.json)

Notes:
- use this cluster for write atomicity, deterministic outputs, and execution guarantees

## Reporting, publication, and paper/export contracts

### Publication/export contracts

- `authority`
  - [contracts/paper_contract_v1.md](../contracts/paper_contract_v1.md)
  - [contracts/export_manifest_contract.md](../contracts/export_manifest_contract.md)
- `support`
  - [contracts/paper_reason_codes_v1.md](../contracts/paper_reason_codes_v1.md)
  - [maintenance/operator_acceptance_matrix.md](../maintenance/operator_acceptance_matrix.md)
- `generated-spec`
  - [contracts/paper_export_schema_v1.json](../contracts/paper_export_schema_v1.json)

Notes:
- use this cluster for publication/export formats and acceptance expectations
- do not start in ad hoc scripts for contract questions

## UI and downstream consumer notes

### UI / Web contract

- `authority`
  - [ui_contract.md](../ui_contract.md)
- `maintenance`
  - Web-specific workflow notes are intentionally deferred for now

Notes:
- Web is a downstream consumer during the current cleanup phase
- do not let Web notes become the primary authority for CLI/DB contracts
- CLI palette/theme notes are now folded into `ui_contract.md`

## Maintenance and current cleanup notes

### Current-state audits and cleanup notes

- `authority`
  - [maintenance/legacy_bridge_cleanup_backlog.md](../maintenance/legacy_bridge_cleanup_backlog.md)
- `support`
  - [maintenance/repo_ownership_map.md](../maintenance/repo_ownership_map.md)
  - [maintenance/workflow_entrypoint_map.md](../maintenance/workflow_entrypoint_map.md)
- `maintenance`
  - [maintenance/housekeeping.md](../maintenance/housekeeping.md) — workspace/logs cadence; **refactor tier order** (merged Wave W1)
  - [maintenance/logs_operator_hygiene_plan.md](../maintenance/logs_operator_hygiene_plan.md) — **P1/P2** logs layout vs code, naming collisions, optional future `logs health` spec (not P0)
  - [maintenance/legacy_static_deprecation_playbook.md](../maintenance/legacy_static_deprecation_playbook.md) — phased legacy-five retirement + Appendix A compatibility buckets
  - [maintenance/legacy_static_reader_dependency_map.md](../maintenance/legacy_static_reader_dependency_map.md) — legacy static five: readers, false positives, retirement order, §2.1.1 mirror wiring, §8 edge cases (planning)
  - [maintenance/legacy_static_tables_consumer_audit.md](../maintenance/legacy_static_tables_consumer_audit.md) — legacy five index (pointers to map + playbook + Web deep dive)

Notes:
- this cluster is valuable for current routing and cleanup work
- do not treat maintenance notes as the stable long-term architecture contract unless promoted explicitly

## Current cleanup implications

High-value later consolidation targets:

- operator routing:
  - `runbook.md`
  - `supported_entrypoints.md`
  - selected sections already moved into maintenance/authority docs
- static workflow:
  - `static_analysis_contract.md`
  - `persistence.md`
  - selected `static_analysis/*` and `use_cases/*`
- DB authority:
  - `database/contract_audit_v1_3.md`
  - `database/ownership_matrix_v1_3.csv`
  - `database/permission_intel_contract.md`
- dynamic/evidence:
  - `dynamic_analysis_contract.md`
  - `storage_contract_v2.md`
  - selected dynamic/export support notes now folded into the dynamic contract

Likely low-value standalone dirs to revisit later:

- `docs/device_analysis/`
- possibly `docs/static_analysis/`

Do not move or delete files based on this index alone. Use it as the routing
layer for later consolidation.
