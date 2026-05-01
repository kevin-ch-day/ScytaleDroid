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
  - [runbook.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/runbook.md)
  - [supported_entrypoints.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/supported_entrypoints.md)
- `support`
  - [workflow_entrypoint_map.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/maintenance/workflow_entrypoint_map.md)
  - [repo_ownership_map.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/maintenance/repo_ownership_map.md)
  - active flag guidance is folded into `runbook.md`

Notes:
- start here when routing operator-flow or menu-entry work
- do not start in generated `output/` or `logs/` for workflow ownership questions

### Device inventory and harvest

- `authority`
  - [device_analysis/README.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/device_analysis/README.md)
- `support`
  - [adb_contract.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/adb_contract.md)
  - [workflow_entrypoint_map.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/maintenance/workflow_entrypoint_map.md)
  - [v1_evidence_catalog_verification.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/design/v1_evidence_catalog_verification.md) — ACK-pending V1 schema/verify semantics (**do not reopen without blocker**)
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
  - [static_analysis_contract.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/static_analysis_contract.md)
  - [persistence.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/persistence.md)
- `support`
  - [static_analysis/static_analysis_data_model.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/static_analysis/static_analysis_data_model.md)
  - [workflow_entrypoint_map.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/maintenance/workflow_entrypoint_map.md)
- `maintenance`
  - [phase5c_task_list.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/maintenance/phase5c_task_list.md)

Notes:
- use this cluster for static pipeline semantics, persistence flow, and data-shape questions
- generated reports and audits validate behavior but are not the authority for workflow design
- static operator workflow notes are now folded into `workflow_entrypoint_map.md`

### Dynamic analysis, evidence, and freeze

- `authority`
  - [dynamic_analysis_contract.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/dynamic_analysis_contract.md)
  - [storage_contract_v2.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/storage_contract_v2.md)
- `support`
  - [contracts/freeze_capture_policy_v1.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/contracts/freeze_capture_policy_v1.md)
  - profile v3 minima and frozen-input notes are folded into `dynamic_analysis_contract.md`
- `generated-spec`
  - [contracts/export_manifest_contract.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/contracts/export_manifest_contract.md)

Notes:
- use this cluster for runtime evidence, freeze/readiness, and dynamic storage questions
- do not treat evidence-pack outputs themselves as architecture truth

## Database and schema authority

### Database ownership, boundaries, and current shape

- `authority`
  - [database/contract_audit_v1_3.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/database/contract_audit_v1_3.md)
  - [database/ownership_matrix_v1_3.csv](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/database/ownership_matrix_v1_3.csv)
- `support`
  - [database/schema_domain_inventory.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/database/schema_domain_inventory.md)
  - [database/derived_index.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/database/derived_index.md)
  - [maintenance/repo_ownership_map.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/maintenance/repo_ownership_map.md)

Notes:
- start here for schema ownership, table-role confusion, and DB cleanup routing
- this is the primary authority cluster for `Phase 5C`

### Permission-intel split, bridge cleanup, and phase migration

- `authority`
  - [database/permission_split_execution_phases.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/database/permission_split_execution_phases.md)
- `support`
  - [maintenance/phase5c_task_list.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/maintenance/phase5c_task_list.md)
- `historical`
  - older split/cutover phase notes were consolidated into the active phase docs

Notes:
- use this cluster for permission-intel cutover, bridge posture, and phase planning
- do not spread live ownership decisions across maintenance notes without updating the authority doc

### Database read models and view contracts

- `authority`
  - [database/view_contract_v_web_static_dynamic_app_summary.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/database/view_contract_v_web_static_dynamic_app_summary.md)
- `support`
  - package/artifact lineage notes are covered in the active audit and workflow docs
- `maintenance`
  - [maintenance/repo_ownership_map.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/maintenance/repo_ownership_map.md)

Notes:
- use this when deciding whether a page/query should consume a DB read model
- this area likely needs expansion later, but it is the closest current read-model authority

## Scoring, findings, and analysis contracts

### Score semantics and risk display

- `authority`
  - [risk_scoring_contract.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/risk_scoring_contract.md)
  - [operational_risk_scoring.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/operational_risk_scoring.md)
- `support`
  - static and paper scoring definitions are folded into the active scoring contract set

Notes:
- use this cluster for score meaning and audit questions
- maintenance audits explain current problems but should not become the normative scoring contract

### Determinism and execution invariants

- `authority`
  - [engineering_invariants.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/engineering_invariants.md)
- `support`
  - [contracts/determinism_comparator.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/contracts/determinism_comparator.md)
  - [contracts/determinism_keys.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/contracts/determinism_keys.md)
  - atomic-write coverage notes are folded into `engineering_invariants.md`
- `generated-spec`
  - [contracts/determinism_static_rules.json](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/contracts/determinism_static_rules.json)
  - [contracts/determinism_waiver_template.json](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/contracts/determinism_waiver_template.json)

Notes:
- use this cluster for write atomicity, deterministic outputs, and execution guarantees

## Reporting, publication, and paper/export contracts

### Publication/export contracts

- `authority`
  - [contracts/paper_contract_v1.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/contracts/paper_contract_v1.md)
  - [contracts/export_manifest_contract.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/contracts/export_manifest_contract.md)
- `support`
  - [contracts/paper_reason_codes_v1.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/contracts/paper_reason_codes_v1.md)
  - [maintenance/operator_acceptance_matrix.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/maintenance/operator_acceptance_matrix.md)
- `generated-spec`
  - [contracts/paper_export_schema_v1.json](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/contracts/paper_export_schema_v1.json)

Notes:
- use this cluster for publication/export formats and acceptance expectations
- do not start in ad hoc scripts for contract questions

## UI and downstream consumer notes

### UI / Web contract

- `authority`
  - [ui_contract.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/ui_contract.md)
- `maintenance`
  - Web-specific workflow notes are intentionally deferred for now

Notes:
- Web is a downstream consumer during the current cleanup phase
- do not let Web notes become the primary authority for CLI/DB contracts
- CLI palette/theme notes are now folded into `ui_contract.md`

## Maintenance, cleanup, and current-phase notes

### Current-state audits and cleanup notes

- `authority`
  - [maintenance/phase5c_task_list.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/maintenance/phase5c_task_list.md)
- `support`
  - [maintenance/repo_ownership_map.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/maintenance/repo_ownership_map.md)
  - [maintenance/workflow_entrypoint_map.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/maintenance/workflow_entrypoint_map.md)
- `maintenance`
  - [maintenance/housekeeping.md](/home/secadmin/Laughlin/GitHub/ScytaleDroid/docs/maintenance/housekeeping.md)

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
  - `database/permission_split_execution_phases.md`
- dynamic/evidence:
  - `dynamic_analysis_contract.md`
  - `storage_contract_v2.md`
  - selected dynamic/export support notes now folded into the dynamic contract

Likely low-value standalone dirs to revisit later:

- `docs/device_analysis/`
- possibly `docs/static_analysis/`

Do not move or delete files based on this index alone. Use it as the routing
layer for later consolidation.
