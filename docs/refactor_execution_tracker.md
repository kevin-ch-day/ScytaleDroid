# Refactor Execution Tracker

This tracker turns the phase plan into an execution checklist with explicit
status, blockers, and merge readiness.

Last updated: 2026-02-16

## Merge Rule

1. Work may overlap on feature branches.
2. Merge to `main` must follow phase order.
3. A phase is merge-ready only when all hard gates and acceptance checks are
   green.

## Current Status Snapshot

1. Phase 1 (`Determinism Comparator Contract`): in progress
2. Phase 2 (`Atomic Persistence`): in progress
3. Phase 3 (`Schema/Data Contract Corrections`): in progress (migration prepared, cutover pending)
4. Phase 4 (`Boundary Enforcement`): not started
5. Phase 5 (`Legacy Publication Isolation + Removal`): in progress (isolation tests present, deletion batches pending)

## Phase Checklist

## Phase 1: Determinism Comparator Contract

Completed evidence:
- `docs/contracts/determinism_comparator.md`
- `docs/contracts/determinism_keys.md`
- `tests/static_analysis/test_determinism_gate_schema.py`
- `tests/inventory/test_inventory_determinism.py`

Open items:
- Ensure comparator is exposed from a stable menu/operator command path.
- Ensure strict mode is the default for nightly/automation entrypoints.
- Verify allowed-diff list parity across scripts and docs.

Exit criteria:
- Comparator command is operator-visible and documented.
- Comparator artifacts are produced consistently at
  `output/audit/comparators/<type>/<id>/diff.json`.
- Fixture tests and schema tests pass in CI.

## Phase 2: Atomic Persistence

Completed evidence:
- `docs/contracts/persistence_uow_tables.md`
- `tests/persistence/test_persist_run_summary_atomicity.py`
- `tests/persistence/test_persistence_write_targets.py`

Open high-risk items:
- Eliminate pre-transaction writes in static persistence flow.
- Move scientific run-row creation fully inside UoW.
- Remove silent suppression of critical risk write failures.
- Align run status mapping at persistence boundary.

Exit criteria:
- Failure injection proves zero scientific rows on failure.
- No orphan scientific rows.
- Critical write failures surface deterministic `PERSIST_*` codes.
- No scientific write occurs before transaction open.

## Phase 3: Schema/Data Contract Corrections

Completed evidence:
- `docs/contracts/static_permission_risk_migration.md`
- `migrations/2026-02-16_static_permission_risk_runid_perm.sql`

Open items:
- Cut over writers/readers to run-aware `static_permission_risk` model after
  freeze boundary allows merge.
- Enforce write-time float canonicalization for scientific fields.
- Enforce required identity key fields at persistence time.

Exit criteria:
- No cross-run overwrite in scientific tables.
- Canonical float values compare exactly in comparator/reporting paths.
- Identity-key validation fails before write on bad rows.

## Phase 4: Boundary Enforcement (Menu -> Service -> Repository)

Open items:
- Remove direct SQL execution from menu/reporting layers.
- Add import-layer guardrails for menu and renderer modules.
- Prove read/load/status paths are write-free.

Exit criteria:
- Menu/renderer modules cannot import repository/db write utilities directly.
- Read-path no-write tests pass for inventory and reporting flows.
- Core menu workflow smoke tests pass.

## Phase 5: Legacy Publication Isolation + Removal

Completed evidence:
- `tests/publication/test_legacy_publication_isolation.py`
- `tests/publication/test_export_manifest_gate.py`
- `docs/maintenance/legacy_prune_batch1.md`

Open items:
- Remove remaining legacy publication menu wiring not required for reproducibility.
- Produce reachability report per deletion candidate.
- Execute deletion batches only after Phase 1-4 merge gates are green.

Next prune candidates (ranked):
1. `scripts/publication/regression_gate_freeze.py`
   - Single in-repo caller: `scripts/operational/write_phase_f1_closure.py`.
   - Remove as a pair with `write_phase_f1_closure.py` if Phase-F closure flow is retired.
2. `scytaledroid/Database/db_utils/menu_actions.py` paper dataset actions
   - Legacy contract sync paths still present (`paper2` alias/order sync).
   - Candidate for relocation behind explicit legacy/export guard.
3. `scytaledroid/DynamicAnalysis/tools/evidence/menu.py` paper2-only helper paths
   - Review `_canonical_paper2_freeze_anchor_path` and ordering helpers for isolation.

Exit criteria:
- Legacy-disabled mode imports/probes no publication paths.
- Export reproducibility checks remain green for touched frozen artifacts.
- Import/menu smoke checks pass after each deletion PR.

## Next Work Queue (Ordered)

1. Phase 2: pre-transaction write removal and fail-loud persistence behavior.
2. Phase 2: status normalization and rollback assertions for full UoW table set.
3. Phase 3: float canonicalization validation path and tests.
4. Phase 4: remove SQL from reporting/menu entrypoints.
5. Phase 5: first low-risk deletion batch with reachability proof.

## Open Decisions to Confirm Before Merge-Critical Work

1. Cutover date/branch policy for `static_permission_risk_vnext` migration.
2. Exact canonical precision/scale rules per scientific float column.
3. MariaDB nightly rollback gate owner/on-call escalation path.
4. Final list of legacy publication modules retained until reproducibility freeze lifts.
