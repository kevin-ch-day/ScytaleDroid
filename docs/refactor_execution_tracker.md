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

1. Phase 1 (`Determinism Comparator Contract`): completed
2. Phase 2 (`Atomic Persistence`): completed
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
- Database Tools menu action: `Inventory determinism comparator (strict)`

Open items:
- none (Phase 1 exit criteria met)

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
- `tests/persistence/test_permission_risk.py` (strict `risk_scores` availability behavior)
- `scytaledroid/StaticAnalysis/cli/persistence/run_envelope.py` (no DB writes in envelope prep)
- `scytaledroid/StaticAnalysis/cli/persistence/run_summary.py` (legacy run creation moved inside transaction)
- `scytaledroid/StaticAnalysis/cli/persistence/permission_risk.py` (fail-loud critical writes)

Open high-risk items:
- none (Phase 2 exit criteria met)

Exit criteria:
- Failure injection proves zero scientific rows on failure.
- No orphan scientific rows.
- Critical write failures surface deterministic `PERSIST_*` codes.
- No scientific write occurs before transaction open.

## Phase 3: Schema/Data Contract Corrections

Completed evidence:
- `docs/contracts/static_permission_risk_migration.md`
- `migrations/2026-02-16_static_permission_risk_runid_perm.sql`
- `scytaledroid/StaticAnalysis/cli/persistence/utils.py` (`canonical_decimal_text`)
- `scytaledroid/StaticAnalysis/cli/persistence/permission_risk.py` (identity validation + score canonicalization)
- `scytaledroid/StaticAnalysis/cli/persistence/run_summary.py` (scope/package identity validation + canonical metric values)
- `tests/persistence/test_numeric_canonicalization.py`
- `scytaledroid/StaticAnalysis/cli/persistence/permission_risk.py` vNext gate:
  `SCYTALEDROID_ENABLE_SPR_VNEXT=1` (default off)
- `tests/persistence/test_permission_risk.py` vNext gate behavior (off-by-default,
  opt-in path exercised)

Open items:
- Cut over writers/readers to run-aware `static_permission_risk` model after
  freeze boundary allows merge.
- Extend write-time float canonicalization beyond current risk/metrics path to
  remaining scientific decimal fields as needed.

Recent extension:
- CVSS finding score fields are now canonicalized at write-time in
  `persist_run_summary` (`cvss.base/bt/be/bte`).

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

1. Phase 3: float canonicalization validation path and tests.
2. Phase 3: identity-key enforcement at persistence boundaries.
3. Phase 4: remove SQL from reporting/menu entrypoints.
4. Phase 5: next low-risk deletion batch with reachability proof.

## Open Decisions to Confirm Before Merge-Critical Work

1. Cutover date/branch policy for `static_permission_risk_vnext` migration.
2. Exact canonical precision/scale rules per scientific float column.
3. MariaDB nightly rollback gate owner/on-call escalation path.
4. Final list of legacy publication modules retained until reproducibility freeze lifts.
