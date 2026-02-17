# Refactor Execution Tracker

This tracker turns the phase plan into an execution checklist with explicit
status, blockers, and merge readiness.

Last updated: 2026-02-17

## Merge Rule

1. Work may overlap on feature branches.
2. Merge to `main` must follow phase order.
3. A phase is merge-ready only when all hard gates and acceptance checks are
   green.

## Current Status Snapshot

1. Phase 1 (`Determinism Comparator Contract`): completed
2. Phase 2 (`Atomic Persistence`): completed
3. Phase 3 (`Schema/Data Contract Corrections`): completed
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
- `tests/persistence/test_permission_risk.py` vNext-authoritative behavior

Open items:
- Extend write-time float canonicalization beyond current risk/metrics path to
  remaining scientific decimal fields as needed.

Recent extension:
- CVSS finding score fields are now canonicalized at write-time in
  `persist_run_summary` (`cvss.base/bt/be/bte`).
- Static determinism gate now includes `static_permission_risk_vnext` identity
  payload + validation checks (missing keys, duplicate keys, non-canonical
  permission names).
- Permission risk persistence now attempts `risk_scores` write independently
  before legacy table availability check, while preserving rollback semantics by
  staying in the same UoW.
- Permission risk runtime persistence is vNext-authoritative:
  - writes `risk_scores` + `static_permission_risk_vnext`
  - legacy `static_permission_risk` is no longer written by runtime
- Cross-run overwrite proof tests were added:
  - legacy overwrite behavior documented as intentional `xfail`
  - vNext run-aware path proves distinct rows per run.
- Runtime reader views now source risk data from `risk_scores` instead of
  `static_permission_risk`:
  - `vw_latest_permission_risk`
  - `v_static_run_category_summary`
- Legacy reference guard added:
  - `tests/persistence/test_legacy_permission_risk_reference_guard.py`
  - prevents new `static_permission_risk` references outside an allowlist.
- Static schema gate now requires canonical `risk_scores` and
  `static_permission_risk_vnext`.
- Database Tools now includes:
  - `Backfill static risk tables (risk_scores + vNext)`
  - `Audit static risk coverage gaps`
  These are idempotent maintenance actions for migration cleanup.

Exit criteria:
- No cross-run overwrite in scientific tables.
- Canonical float values compare exactly in comparator/reporting paths.
- Identity-key validation fails before write on bad rows.
- Runtime writes are run-aware (no legacy overwrite-prone table in hot path).

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
1. `scytaledroid/Database/db_utils/menu_actions.py` paper dataset actions
   - Legacy contract sync paths still present (`paper2` alias/order sync).
   - Candidate for relocation behind explicit legacy/export guard.
2. `scytaledroid/DynamicAnalysis/tools/evidence/menu.py` paper2-only helper paths
   - Review `_canonical_paper2_freeze_anchor_path` and ordering helpers for isolation.

Exit criteria:
- Legacy-disabled mode imports/probes no publication paths.
- Export reproducibility checks remain green for touched frozen artifacts.
- Import/menu smoke checks pass after each deletion PR.

## Next Work Queue (Ordered)

1. Phase 3: float canonicalization validation path and tests.
2. Phase 3: permission-risk reader migration map + cutover wiring.
3. Phase 4: remove SQL from reporting/menu entrypoints.
4. Phase 5: next low-risk deletion batch with reachability proof.

## Open Decisions to Confirm Before Merge-Critical Work

1. Cutover date/branch policy for `static_permission_risk_vnext` migration.
2. Exact canonical precision/scale rules per scientific float column.
3. MariaDB nightly rollback gate owner/on-call escalation path.
4. Final list of legacy publication modules retained until reproducibility freeze lifts.
