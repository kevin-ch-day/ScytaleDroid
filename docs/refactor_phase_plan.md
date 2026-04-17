# Refactor Phase Plan

This plan defines execution order, hard gates, and acceptance criteria for
complexity reduction and legacy removal.

Execution tracking lives in:

- `docs/refactor_execution_tracker.md`

Execution order is locked and merge-gated:

1. Phase 1
2. Phase 2
3. Phase 3
4. Phase 4
5. Phase 5

No later phase may merge before the previous phase is green.

## Phase 1: Determinism Comparator Contract (Highest Priority)

Scope:
- Inventory comparator as a hard gate with machine-readable diff output.
- Key-based comparison (not row-order comparison).
- Strict required identity fields for inventory snapshot/package rows.
- Allowed-diff list locked to ephemeral fields only.

Hard gates:
- Same input state -> same comparator result and same decision payload.
- Missing required key fields fail strict mode.
- Duplicate key rows fail strict mode.
- Comparator artifact written to `output/audit/comparators/.../diff.json`.

Acceptance:
- Comparator tests pass on deterministic fixture data.
- Comparator JSON schema contract test passes.
- Strict mode is default for automation/nightly runs.

## Phase 2: Atomic Persistence

Scope:
- Static persistence unit-of-work guarantees for scientific tables.
- Eliminate write side-effects before transaction start.
- Move run-row creation fully inside the UoW.
- Normalize scientific run statuses to `STARTED|COMPLETED|FAILED`.
- Fail loud on critical persistence errors (no silent suppression).

Hard gates:
- Scientific persistence is all-or-nothing across run + findings + risk + metadata.
- Failure injection proves no scientific rows committed on failure.
- No orphan rows in scientific tables after injected failure.
- Pre-transaction write target count is zero.

Acceptance:
- Rollback proof test suite passes.
- Operator-facing error codes are consistent (`PERSIST_*` contract).
- Ledger/audit rows are allowed only in non-scientific ledger tables.

## Phase 3: Schema and Data Contract Corrections

Scope:
- Correct run-aware risk table model (`static_permission_risk` migration path).
- Write-time canonicalization for scientific float fields.
- Enforce identity key presence at persistence time for scientific rows.
- Remove cross-run overwrite behavior (no upsert masking in scientific tables).

Hard gates:
- `static_permission_risk` target uniqueness is run-aware (`run_id, permission_name`).
- Canonical float validation runs before DB write.
- Overflow/scale violations fail with deterministic validation error.
- Scientific writes do not depend on legacy `runs` table side effects.

Acceptance:
- Migration plan and cutover switch are committed and tested.
- Contract tests cover key uniqueness and canonicalized persistence values.
- DB/backend parity checks pass for touched query paths.

## Phase 4: Boundary Enforcement (Menu -> Service -> Repository)

Scope:
- Remove SQL/transaction control from menu actions.
- Enforce read-path purity (`load/status/compute/drift` do not mutate state).
- Isolate backend-specific SQL from shared menu/reporting paths.

Hard gates:
- Menu modules do not execute SQL directly.
- Service layer owns orchestration.
- Read/compute flows do not write DB/fs state (except logs).

Acceptance:
- Menu smoke tests pass.
- Layering checks pass for touched paths.
- No-write-on-load/read tests pass for inventory + reporting entry paths.

## Phase 5: Legacy Publication Isolation and Removal

Scope:
- Keep only minimal paper export reproducibility path.
- Remove legacy publication actions from active workflows.
- Remove unreachable/deprecated legacy paths after isolation proves safe.

Hard gates:
- Core reporting has no runtime dependency on a legacy publication toggle.
- Legacy publication modules are not imported in core workflows except bounded read fallback.
- No unnecessary filesystem probes for removed legacy publication paths.
- Reachability proof is required before each deletion batch.

Acceptance:
- Core reporting smoke tests pass without legacy branches.
- No unexpected publication probes/imports in core workflow.
- Export reproducibility checks pass for PRs touching frozen outputs.
- Import smoke and menu smoke pass.
- Removal report includes rollback note per candidate.

## Cross-Phase Critical Risks (Must Stay Visible)

1. Scientific writes that happen before transaction open.
2. Cross-run overwrite behavior in scientific tables.
3. Silent persistence failure paths that still mark runs as complete.
4. Menu/reporting paths that execute SQL directly.
5. Legacy publication coupling in core runtime paths.

These risks must be reduced in phase order; deletion/cleanup work must not
proceed ahead of determinism and atomic persistence gates.
