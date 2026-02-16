# Refactor Test Matrix

This matrix ties each refactor/removal PR to risk coverage and acceptance checks.

## Priority Order

1. PR1 and PR2 are hard blockers for all later merges.
2. PR3 can proceed in branch, but merge only after PR2 is green.
3. PR4 and PR5 are blocked on PR1-PR3 merge completion.

## PR1: Determinism Comparator Contract

- Risks:
  - Drift hidden by row-order changes or weak comparison logic.
  - Missing/duplicate identity keys allow false PASS results.
  - Comparator output lacks machine-readable audit trace.
- Required tests:
  - Deterministic fixture compare PASS in strict mode.
  - Comparator JSON schema validation.
  - Missing-key and duplicate-key fixture compares FAIL.
  - Allowed-diff field behavior test (ephemeral field changes only).
- Acceptance:
  - Same input yields same decision enum + reason code + next action.
  - Strict mode fails on any non-allowed diff.
  - Comparator artifact is persisted under `output/audit/comparators/...`.

## PR2: Persistence Atomicity

- Risks:
  - Pre-transaction side effects create partial scientific rows.
  - Critical writer errors are swallowed and run appears successful.
  - Run status vocabulary drifts across code paths.
- Required tests:
  - Failure injection inside persistence unit-of-work.
  - Before/after row-count and orphan checks for scientific tables.
  - Guard test that run row is created only inside transaction scope.
  - Fail-loud test for permission risk/risk score persistence failures.
  - Status normalization test (`RUNNING/ABORTED` mapped before commit).
- Acceptance:
  - Counts unchanged after injected failure.
  - No scientific orphan rows.
  - No scientific rows committed when injected failure occurs.
  - Menu gets consistent operator-facing failure code/message.

## PR3: Schema/Data Contract Corrections

- Risks:
  - `static_permission_risk` cross-run overwrite masks drift.
  - Float representation drift causes false comparator/report differences.
  - Scientific identity keys not enforced at persistence boundaries.
- Required tests:
  - Migration/contract tests for run-aware permission risk keys.
  - Write-time float canonicalization + overflow fail tests.
  - Persistence write-target allowlist test vs UoW docs.
- Acceptance:
  - Data contract tests pass on supported DB backends for touched paths.
  - No cross-run overwrite behavior in scientific tables.

## PR4: Boundary Enforcement (Menu -> Service -> Repository)

- Risks:
  - SQL in menu paths creates hidden coupling and side effects.
  - Read/status flows mutate DB/fs by accident.
  - Backend-specific SQL leaks into shared path and breaks portability.
- Required tests:
  - Import-layer guard: menu/renderer modules cannot import DB/repository modules directly.
  - No-write-on-load/read tests for inventory/reporting flows.
  - Menu workflow smoke test through major sections.
- Acceptance:
  - Structural guardrail prevents DB imports from renderer/menu layers.
  - Service layer is sole owner of persistence orchestration.

## PR5: Legacy Publication Isolation + Removal

- Risks:
  - Legacy modules still impact core runtime.
  - Hidden file probes and noisy warnings when disabled.
  - Deletion of reachable code without comparators/manifest checks.
- Required tests:
  - Menu render smoke with `SCYTALEDROID_ENABLE_LEGACY_PUBLICATION=0`.
  - Import/probe smoke confirming no legacy publication modules are loaded.
  - Reachability report per removed candidate.
  - Import smoke + menu smoke.
  - Export reproducibility check only for PRs touching export paths.
- Acceptance:
  - Core reporting works with legacy publication disabled.
  - Legacy entries are hidden by default.
  - No removed component is reachable from core menu workflows.
  - Smoke checks pass.
