# Refactor Test Matrix

This matrix ties each refactor/removal PR to risk coverage and acceptance checks.

## PR1: Inventory Determinism + Read-Path Purity

- Risks:
  - Drift decisions change across identical inputs.
  - Hidden writes in load/compute paths.
- Required tests:
  - Deterministic guard decision object equality on repeated input.
  - No-write-on-load test (DB write spies stay at 0).
- Acceptance:
  - Same input yields same decision enum + reason code.
  - Read path executes with zero DB writes.

## PR2: Persistence Atomicity

- Risks:
  - Partial persistence on mid-run failure.
  - Orphan run/finding/risk rows.
- Required tests:
  - Failure injection inside persistence unit-of-work.
  - Before/after row-count and orphan checks.
- Acceptance:
  - Counts unchanged after injected failure.
  - No orphan rows.
  - Menu gets consistent operator-facing failure code/message.

## PR3: Renderer/DB Separation

- Risks:
  - Renderer paths accidentally write DB state.
  - Coupling between render and persistence layers.
- Required tests:
  - Import-layer guard: renderer modules cannot import DB/repository modules.
  - Renderer output smoke test.
- Acceptance:
  - Structural guardrail prevents DB imports from renderer modules.

## PR4: Legacy Publication Isolation (Default Off)

- Risks:
  - Legacy modules still impact core runtime.
  - Hidden file probes and noisy warnings when disabled.
- Required tests:
  - Menu render smoke with `SCYTALEDROID_ENABLE_LEGACY_PUBLICATION=0`.
  - Import/probe smoke confirming no legacy publication modules are loaded.
- Acceptance:
  - Core reporting works with legacy publication disabled.
  - Legacy entries are hidden by default.

## PR5: Legacy Removal

- Risks:
  - Removing reachable code paths.
  - Unintended breakage in menu-driven flows.
- Required tests:
  - Reachability report per removed component.
  - Import smoke + menu smoke.
  - Export reproducibility check only for PRs touching export paths.
- Acceptance:
  - No removed component is reachable from core menu workflows.
  - Smoke checks pass.
