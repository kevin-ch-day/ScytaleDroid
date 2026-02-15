# Refactor Phase Plan

This plan defines execution order, hard gates, and acceptance criteria for
complexity reduction and legacy removal.

## Phase 1: Determinism + Purity (Highest Priority)

Scope:
- Inventory guard decision determinism.
- Read-path purity in inventory metadata loading.

Hard gates:
- Same input state -> same guard decision (`decision_enum`, `reason_code`,
  `next_action`, `prompt_key`).
- Read/load path performs zero DB writes.

Acceptance:
- Determinism tests pass.
- No-write-on-load tests pass.

## Phase 2: Atomic Persistence

Scope:
- Static persistence unit-of-work guarantees.

Hard gates:
- Run persistence is all-or-nothing across run + findings + risk + metadata.
- Failure injection shows no partial rows and no orphans.

Acceptance:
- Rollback proof test suite passes.
- Operator-facing error surface remains consistent.

## Phase 3: Boundary Enforcement (Menu -> Service -> Repository)

Scope:
- Remove SQL/transaction control from menu actions.

Hard gates:
- Menu modules do not execute SQL directly.
- Service layer owns orchestration.

Acceptance:
- Menu smoke tests pass.
- Layering checks pass for touched paths.

## Phase 4: Legacy Publication Isolation (Default Off)

Scope:
- Keep only minimal paper export reproducibility path.
- Hide legacy publication actions by default.

Hard gates:
- `SCYTALEDROID_ENABLE_LEGACY_PUBLICATION=0` produces no legacy menu entries.
- Core reporting flow is unaffected when legacy is disabled.

Acceptance:
- Legacy-disabled smoke tests pass.
- No unexpected publication probes/imports in core workflow.

## Phase 5: De-risked Legacy Removal

Scope:
- Remove unreachable/deprecated legacy paths after isolation.

Hard gates:
- Reachability proof for each deletion candidate.
- Export reproducibility check for PRs touching export paths.

Acceptance:
- Import smoke and menu smoke pass.
- Removal report includes rollback note per candidate.
