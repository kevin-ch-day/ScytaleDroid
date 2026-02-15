# Inventory Guard Determinism Contract

This contract defines deterministic behavior for inventory guard decisions.

## Inputs

Given identical:
- persisted inventory metadata state,
- current function inputs (`serial`, scope package list),
- guard configuration constants,

the guard must produce identical decision outputs.

## Decision Object (authoritative)

`ensure_recent_inventory()` records a decision object with these fields:

- `decision_enum`: one of `allow`, `prompt`, `deny`, `unknown`
- `reason_code`: stable machine-readable reason token
- `next_action`: one of `continue`, `prompt_choice`, `cancel`, `none`
- `prompt_key`: stable prompt-classification key
- `policy`, `stale_level`, `reason`, `scope_changed`, `scope_hash_changed`,
  `packages_changed`, `age_seconds`, `package_delta`, `package_delta_brief`,
  `guard_brief`

Consumers should use `decision_enum` + `reason_code` as primary semantics.

## Purity Rule

Inventory metadata load/compute paths are read-only:

- no DB writes,
- no scope-hash reconciliation writes,
- no filesystem mutations beyond logs.

## Acceptance Rules

- Repeated runs over identical inputs yield identical
  `decision_enum` + `reason_code` + `next_action` + `prompt_key`.
- No-write-on-load tests remain green.
