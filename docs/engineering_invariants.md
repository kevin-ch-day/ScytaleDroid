# Engineering Invariants

This file defines non-negotiable runtime invariants for ScytaleDroid.

## 1) Read Paths Are Pure

Functions classified as `load`, `status`, `compute`, `drift`, and `preview` are read-only.

- No DB write operations.
- No filesystem mutations except logging.
- No hidden state mutation that changes later decisions.

## 2) Evidence Packs Are Immutable

Evidence pack directories are append-only ground truth.

- No in-place repair of existing packs.
- Regeneration must produce new artifacts/paths, not mutate old packs.

## 3) Persistence Is Atomic

Static persistence is all-or-nothing at the unit-of-work boundary.

- Either run row + related findings/risk/metadata commit together, or none commit.
- Failures must not leave orphan rows.
- Scientific run state vocabulary is fixed to `STARTED`, `COMPLETED`, `FAILED`.

## 4) Determinism Comparator Is Contractual

Determinism gates are key-based and machine-readable.

- Row order is not authoritative; identity keys are.
- Missing required key fields are strict failures.
- Comparator artifacts are written under `output/audit/comparators/...`.

## 5) Menu Is Non-Authoritative

Menu modules are UI-only orchestration entry points.

- Menu code performs no SQL directly.
- Menu code performs no transaction control.
- Services orchestrate; repositories access DB/filesystem.

## 6) Legacy Publication Is Opt-In

Legacy publication/export code is isolated and disabled by default.

- `SCYTALEDROID_ENABLE_LEGACY_PUBLICATION=0` is the default behavior.
- Core workflows must run without importing or probing legacy publication paths.
- Legacy publication support is temporary and exists only for Paper #2 reproducibility.

## 7) Export Freeze Is Manifest-Driven

Frozen Paper #2 exports are validated against a versioned baseline manifest.

- Source of truth: `tests/baseline/paper2_export_manifest.json`.
- Verification is hash+size based using declared normalization rules.
- Drift requires a documented rationale under `docs/drift/` and approval.
