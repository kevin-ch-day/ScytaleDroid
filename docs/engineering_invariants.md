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

Derived filesystem artifacts (indexes, manifests, receipts, small JSON/CSV outputs)
are written atomically (temp + replace) to avoid corrupt partial files.

Current coverage includes:

- derived dataset index artifacts
- publication bundle manifests and small sidecars
- ML per-run and per-dataset JSON sidecars

Intentionally not atomic:

- authoritative evidence pack directories under `output/evidence/**`
- PCAPs and other large capture binaries
- large raw logs or device-side artifacts

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

## 6) Legacy Publication Is Read-Fallback Only

Legacy publication naming is no longer an active workflow branch.

- Core workflows must run without a legacy publication toggle.
- Remaining legacy publication support is read-side fallback only.
- Compatibility exists only for bounded Paper #2 reproducibility/migration seams.

## 7) Export Freeze Is Manifest-Driven

Frozen Paper #2 exports are validated against a versioned baseline manifest.

- Source of truth: `tests/baseline/publication_export_manifest.json`.
- Verification is hash+size based using declared normalization rules.
- Drift requires a documented rationale under `docs/drift/` and approval.

## 8) Profiles Are Explicit And Isolated

The tool supports multiple paper/research profiles. Operators must never rely on
"latest runs" selection when generating paper-facing exports.

- Filesystem artifacts are canonical; DB is optional and derived.
- Profile v2 (FROZEN) is archival truth and must never expand beyond the frozen cohort.
- Profile v3 (STRUCTURAL) is catalog-defined and must match the catalog package set exactly.
- Refresh snapshots (when implemented) must be stamped and must never overwrite archival v2 outputs:
  - `output/publication/profile_v2_refresh/<stamp>/`
- Paper-facing exports are manifest-driven (no implicit "newest artifacts").
