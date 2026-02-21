# Paper Contract v1

This contract defines paper-mode invariants for dynamic cohort construction and gating.

## Versions
- `paper_contract_version`: `1`
- `reason_taxonomy_version`: `1`
- `freeze_contract_version`: `1`

## Identity Tuple (Paper Mode Required)
- `package_name_lc`
- `version_code`
- `base_apk_sha256` (64 hex)
- `artifact_set_hash` (64 hex)
- `signer_set_hash` (64 hex)
- `static_handoff_hash` (64 hex)

Missing/invalid identity fields are paper-ineligible.

## Hash Normalization
Before equality compare:
- `strip()` whitespace
- lowercase
- exact expected hex length
- reject non-hex characters

Failure reason:
- `ML_SKIPPED_BAD_IDENTITY_HASH`

## Identity Timepoints
- `identity_checked_at_start_utc`
- `identity_checked_at_end_utc`
- `identity_checked_at_gate_utc`

Snapshots:
- `identity_start`
- `identity_end`
- `identity_gate`

## Freeze Fail-Closed Rules
Freeze build fails when:
- duplicate app-build identity appears (`FREEZE_DUPLICATE_IDENTITY`)
- mixed/invalid paper contract fields
- run identity hash fields are missing/invalid
- threshold contract mismatch for paper mode

## Exclusion Taxonomy (v1)
- `ML_SKIPPED_BASELINE_GATE_FAIL`
- `ML_SKIPPED_MISSING_FREEZE_MANIFEST`
- `ML_SKIPPED_BAD_FREEZE_CHECKSUM`
- `ML_SKIPPED_MISSING_STATIC_LINK`
- `ML_SKIPPED_MISSING_BASE_APK_SHA256`
- `ML_SKIPPED_MISSING_STATIC_FEATURES`
- `ML_SKIPPED_APK_CHANGED_DURING_RUN`
- `ML_SKIPPED_BAD_IDENTITY_HASH`
- `ML_SKIPPED_INCOMPLETE_ARTIFACT_SET`

Unknown reason codes are invalid in paper mode.

## Paper vs Non-Paper
- Paper mode: fail-closed, immutable grouping by build identity tuple.
- Non-paper mode: best-effort, exploratory outputs allowed, but not paper-eligible.
