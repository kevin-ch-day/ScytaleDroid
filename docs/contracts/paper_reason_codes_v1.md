# Paper Reason Codes v1

Paper mode uses evidence-first derived eligibility. `paper_exclusion_reason_code` is
the most specific primary reason chosen by deterministic precedence.

## Deterministic Rule

- `paper_eligible=true` only when no exclusion reasons are present.
- If multiple exclusions apply, choose the lowest-precedence-rank code.
- Persist:
  - `paper_eligible`
  - `paper_exclusion_reason_code` (primary)
  - optional `paper_exclusion_reason_codes` (all, sorted unique)

## Precedence (highest -> lowest)

1. Script/protocol:
   - `EXCLUDED_SCRIPT_HASH_MISMATCH`
   - `EXCLUDED_SCRIPT_ABORT`
   - `EXCLUDED_SCRIPT_END_MISSING`
   - `EXCLUDED_SCRIPT_STEP_MISSING`
   - `EXCLUDED_SCRIPT_TIMEOUT`
   - `EXCLUDED_SCRIPT_UI_STATE_MISMATCH`
2. Identity/policy:
   - `EXCLUDED_IDENTITY_MISMATCH`
   - `EXCLUDED_POLICY_VERSION_MISMATCH`
   - `EXCLUDED_MISSING_REQUIRED_IDENTITY_FIELD`
3. Evidence/artifacts:
   - `EXCLUDED_NO_EVIDENCE_PACK`
   - `EXCLUDED_INCOMPLETE_ARTIFACT_SET`
   - `EXCLUDED_TSHARK_PARSE_FAILED`
   - `EXCLUDED_CAPINFOS_PARSE_FAILED`
   - `EXCLUDED_FEATURE_EXTRACTION_FAILED`
4. Window/duration/quality:
   - `EXCLUDED_WINDOW_COUNT_MISSING`
   - `EXCLUDED_WINDOW_COUNT_TOO_LOW`
   - `EXCLUDED_DURATION_TOO_SHORT`
   - `EXCLUDED_MISSING_QUALITY_KEYS`
5. Intent/cohort:
   - `EXCLUDED_INTENT_NOT_ALLOWED`
   - `EXCLUDED_MANUAL_NON_COHORT`
   - `EXCLUDED_EXTRA_RUN`
6. Selection/ranking:
   - `EXCLUDED_OUTSIDE_REPLACEMENT_SCOPE`
   - `EXCLUDED_NOT_SELECTED_BY_DETERMINISTIC_RANK`
7. Fallback:
   - `EXCLUDED_INTERNAL_ERROR`

## Current lock highlights

- Manual interaction is always non-cohort in paper mode.
- Missing `window_count` is fail-closed in paper mode.
- Missing required identity/static linkage fields is fail-closed.
- Policy version mismatch is fail-closed.
