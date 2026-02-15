# Sprint 0.2 Acceptance (Identity + Linkage)

Note: This is a historic acceptance checklist for early identity/linkage work.
Current implementation contracts live in `docs/engineering_invariants.md` and
`docs/refactor_phase_plan.md`. Legacy paper export references are optional and
kept under `docs/paper2/`.

Scope: static run identity, run_map linkage, and diagnostic linkage reporting.

## Diagnostic linkage acceptance (state machine)

Diagnostic output must report the correct linkage state for every app:

- **VALID (run_map)** when run_map exists for the session and validates.
- **VALID (db_link)** when static_session_run_links resolves deterministically.
- **VALID (db_lookup)** when read-only lookup by package + run_signature resolves deterministically.
- **UNAVAILABLE** only when neither authoritative source exists.
- **INVALID** when sources conflict or are malformed.

Dynamic-ready **PASS** is allowed only when every app is VALID (run_map/db_link/db_lookup).

## Run identity requirements

Each app must compute and surface:

- base_apk_sha256 (base split only)
- artifact_set_hash (ordered split list hash; order=split_name_lex)
- run_signature (v1) and run_signature_version
- identity_valid + identity_error_reason when invalid

Identity must be **VALID** for all split apps in scope.

## Run_map completeness (non-dry runs)

Non-dry runs must hard-fail if any run_map entry is missing:

- static_run_id
- pipeline_version
- base_apk_sha256
- artifact_set_hash
- run_signature
- run_signature_version

Diagnostic runs may proceed with incomplete run_map but must surface
UNAVAILABLE/INVALID states and fail dynamic-ready.

## Schema hardening (linkage table)

`static_session_run_links` must be strict:

- pipeline_version NOT NULL
- base_apk_sha256 NOT NULL
- artifact_set_hash NOT NULL
- run_signature NOT NULL
- run_signature_version NOT NULL
- identity_valid NOT NULL

`static_analysis_runs` remains nullable for legacy rows, but new COMPLETED
runs must populate pipeline_version and signature fields (enforced in code/tests).
