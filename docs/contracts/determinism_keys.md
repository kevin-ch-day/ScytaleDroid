# Determinism Keys Contract

This document locks identity keys used by comparators and determinism tests.

## Inventory Comparator (PR1)

### Snapshot identity key

`device_inventory_snapshots` row identity is:

1. `device_serial`
2. `package_list_hash`
3. `package_signature_hash`
4. `scope_hash`

All four are required in strict mode.

### Package identity key

`device_inventory` row identity for drift-set comparison is:

1. `package_name_lc` (canonical lowercase)
2. `version_code_norm` (canonical string)

Both are required in strict mode.

### Secondary integrity fields (non-key, but compared)

1. `signer_cert_digest`
2. `split_membership_hash`

Any change in these fields is a disallowed diff in strict mode.

### Strict mode behavior

1. Missing required identity fields -> comparator `FAIL`.
2. Duplicate row keys -> comparator `FAIL`.
3. Row order differences are ignored by canonical keying.

## Static Tables (PR2+ proposal)

These keys are proposed and will be finalized with persistence/UoW contracts:

1. `static_analysis_runs`: `(session_stamp, app_version_id)` logical key; `id` physical key.
2. `static_analysis_findings`: `(run_id, detector, rule_id, evidence_hash, severity, category)` synthetic logical key.
3. `static_permission_matrix`: `(run_id, permission_name)`.
4. `risk_scores`: `(package_name, session_stamp, scope_label)`.
5. `static_permission_risk` (target schema): `(run_id, permission_name)`.

## Static Permission Risk vNext Comparator Rules

For `static_permission_risk_vnext` comparisons:

1. Identity key is `(run_id, permission_name)` with `permission_name` canonical lowercase.
2. Duplicate keys are a hard `FAIL`.
3. Missing `permission_name` is a hard `FAIL`.
4. Case-mismatched permission names are a hard `FAIL` (canonicalization violation).
5. Comparator compares full row payload by key:
   `risk_score`, `risk_class`, `rationale_code`.
