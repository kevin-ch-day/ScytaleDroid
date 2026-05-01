# Static Risk Surface Contract

This project currently exposes three different static-risk surfaces. They are
not interchangeable.

## 1. Permission run score

Authoritative store: `risk_scores`

Meaning:
- run-scoped permission-only score
- persisted during static-analysis permission scoring
- keyed by `(package_name, session_stamp, scope_label)`

Columns that matter:
- `risk_score`
- `risk_grade`
- `dangerous`
- `signature`
- `vendor`

Use this when the question is:
- "What did the permission scoring model assign to this run?"

Do not use this as:
- the permission-audit score
- the composite static score shown in the CLI

## 2. Permission audit app score

Authoritative store: `permission_audit_apps`

Meaning:
- per-app permission-governance audit result for a snapshot/run
- persisted as part of permission audit outputs

Columns that matter:
- `score_raw`
- `score_capped`
- `grade`
- `dangerous_count`
- `signature_count`
- `vendor_count`

Use this when the question is:
- "What governance-oriented permission audit score did the app receive?"

Do not treat this as the same score as `risk_scores.risk_score`.

Current implementation note:
- new runs should now apply the same detector-derived penalty inputs
  (`flagged_normal_count`, `weak_guard_count`) that the run-level
  `risk_scores` path already uses
- historical rows may still diverge because older `permission_audit_apps`
  rows were produced without those inputs

Current decomposition caveat:
- `combos_total`
- `surprises_total`
- `legacy_total`
- `vendor_modifier`

These columns are persisted compatibility/decomposition fields, but recent
rows often carry `0.000`. They should not be assumed to represent active score
contributors unless the underlying score detail payload confirms they were used.

## 3. Composite static score

Current surface: CLI/runtime analytics only

Meaning:
- mixed static posture score rendered from multiple signals
- built from permission profile, manifest/network/storage/components/secrets,
  and correlation signals during report rendering

Current status:
- not persisted as a canonical DB row
- not represented by one authoritative table today

Implication:
- broad DB consumers should not assume there is a single persisted
  `composite_static_score` column to join against
- if a DB consumer needs all three surfaces together, use
  `vw_static_risk_surfaces_latest` for the persisted surfaces and treat the
  composite CLI score as a separate runtime contract until it is explicitly
  persisted

## Read model

Use:
- `vw_static_risk_surfaces_latest`

This view makes the surfaces explicit by naming them separately:
- `permission_run_*`
- `permission_audit_*`
- `legacy_bucket_*`
- `composite_static_surface_state`

Known integrity checks:
- compare `permission_run_*` and `permission_audit_*` counts/score deltas
  before treating them as interchangeable
- `metrics.run_id` is still keyed to the legacy `runs` bridge, not
  `static_run_id`, so ad hoc score debugging must resolve the linked
  legacy run first

The `legacy_bucket_*` columns are supporting lineage only. They do not turn the
legacy bucket rollup into the canonical composite static score.
