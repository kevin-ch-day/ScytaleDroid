# Dataset Tracker `paper_*` Seam Classification

Date: 2026-04-16

Scope:
- [scytaledroid/DynamicAnalysis/pcap/dataset_tracker.py](/home/secadmin/Laughlin/GitHub/ScytaleDroid/scytaledroid/DynamicAnalysis/pcap/dataset_tracker.py)

Purpose:
- classify the remaining `paper_*` names before any migration work
- separate canonical logic from compatibility fields
- identify what can be renamed later versus what requires a migration plan

## Canonical Now

These are already aligned with the current platform model and should remain the preferred path:

- `derive_freeze_eligibility`
  - imported from `scytaledroid.DynamicAnalysis.freeze_eligibility`
  - this is the canonical evaluator used by the tracker refresh/derivation paths

## Persisted Compatibility Fields

These are stored on tracker rows and are part of the current derived JSON shape.
They are not safe to rename casually.

- `paper_eligible`
- `paper_exclusion_primary_reason_code`
- `paper_exclusion_all_reason_codes`

Why they are compatibility-sensitive:
- they are written into `data/archive/dataset_plan.json`
- downstream tools and exports may read them directly
- historical tracker rows may already contain them

Action:
- keep as-is for now
- if renamed later, require explicit read/write alias strategy or migration

## In-Memory / Helper Names That Can Be Reviewed Later

These are implementation names, not the persisted field names themselves:

- `_refresh_paper_eligibility_in_place(...)`
- `_derive_paper_eligibility_fields(...)`

These are good candidates for later internal rename/alias cleanup, but only after the
compatibility strategy for the persisted tracker fields is defined.

Recommended future direction:
- canonical helper names may move toward `freeze` or `cohort` language
- returned field keys should continue writing the compatibility `paper_*` names until migration is approved

## UI / Derived Verdict Layer

`derive_three_verdicts_for_row(...)` still reads the compatibility field names, but it is
presenting domain verdicts:

- technical validity
- protocol compliance
- cohort eligibility

This is acceptable for now because it is a read layer over the compatibility fields, not a
new naming seam.

## Migration Guidance

Do now:
- keep `derive_freeze_eligibility` as the canonical evaluator
- avoid adding new `paper_*` names
- document compatibility boundaries

Do later, with explicit approval:
- alias or rename helper function names
- migrate persisted tracker field names
- rename export/report readers that depend on `paper_*`

Do not do casually:
- rename `paper_eligible` or exclusion fields in-place
- change tracker JSON contract without a versioned migration path
