# Inventory Rerun & Failure Semantics (current behavior)

Scope: physical device inventory sync (metadata-only).

- **Writes happen at the end**: package metadata is collected in memory; snapshot + DB sync happen only after collection finishes. If interrupted mid-collection, no new snapshot or DB changes are written; last good snapshot remains.
- **Delta criteria** (unchanged): compares stable fields per package: `version_code`, `version_name`, `primary_path`, `split_count`. Reordering of split paths is normalized; benign reordering alone should not produce a delta.
- **Rerun behavior**: an immediate rerun after a successful sync reports “identical to previous snapshot” if those fields haven’t changed. Runtime remains similar because we still collect fresh metadata; no caching/batching is used yet.
- **Failure visibility**: a per-package failure during collection currently aborts the run (no partial snapshot). There is no per-package skip counter yet; errors surface as run failure.
- **Partial runs**: if the run stops before persistence, the next run starts from the last complete snapshot; there is no “incomplete” marker today—interruption means “no new snapshot written.”

Status: documentation only (no behavior change). Use this as operator guidance until further guardrails are added.
