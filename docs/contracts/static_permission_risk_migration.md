# `static_permission_risk` Migration Plan (Deferred Cutover)

This document tracks the approved schema correction for `static_permission_risk`.

## Target Model

`static_permission_risk` is permission-granular and run-aware.

Required columns:

1. `run_id` (FK to `static_analysis_runs.id`, NOT NULL)
2. `permission_name` (canonicalized string, NOT NULL)
3. `risk_score` (DECIMAL, NOT NULL)
4. `risk_class` (nullable)
5. `rationale_code` (nullable)
6. `created_at_utc` (NOT NULL)

Uniqueness:

1. `UNIQUE(run_id, permission_name)`

## Prepared Migration Artifact

Prepared SQL file:

`migrations/2026-02-16_static_permission_risk_runid_perm.sql`

Phase 1 (`safe now`) creates `static_permission_risk_vnext` only.
Runtime persistence is now vNext-authoritative.

## Why Cutover Is Deferred

1. Paper #2 export reproducibility is frozen during review.
2. Some legacy table references are retained for migration/audit only.
3. Cutover will happen only after:
   1. writer path is vNext-only
   2. determinism gates pass
   3. persistence rollback proof passes

## Transition Guardrails (Current)

1. Static schema gate requires canonical `risk_scores` and
   run-aware `static_permission_risk_vnext`.
2. Permission-risk persistence writes `risk_scores` + `static_permission_risk_vnext`.

## Current Risk Until Cutover

Legacy table still has `UNIQUE(apk_id)` and may overwrite cross-run rows.
This is explicitly tracked as technical debt with an approved migration path.
