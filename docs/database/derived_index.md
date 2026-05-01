# Database as a Derived Index (Freeze/Profile Mode)

Freeze/profile posture:
- Evidence packs are authoritative.
- The DB is a rebuildable **accelerator** (fast querying/reporting), not ground truth.

## What the DB is used for

- Fast “what do we have?” queries (runs by app, baseline vs interactive, recent runs).
- Derived indicators/features indexing (e.g., DNS/SNI counts, transport mix, per-run rates).
- Reporting exports that benefit from SQL instead of scanning JSON.

## What the DB must NOT be used for

- Selecting the frozen dataset for freeze/profile ML.
- Training/scoring ML (no DB reads in ML runner).
- Any logic that changes run validity or dataset inclusion.

## Rebuild workflow (preferred)

Use:
- **Reporting → Tier-1 quick fix** (or **Tier-1 end-to-end**)

Characteristics:
- Idempotent upserts.
- Safe to drop/rebuild the DB without losing the dataset.
- DB drift can happen (deleted evidence packs, partial indexing); fix by rebuild or pruning orphans.

## Drift hygiene

- Orphan rows (evidence path missing) are safe to delete; they are derived.
- Evidence packs remain the truth.
