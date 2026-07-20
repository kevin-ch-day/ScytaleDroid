# IEEE-CARS-2026 Evidence Package

Submission package ID: `IEEE-CARS-2026`.

This directory holds only reviewed package-selection inputs. It is not a place
to copy a manuscript, APK, PCAP, database export, credentials, or the whole
workspace. The final hash-locked manifest names the exact external files after
they have been explicitly reviewed.

Required review inputs:

- selected APK ledger
- selected dynamic-evidence ledger
- scoped database-export specification and completed receipt
- current manuscript path, added explicitly when the capsule manifest is built

The reporting menu's `IEEE-CARS-2026 evidence package` view is read-only. It
shows the latest cutoff, generated writing workspace, and capsule readiness.

Create review drafts from a chosen freeze without copying evidence:

```bash
PYTHONPATH=. python scripts/operator/draft_paper_freeze_capsule_ledgers.py \
  --paper-id IEEE-CARS-2026 \
  --freeze-manifest output/paper/<freeze>/paper_freeze_manifest.json \
  --out-dir output/audit/research_capsules/IEEE-CARS-2026
```

The resulting drafts must be reviewed and changed to `APPROVED` before a
capsule manifest can be archive-ready.
