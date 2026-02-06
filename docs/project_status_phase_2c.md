# Project Status — Phase 2C (Legacy Snapshot)

## Phase / Sprint Status (historic)
- **Phase 2C (telemetry stabilization + Tier-1 readiness):** complete.
- Sampling stability, QA gates, and dataset export are functional and verified.
- Remaining work is **post-sprint polish**, not system stability.

## What Is Working (confirmed by SQL + audits)

### Telemetry & QA
- ✅ 5 dataset-tier runs exist and **PASS QA**.
- ✅ `capture_ratio ≈ 0.99`.
- ✅ `max_gap` within threshold.
- ✅ `telemetry_partial_samples` not present.
- ✅ Tier-1 audit reflects correct counts.

### PCAP
- ✅ PCAP capture successful (30–100MB files).
- ✅ Backfill action populates DB fields:
  - `pcap_relpath` / `pcap_bytes` / `pcap_valid` / `validated_at`.
- ✅ Audit now shows PCAP valid runs **5/5**.

### Export
- ✅ Tier-1 export pack works (manifest, summary, rollup, telemetry CSVs).
- ✅ Reporting and audit menus now accurate.

## Current Risks (non-blocking, tracked)

### ⚠ Netstats availability varies by run
- New parser + delta logic now produce **non-zero netstats bytes** when available.
- Some runs still report `netstats_missing` (Android 15 + VPN variability).
- Export policy now **skips network CSVs unless `netstats_ok`**, keeping Feature Health honest.

### ⚠ Orphan evidence record (optional cleanup)
- One orphan `permission_audit_snapshot` with missing `relpath`/`sha`.
- Not blocking Tier-1 readiness, but pollutes audit.
- Repair action exists: **“Delete orphan permission snapshots.”**

## What Remains (post-Phase 2C polish)

### ✅ Already done
- Tier-1 QA gates validated (5 QA-pass runs).
- PCAP persistence + backfill (5/5 valid).
- Export pipeline functional (manifest, summary, rollup, telemetry).
- Guided dataset run flow.
- Feature health audit generated during export (file-based).

### ✅ Completed checks
- Netstats bytes validated (non-zero deltas confirmed on dataset run).
- Dataset tier persists `netstats_missing` rows.
- Feature Health gating now conditional on network CSV presence.

### ⚠ Optional cleanup
- Remove orphan evidence row (permission_audit_snapshot).

## Code Updates Still Recommended
- Extend feature health audit thresholds once baseline metrics are collected (per-app variance targets).
- Add a health-check query for **zero-valued netstats bytes** to highlight constant-zero network features.

## Backlog (post-Phase 2C / Phase 3)

### High priority
- Extend **feature health audit** thresholds after baseline runs.
- Add **PCAP vs netstats consistency** check (ratio of `netstats_bytes / pcap_bytes`).
- Add dataset **manifest versioning stamp** in export (`v1.0` / `v1.1`).

### Medium priority
- Add “Tier-1 readiness achieved” banner after 2 passes.
- Optional: auto-prompt export after readiness gate passes.
- Add “netstats parser diagnostic” tool for UI.

### Low priority / after paper
- Menu refactor (dynamic menu is large/god-file).
- Advanced PCAP stats explorer in Reporting.

## Immediate Next Actions (this week)
1. Run Tier-1 audit + export after each new dataset run.
2. Clean orphan evidence row (optional).
