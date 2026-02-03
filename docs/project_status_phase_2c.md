# Project Status — Phase 2C (Tier-1 Readiness)

## Phase / Sprint Status
- **Phase 2C (telemetry stabilization + Tier-1 readiness):** nearly complete.
- Sampling stability, QA gates, and dataset export are functional.
- Remaining work is **data correctness**, not system stability.

## What Is Working (confirmed by SQL + audits)

### Telemetry & QA
- ✅ 2 dataset-tier runs exist and **PASS QA**.
- ✅ `capture_ratio ≈ 0.99`.
- ✅ `max_gap` within threshold.
- ✅ `telemetry_partial_samples` not present.
- ✅ Tier-1 audit reflects correct counts.

### PCAP
- ✅ PCAP capture successful (60–100MB files).
- ✅ Backfill action now populates DB fields:
  - `pcap_relpath` / `pcap_bytes` / `pcap_valid` / `validated_at`.
- ✅ Audit now shows PCAP valid runs **2/2**.

### Export
- ✅ Tier-1 export pack works (manifest, summary, rollup, telemetry CSVs).
- ✅ Reporting and audit menus now accurate.

## Current Blocking Issues (must resolve before ML)

### ❌ Netstats bytes are all zero
- Netstats rows exist, but `bytes_in/out = 0`.
- This makes network features unusable (constant zero features).
- PCAP shows heavy traffic → confirms parser/format mismatch.

**Suspected cause**
- Android 15 `dumpsys netstats` output format changed.

**Fix path**
- Added fallback to `dumpsys netstats --uid <uid>` in sampler.
- Expanded parser patterns to handle `rx_bytes`/`tx_bytes` and uid-less output from `--uid` runs.
- Centralized netstats collection/parsing into dedicated modules with debug capture support.
- Need validation with a fresh dataset run.
- If still zero, adjust parser using real `dumpsys` output.

### ❌ Dataset-tier network rows can be absent if netstats missing
- Previously dataset tier filtered out non-netstats rows, causing empty network telemetry.
- Fixed now: dataset tier persists `netstats_missing` rows.
- Needs validation with a new run.

### ⚠ Orphan evidence record (optional cleanup)
- One orphan `permission_audit_snapshot` with missing `relpath`/`sha`.
- Not blocking Tier-1 readiness, but pollutes audit.
- Repair action exists: **“Delete orphan permission snapshots.”**

## What Remains to Finish Phase 2C

### ✅ Already done
- Tier-1 QA gates validated.
- PCAP persistence + backfill.
- Export pipeline functional.
- Guided dataset run flow.
- Feature health audit generated during export (file-based).

### ⏳ In progress
- Validate netstats bytes after parser changes.
- Confirm dataset tier persists `netstats_missing` rows.
- Review new feature health audit output for network byte degeneracy.

### ✅ Optional cleanup
- Remove orphan evidence row.

## Code Updates Still Needed / Recommended
- Validate netstats debug captures on real Android 15 output and tune parser if needed.
- Extend feature health audit thresholds once baseline metrics are collected (e.g., per-app variance targets).
- Add a health-check query for **zero-valued netstats bytes** (distinct from missing rows) to highlight constant-zero network features.

## Backlog (post-Phase 2C / Phase 3)

### High priority
- Extend **feature health audit**:
  - tune thresholds after baseline runs.
  - add per-feature targets.
- Add **PCAP vs netstats consistency** check:
  - ratio of `netstats_bytes / pcap_bytes` per run.
- Add dataset **manifest versioning stamp** in export (`v1.0` / `v1.1`).

### Medium priority
- Add “Tier-1 readiness achieved” banner after 2 passes.
- Optional: auto-prompt export after readiness gate passes.
- Add “netstats parser diagnostic” tool for UI.

### Low priority / after paper
- Menu refactor (dynamic menu is large/god-file).
- Consolidate telemetry pipelines (BehaviorAnalysis vs DynamicAnalysis).
- Advanced PCAP stats explorer in Reporting.

## Immediate Next Actions (this week)
1. Run a new **dataset-tier session** (guided).
2. Execute 4 netstats SQL checks to verify bytes.
3. If bytes still zero:
   - Capture 20 lines of `dumpsys netstats` output.
   - Update parser for Android 15 format.
4. Run Tier-1 audit + export again.
5. Clean orphan evidence row (optional).
