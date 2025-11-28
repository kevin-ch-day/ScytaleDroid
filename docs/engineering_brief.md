# ScytaleDroid – Engineering Brief (Research Platform Story)

## What ScytaleDroid Is
- Research platform for harvesting APKs from real Android devices, running repeatable static analysis across app sets, and persisting findings to a database.
- Findings are mapped to OWASP MASVS v2.1 and scored with CVSS v4.0 so published tables/figures (e.g., CARS 2025) are reproducible.
- Think “toolchain behind academic studies,” not a one-off script; every change impacts reproducibility claims.

## Research Context (keep in mind)
- **Deconstructing Twitter App:** Single-app static teardown (manifest, exported components, permissions, network config, hardcoded material). Mostly bespoke scripts.
- **CARS2025 Social Media:** Generalizes to multiple social apps (Twitter/X, FB, IG, TikTok, Snapchat, etc.) and looks for patterns:
  - Exported components without guards
  - Excessive/high-risk permissions
  - Legacy storage flags
  - Hardcoded API keys/secrets/endpoints
  - Cleartext or weak network configs
- ScytaleDroid’s job: industrialize these methods and make them extensible to new app sets and studies.

## Current State (Phase 2: device/inventory/harvest – effectively done)
- **Inventory engine:** `DeviceAnalysis/inventory/*` + `inventory_service` collect packages, persist snapshots, sync app definitions, compute a single InventoryDelta reused across UI (summary cards, dashboard, gating).
- **Staleness/gating:** 24h age semantics; “fresh + diff” surfaces a single dialog; stale forces sync prompt.
- **Harvesting:** Menu → Pull APKs → scope selection → clean handling of multi-split APKs; per-package summaries; artifacts under `data/apks/device_apks/...`.
- **Menu/UX:** Device Analysis menu stable; shortcuts (`r`, `c`, `i`, `s`, `l`, `q/0`) consistent.
- **Classification sanity:** Inventory summary shows user-scope candidates, Play vs sideload vs unknown for user apps, roles by partition (User/OEM/System/Mainline/Vendor).

## What’s Next (Phases 3 & 4)
### Phase 3 – Research-complete, reproducible engine
- **Static run metadata + DB:** `static_service.run_scan` as the only entry; stamp pipeline_version, catalog_versions, config_hash, study_tag, run_started_utc; persist to `static_analysis_runs` (run_id, started_utc, scope/app_count, pipeline_version, catalog_versions, config_hash, study_tag).
- **Analyzers for paper issue classes:** Implement checks (manifest/components, permissions, legacy storage, network config, secrets) in `StaticAnalysis/checks/*`; normalize findings with app identity, MASVS control, CVSS v4 vector/severity into `static_analysis_findings`.
- **Performance modes (honest):** Baseline = truth. Document and log modes (`baseline`, `user_only`, `bulk`, `incremental` if added). Any fast mode must match baseline semantics for delta/scope/roles on the same device. Log timing with mode.

### Phase 4 – Operator-ready UX & diagnostics
- **Device panel polish:** Add device summary (model/serial/type/Android/OEM/root; optional battery/Wi-Fi) above inventory using DisplayUtils styling.
- **Harvest output modes:** `SCYTALEDROID_OUTPUT_MODE=compact|verbose` (default compact for demos: per-package + summary only; verbose keeps artifact lines).
- **Reporting hook:** “Recent static runs” view showing run_id, UTC date, scope, app/finding counts, pipeline/catalog, study tag. From harvest summary, offer “run static analysis on this harvest” via `static_service`.
- **Diagnostics flags:** Debug flag logs ADB call counts/time every N packages; optional “previous snapshot” mini-block and live sanity metric in progress UI; keep disabled in normal UX.

## Design Principles & Constraints
- **Correctness > speed:** Baseline mode is sacrosanct; no optimizations that drop fields or change semantics silently.
- **Single sources of truth:** One menu spec; one gating helper for freshness states; one InventoryDelta reused across UI; one place for run metadata stamping.
- **Service-layer architecture:** Controllers orchestrate; work happens in services/subpackages. ADB via `adb_utils` only.
- **Test + transcript discipline:** For non-trivial changes, run smoke imports/pytest; capture at least one transcript of inventory + pull (and static when applicable).
- **Publication standard:** Any change affecting counts/classifications/risk must be explainable in a methods section (e.g., how user_only mode filters by partition).

## What “done” means
- **Phase 3:** Static run metadata persisted + visible in reporting; analyzers implemented and tested with fixtures for the paper’s issue classes; fast modes documented and parity-checked against baseline.
- **Phase 4:** Device panel polished; compact/verbose harvest output; Recent static runs view wired to DB; debug diagnostics present but quiet by default.
