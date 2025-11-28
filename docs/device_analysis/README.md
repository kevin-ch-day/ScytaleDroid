# ScytaleDroid – Device Analysis Overview

This guide summarizes what ScytaleDroid delivers today, what gaps we are
closing in the Device Analysis workflow, and the exact ways collaborators can
help move the project forward.

## What ScytaleDroid is

ScytaleDroid is a menu-driven CLI that connects to live Android devices and
pulls APK artifacts into a structured repository. The toolchain favors a
"database-first" architecture:

- Every artifact is stored with a deterministic file path and filename that
  embeds the package name and version code.
- Each file is assigned an `apk_id` row in the `android_apk_repository` table,
  which becomes the anchor for static, dynamic, and threat-intel analysis.
- Helper metadata such as user-friendly labels live in `android_app_definitions`
  and stay synchronized automatically during inventory runs.

## Device Analysis status (Phase 1)

Device Analysis is the first pillar of v2. It covers the pipeline from device
inventory to curated APK harvesting and repository ingestion.

### Device dashboard refresh (new)

- The Device Dashboard now opens with a color-coded status card that surfaces
  the most recent refresh time, aggregate connection state, detected device
  count, and any adb warnings before an analyst dives into menu options.
- When a handset is active, a compact card highlights serial, Android build,
  battery, Wi-Fi, and root posture so operators can validate the target at a
  glance.
- Every detected handset is listed in a table with state badges so multi-device
  benches are easy to scan, and the disconnected view now embeds the last seen
  device plus clear guidance on how to reconnect.
- The dashboard automatically adapts its palette to Fedora's dark/light themes
  (override with `SCYTALE_UI_THEME`) and exposes a high-contrast preset, while
  ASCII-safe glyphs engage automatically or via `ASCII_UI=1` for legacy
  terminals.
- Palette definitions now live under `scytaledroid/Utils/DisplayUtils/colors/`
  so engineers can extend the registry without wading through rendering logic;
  drop a new module that registers a `Palette` and it is instantly available to
  the CLI theme switcher.

### Inventory (shipping today)

- Runs `pm list packages`, `pm path`, and `dumpsys` to capture package metadata.
- Classifies packages by install path: `/data` (User), `/product` (OEM),
  `/system*` (System), `/apex` (Mainline), `/vendor` (Vendor).
- Records the installer package, family hints (`com.android.*`, `com.google.*`,
  `com.motorola.*`), and analyst-friendly profiles (Social, Shopping,
  Messaging).
- Saves the snapshot on disk and keeps the `android_app_definitions` table in
  sync with the latest labels.

### Harvest (tightening right now)

- Detects when inventories are only soft-stale and routes to the
  **quick-harvest** runner, which resolves live paths with `pm path` and skips
  the legacy snapshot dependency entirely.
- Presents a scope selector before any pulls. The default scope harvests only
  Play Store apps plus `/data` user apps.
- Optional filters allow profile-only pulls, family targeting with a Google
  allow-list, or explicit package patterns (`com.openai.chatgpt`,
  `com.google.*`, etc.).
- Filters unreadable paths so `/system`, `/product`, `/vendor`, and `/apex`
  artifacts are skipped on non-root devices.
- Enforces filenames shaped like `com_package_name_<vercode>__artifact.apk`
  (e.g., `com_motorola_aiservices_281117118__split_config.arm64_v8a.apk`).
- Deduplicates artifacts by `sha256`, optionally keeping the latest copy when
  `HARVEST_KEEP_LAST` is enabled, and records any skips in the CLI summary.
- Emits `*.meta.json` sidecars per artifact with configurable fields and writes
  database rows when `HARVEST_WRITE_DB` remains enabled.
- Inserts one repository row per artifact and prints each `apk_id` so analysts
  can immediately find the files in the database when DB writes are active.
- Finishes each run with a condensed summary card that surfaces scope, pull
  mode, package and artifact breakdowns (clean pulls, partial issues, blocked,
  deduped, failed), runtime skip callouts, and guard notices. A follow-up
  highlights section then spells out the key wins and warnings before the CLI
  dives into the detailed skip breakdowns and per-package diagnostics.

### Database integration (foundation for all phases)

- `android_app_definitions(app_id, package_name, app_name)` stores the
  package→label mapping and is updated whenever new metadata is discovered.
- `android_apk_repository` holds per-file metadata: hashes, size, installer,
  version info, split membership, and the original device path.
- Unique constraints on `sha256` guarantee deduplication even when the same APK
  is harvested multiple times.

## What success looks like for Phase 1

- Default pulls touch only Play Store and `/data` user apps instead of hundreds
  of protected packages.
- Permission-denied spam disappears because unreadable system partitions are
  filtered before any `adb pull` executes.
- Every artifact lands in the DB with an `apk_id`, making follow-on analysis
  deterministic and traceable.
- Analysts can target high-value subsets—profiles, brand families, or explicit
  packages—without editing code.

## Roadmap after Device Analysis

Once the harvest loop is fully locked down, the same database-first approach
expands to:

1. **Static analysis:** manifest parsing, permission and API surfacing, tracker
   detection, ML-driven risk scoring, and differential comparisons fuelled by
   the static-analysis pipeline. Harvest runs now drop artifacts directly into
   the repository folders that `StaticAnalysis/core/pipeline.py` consumes,
   enabling reproducibility bundles (manifest, NSC, strings) and split-aware
   posture diffing without additional preparation.
2. **Dynamic analysis:** sandbox executions, behavior logging, and network
   capture ingestion.
3. **Threat-intel enrichment:** signer lineage analysis and reputation
   scoring sourced from internal datasets.
4. **Web UI:** searchable catalogs, version diffs across devices, and per-app
   dossiers built from the `apk_id` records.

## How collaborators can help right now

- **Run the tool on diverse hardware:** Samsung, Pixel, carrier variants, rooted
  vs. non-rooted. Report inventory counts, misclassified packages, and Play apps
  missed by the default scope.
- **Refine scopes:** contribute Google allow-lists, new analyst profiles, or
  family rules that improve default targeting.
- **Propose analysis schemas:** suggest the tables and indicators you need for
  the upcoming static/dynamic/threat-intel phases (e.g., permissions, trackers,
  string intel).
- **Validate filenames & DB rows:** confirm harvested files match the
  `com_package_vercode__artifact.apk` convention, that `apk_id` entries exist
  per artifact, and that static-analysis reports link back via the stored
  `apk_id` metadata.
- **Feed the static-analysis loop:** capture before/after harvests of the same
  app so the correlation detector can highlight manifest drift, permission
  expansion, or cleartext policy changes across versions.

## Operational checklist

1. Connect a device with USB debugging enabled.
2. Run `./run.sh` and open **Device Analysis**.
3. Choose **5: Inventory & DB sync** to capture the latest snapshot.
4. Choose **7: Pull APKs** and pick a scope (default = Play + `/data`).
5. Review the boxed harvest summary for scope, pull mode, package/artifact
   breakdowns, runtime skip alerts, guard notices, and the highlight callouts.
   Then scan the dedicated pre-flight and runtime skip sections or policy
   notices if something looks off.
6. Optional: jump to **Static Analysis** → _Analyze repository artifact_ to run
   the detector pipeline on freshly harvested APKs and persist the accompanying
   reproducibility bundle.

## Repository layout (Device Analysis modules)

```
scytaledroid/DeviceAnalysis/
  inventory.py        # inventory capture & classification
  adb_utils.py        # adb helper functions
  apk_pull.py         # orchestrates scoped harvests
  harvest/
    rules.py          # brand/path logic and filename builder
    scope.py          # package selection helpers
    planner.py        # device path planning & skip reasons
    runner.py         # adb pulls, hashing, DB inserts
    summary.py        # presentation helpers for CLI output
```

Keep this structure in mind when proposing changes or contributing code—the
harvest submodules deliberately isolate scope, planning, and execution so they
can be tested independently.

## Inventory guard logging and improvement targets

What is logged today

- Inventory deltas are computed once during a sync and persisted in snapshot
  metadata (new/removed/updated/changed), so dashboards and guard prompts read
  the same numbers instead of recomputing on the fly.【F:scytaledroid/DeviceAnalysis/inventory/runner.py†L148-L186】【F:scytaledroid/DeviceAnalysis/inventory_meta.py†L18-L66】
- The guard flow surfaces its decision through CLI status messages when a stale
  snapshot or package changes require user action; fresh, unchanged snapshots
  return immediately without prompting.【F:scytaledroid/DeviceAnalysis/device_menu/inventory_guard/ensure_recent_inventory.py†L88-L152】
- The last guard decision is stored in memory (`_LAST_GUARD_DECISION`) for
  troubleshooting during a single CLI session.【F:scytaledroid/DeviceAnalysis/device_menu/inventory_guard/ensure_recent_inventory.py†L23-L47】

What is **not** logged or persisted

- Guard prompts and operator choices are printed to the console only; they are
  not emitted through `LoggingUtils` or persisted alongside the inventory
  snapshot metadata for later review.【F:scytaledroid/DeviceAnalysis/device_menu/inventory_guard/ensure_recent_inventory.py†L132-L175】
- The in-memory guard context is cleared on each call and never written to disk
  or the database, so cross-run auditing is currently impossible.【F:scytaledroid/DeviceAnalysis/device_menu/inventory_guard/ensure_recent_inventory.py†L23-L81】

Current issues to watch

- Because prompts are console-only, there is no audit trail showing whether an
  analyst bypassed a stale snapshot warning or how often quick-sync shortcuts
  are used. This complicates incident review for missed APK pulls and hides
  guard regressions when running unattended scripts.【F:scytaledroid/DeviceAnalysis/device_menu/inventory_guard/ensure_recent_inventory.py†L132-L175】
- Dashboard summaries depend on persisted deltas; if snapshot metadata is
  missing or malformed, the guard falls back to zeroed deltas and may under-
  report changes. Hardened validation for metadata loading would reduce this
  risk.【F:scytaledroid/DeviceAnalysis/device_menu/inventory_guard/ensure_recent_inventory.py†L88-L112】【F:scytaledroid/DeviceAnalysis/inventory_meta.py†L49-L112】

Design improvements (database-aware)

- Emit structured guard decisions (status, delta details, operator choice,
  scope hash) via `LoggingUtils` and optionally persist them alongside the
  snapshot metadata or to a small audit table in the existing database. This
  would let us correlate APK pulls with the guard posture when debugging
  missing artifacts.【F:scytaledroid/DeviceAnalysis/device_menu/inventory_guard/ensure_recent_inventory.py†L23-L175】【F:scytaledroid/DeviceAnalysis/inventory/runner.py†L148-L186】
- Promote `_LAST_GUARD_DECISION` to a typed data class and serialize it when a
  sync or APK pull completes, so automated runs can surface guard coverage in
  dashboards without manual log scraping.【F:scytaledroid/DeviceAnalysis/device_menu/inventory_guard/ensure_recent_inventory.py†L23-L81】
- Treat snapshot metadata as a contract: validate delta presence and shape at
  load time, and drop to a “stale until proven fresh” posture if anything is
  missing to avoid silent mis-gating. This can be implemented in
  `inventory_meta.InventoryMeta.from_payload` with explicit warnings and
  database-backed fallbacks where available.【F:scytaledroid/DeviceAnalysis/inventory_meta.py†L49-L112】
- Consider writing guard outcomes to the same database that already receives
  harvested APK rows, so investigators can join pull history with device guard
  posture during retrospectives.【F:docs/device_analysis/README.md†L32-L70】【F:scytaledroid/DeviceAnalysis/inventory/runner.py†L186-L193】
