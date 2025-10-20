# ScytaleDroid

ScytaleDroid v2 is a menu-driven toolkit for harvesting, cataloging, and
analyzing Android application packages (APKs) from real devices. The project
emphasizes a "database-first" design so every artifact is traced by an
`apk_id`, paired with predictable filenames, and ready for follow-on static,
dynamic, or threat-intel analysis.

## Feature highlights

* **Quick start.** `./run.sh` launches the CLI. Use *Device Analysis → 5* to
  capture an inventory, then *Device Analysis → 7* to harvest scoped APKs. When
  inventories are only soft-stale the pull step defaults to the quick-harvest
  path, which resolves APK locations live with `pm path` so you can grab fresh
  artifacts without taking a full filesystem snapshot.
* **Database-first harvesting.** Durable tables, strict filename conventions,
  and scoped pulls replace the JSON/CSV-heavy v1 tooling. Hash-aware dedupe and
  optional DB writes keep collections lean while maintaining provenance.
* **Research-grade static analysis.** A modular detector pipeline surfaces
  manifest hygiene, IPC exposure, provider ACLs, network posture, secrets,
  storage/backup hygiene, WebView hardening, crypto misuse, DFIR hints, and a
  correlation layer that synthesizes P0/P1 risk stories from the detector
  output. Permissions are grouped and scored using a refreshed Android
  permission catalog—no hard-coded lists.
* **Canonical persistence & analytics.** Every run lands in the relational
  schema (`static_analysis_runs`, `static_analysis_findings`, provider ACL
  tables) with severity/category matrices, novelty indicators, workload
  profiles, and reproducibility bundles so analysts can mine cross-run trends
  without parsing JSON artefacts.
* **Differential awareness.** Static-analysis runs persist a pipeline trace,
  split-aware posture snapshot, network security policy graph, lineage-aware
  diff basis, and a reproducibility bundle (manifest + NSC + strings digest).
  The correlation engine prefers prior scans from the same version line and
  highlights detector, SDK, and secret-surface drift automatically.
* **Operator-centric UX.** Hero banners, highlight ribbons, severity-aware
  summary cards, and menu panels mirror across Device and Static analysis so
  investigators can jump between harvesting and review without context
  switching.
* **Permission-first field view.** Abbreviation map (shown once), postcard
  summaries, a Signal Matrix, and a Permission Matrix (`x/*/-`) with a fixed
  capability order and subtle colouring when ANSI is available.
* **Composite risk scoring.** The static risk engine in
  `scytaledroid/StaticAnalysis/risk/` centralises weighting, factor caps, and
  banding so CLI output and downstream consumers share the same numeric score
  and grade model.
* **DB snapshots for trust.** Risk snapshots (per app, per run) are written to
  the database (when configured) for longitudinal analysis and dashboards.
* **Housekeeping shortcuts.** The Utilities menu exposes a static-analysis
  housekeeping action that prunes JSON/HTML exports older than 30 days and
  resets cache/temp directories so local runs stay lean.

### Static analysis preview

- Use the main menu option **Static analysis** to review harvested APKs without
  leaving the CLI. Each run executes the detector pipeline, records per-stage
  timings, and persists a reproducibility bundle with manifest, network
  security, and string-index snapshots.
- Default runs launch immediately using sane defaults (auto workers, INFO log
  level, cache purge). Advanced overrides remain available from the CLI for
  analysts who need to tweak thresholds or detector subsets.
- Section renderers surface deterministic tables for component exposure,
  provider ACLs, secrets, storage risk, crypto posture, DFIR evidence hints,
  and correlation-backed findings. Evidence is capped per section with
  hash-derived pointers so secrets never print to screen. Highlight ribbons
  call out suppressed secrets, NSC-enforced cleartext blocking, and unguarded
  providers the moment a run finishes.
- Analyses are saved as JSON reports under `data/static_analysis/reports/` and
  simultaneously promoted into the canonical database. Diff views highlight
  permission drift, network-security changes, SDK/native deltas, and
  string-cluster shifts with lineage-aware baselines.
- Permission analysis renders a concise, field‑friendly view:
  - Postcards: Risk bar + Score/Grade + High‑signal + Footprint table
  - Risk Summary: Abbr | Score | Grade | D | S | V
  - Signal Matrix: Dangerous/Signature signals per app
  - Permission Matrix: `x/*/-` by app x permission (top 10 in “All apps”; all in narrow scopes)
- You can also analyse a standalone APK outside the repository by choosing the
  "Analyze APK from local path" option and pointing the CLI at the file.

### Harvest configuration highlights

- `HARVEST_DEDUP_SHA256` / `HARVEST_KEEP_LAST` control hash-based dedupe. Keep
  quick re-pulls light by skipping identical artifacts or force the latest copy
  when needed.
- `HARVEST_WRITE_DB` toggles repository writes so test runs can avoid touching
  the database while still producing on-disk artifacts and metadata.
- `HARVEST_META_FIELDS` accepts a comma-delimited list of metadata keys so the
  sidecar `*.meta.json` files stay focused on the attributes your workflow
  expects.

## Documentation map

* [`docs/device_analysis/README.md`](docs/device_analysis/README.md) – current
  harvesting workflow, scope controls, and repository layout.
* [`docs/static_analysis_contract.md`](docs/static_analysis_contract.md) –
  detector contracts, pipeline order, and rendering requirements.
* [`docs/static_analysis/static_analysis_pipeline_plan.md`](docs/static_analysis/static_analysis_pipeline_plan.md) – roadmap,
  implementation status, and research backlog.
* [`docs/maintenance/housekeeping.md`](docs/maintenance/housekeeping.md) – log
  locations, housekeeping behaviour, and retention policy controls.
* [`docs/database`](docs/database) – schema notes and read-side query
  blueprints for downstream portals.
* [`docs/database/permission_analysis_schema.md`](docs/database/permission_analysis_schema.md) – risk
  snapshots and proposed matrix/rationale tables.
* [`docs/static_analysis_analytics.md`](docs/static_analysis_analytics.md) –
  severity/category matrices, workload profiling, and novelty indicators.
* [`docs/static_analysis_improvement_plan.md`](docs/static_analysis_improvement_plan.md) –
  current milestone recap and next tightening steps.
* [`RENAME_GUIDE.md`](RENAME_GUIDE.md) – module naming map and deprecation plan.

For a detailed overview tailored to collaborators, including what is finished,
what we are tightening now, and how others can help, start with the device and
static analysis guides above.

## Configuration (env)

- `FORCE_COLOR` / `NO_COLOR` – colour control in console
- `SCY_PERMISSION_RISK_TOML` – optional path to TOML scoring config. If unset,
  the engine looks for `config/permission_risk.toml` or
  `data/config/permission_risk.toml`.

Example TOML:

```
[base]
dangerous_weight = 0.35
signature_weight = 1.25
vendor_weight    = 0.08

[bonuses]
breadth_step = 0.2
breadth_cap  = 2.0

[normalize]
max_score = 10.0
```
