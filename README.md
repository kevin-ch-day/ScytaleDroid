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
  output. Permissions are grouped and scored using the Androguard
  protection-level metadata—no hard-coded lists.
* **Differential awareness.** Static-analysis runs persist a pipeline trace,
  split-aware posture snapshot, network security policy graph, and a
  reproducibility bundle (manifest + NSC + strings digest). The correlation
  engine compares current results with prior runs to highlight drift.
* **Operator-centric UX.** Status banners, deterministic wording, and CLI menu
  summaries mirror across Device and Static analysis so investigators can jump
  between harvesting and review without context switching.

### Static analysis preview

- Use the main menu option **Static analysis** to review harvested APKs without
  leaving the CLI. Each run executes the detector pipeline, records per-stage
  timings, and persists a reproducibility bundle with manifest, network
  security, and string-index snapshots.
- Section renderers surface deterministic tables for component exposure,
  provider ACLs, secrets, storage risk, crypto posture, DFIR evidence hints,
  and correlation-backed findings. Evidence is capped per section with
  hash-derived pointers so secrets never print to screen.
- Analyses are saved as JSON reports under `data/static_analysis/reports/` so
  investigators can re-open previous runs from the menu or ingest them into
  downstream tooling. Diff views highlight permission drift, cleartext policy
  changes, and split-aware risk composition.
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
* [`docs/database`](docs/database) – schema notes and read-side query
  blueprints for downstream portals.

For a detailed overview tailored to collaborators, including what is finished,
what we are tightening now, and how others can help, start with the device and
static analysis guides above.
