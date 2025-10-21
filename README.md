# ScytaleDroid

[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CLI](https://img.shields.io/badge/interface-menu--driven-orange.svg)](./run.sh)

ScytaleDroid is a menu-driven toolkit for harvesting, cataloging, and analyzing Android
application packages (APKs) from real devices. The project emphasizes a
"database-first" design so every artifact is traced by an `apk_id`, paired with
predictable filenames, and ready for follow-on static, dynamic, or threat-intel
analysis.

- [Feature highlights](#feature-highlights)
- [Quick start](#quick-start)
  - [Prerequisites](#prerequisites)
  - [Environment setup](#environment-setup)
  - [Verify connectivity](#verify-connectivity)
- [Usage](#usage)
  - [Launch the menu](#launch-the-menu)
  - [Harvest devices](#harvest-devices)
  - [Run static analysis](#run-static-analysis)
  - [Work with standalone APKs](#work-with-standalone-apks)
- [Project layout & docs](#project-layout--docs)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)

## Feature highlights

- **Quick start.** `./run.sh` launches the CLI. Use _Device Analysis → 5_ to
  capture an inventory, then _Device Analysis → 7_ to harvest scoped APKs. When
  inventories are only soft-stale the pull step defaults to the quick-harvest
  path, which resolves APK locations live with `pm path` so you can grab fresh
  artifacts without taking a full filesystem snapshot.
- **Database-first harvesting.** Durable tables, strict filename conventions,
  and scoped pulls replace the JSON/CSV-heavy v1 tooling. Hash-aware dedupe and
  optional DB writes keep collections lean while maintaining provenance.
- **Research-grade static analysis.** A modular detector pipeline surfaces
  manifest hygiene, IPC exposure, provider ACLs, network posture, secrets,
  storage/backup hygiene, WebView hardening, crypto misuse, DFIR hints, and a
  correlation layer that synthesizes P0/P1 risk stories from the detector
  output. Permissions are grouped and scored using a refreshed Android
  permission catalog—no hard-coded lists.
- **Canonical persistence & analytics.** Every run lands in the relational
  schema (`static_analysis_runs`, `static_analysis_findings`, provider ACL
  tables) with severity/category matrices, novelty indicators, workload
  profiles, and reproducibility bundles so analysts can mine cross-run trends
  without parsing JSON artefacts.
- **Differential awareness.** Static-analysis runs persist a pipeline trace,
  split-aware posture snapshot, network security policy graph, lineage-aware
  diff basis, and a reproducibility bundle (manifest + NSC + strings digest).
  The correlation engine prefers prior scans from the same version line and
  highlights detector, SDK, and secret-surface drift automatically.
- **Operator-centric UX.** Hero banners, highlight ribbons, severity-aware
  summary cards, and menu panels mirror across Device and Static analysis so
  investigators can jump between harvesting and review without context
  switching.
- **Permission-first field view.** Abbreviation map (shown once), postcard
  summaries, a Signal Matrix, and a Permission Matrix (`x/*/-`) with a fixed
  capability order and subtle colouring when ANSI is available.
- **Composite risk scoring.** The static risk engine in
  `scytaledroid/StaticAnalysis/risk/` centralises weighting, factor caps, and
  banding so CLI output and downstream consumers share the same numeric score
  and grade model.
- **DB snapshots for trust.** Risk snapshots (per app, per run) are written to
  the database (when configured) for longitudinal analysis and dashboards.
- **Housekeeping shortcuts.** The Utilities menu exposes a static-analysis
  housekeeping action that prunes JSON/HTML exports older than 30 days and
  resets cache/temp directories so local runs stay lean.

## Quick start

### Prerequisites

ScytaleDroid targets modern Linux hosts. Before running the toolkit make sure you have:

- **Python 3.11 or newer.** The project is linted and typed against Python 3.13; a 3.11+
  interpreter is required for the CLI and utilities.
- **ADB** with access to the devices you plan to inventory. Confirm `adb devices`
  returns the hardware you want to target.
- **SQLite 3.35+** (ships with modern distros) for the local persistence layer. If you
  point the CLI at a remote database, provision credentials with read/write access.
- **Virtual environment (recommended).** Use `python -m venv .venv && source .venv/bin/activate`
  to keep dependencies isolated.

### Environment setup

1. Clone the repository and enter it:
   ```bash
   git clone https://github.com/<your-org>/ScytaleDroid.git
   cd ScytaleDroid
   ```
2. Install dependencies using the helper script:
   ```bash
   ./setup.sh
   ```
   The script validates Python availability, upgrades `pip`, and installs the packages
   declared in `requirements.txt`.
3. (Optional) Install developer tooling:
   ```bash
   python -m pip install --upgrade ruff pytest
   ```
   The repository includes Ruff and Pytest configuration so the commands above
   align with our linting and test expectations.

### Verify connectivity

ScytaleDroid talks to devices and (optionally) a backing database. Useful smoke checks:

```bash
adb devices              # Ensure your device is listed and authorized
python -m scytaledroid --help  # Confirm the package imports cleanly
```

If you are targeting a remote database, export the DSN variables your environment requires
before launching the CLI.

## Usage

### Launch the menu

The CLI wraps common collection and analysis workflows behind a curses-style menu. The
fastest way to explore it is:

```bash
./run.sh
```

Passing `--help` reveals every sub-command:

```bash
./run.sh --help
```

### Harvest devices

1. Connect one or more Android devices with USB debugging enabled.
2. Launch the CLI and choose **Device analysis** → **5. Capture inventory** to snapshot
   the installed packages.
3. Choose **Device analysis** → **7. Harvest scoped APKs** to download the APKs for the
   scope you defined. When inventories are only soft-stale, the quick-harvest path uses
   `pm path` for fresh pulls without full filesystem snapshots.
4. Review harvested artifacts under `data/device_analysis/` or in the configured database
   tables.

### Run static analysis

Static analysis pipelines run directly from the menu or via the module entry point:

```bash
./run.sh static --profile full --scope QA --session "$(date +%Y%m%d-%H%M%S)"
```

During a run the CLI prints severity-aware progress and highlight ribbons for items like
suppressed secrets, NSC enforcement, and unguarded providers. Results are persisted to the
canonical tables and exported under `data/static_analysis/reports/`.

To simulate a run without touching the database use a dry-run:

```bash
python -m scytaledroid.StaticAnalysis.cli.run --profile full --dry-run
```

### Work with standalone APKs

The **Analyze APK from local path** option lets you point the CLI at an individual APK file.
This is useful for regression testing or reviewing artifacts harvested outside ScytaleDroid.

## Project layout & docs

ScytaleDroid keeps detailed operator documentation under `docs/`:

- [`docs/device_analysis/README.md`](docs/device_analysis/README.md) – current
  harvesting workflow, scope controls, and repository layout.
- [`docs/static_analysis_contract.md`](docs/static_analysis_contract.md) –
  detector contracts, pipeline order, and rendering requirements.
- [`docs/static_analysis/static_analysis_pipeline_plan.md`](docs/static_analysis/static_analysis_pipeline_plan.md) – roadmap,
  implementation status, and research backlog.
- [`docs/maintenance/housekeeping.md`](docs/maintenance/housekeeping.md) – log
  locations, housekeeping behaviour, and retention policy controls.
- [`docs/database`](docs/database) – schema notes and read-side query
  blueprints for downstream portals.
- [`docs/database/permission_analysis_schema.md`](docs/database/permission_analysis_schema.md) – risk
  snapshots and proposed matrix/rationale tables.
- [`docs/static_analysis_analytics.md`](docs/static_analysis_analytics.md) –
  severity/category matrices, workload profiling, and novelty indicators.
- [`docs/static_analysis_improvement_plan.md`](docs/static_analysis_improvement_plan.md) –
  current milestone recap and next tightening steps.
- [`docs/runbook.md`](docs/runbook.md) – step-by-step static analysis and persistence runbook.
- [`RENAME_GUIDE.md`](RENAME_GUIDE.md) – module naming map and deprecation plan.

## Configuration

Environment variables control CLI behaviour:

- `FORCE_COLOR` / `NO_COLOR` – colour control in console.
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

Additional configuration for persistence, database promotion, and analytics can be found in
[`docs/runbook.md`](docs/runbook.md).

## Contributing

We welcome bug reports, feature requests, and pull requests. Please review the
[contribution guidelines](CONTRIBUTING.md) for details on our development workflow, coding
style, and testing expectations. Adherence to the [Code of Conduct](CODE_OF_CONDUCT.md) is
required for all community interactions.

To run the test suite locally:

```bash
pytest
```

Linting is handled by Ruff:

```bash
ruff check .
ruff format --check .
```

## License

ScytaleDroid is distributed under the terms of the [MIT License](LICENSE).
