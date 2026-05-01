# ScytaleDroid

[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CLI](https://img.shields.io/badge/interface-menu--driven-orange.svg)](./run.sh)

ScytaleDroid is a menu-driven toolkit for inventorying Android devices,
harvesting APKs, and running static and dynamic analysis with research-grade
provenance. Static analysis persists into a canonical database schema for
cross-run analytics and reporting. Dynamic analysis is evidence-pack-first:
evidence packs are authoritative and the DB is a rebuildable derived index for
querying and reporting.

Publication bundle exports are optional and isolated from core workflows. The
primary operator experience is the menu-driven CLI launched via `./run.sh`.

Dynamic analysis runs are executed on physical devices (non-root telemetry),
structured as dynamic sessions, and designed to support time-series anomaly
detection pipelines (Isolation Forest / One-Class SVM) with reproducible
baseline linkage.

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
- [DB integration helpers](#db-integration-helpers)
- [Project layout & docs](#project-layout--docs)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)

## Feature highlights

- **Scope-first operator flow.** `./run.sh` launches the CLI. The intended flow
  is inventory → harvest → static analysis by scope → dynamic capture/reporting.
  Static analysis is now centered on operator scopes such as “all harvested
  apps”, “by profile/category”, and “one app”, rather than raw library groups.
- **Database-backed harvesting.** Durable tables, strict filename conventions,
  and scoped pulls replace the JSON/CSV-heavy v1 tooling. Hash-aware dedupe and
  optional DB writes keep collections lean while maintaining provenance. For
  dynamic collection, evidence packs remain authoritative and the DB is a
  derived index.
- **Research-grade static analysis.** A modular detector pipeline surfaces
  manifest hygiene, IPC exposure, provider ACLs, network posture, secrets,
  storage/backup hygiene, WebView hardening, crypto misuse, DFIR hints, and a
  correlation layer that synthesizes P0/P1 risk stories from the detector
  output. Permissions are grouped and scored using governance snapshots plus
  catalog metadata (no hard-coded lists).
- **Canonical persistence & analytics.** Every static run lands in canonical
  tables such as `static_analysis_runs`, `static_analysis_findings`,
  `static_permission_matrix`, `static_permission_risk_vnext`,
  `static_fileproviders`, and `static_provider_acl`, with supporting views for
  cross-run analytics and Web reporting.
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
- **Risk and finding read models.** Permission run scores, permission audit
  scores, and canonical finding totals are now surfaced through explicit DB
  views so downstream readers do not have to guess which legacy table is
  authoritative.

## Quick start

### Prerequisites

ScytaleDroid targets modern Linux hosts. Before running the toolkit make sure you have:

- **Python 3.11 or newer.** The project is linted and typed against Python 3.13; a 3.11+
  interpreter is required for the CLI and utilities.
- **ADB** with access to the devices you plan to inventory. Confirm `adb devices`
  returns the hardware you want to target.
- (Optional) **MariaDB/MySQL** if you want DB-backed persistence and cross-run analytics.
  The tool runs end-to-end without a DB; when enabled, DB writes are strict and require
  a compatible MySQL/MariaDB backend.
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

ScytaleDroid talks to devices and, optionally, a backing MariaDB/MySQL database.
Useful smoke checks:

```bash
adb devices              # Authorized device(s) listed as 'device'
./run.sh                 # Launch CLI (--deploy-check for host/ADB/DB probe)
```

If you are targeting a database, export the DSN variables your environment
requires before launching the CLI.

## Usage

### Launch the menu

The primary supported interface is the menu-driven CLI:

```bash
./run.sh
```

The API server is not auto-started on CLI launch. Start or stop it explicitly
from `Main Menu → API server`.

### Harvest devices

1. Connect one or more Android devices with USB debugging enabled.
2. Launch the CLI and capture inventory from **Device analysis**.
3. Harvest APKs from **Device analysis** using the scoped harvest path.
4. Review harvested artifacts in the configured storage roots and database
   tables. `android_apk_repository` is the cumulative harvested artifact
   catalog; `apps` is canonical package identity.

### Run static analysis

After inventory and harvest are complete, use the **Static Analysis** menu and
choose a scope:

- `Analyze all harvested apps`
- `Analyze by profile/category`
- `Analyze one app`
- `Re-analyze last app`
- `Compare two app versions`

Completed runs persist canonical rows to `static_analysis_runs` and
`static_analysis_findings`, then refresh the summary/reporting surfaces that the
CLI and Web app consume.

### Baseline Audit Commands

Determinism hard gate (same APK scanned twice, strict analytical diff):

```bash
python scripts/static_analysis/determinism_gate.py --db-target "mysql://user:pass@localhost:3306/scytaledroid_db_dev" --apk /path/to/app.apk --profile full --output output/audit/determinism/result.json
```

Corpus tables (from canonical DB snapshot boundary):

```bash
python scripts/static_analysis/static_baseline_tables.py --db-target "mysql://user:pass@localhost:3306/scytaledroid_db_dev" --out-dir output/audit/static_baseline --formats csv json
```

Baseline contracts:

- `docs/static_baseline_contract.md`
- `docs/risk_scoring_contract.md`

### Work with standalone APKs

The CLI still supports standalone APK analysis for local review and regression
testing, but the core operator model is harvest-first so provenance, version
identity, and run linkage stay intact.

## DB integration helpers

- Database connection and schema checks are menu-driven from **Database tools**.
- Baseline static audit scripts accept explicit DB targets (`--db-target`) for reproducible checks.
- Inventory determinism comparator is available from **Database tools**
  (`Inventory determinism comparator (strict)`) and writes JSON artifacts under
  `output/audit/comparators/inventory_guard/`.

## Project layout & docs

The active docs set is intentionally smaller now. These are the main sources of
truth:

- [`docs/runbook.md`](docs/runbook.md)
  - operator flow, persistence checks, troubleshooting
- [`docs/maintenance/workflow_entrypoint_map.md`](docs/maintenance/workflow_entrypoint_map.md)
  - CLI workflow routing for inventory, harvest, static selection, and persistence
- [`docs/static_analysis_contract.md`](docs/static_analysis_contract.md)
  - detector/rendering contract and execution invariants
- [`docs/static_analysis/static_analysis_data_model.md`](docs/static_analysis/static_analysis_data_model.md)
  - canonical static tables, finding surfaces, and analytics payloads
- [`docs/dynamic_analysis_contract.md`](docs/dynamic_analysis_contract.md)
  - dynamic/evidence-pack contract
- [`docs/database/contract_audit_v1_3.md`](docs/database/contract_audit_v1_3.md)
  - current DB ownership and boundary decisions
- [`docs/supported_entrypoints.md`](docs/supported_entrypoints.md)
  - supported public interface boundary

Useful supporting references:

- [`docs/device_analysis/README.md`](docs/device_analysis/README.md)
- [`docs/database/queries/README.md`](docs/database/queries/README.md)
- [`docs/maintenance/housekeeping.md`](docs/maintenance/housekeeping.md)

Historical planning notes have been trimmed aggressively; new work should
follow the smaller contract set above.

## Configuration

Environment variables control CLI behaviour:

- `FORCE_COLOR` / `NO_COLOR` – colour control in console.
- `SCY_PERMISSION_RISK_TOML` – optional path to TOML scoring config. If unset,
  the engine looks for `config/permission_risk.toml` or
  `data/config/permission_risk.toml`.
- `SCYTALEDROID_DB_URL` – set to a MariaDB DSN when using the shared backend (e.g.,
  `mysql://user:pass@localhost:3306/scytaledroid_db_dev`); place it in `.env`
  for convenience and run via `./run_mariadb.sh`.
- `SCYTALEDROID_PERMISSION_INTEL_DB_URL` (or the prefixed
  `SCYTALEDROID_PERMISSION_INTEL_DB_*` variables) – optional separate
  permission-intel database target. If unset, ScytaleDroid stays in
  compatibility mode and reads permission reference data from the main DB.

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

## Supported interfaces

The supported public interface is intentionally small. See:

- [`docs/supported_entrypoints.md`](docs/supported_entrypoints.md)

Deprecation/versioning policy currently follows the supported entrypoints and
contract docs above rather than a separate standalone note.

## Contributing

We welcome bug reports, feature requests, and pull requests. Please review the
[contribution guidelines](docs/CONTRIBUTING.md) for details on our development workflow, coding
style, and testing expectations. Adherence to the [Code of Conduct](docs/CODE_OF_CONDUCT.md) is
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
