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

- **Python 3.11, 3.12, or 3.13.** The pinned dependency locks and CI coverage target this
  range. Python 3.13 is recommended for a new deployment.
- **ADB** with access to the devices you plan to inventory. Confirm `adb devices`
  returns the hardware you want to target.
- (Optional) **MariaDB/MySQL** if you want DB-backed persistence and cross-run analytics.
  The tool runs end-to-end without a DB; when enabled, DB writes are strict and require
  a compatible MySQL/MariaDB backend.
- **Virtual environment.** `./setup.sh` creates and uses `.venv` automatically so project
  dependencies cannot conflict with unrelated system packages.

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
   The script selects Python 3.11-3.13, creates `.venv`, installs the pinned runtime lock without
   upgrading packaging tools by default, prepares workspace directories, and reports missing Fedora
   runtime tools.
3. Create your local configuration without copying any existing secrets:
   ```bash
   cp .env.example .env
   ```
   Configure the database credentials, restore data if this is a migration, then run:
   ```bash
   ./run.sh --new-system-check --require-database
   ```
4. (Optional) Install developer tooling:
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
./run.sh --new-system-check --require-database  # Validate a provisioned host
./run.sh                 # Launch the operator console
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

#### API security and uploads

The JSON API fails closed by default through both supported runtime startup and
direct ASGI app construction. Set a unique `SCYTALEDROID_API_KEY` in your local
`.env`; empty values and the documented placeholder value `change-me` are
rejected. Clients may authenticate with either `Authorization: Bearer <key>` or
`X-API-Key: <key>`.

Unauthenticated API mode is only for local development and tests:

```bash
SCYTALEDROID_API_AUTH_DISABLED=1 SCYTALEDROID_ENV=test
```

That bypass is rejected unless the API binds to a loopback host. Do not use it
for shared workstations or network-accessible API services.

The `/upload` endpoint accepts only a single `.apk` filename. Uploaded bytes are
streamed into the upload inbox first, validated as a ZIP-compatible APK with
`AndroidManifest.xml`, and parsed for APK metadata before promotion to the
canonical APK store. Rejected uploads return a stable `reason_code` and do not
create normal canonical APK artifacts, sidecars, or upload receipts.

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

Baseline and determinism contracts (closest authority to the baseline audit scripts above):

- `docs/contracts/determinism_comparator.md` — strict analytical diff / comparator contract used with `determinism_gate.py`
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

We welcome bug reports, feature requests, and pull requests. Please review
[`AGENTS.md`](AGENTS.md) for repo-specific development workflow, coding style,
testing expectations, and high-risk areas. Security-sensitive reports should
follow [`SECURITY.md`](SECURITY.md).

To run the test suite locally:

```bash
pytest
```

The default test suite is hermetic and does not require the separate Web
repository. To opt into the external Web smoke contract, set both:

```bash
SCYTALEDROID_WEB_ROOT=/path/to/ScytaleDroid-Web \
SCYTALEDROID_RUN_WEB_INTEGRATION=1 \
python -m pytest tests/database/test_web_db_scripts.py -q
```

GitHub Actions enforces the currently clean developer-signal checks:

```bash
python -m compileall -q scytaledroid scripts main.py
python -m pytest tests/gates -q
python -m pytest -q
```

Linting is handled by Ruff:

```bash
ruff check .
ruff format --check .
```

## License

ScytaleDroid is distributed under the terms of the [MIT License](LICENSE).

## Dependency locks, Python support, and optional services

### Supported Python policy

ScytaleDroid supports Python 3.11, 3.12, and 3.13. The minimum supported runtime and syntax target is Python 3.11; tooling may run on newer interpreters, but project changes must not introduce Python 3.12/3.13-only syntax unless the support policy is deliberately revised.

### Reproducible dependency installation

Runtime dependencies are maintained in `requirements.in` and pinned in `requirements.lock`. Development and test dependencies are maintained in `requirements-dev.in` and pinned in `requirements-dev.lock`. `requirements.txt` remains a compatibility entry point for existing `pip install -r requirements.txt` users and delegates to the runtime lock.

Recommended installs:

```bash
python -m pip install -r requirements.lock
python -m pip install -r requirements-dev.lock
```

Regenerate locks only when dependency inputs intentionally change:

```bash
python -m pip install pip-tools
python -m piptools compile --resolver=backtracking --upgrade --max-rounds 30 -o requirements.lock requirements.in
python -m piptools compile --resolver=backtracking --upgrade --max-rounds 30 -o requirements-dev.lock requirements-dev.in
```

`setup.sh` installs from the pinned runtime lock by default and no longer upgrades `pip`, `setuptools`, or `wheel` unless explicitly requested with `SCYTALEDROID_SETUP_UPGRADE_TOOLING=1 ./setup.sh`.

### Bounded typing check

The repository is not yet type-clean end to end. The repeatable typing entry point for the currently maintained clean scope is:

```bash
python -m mypy --config-file mypy-bounded.ini scytaledroid/Database/db_core/optional.py scytaledroid/DynamicAnalysis/pcap/enrichment_outcome.py
```

Broader package discovery was inspected with both `python -m mypy -p scytaledroid` and `python -m mypy scytaledroid --namespace-packages --explicit-package-bases`; both expose pre-existing repository-wide typing debt, especially under DeviceAnalysis and StaticAnalysis. Those areas remain deferred rather than hidden behind a broad ignore-all gate.

### Database-disabled behavior

The operational database is optional for filesystem-only workflows. `db_enabled()` remains the configuration source of truth. New optional access helpers in `scytaledroid.Database.db_core.optional` make this boundary explicit:

- `maybe_get_database()` returns `None` only when the database is deliberately disabled.
- `require_database()` raises `DatabaseUnavailableError` for DB-required workflows when persistence is disabled or unavailable.
- Configured connection failures are classified separately from disabled configuration and are not silently converted into filesystem-only operation.

Filesystem-only API construction, APK upload validation/canonical artifact handling, static artifact file operations, dynamic evidence/PCAP feature inspection, and script help/dry informational commands are expected to remain usable without a live MariaDB service. Canonical persistence, DB posture checks, schema tools, and DB-backed read models still require an enabled and reachable database.

### PCAP enrichment outcomes

PCAP enrichment now records explicit structured states instead of collapsing failures into ambiguous empty output:

| Status | Meaning | Usable output |
| --- | --- | --- |
| `completed` | Packet metadata enrichment completed with observations. | Yes |
| `completed_no_observations` | Enrichment ran successfully but observed no packet-level data. | Yes, explicitly empty |
| `skipped_tool_unavailable` | Required packet tool such as `tshark` was unavailable. | No |
| `skipped_not_applicable` | The run did not include an applicable PCAP path/file. | No |
| `failed_input_invalid` | The source PCAP report was already invalid. | No |
| `failed_tool_execution` | The external tool failed to run successfully. | No |
| `failed_parser` | Tool output could not be parsed into the expected structure. | No |
| `failed_internal` | Internal enrichment application failed. | No |

Each outcome includes a stable `reason_code`, operator-facing `message`, `usable` flag, observation count, safe source reference, and legacy status mapping for older consumers.

### CI coverage

CI installs pinned development dependencies from `requirements-dev.lock`. Python 3.11 runs source compilation, gate tests, the bounded mypy check, and the full pytest suite. Python 3.12 and 3.13 run source compilation, gate tests, and a fast compatibility slice (`tests/api`, the Web DB script gate, and PCAP feature tests). CI intentionally does not require MariaDB, Android devices, `tshark`, the separate Web checkout, or a production `.env`.
