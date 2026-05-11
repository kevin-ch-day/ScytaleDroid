# CLI Persistence Layout

The CLI persistence pipeline lives under `scytaledroid/StaticAnalysis/cli/persistence/`.

- **`run_summary.py`** — Orchestrates overall run persistence (`persist_run_summary`, `PersistenceOutcome`). Coordinates findings, metrics, baselines, permission matrix/risk, storage surface, handoff, and transaction retries.
- **`stage_writers.py`** — Wires MASVS, storage surface, **`persist_permission_matrix`**, and **`persist_permission_risk`** using report `detector_metrics.permissions_profile`.
- **`transaction_flow.py`** — Single DB transaction around staged writers; failure stage names feed run-health / audit.
- **`permission_matrix.py` / `permission_risk.py`** — Canonical `static_permission_matrix` and `static_permission_risk_vnext` writers (shared dedupe rule).
- **`static_sections.py`** — Baseline (`static_findings*`) and string summary persistence.
- **`utils.py`** — Shared helpers (`truncate`, `first_text`, `safe_int`, severity normalization).
- Other writers: `findings_writer.py`, `metrics_writer.py`, `static_findings_writer.py`, `strings_writer.py`, etc.

**Canonical imports (no separate re-export module):** application code should import from  
`scytaledroid.StaticAnalysis.cli.persistence.run_summary` (e.g. `persist_run_summary`, `PersistenceOutcome`).  
`scytaledroid.StaticAnalysis.cli.execution.results` already uses that path.

**Related but separate:** `scytaledroid/StaticAnalysis/persistence/` holds report file I/O (`save_report`, `load_report`, …) and **`ingest`** helpers used by the CLI — not the DB transaction pipeline above.

Integration tests: `tests/integration/test_persist_run_summary.py` (opt-in DB). Unit tests: `tests/persistence/`.

## Running persistence tests locally

The persistence integration tests (`tests/integration/`) require a MariaDB/MySQL instance. These tests are **opt-in** and will be skipped unless you explicitly set `SCYTALEDROID_TEST_DB_URL` (recommended) or `SCYTALEDROID_DB_URL` to a working DSN in your environment.

For smoke runs without a database, just run `pytest`; the DB integration suite will self-skip when not configured.
