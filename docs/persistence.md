# CLI Persistence Layout

The CLI persistence pipeline lives under `scytaledroid/StaticAnalysis/cli/persistence/`.

- **`run_summary.py`** — Orchestrates overall run persistence (`persist_run_summary`, `PersistenceOutcome`). Coordinates findings, metrics, baselines, permission matrix/risk, storage surface, handoff, and transaction retries.
- **`stage_writers.py`** — Wires MASVS, storage surface, **`persist_permission_matrix`**, and **`persist_permission_risk`** using report `detector_metrics.permissions_profile`.
- **`transaction_flow.py`** — Single DB transaction around staged writers; failure stage names feed run-health / audit.
- **`permission_matrix.py` / `permission_risk.py`** — Canonical `static_permission_matrix` and `static_permission_risk_vnext` writers (shared dedupe rule).
- **`static_sections.py`** — Baseline (`static_findings*`) and string summary persistence.
- **`utils.py`** — Shared helpers (`truncate`, `first_text`, `safe_int`, severity normalization).
- Other modules in this package: `findings_writer.py`, `metrics_writer.py`, `static_findings_writer.py`, `strings_writer.py`, etc. **Names are historical:** e.g. `findings_writer.py` covers MASVS/control coverage and related surfaces; it does **not** mean writes to the legacy base table `findings`. Canonical SAR rows go to `static_analysis_findings` via the orchestrated pipeline above.

**Canonical imports (no separate re-export module):** application code should import from  
`scytaledroid.StaticAnalysis.cli.persistence.run_summary` (e.g. `persist_run_summary`, `PersistenceOutcome`).  
`scytaledroid.StaticAnalysis.cli.execution.results` already uses that path.

**Related but separate:** `scytaledroid/StaticAnalysis/persistence/` holds report file I/O (`save_report`, `load_report`, …) and **`ingest`** helpers used by the CLI — not the DB transaction pipeline above.

## Risk surfaces (policy wording)

- **`static_permission_matrix`** — canonical **permission facts** for the run (evidence-oriented rows).
- **`static_permission_risk_vnext`** — canonical **run-scoped permission risk detail** (deduped keys, coarse risk class).
- **`risk_scores`** — persisted **operator/session rollup** on the analyst core DB (`session_stamp`, package, grades); **not** the same contract as `schema_gate.static_schema_gate()`. A completed static run may exist without rollup rows if scoring stages were skipped or non-fatal.
- **`metrics`**, **`buckets`**, **`contributors`** (and legacy **`findings`**) — **legacy mirror / reconcile** surfaces; optional counts for diagnostics. **No** normal runtime `INSERT` from current Python static persistence into the legacy-five family.

Integration tests: `tests/integration/test_persist_run_summary.py` (opt-in DB). Unit tests: `tests/persistence/`.

## Running persistence tests locally

The persistence integration tests (`tests/integration/`) require a MariaDB/MySQL instance. These tests are **opt-in** and will be skipped unless you explicitly set `SCYTALEDROID_TEST_DB_URL` (recommended) or `SCYTALEDROID_DB_URL` to a working DSN in your environment.

For smoke runs without a database, just run `pytest`; the DB integration suite will self-skip when not configured.
