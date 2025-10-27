# CLI Persistence Layout

The CLI persistence pipeline now lives under `scytaledroid/StaticAnalysis/cli/persistence/`.

- `run_summary.py`: orchestrates the overall run persistence (`persist_run_summary`). It coordinates detector findings, metrics, static baselines, permission risk, and storage surface persistence.
- `permission_risk.py`: writes the `static_permission_risk` snapshot using the metrics bundle. It supports metadata/baseline hash fallbacks and adds metrics entries.
- `static_sections.py`: handles baseline (`static_findings*`) and string summary persistence plus storage surface module execution.
- `utils.py`: shared helpers (`truncate`, `first_text`, `safe_int`, severity normalization).
- Existing writers (`findings_writer.py`, `metrics_writer.py`, `static_findings_writer.py`, `strings_writer.py`) continue to focus on their specific tables.

`scytaledroid/StaticAnalysis/cli/db_persist.py` now simply re-exports `persist_run_summary` and `PersistenceOutcome` for backward compatibility.

Integration tests cover the pipeline end-to-end (`tests/integration/test_persist_run_summary.py`), and new unit tests under `tests/persistence/` target helper modules.
