# Supported Entry Points

This project has both supported operator interfaces and internal helper scripts.
Only the entry points listed as **Supported (stable)** are considered part of the
public interface and are expected to remain compatible across minor releases.

## Supported (stable)

### TUI (primary)

- `./run.sh` (launches the interactive menus)

### Blessed batch entry points (repo-run)

These are intended for reproducible artifact generation and automation:

- `scripts/publication/publication_exports.py`
- `scripts/publication/publication_results_numbers.py`
- `scripts/publication/publication_scientific_qa.py`
- `scripts/publication/publication_pipeline_audit.py`
- `scripts/publication/publication_ml_audit_report.py`
- `scripts/publication/ingest_publication_bundle.py` (optional; DB mirror ingest)
- `scripts/publication/profile_v3_exports.py`

## Not supported (best-effort)

- Anything under `scripts/` that is not listed above.
- Developer-only or exploratory utilities under `scripts/experimental/`.
