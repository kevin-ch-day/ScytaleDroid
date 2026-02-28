from __future__ import annotations

from pathlib import Path


def _iter_text_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        if p.suffix.lower() not in {".md", ".py", ".sh", ".txt", ".json"}:
            continue
        out.append(p)
    return out


def test_no_paper_terms_leakage_in_docs_and_scripts_outside_allowlist() -> None:
    """Gate to prevent new paper-era naming leakage in OSS-facing surfaces.

    This is intentionally scoped to docs/scripts/README for PR2. PR3 expands
    this to core library code once user-facing wording is cleaned.
    """

    allow_prefixes = (
        Path("docs/legacy/"),
        Path("docs/paper2/"),  # stubs (planned removal v4.0)
    )
    allow_exact = {
        Path("docs/contracts/paper2_capture_policy_v1.md"),  # stub (planned removal v4.0)
        # Temporary exceptions: these scripts still write legacy output paths and
        # will be cleaned as part of the experimental output rename milestone.
        Path("scripts/analysis/risk_scoring_artifacts.py"),
        Path("scripts/experimental/ml_diagnostics.py"),
        # Temporary allowlist (v2.x): existing OSS-facing text that still contains
        # paper2 wording. PR3 shrinks this set as wording is cleaned.
        Path("README.md"),
        Path("docs/architecture_module_map.md"),
        Path("docs/contracts/export_manifest_contract.md"),
        Path("docs/deviceanalysis-architecture.md"),
        Path("docs/engineering_invariants.md"),
        Path("docs/maintenance/housekeeping.md"),
        Path("docs/phase_f1_touchpoint_map.md"),
        Path("docs/project_status_phase_2c.md"),
        Path("docs/refactor_execution_tracker.md"),
        Path("docs/runbook.md"),
        Path("docs/sprint_0_2_acceptance.md"),
        Path("docs/supported_entrypoints.md"),
        Path("scripts/dynamic/evidence_hunt.py"),
        Path("scripts/publication/export_manifest_gate.py"),
        Path("scripts/publication/ingest_publication_bundle.py"),
        Path("scripts/publication/publication_exports.py"),
        Path("scripts/publication/publication_ml_audit_report.py"),
        Path("scripts/publication/publication_pipeline_audit.py"),
        Path("scripts/publication/publication_results_numbers.py"),
        Path("scripts/publication/publication_scientific_qa.py"),
    }

    roots = [Path("README.md"), Path("docs"), Path("scripts")]
    violations: list[str] = []
    for root in roots:
        files = [root] if root.is_file() else _iter_text_files(root)
        for path in files:
            rel = path
            if rel in allow_exact or any(str(rel).startswith(str(prefix)) for prefix in allow_prefixes):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            lowered = text.lower()
            if "paper1" in lowered or "paper2" in lowered:
                violations.append(str(rel))

    assert not violations, "paper-era naming leakage found outside allowlist: " + ", ".join(sorted(violations))
