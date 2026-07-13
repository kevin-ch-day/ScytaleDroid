from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCAN_ROOTS = (
    REPO_ROOT / "scytaledroid" / "Reporting",
    REPO_ROOT / "scripts" / "publication",
)
PUBLICATION_ASSUMPTION_SCAN_ROOTS = (
    REPO_ROOT / "scytaledroid" / "DynamicAnalysis" / "ml",
    REPO_ROOT / "scytaledroid" / "Publication",
    REPO_ROOT / "scytaledroid" / "Reporting",
    REPO_ROOT / "scripts" / "publication",
)
RETIRED_TOKENS = (
    "publication_exports_service",
    "publication_scientific_qa_service",
    "publication_results_numbers_service",
    "publication_results_v1.json",
    "expected 36",
    "len(included_run_ids) != 36",
)
RETIRED_COHORT_ASSUMPTIONS = (
    "frozen 12-app dataset",
    "exact 4/4/4",
    "n=12",
    "cohort_expected_n_packages_v2:12",
    "cohort_expected_n_apps_v2:12",
)
ALLOWLIST = {
    Path("scytaledroid/Reporting/services/paper2_results_v2_service.py"),
}


def _source_files() -> list[Path]:
    files: list[Path] = []
    for root in SCAN_ROOTS:
        if not root.exists():
            continue
        files.extend(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)
    return sorted(files)


def _source_files_under(roots: tuple[Path, ...]) -> list[Path]:
    files: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        files.extend(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)
    return sorted(files)


def test_paper2_v1_publication_generation_path_is_retired() -> None:
    violations: list[str] = []
    for path in _source_files():
        rel = path.relative_to(REPO_ROOT)
        if rel in ALLOWLIST:
            continue
        text = path.read_text(encoding="utf-8")
        for token in RETIRED_TOKENS:
            if token in text:
                violations.append(f"{rel}: {token}")

    assert not violations, "Retired Paper 2 v1 publication path is still active:\n" + "\n".join(violations)


def test_paper2_publication_paths_do_not_reintroduce_fixed_12_app_assumptions() -> None:
    violations: list[str] = []
    for path in _source_files_under(PUBLICATION_ASSUMPTION_SCAN_ROOTS):
        rel = path.relative_to(REPO_ROOT)
        text = path.read_text(encoding="utf-8")
        for token in RETIRED_COHORT_ASSUMPTIONS:
            if token in text:
                violations.append(f"{rel}: {token}")

    assert not violations, "Fixed 12-app Paper 2 publication assumption is still active:\n" + "\n".join(violations)
