from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.ml import artifact_bundle_writer
from scytaledroid.Publication import publication_contract


def test_rank_tertiles_uses_current_cohort_size_for_15_apps() -> None:
    values = {f"pkg{i:02d}": float(i) for i in range(15)}

    grades, missing = artifact_bundle_writer._rank_tertiles(values, ascending=True)

    assert missing == []
    assert list(grades.values()).count("Low") == 5
    assert list(grades.values()).count("Medium") == 5
    assert list(grades.values()).count("High") == 5


def test_publication_cohort_enforcement_accepts_15_app_freeze_when_results_match(tmp_path: Path) -> None:
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    packages = [f"com.example.app{i:02d}" for i in range(15)]
    (manifests / "dataset_freeze.json").write_text(
        json.dumps({"apps": {pkg: {} for pkg in packages}}),
        encoding="utf-8",
    )
    (manifests / "publication_results_v1.json").write_text(
        json.dumps(
            {
                "n_apps": len(packages),
                "per_app": [{"package_name": pkg} for pkg in packages],
            }
        ),
        encoding="utf-8",
    )

    assert publication_contract._cohort_enforcement_v2(tmp_path) == []


def test_publication_cohort_enforcement_rejects_results_count_mismatch(tmp_path: Path) -> None:
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    packages = [f"com.example.app{i:02d}" for i in range(15)]
    (manifests / "dataset_freeze.json").write_text(
        json.dumps({"apps": {pkg: {} for pkg in packages}}),
        encoding="utf-8",
    )
    (manifests / "publication_results_v1.json").write_text(
        json.dumps(
            {
                "n_apps": 12,
                "per_app": [{"package_name": pkg} for pkg in packages],
            }
        ),
        encoding="utf-8",
    )

    errors = publication_contract._cohort_enforcement_v2(tmp_path)

    assert "cohort_n_apps_mismatch:freeze:15:results:12" in errors
