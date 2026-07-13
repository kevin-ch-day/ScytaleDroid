from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.ml import artifact_bundle_writer
from scytaledroid.Publication import publication_contract
from scytaledroid.Publication.paper2_v2_contract import validate_paper2_v2_results_contract


def test_rank_tertiles_uses_current_cohort_size_for_15_apps() -> None:
    values = {f"pkg{i:02d}": float(i) for i in range(15)}

    grades, missing = artifact_bundle_writer._rank_tertiles(values, ascending=True)

    assert missing == []
    assert list(grades.values()).count("Low") == 5
    assert list(grades.values()).count("Medium") == 5
    assert list(grades.values()).count("High") == 5


def test_rank_tertiles_uses_current_cohort_size_for_14_apps() -> None:
    values = {f"pkg{i:02d}": float(i) for i in range(14)}

    grades, missing = artifact_bundle_writer._rank_tertiles(values, ascending=True)

    assert missing == []
    assert len(grades) == 14
    assert list(grades.values()).count("Low") == 5
    assert list(grades.values()).count("Medium") == 5
    assert list(grades.values()).count("High") == 4


def test_rank_tertiles_uses_current_cohort_size_for_13_apps() -> None:
    values = {f"pkg{i:02d}": float(i) for i in range(13)}

    grades, missing = artifact_bundle_writer._rank_tertiles(values, ascending=True)

    assert missing == []
    assert len(grades) == 13
    assert list(grades.values()).count("Low") == 5
    assert list(grades.values()).count("Medium") == 4
    assert list(grades.values()).count("High") == 4


def test_rank_tertiles_ties_are_deterministic_at_boundaries() -> None:
    values = {
        "pkg_b": 1.0,
        "pkg_a": 1.0,
        "pkg_c": 2.0,
        "pkg_d": 2.0,
        "pkg_e": 3.0,
        "pkg_f": 3.0,
    }

    grades, missing = artifact_bundle_writer._rank_tertiles(values, ascending=True)

    assert missing == []
    assert grades == {
        "pkg_a": "Low",
        "pkg_b": "Low",
        "pkg_c": "Medium",
        "pkg_d": "Medium",
        "pkg_e": "High",
        "pkg_f": "High",
    }


def test_rank_tertiles_all_identical_values_use_stable_rank_bins() -> None:
    values = {f"pkg{i:02d}": 1.0 for i in range(6)}

    grades, missing = artifact_bundle_writer._rank_tertiles(values, ascending=True)

    assert missing == []
    assert grades == {
        "pkg00": "Low",
        "pkg01": "Low",
        "pkg02": "Medium",
        "pkg03": "Medium",
        "pkg04": "High",
        "pkg05": "High",
    }


def test_rank_tertiles_reports_missing_scores_without_dropping_eligible_apps() -> None:
    values = {"pkg_a": 1.0, "pkg_b": None, "pkg_c": 2.0, "pkg_d": None, "pkg_e": 3.0}

    grades, missing = artifact_bundle_writer._rank_tertiles(values, ascending=True)

    assert missing == ["pkg_b", "pkg_d"]
    assert sorted(grades) == ["pkg_a", "pkg_c", "pkg_e"]
    assert grades == {"pkg_a": "Low", "pkg_c": "Medium", "pkg_e": "High"}


def test_rank_tertiles_shuffled_input_order_produces_identical_assignments() -> None:
    ordered = {f"pkg{i:02d}": float(i % 4) for i in range(15)}
    shuffled = dict(reversed(list(ordered.items())))

    grades_ordered, missing_ordered = artifact_bundle_writer._rank_tertiles(ordered, ascending=True)
    grades_shuffled, missing_shuffled = artifact_bundle_writer._rank_tertiles(shuffled, ascending=True)

    assert missing_ordered == missing_shuffled == []
    assert grades_ordered == grades_shuffled


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


def test_paper2_v2_contract_accepts_matching_15_app_package(tmp_path: Path) -> None:
    output_root = _write_paper2_v2_fixture(tmp_path)

    result = validate_paper2_v2_results_contract(output_root)

    assert result.ok, result.errors
    assert result.details["freeze_packages"] == 15


def test_paper2_v2_contract_rejects_wrong_version_code(tmp_path: Path) -> None:
    output_root = _write_paper2_v2_fixture(tmp_path, cohort_mutation={"selected_version_code": "999"})

    result = validate_paper2_v2_results_contract(output_root)

    assert not result.ok
    assert any("selected_version_code" in error for error in result.errors)


def test_paper2_v2_contract_rejects_wrong_base_apk_hash(tmp_path: Path) -> None:
    output_root = _write_paper2_v2_fixture(tmp_path, cohort_mutation={"selected_base_apk_sha256": "b" * 64})

    result = validate_paper2_v2_results_contract(output_root)

    assert not result.ok
    assert any("selected_base_apk_sha256" in error for error in result.errors)


def test_paper2_v2_contract_rejects_stale_freeze_hash(tmp_path: Path) -> None:
    output_root = _write_paper2_v2_fixture(tmp_path, results_mutation={"freeze_sha256": "stale"})

    result = validate_paper2_v2_results_contract(output_root)

    assert not result.ok
    assert any("freeze_sha256" in error for error in result.errors)


def test_paper2_v2_contract_rejects_stale_included_run_set_hash(tmp_path: Path) -> None:
    output_root = _write_paper2_v2_fixture(
        tmp_path,
        deterministic_mutation={"included_run_set_hash": "stale"},
    )

    result = validate_paper2_v2_results_contract(output_root)

    assert not result.ok
    assert any("included_run_set_hash" in error for error in result.errors)


def test_paper2_v2_contract_rejects_missing_feature_contract(tmp_path: Path) -> None:
    output_root = _write_paper2_v2_fixture(
        tmp_path,
        deterministic_mutation={"feature_contract_hash": ""},
    )

    result = validate_paper2_v2_results_contract(output_root)

    assert not result.ok
    assert "missing_deterministic_field:feature_contract_hash" in result.errors


def test_paper2_v2_contract_rejects_missing_model_parameter_hash(tmp_path: Path) -> None:
    output_root = _write_paper2_v2_fixture(
        tmp_path,
        deterministic_mutation={"model_parameter_hash": ""},
    )

    result = validate_paper2_v2_results_contract(output_root)

    assert not result.ok
    assert "missing_deterministic_field:model_parameter_hash" in result.errors


def _write_paper2_v2_fixture(
    tmp_path: Path,
    *,
    cohort_mutation: dict[str, str] | None = None,
    results_mutation: dict[str, str] | None = None,
    deterministic_mutation: dict[str, str] | None = None,
) -> Path:
    output_root = tmp_path / "paper2_v2"
    output_root.mkdir()
    package_names = [f"com.example.app{i:02d}" for i in range(15)]
    freeze_path = tmp_path / "dataset_freeze.json"
    dataset_plan_path = tmp_path / "dataset_plan.json"
    included_run_ids = [f"run-{i:02d}" for i in range(15)]
    apps = {
        pkg: {
            "selected_version_code": str(1000 + i),
            "selected_base_apk_sha256": f"{i:064x}",
            "included_run_ids": [included_run_ids[i]],
        }
        for i, pkg in enumerate(package_names)
    }
    freeze = {
        "apps": apps,
        "freeze_dataset_hash": "freeze-hash",
        "included_run_ids": included_run_ids,
    }
    freeze_path.write_text(json.dumps(freeze, sort_keys=True), encoding="utf-8")
    plan = {
        "apps": {
            pkg: {
                "runs": [
                    {
                        "run_id": included_run_ids[i],
                        "version_code": str(1000 + i),
                        "base_apk_sha256": f"{i:064x}",
                        "artifact_set_hash": f"{i + 100:064x}",
                    }
                ]
            }
            for i, pkg in enumerate(package_names)
        }
    }
    dataset_plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
    deterministic = {
        "dataset_lock_sha256": "freeze-hash",
        "feature_contract_hash": "feature-hash",
        "included_run_set_hash": hashlib.sha256(
            json.dumps(sorted(included_run_ids), sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "ml_scoring_run_id": "score-hash",
        "model_parameter_hash": "model-hash",
    }
    if deterministic_mutation:
        deterministic.update(deterministic_mutation)
    results = {
        "dataset_plan_path": str(dataset_plan_path),
        "deterministic_manifest": deterministic,
        "freeze_path": str(freeze_path),
        "freeze_sha256": _sha256(freeze_path),
    }
    if results_mutation:
        results.update(results_mutation)
    (output_root / "publication_results_v2.json").write_text(json.dumps(results, sort_keys=True), encoding="utf-8")

    with (output_root / "paper2_cohort_v2.csv").open("w", encoding="utf-8", newline="") as handle:
        fields = ["package_name", "selected_version_code", "selected_base_apk_sha256", "artifact_set_hashes"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for i, pkg in enumerate(package_names):
            row = {
                "package_name": pkg,
                "selected_version_code": str(1000 + i),
                "selected_base_apk_sha256": f"{i:064x}",
                "artifact_set_hashes": f"{i + 100:064x}",
            }
            if cohort_mutation and i == 0:
                row.update(cohort_mutation)
            writer.writerow(row)

    with (output_root / "paper2_per_app_rdi_v2.csv").open("w", encoding="utf-8", newline="") as handle:
        fields = ["package_name", "if_baseline_rdi", "if_interactive_rdi", "if_delta_rdi"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for pkg in package_names:
            writer.writerow(
                {
                    "package_name": pkg,
                    "if_baseline_rdi": "0.05",
                    "if_interactive_rdi": "0.7",
                    "if_delta_rdi": "0.65",
                }
            )
    return output_root


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
