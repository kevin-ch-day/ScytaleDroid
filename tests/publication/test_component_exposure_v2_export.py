from __future__ import annotations

import csv
import json

import pytest
from scripts.publication.export_component_exposure_v2 import build_rows, main


def test_export_deduplicates_provider_rows_and_keeps_guard_buckets(tmp_path) -> None:
    cohort = [
        {
            "app_label": "Example",
            "package_name": "com.example",
            "selected_base_apk_sha256": "a" * 64,
            "contributing_static_run_id": "7",
        }
    ]
    findings = [
        {"run_id": "7", "finding_id": "ipc_provider_world_com.example.Provider"},
        {"run_id": "7", "finding_id": "provider_world_com.example.Provider"},
        {"run_id": "7", "finding_id": "ipc_activity_weak_permission_com.example.Activity"},
        {"run_id": "7", "finding_id": "ipc_service_unknown_permission_com.example.Service"},
        {"run_id": "7", "finding_id": "manifest_exported_weak_guards"},
    ]
    row = build_rows(cohort, findings)[0]
    assert row["raw_finding_rows"] == 5
    assert row["exported_component_identities"] == 3
    assert row["ipc_components_without_permission_guard"] == 1
    assert row["ipc_components_with_weak_permission_guard"] == 1
    assert row["unguarded_ipc_components"] == 2

    cohort_path = tmp_path / "cohort.csv"
    finding_path = tmp_path / "findings.csv"
    with cohort_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(cohort[0]))
        writer.writeheader()
        writer.writerows(cohort)
    with finding_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(findings[0]))
        writer.writeheader()
        writer.writerows(findings)

    output_dir = tmp_path.parent / f"{tmp_path.name}-derived"
    assert main([
        "--cohort-manifest", str(cohort_path),
        "--finding-rows", str(finding_path),
        "--output-dir", str(output_dir),
    ]) == 0
    receipt = json.loads((output_dir / "receipt.json").read_text(encoding="utf-8"))
    assert receipt["selected_app_builds"] == 1
    assert receipt["components_without_manifest_permission"] == 1
    assert receipt["components_labeled_weak_by_detector"] == 1
    assert receipt["vulnerability_count"] is None
    with pytest.raises(SystemExit):
        main([
            "--cohort-manifest", str(cohort_path),
            "--finding-rows", str(finding_path),
            "--output-dir", str(output_dir),
        ])


def test_export_rejects_findings_outside_selected_run() -> None:
    with pytest.raises(ValueError, match="outside the selected cohort"):
        build_rows(
            [{"contributing_static_run_id": "7"}],
            [{"run_id": "8", "finding_id": "ipc_activity_open_Other"}],
        )


def test_export_removes_only_exact_reviewed_signature_false_weak_rows() -> None:
    cohort = [{"contributing_static_run_id": "7", "package_name": "com.example"}]
    findings = [
        {
            "id": "101", "run_id": "7",
            "finding_id": "ipc_activity_weak_permission_com.example.Secure",
        },
        {
            "id": "102", "run_id": "7",
            "finding_id": "ipc_service_weak_permission_com.example.Review",
        },
    ]
    review = [{
        "finding_db_id": "101",
        "static_run_id": "7",
        "finding_id": findings[0]["finding_id"],
        "recorded_protection_level": "0x00000002",
        "adjudication_status": "CONFIRMED_GUARD_CLASSIFICATION_ERROR",
    }]
    row = build_rows(cohort, findings, review)[0]
    assert row["ipc_components_with_weak_permission_guard"] == 2
    assert row["reviewed_signature_false_weak_rows"] == 1
    assert row["weak_guard_labels_after_known_corrections"] == 1
    with pytest.raises(ValueError, match="does not match"):
        build_rows(cohort, findings, [{**review[0], "finding_id": "wrong"}])
