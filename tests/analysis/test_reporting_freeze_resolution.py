from __future__ import annotations

from pathlib import Path

from scytaledroid.Reporting.services import publication_exports_service
from scytaledroid.Reporting.services import publication_pipeline_audit_service
from scytaledroid.Reporting.services import publication_results_numbers_service
from scytaledroid.Reporting.services import publication_scientific_qa_service
from scytaledroid.Reporting.services import risk_scoring_artifacts_service
from scripts.publication import publication_ml_audit_report


def test_reporting_services_resolve_freeze_path_at_runtime(monkeypatch, tmp_path: Path) -> None:
    freeze_path = tmp_path / "archive" / "research_cohorts" / "research_dataset_beta" / "dataset_freeze.json"
    freeze_path.parent.mkdir(parents=True, exist_ok=True)
    freeze_path.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(
        publication_exports_service,
        "resolve_dataset_freeze_read_path",
        lambda: freeze_path,
    )
    monkeypatch.setattr(
        publication_results_numbers_service,
        "resolve_dataset_freeze_read_path",
        lambda: freeze_path,
    )
    monkeypatch.setattr(
        publication_scientific_qa_service,
        "resolve_dataset_freeze_read_path",
        lambda: freeze_path,
    )
    monkeypatch.setattr(
        publication_pipeline_audit_service,
        "resolve_dataset_freeze_read_path",
        lambda: freeze_path,
    )
    monkeypatch.setattr(
        risk_scoring_artifacts_service,
        "resolve_dataset_freeze_read_path",
        lambda: freeze_path,
    )
    monkeypatch.setattr(
        publication_ml_audit_report,
        "resolve_dataset_freeze_read_path",
        lambda: freeze_path,
    )

    assert publication_exports_service._freeze_path() == freeze_path
    assert publication_results_numbers_service._freeze_path() == freeze_path
    assert publication_scientific_qa_service._freeze_path() == freeze_path
    assert publication_pipeline_audit_service._freeze_path() == freeze_path
    assert risk_scoring_artifacts_service._freeze_path() == freeze_path
    assert publication_ml_audit_report._freeze_path() == freeze_path
