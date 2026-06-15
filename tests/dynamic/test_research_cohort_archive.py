from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis import research_cohort_archive


def test_resolve_dataset_plan_read_path_prefers_active_cohort_path(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(research_cohort_archive.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(research_cohort_archive, "active_research_cohort_key", lambda: "research_dataset_beta")

    active = tmp_path / "archive" / "research_cohorts" / "research_dataset_beta" / "dataset_plan.json"
    active.parent.mkdir(parents=True, exist_ok=True)
    active.write_text("{}", encoding="utf-8")

    resolved = research_cohort_archive.resolve_dataset_plan_read_path()

    assert resolved == active


def test_write_dataset_plan_payload_mirrors_legacy_file(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(research_cohort_archive.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(research_cohort_archive, "active_research_cohort_key", lambda: "research_dataset_beta")

    payload = {"apps": {"com.example.app": {"runs": []}}, "updated_at": "2026-06-15T00:00:00Z"}
    primary = research_cohort_archive.write_dataset_plan_payload(payload)

    legacy = tmp_path / "archive" / "dataset_plan.json"
    assert primary == tmp_path / "archive" / "research_cohorts" / "research_dataset_beta" / "dataset_plan.json"
    assert json.loads(primary.read_text(encoding="utf-8"))["apps"]["com.example.app"]["runs"] == []
    assert json.loads(legacy.read_text(encoding="utf-8"))["apps"]["com.example.app"]["runs"] == []


def test_write_dataset_freeze_payload_mirrors_legacy_file(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(research_cohort_archive.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(research_cohort_archive, "active_research_cohort_key", lambda: "research_dataset_beta")

    payload = {"dataset_id": "Research Dataset Beta", "included_run_ids": ["run-1"]}
    primary = research_cohort_archive.write_dataset_freeze_payload(payload)

    legacy = tmp_path / "archive" / "dataset_freeze.json"
    assert primary == tmp_path / "archive" / "research_cohorts" / "research_dataset_beta" / "dataset_freeze.json"
    assert json.loads(primary.read_text(encoding="utf-8"))["dataset_id"] == "Research Dataset Beta"
    assert json.loads(legacy.read_text(encoding="utf-8"))["included_run_ids"] == ["run-1"]
