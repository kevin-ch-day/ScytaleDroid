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


def test_new_active_cohort_does_not_read_legacy_tracker(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(research_cohort_archive.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(research_cohort_archive, "active_research_cohort_key", lambda: "research_dataset_beta")
    legacy = tmp_path / "archive" / "dataset_plan.json"
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.write_text('{"apps": {"com.example.from_alpha": {}}}', encoding="utf-8")

    resolved = research_cohort_archive.resolve_dataset_plan_read_path()

    assert resolved == tmp_path / "archive" / "research_cohorts" / "research_dataset_beta" / "dataset_plan.json"
    assert not resolved.exists()


def test_new_active_cohort_does_not_read_legacy_freeze(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(research_cohort_archive.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(research_cohort_archive, "active_research_cohort_key", lambda: "research_dataset_beta")
    legacy = tmp_path / "archive" / "dataset_freeze.json"
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.write_text('{"cohort_key": "research_dataset_alpha"}', encoding="utf-8")

    resolved = research_cohort_archive.resolve_dataset_freeze_read_path()

    assert resolved == tmp_path / "archive" / "research_cohorts" / "research_dataset_beta" / "dataset_freeze.json"
    assert not resolved.exists()


def test_write_dataset_plan_payload_mirrors_legacy_file(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(research_cohort_archive.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(research_cohort_archive, "active_research_cohort_key", lambda: "research_dataset_beta")

    payload = {"apps": {"com.example.app": {"runs": []}}, "updated_at": "2026-06-15T00:00:00Z"}
    primary = research_cohort_archive.write_dataset_plan_payload(payload)

    legacy = tmp_path / "archive" / "dataset_plan.json"
    assert primary == tmp_path / "archive" / "research_cohorts" / "research_dataset_beta" / "dataset_plan.json"
    assert json.loads(primary.read_text(encoding="utf-8"))["apps"]["com.example.app"]["runs"] == []
    assert json.loads(legacy.read_text(encoding="utf-8"))["apps"]["com.example.app"]["runs"] == []
    assert json.loads(primary.read_text(encoding="utf-8"))["cohort_key"] == "research_dataset_beta"


def test_write_dataset_plan_rejects_foreign_cohort_identity(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(research_cohort_archive.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(research_cohort_archive, "active_research_cohort_key", lambda: "research_dataset_beta")

    try:
        research_cohort_archive.write_dataset_plan_payload({"cohort_key": "research_dataset_alpha", "apps": {}})
    except ValueError as exc:
        assert "cohort mismatch" in str(exc).lower()
    else:  # pragma: no cover - assertion guard
        raise AssertionError("foreign cohort plan was accepted")


def test_write_dataset_freeze_payload_mirrors_legacy_file(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(research_cohort_archive.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(research_cohort_archive, "active_research_cohort_key", lambda: "research_dataset_beta")

    payload = {"dataset_id": "Research Dataset Beta", "included_run_ids": ["run-1"]}
    primary = research_cohort_archive.write_dataset_freeze_payload(payload)

    legacy = tmp_path / "archive" / "dataset_freeze.json"
    assert primary == tmp_path / "archive" / "research_cohorts" / "research_dataset_beta" / "dataset_freeze.json"
    assert json.loads(primary.read_text(encoding="utf-8"))["dataset_id"] == "Research Dataset Beta"
    assert json.loads(legacy.read_text(encoding="utf-8"))["included_run_ids"] == ["run-1"]
    assert json.loads(primary.read_text(encoding="utf-8"))["cohort_key"] == "research_dataset_beta"


def test_write_dataset_freeze_rejects_foreign_cohort_identity(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(research_cohort_archive.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(research_cohort_archive, "active_research_cohort_key", lambda: "research_dataset_beta")

    try:
        research_cohort_archive.write_dataset_freeze_payload(
            {"cohort_key": "research_dataset_alpha", "included_run_ids": []}
        )
    except ValueError as exc:
        assert "cohort mismatch" in str(exc).lower()
    else:  # pragma: no cover - assertion guard
        raise AssertionError("foreign cohort freeze was accepted")
