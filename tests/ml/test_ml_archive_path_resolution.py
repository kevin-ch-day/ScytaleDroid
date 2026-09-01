from __future__ import annotations

from pathlib import Path

from scytaledroid.DynamicAnalysis import research_cohort_archive
from scytaledroid.DynamicAnalysis.ml import deliverable_bundle_paths, evidence_pack_ml_orchestrator


def test_ml_freeze_anchor_prefers_active_cohort_path(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(research_cohort_archive.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(research_cohort_archive, "active_research_cohort_key", lambda: "research_dataset_beta")

    active = tmp_path / "archive" / "research_cohorts" / "research_dataset_beta" / "dataset_freeze.json"
    legacy = tmp_path / "archive" / "dataset_freeze.json"
    active.parent.mkdir(parents=True, exist_ok=True)
    legacy.parent.mkdir(parents=True, exist_ok=True)
    active.write_text("{}", encoding="utf-8")
    legacy.write_text("{}", encoding="utf-8")

    assert deliverable_bundle_paths.freeze_anchor_path() == active
    assert evidence_pack_ml_orchestrator.default_freeze_manifest_path() == active


def test_ml_paper_artifacts_lockfile_is_dataset_adjacent(tmp_path: Path) -> None:
    freeze = tmp_path / "archive" / "research_cohorts" / "research_dataset_beta" / "dataset_freeze.json"

    assert evidence_pack_ml_orchestrator.paper_artifacts_path(freeze) == freeze.parent / "paper_artifacts.json"


def test_locked_runtime_bundle_paths_preserve_legacy_aliases() -> None:
    assert deliverable_bundle_paths.output_locked_runtime_bundle_root() == (
        deliverable_bundle_paths.output_locked_runtime_bundle_root()
    )
    assert deliverable_bundle_paths.output_locked_runtime_bundle_tables_dir() == (
        deliverable_bundle_paths.output_locked_runtime_bundle_tables_dir()
    )
    assert deliverable_bundle_paths.output_locked_runtime_bundle_artifacts_manifest_path() == (
        deliverable_bundle_paths.output_locked_runtime_bundle_artifacts_manifest_path()
    )
