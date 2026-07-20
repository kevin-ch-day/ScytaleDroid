from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Reporting.ieee_cars_2026_package import ieee_cars_2026_package_status


def test_status_is_read_only_and_distinguishes_unlabeled_workspace(tmp_path: Path) -> None:
    paper_root = tmp_path / "output" / "paper"
    freeze_path = paper_root / "dynamic_paper_freeze_20260719" / "paper_freeze_manifest.json"
    freeze_path.parent.mkdir(parents=True)
    freeze_path.write_text(json.dumps({"summary": {"ready": 15, "apps_total": 15}}), encoding="utf-8")
    workspace_path = paper_root / "paper3_draft_workspace_20260719" / "paper3_source_manifest.json"
    workspace_path.parent.mkdir(parents=True)
    workspace_path.write_text(json.dumps({"publication_target": {"submission_id": "other"}}), encoding="utf-8")

    status = ieee_cars_2026_package_status(repo_root=tmp_path)

    assert status["read_only"] is True
    assert status["target"]["identifier"] == "IEEE-CARS-2026"
    assert status["freeze_manifest"]["readiness_ready"] == 15
    assert status["writing_workspace"]["target_labeled"] is False
    assert status["writing_workspace"]["manuscript_pdf"] is None
    assert status["capsule"]["ready_to_archive"] is False
    assert status["capsule"]["missing_required_roles"] == ["not generated"]
    assert status["draft_ledgers"] == []


def test_status_prefers_labeled_workspace_when_it_is_newest(tmp_path: Path) -> None:
    paper_root = tmp_path / "output" / "paper"
    workspace_path = paper_root / "IEEE-CARS-2026_draft_workspace_20260719" / "paper3_source_manifest.json"
    workspace_path.parent.mkdir(parents=True)
    workspace_path.write_text(
        json.dumps(
            {
                "publication_target": {"submission_id": "IEEE-CARS-2026"},
                "manuscript_pdf": "/review/IEEE_CARS_2026_Paper.pdf",
            }
        ),
        encoding="utf-8",
    )

    status = ieee_cars_2026_package_status(repo_root=tmp_path)

    assert status["writing_workspace"]["target_labeled"] is True
    assert status["writing_workspace"]["manuscript_pdf"] == "/review/IEEE_CARS_2026_Paper.pdf"
