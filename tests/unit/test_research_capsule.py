from __future__ import annotations

from pathlib import Path

import pytest
from scytaledroid.Publication.research_capsule import (
    build_research_capsule_manifest,
    inventory_item,
)


def test_capsule_manifest_hashes_explicit_inputs_and_checks_required_roles(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    paper = repo / "paper"
    paper.mkdir()
    (paper / "table.csv").write_text("app,value\nExample,1\n", encoding="utf-8")
    freeze = repo / "freeze.json"
    freeze.write_text("{}\n", encoding="utf-8")
    archive = tmp_path / "mercury"
    archive.mkdir()

    manifest = build_research_capsule_manifest(
        paper_id="paper3",
        repo_root=repo,
        items={"publication": [paper], "freeze": [freeze]},
        required_roles=("publication", "freeze", "db_export"),
        archive_root=archive,
    )

    assert manifest["paper_id"] == "paper3"
    assert manifest["items"][0]["kind"] == "file"
    assert manifest["items"][1]["kind"] == "directory"
    assert manifest["items"][1]["file_count"] == 1
    assert manifest["missing_required_roles"] == ["db_export"]
    assert manifest["ready_to_archive"] is False
    assert manifest["archive_destination"]["writable"] is True


def test_capsule_manifest_marks_missing_inputs_without_claiming_ready(tmp_path: Path) -> None:
    manifest = build_research_capsule_manifest(
        paper_id="paper1",
        repo_root=tmp_path,
        items={"apk": [tmp_path / "missing.apk"]},
    )

    assert manifest["missing_items"] == ["missing.apk"]
    assert manifest["ready_to_archive"] is False


def test_capsule_refuses_to_hash_dotenv_as_configuration(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("SECRET=value\n", encoding="utf-8")

    with pytest.raises(ValueError, match="refusing to inventory .env"):
        inventory_item(env_path, repo_root=tmp_path, role="config")

    production_env = tmp_path / ".env.production"
    production_env.write_text("SECRET=value\n", encoding="utf-8")
    with pytest.raises(ValueError, match="refusing to inventory .env"):
        inventory_item(production_env, repo_root=tmp_path, role="config")


def test_capsule_stays_unready_when_ledger_validation_is_unresolved(tmp_path: Path) -> None:
    source = tmp_path / "freeze.json"
    source.write_text("{}", encoding="utf-8")

    manifest = build_research_capsule_manifest(
        paper_id="paper3",
        repo_root=tmp_path,
        items={"freeze": [source]},
        selection_validation={"evidence_ledger": ["evidence_missing:pcap"]},
    )

    assert manifest["ready_to_archive"] is False
    assert manifest["unresolved_selection"] == {"evidence_ledger": ["evidence_missing:pcap"]}
