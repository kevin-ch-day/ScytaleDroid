from __future__ import annotations

import json
from pathlib import Path

from scripts.static_analysis.quarantine_unreferenced_static_archive_reports import (
    quarantine_session,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_quarantine_session_moves_only_unreferenced_archive_and_latest(
    tmp_path: Path,
) -> None:
    repo_root = tmp_path
    session = "sess-1"
    stale_hash = "a" * 64
    keep_hash = "b" * 64
    archive_dir = repo_root / "data/static_analysis/reports/archive" / session
    latest_dir = repo_root / "data/static_analysis/reports/latest"
    stale_archive = archive_dir / f"{stale_hash}.json"
    stale_latest = latest_dir / f"{stale_hash}.json"
    keep_archive = archive_dir / f"{keep_hash}.json"
    _write_json(
        stale_archive,
        {
            "generated_at": "2026-07-02T00:00:00+00:00",
            "manifest": {"package_name": "com.example.stale"},
            "metadata": {"session_stamp": session},
        },
    )
    _write_json(stale_latest, {"metadata": {"session_stamp": session}})
    _write_json(keep_archive, {"metadata": {"execution_id": "exec-1"}})
    artifact_map = repo_root / "output/audit/run_artifacts/sess-1-postrun.json"
    _write_json(
        artifact_map,
        {
            "evidence_vs_log_stream": {
                "evidence_path_alignment": {
                    "archive_paths_on_disk_not_in_log_events": [
                        str(stale_archive.relative_to(repo_root))
                    ]
                }
            }
        },
    )

    dry_run = quarantine_session(
        repo_root=repo_root,
        session=session,
        artifact_map_path=artifact_map,
        quarantine_root=repo_root / "output/quarantine/static_archive_unreferenced",
        apply=False,
    )

    assert dry_run["candidate_archive_count"] == 1
    assert dry_run["files_to_move_count"] == 2
    assert stale_archive.exists()
    assert stale_latest.exists()

    applied = quarantine_session(
        repo_root=repo_root,
        session=session,
        artifact_map_path=artifact_map,
        quarantine_root=repo_root / "output/quarantine/static_archive_unreferenced",
        apply=True,
    )

    assert applied["candidate_archive_count"] == 1
    assert not stale_archive.exists()
    assert not stale_latest.exists()
    assert keep_archive.exists()
    quarantine_root = repo_root / applied["quarantine_root"]
    assert (quarantine_root / "archive" / stale_archive.name).exists()
    assert (quarantine_root / "latest" / stale_latest.name).exists()
    assert (quarantine_root / "receipt.json").exists()
