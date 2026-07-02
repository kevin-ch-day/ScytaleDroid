from __future__ import annotations

import json
from pathlib import Path

from scripts.static_analysis.repair_static_report_execution_context import repair_session


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_repair_session_patches_only_logged_archive_and_latest_reports(
    tmp_path: Path,
) -> None:
    repo_root = tmp_path
    session = "sess-1"
    sha = "a" * 64
    stale_sha = "b" * 64
    archive = repo_root / "data/static_analysis/reports/archive" / session / f"{sha}.json"
    latest = repo_root / "data/static_analysis/reports/latest" / f"{sha}.json"
    stale = repo_root / "data/static_analysis/reports/archive" / session / f"{stale_sha}.json"
    report = {"hashes": {"sha256": sha}, "metadata": {"session_stamp": session}}
    _write_json(archive, report)
    _write_json(latest, report)
    _write_json(stale, {"hashes": {"sha256": stale_sha}, "metadata": {"session_stamp": session}})

    jsonl = repo_root / "logs/static_analysis.jsonl"
    jsonl.parent.mkdir(parents=True, exist_ok=True)
    jsonl.write_text(
        json.dumps(
            {
                "event": "report.saved",
                "session_stamp": session,
                "execution_id": "exec-1",
                "ts": "2026-07-02T00:00:00+00:00",
                "archive_path": str(archive.relative_to(repo_root)),
                "report_sha256": sha,
                "package_name": "com.example",
                "normalized_package_name": "com.example",
                "manifest_package_name": "com.example",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    dry_run = repair_session(
        repo_root=repo_root,
        session=session,
        jsonl_path=jsonl,
        apply=False,
    )

    assert dry_run["report_files_needing_update"] == 2
    assert "execution_id" not in json.loads(archive.read_text(encoding="utf-8"))["metadata"]

    applied = repair_session(
        repo_root=repo_root,
        session=session,
        jsonl_path=jsonl,
        apply=True,
    )

    assert applied["report_files_needing_update"] == 2
    for path in (archive, latest):
        metadata = json.loads(path.read_text(encoding="utf-8"))["metadata"]
        assert metadata["execution_id"] == "exec-1"
        assert metadata["report_saved_at_utc"] == "2026-07-02T00:00:00+00:00"
        assert metadata["report_sha256"] == sha
    stale_metadata = json.loads(stale.read_text(encoding="utf-8"))["metadata"]
    assert "execution_id" not in stale_metadata
