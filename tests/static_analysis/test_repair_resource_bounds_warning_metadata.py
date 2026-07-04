from __future__ import annotations

import json
from pathlib import Path

from scripts.static_analysis.repair_resource_bounds_warning_metadata import repair_session


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_repair_session_patches_archive_and_latest_reports(tmp_path: Path) -> None:
    repo_root = tmp_path
    session = "20260702-all-full"
    apk_sha = "a" * 64
    archive_path = (
        repo_root
        / "data/static_analysis/reports/archive"
        / session
        / f"{apk_sha}.json"
    )
    latest_path = repo_root / "data/static_analysis/reports/latest" / f"{apk_sha}.json"
    report = {
        "hashes": {"sha256": apk_sha},
        "metadata": {
            "parse_error_resources": True,
            "string_index_resource_strings": 0,
            "parser_provenance": {"resource_bounds_warning_count": 0},
        },
    }
    _write_json(archive_path, report)
    _write_json(latest_path, report)

    jsonl_path = repo_root / "logs/static_analysis.jsonl"
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    jsonl_path.write_text(
        json.dumps(
            {
                "event": "strings.resource_bounds_warning",
                "apk_path": f"/tmp/{apk_sha}.apk",
                "warning_lines": [
                    "We are out of bound with this complex entry. Count: 65536"
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    dry_run = repair_session(
        repo_root=repo_root,
        session=session,
        jsonl_path=jsonl_path,
        archive_dir=archive_path.parent,
        apply=False,
    )

    assert dry_run["report_files_needing_update"] == 2
    assert json.loads(archive_path.read_text(encoding="utf-8"))["metadata"][
        "parser_provenance"
    ]["resource_bounds_warning_count"] == 0

    applied = repair_session(
        repo_root=repo_root,
        session=session,
        jsonl_path=jsonl_path,
        archive_dir=archive_path.parent,
        apply=True,
    )

    assert applied["report_files_needing_update"] == 2
    for path in (archive_path, latest_path):
        payload = json.loads(path.read_text(encoding="utf-8"))
        metadata = payload["metadata"]
        assert metadata["resource_bounds_warnings"] == [
            "We are out of bound with this complex entry. Count: 65536"
        ]
        assert metadata["parser_provenance"]["resource_bounds_warning_count"] == 1
        assert metadata["parser_provenance"]["resource_bounds_warning_severity"] == "warn"
        assert metadata["parser_provenance"]["resource_bounds_warning_kind"] == "complex_entry"
        assert metadata["parser_provenance"]["resource_parse_state"] == "partial"
        assert metadata["parser_provenance"]["resource_parse_partial"] is True
        assert metadata["parser_provenance"]["resource_reparse_candidate"] is True
