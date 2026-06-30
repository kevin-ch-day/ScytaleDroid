from __future__ import annotations

import json

from scytaledroid.Database.db_utils import artifact_registry_static_blocked_file_presence as blocked


def test_help_is_safe_without_pythonpath(assert_safe_script_help) -> None:
    out = assert_safe_script_help("scripts/db/report_artifact_registry_static_blocked_file_presence.py").lower()
    assert out.startswith("usage:")
    assert "blocked_file_presence" in out


def test_collect_static_blocked_file_presence_report(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        blocked,
        "collect_static_session_retirement_report",
        lambda run_sql, repo_root: {  # noqa: ARG005
            "legacy_session_retirement_sessions": [
                {
                    "session_stamp": "20260428-all-full",
                    "recommended_action": "blocked_file_present_review",
                    "overlap_registry_rows": 12,
                    "file_missing_registry_rows": 10,
                },
                {
                    "session_stamp": "20260429-rda-full",
                    "recommended_action": "candidate_small_session_retirement_review",
                    "overlap_registry_rows": 5,
                    "file_missing_registry_rows": 5,
                },
            ],
            "_dangling_rows": [
                {
                    "session_stamp": "20260428-all-full",
                    "package": "com.example.alpha",
                    "run_id": 100,
                    "artifact_id": 1,
                    "artifact_type": "static_report",
                    "host_path_family": "static_reports_latest",
                    "host_path_exists": True,
                    "host_path": str(tmp_path / "alpha.json"),
                },
                {
                    "session_stamp": "20260428-all-full",
                    "package": "com.example.alpha",
                    "run_id": 100,
                    "artifact_id": 2,
                    "artifact_type": "dep_snapshot",
                    "host_path_family": "dep_snapshot",
                    "host_path_exists": True,
                    "host_path": str(tmp_path / "alpha.dep.json"),
                },
                {
                    "session_stamp": "20260428-all-full",
                    "package": "com.example.beta",
                    "run_id": 101,
                    "artifact_id": 3,
                    "artifact_type": "static_report",
                    "host_path_family": "static_reports_latest",
                    "host_path_exists": False,
                    "host_path": str(tmp_path / "beta.json"),
                },
                {
                    "session_stamp": "20260429-rda-full",
                    "package": "com.example.skip",
                    "run_id": 102,
                    "artifact_id": 4,
                    "artifact_type": "static_report",
                    "host_path_family": "static_reports_latest",
                    "host_path_exists": True,
                    "host_path": str(tmp_path / "skip.json"),
                },
            ],
        },
    )

    report = blocked.collect_static_blocked_file_presence_report(lambda *args, **kwargs: None, repo_root=tmp_path)
    summary = report["summary"]
    assert summary["blocked_session_count"] == 1
    assert summary["blocked_file_present_row_count"] == 2
    assert summary["blocked_sessions"] == ["20260428-all-full"]
    assert len(report["blocked_package_rollup"]) == 1
    assert report["blocked_package_rollup"][0]["package"] == "com.example.alpha"


def test_write_static_blocked_file_presence_bundle(tmp_path: Path) -> None:
    report = {
        "summary": {"blocked_session_count": 1},
        "blocked_sessions": [{"session_stamp": "20260428-all-full"}],
        "blocked_file_present_rows": [{"artifact_id": 1}],
        "blocked_package_rollup": [{"package": "com.example.alpha"}],
        "blocked_path_family_rollup": [{"host_path_family": "static_reports_latest"}],
    }
    out_dir = tmp_path / "audit"
    files = blocked.write_static_blocked_file_presence_bundle(report, out_dir)
    names = {path.name for path in files}
    assert "summary.json" in names
    assert "blocked_file_present_rows.csv" in names
    payload = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert payload["blocked_session_count"] == 1
