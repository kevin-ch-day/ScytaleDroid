from __future__ import annotations

import json

from scytaledroid.Database.db_utils import artifact_registry_static_session_retirement as retirement


def test_help_is_safe_without_pythonpath(assert_safe_script_help) -> None:
    out = assert_safe_script_help("scripts/db/report_artifact_registry_static_session_retirement.py").lower()
    assert out.startswith("usage:")
    assert "static_session_retirement" in out


def test_collect_static_session_retirement_report(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        retirement,
        "collect_artifact_registry_static_dangling_report",
        lambda run_sql, repo_root: {  # noqa: ARG005
            "static_dangling_rows": [
                {
                    "artifact_id": 1,
                    "resolved_static_run_id": 100,
                    "legacy_runs_row_present": True,
                    "host_path_exists": False,
                    "host_path_family": "static_reports_latest",
                    "primary_reason": "legacy_mirror_only_file_missing",
                    "meta_package_name": "com.example.alpha",
                    "created_at_utc": "2026-02-08 00:00:00",
                    "host_path": str(tmp_path / "a.json"),
                },
                {
                    "artifact_id": 2,
                    "resolved_static_run_id": 101,
                    "legacy_runs_row_present": True,
                    "host_path_exists": True,
                    "host_path_family": "dep_snapshot",
                    "primary_reason": "legacy_mirror_only_with_file",
                    "meta_package_name": "com.example.beta",
                    "created_at_utc": "2026-02-08 00:05:00",
                    "host_path": str(tmp_path / "b.json"),
                },
                {
                    "artifact_id": 3,
                    "resolved_static_run_id": 102,
                    "legacy_runs_row_present": False,
                    "host_path_exists": False,
                    "host_path_family": "dep_snapshot",
                    "primary_reason": "truly_detached",
                    "meta_package_name": "com.example.skip",
                    "created_at_utc": "2026-02-08 00:10:00",
                    "host_path": str(tmp_path / "c.json"),
                },
            ]
        },
    )
    monkeypatch.setattr(
        retirement,
        "collect_static_legacy_overlap_report",
        lambda run_sql: {  # noqa: ARG005
            "legacy_overlap_sessions": [
                {
                    "session_stamp": "20260429-small",
                    "overlap_run_ids": 1,
                    "metrics_rows": 0,
                    "buckets_rows": 0,
                    "contributor_rows": 0,
                    "finding_rows": 8,
                },
                {
                    "session_stamp": "20260430-blocked",
                    "overlap_run_ids": 1,
                    "metrics_rows": 10,
                    "buckets_rows": 2,
                    "contributor_rows": 1,
                    "finding_rows": 20,
                },
            ],
            "legacy_overlap_runs": [
                {"run_id": 100, "package": "com.example.alpha", "session_stamp": "20260429-small", "metrics_rows": 0, "buckets_rows": 0, "contributor_rows": 0, "finding_rows": 8},
                {"run_id": 101, "package": "com.example.beta", "session_stamp": "20260430-blocked", "metrics_rows": 10, "buckets_rows": 2, "contributor_rows": 1, "finding_rows": 20},
            ],
        },
    )

    report = retirement.collect_static_session_retirement_report(lambda *args, **kwargs: None, repo_root=tmp_path)
    summary = report["summary"]
    assert summary["legacy_overlap_session_count"] == 2
    assert summary["candidate_session_count"] == 1
    assert summary["blocked_session_count"] == 1
    assert summary["recommended_candidate_order"] == ["20260429-small"]

    sessions = report["legacy_session_retirement_sessions"]
    assert sessions[0]["session_stamp"] == "20260429-small"
    assert sessions[0]["recommended_action"] == "candidate_small_session_retirement_review"
    assert sessions[1]["recommended_action"] == "blocked_file_present_review"


def test_write_static_session_retirement_bundle(tmp_path: Path) -> None:
    report = {
        "summary": {"legacy_overlap_session_count": 1},
        "legacy_session_retirement_sessions": [{"session_stamp": "20260429-small"}],
        "legacy_session_retirement_candidates": [{"session_stamp": "20260429-small"}],
        "legacy_session_retirement_runs": [{"run_id": 100}],
        "legacy_session_retirement_samples": [{"artifact_id": 1}],
    }
    out_dir = tmp_path / "audit"
    files = retirement.write_static_session_retirement_bundle(report, out_dir)
    names = {path.name for path in files}
    assert "summary.json" in names
    assert "legacy_session_retirement_sessions.csv" in names
    payload = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert payload["legacy_overlap_session_count"] == 1
