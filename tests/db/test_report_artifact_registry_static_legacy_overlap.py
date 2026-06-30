from __future__ import annotations

import json

from scytaledroid.Database.db_utils.artifact_registry_static_legacy_overlap import (
    collect_static_legacy_overlap_report,
    write_static_legacy_overlap_bundle,
)


def test_help_is_safe_without_pythonpath(assert_safe_script_help) -> None:
    out = assert_safe_script_help("scripts/db/report_artifact_registry_static_legacy_overlap.py").lower()
    assert out.startswith("usage:")
    assert "static_legacy_overlap" in out


def test_collect_static_legacy_overlap_report() -> None:
    def fake_run_sql(
        sql: str,
        params: tuple[object, ...] | tuple[()] = (),
        *,
        fetch: str = "all",
        dictionary: bool = False,
        query_name: str | None = None,
    ):
        del sql, params, fetch, dictionary
        if query_name == "artifact_registry_static_legacy_overlap.summary":
            return {
                "overlap_registry_rows": 12,
                "overlap_run_ids": 3,
                "overlap_session_stamps": 2,
                "host_path_rows": 12,
                "blank_host_rows": 0,
            }
        if query_name == "artifact_registry_static_legacy_overlap.sessions":
            return [
                {
                    "session_stamp": "20260430-all-full",
                    "overlap_run_ids": 2,
                    "metrics_rows": 10,
                    "buckets_rows": 4,
                    "contributor_rows": 3,
                    "finding_rows": 20,
                },
                {
                    "session_stamp": "20260429-rda-full",
                    "overlap_run_ids": 1,
                    "metrics_rows": 0,
                    "buckets_rows": 0,
                    "contributor_rows": 0,
                    "finding_rows": 5,
                },
            ]
        if query_name == "artifact_registry_static_legacy_overlap.runs":
            return [
                {
                    "run_id": 100,
                    "package": "com.example.alpha",
                    "session_stamp": "20260430-all-full",
                    "metrics_rows": 5,
                    "buckets_rows": 2,
                    "contributor_rows": 1,
                    "finding_rows": 10,
                },
                {
                    "run_id": 101,
                    "package": "com.example.alpha",
                    "session_stamp": "20260430-all-full",
                    "metrics_rows": 5,
                    "buckets_rows": 2,
                    "contributor_rows": 2,
                    "finding_rows": 10,
                },
                {
                    "run_id": 102,
                    "package": "com.example.beta",
                    "session_stamp": "20260429-rda-full",
                    "metrics_rows": 0,
                    "buckets_rows": 0,
                    "contributor_rows": 0,
                    "finding_rows": 5,
                },
            ]
        raise AssertionError(f"unexpected query_name: {query_name}")

    report = collect_static_legacy_overlap_report(fake_run_sql)
    assert report["summary"]["overlap_registry_rows"] == 12
    assert report["summary"]["top_session_stamps"] == ["20260430-all-full", "20260429-rda-full"]
    assert report["legacy_overlap_top_packages"] == [
        {"package": "com.example.alpha", "run_count": 2},
        {"package": "com.example.beta", "run_count": 1},
    ]


def test_write_static_legacy_overlap_bundle(tmp_path: Path) -> None:
    report = {
        "summary": {"overlap_registry_rows": 1},
        "legacy_overlap_sessions": [{"session_stamp": "20260430-all-full"}],
        "legacy_overlap_runs": [{"run_id": 1}],
        "legacy_overlap_top_packages": [{"package": "com.example.alpha", "run_count": 1}],
    }
    out_dir = tmp_path / "audit"
    files = write_static_legacy_overlap_bundle(report, out_dir)
    names = {path.name for path in files}
    assert "summary.json" in names
    assert "legacy_overlap_sessions.csv" in names
    payload = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert payload["overlap_registry_rows"] == 1
