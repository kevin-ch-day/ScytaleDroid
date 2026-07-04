"""Tests for read-only artifact registry cleanup candidate report."""

from __future__ import annotations

import pytest
from scytaledroid.Database.db_utils.artifact_registry_cleanup_report import (
    CATEGORY_ACTIONS,
    collect_cleanup_candidate_report,
    format_text_report,
)


def test_format_text_report_includes_sections() -> None:
    data = {
        "recent_days_window": 7,
        "old_days_threshold": 90,
        "run_type_filter": None,
        "summary_counts": {
            "total_rows": 105,
            "linked_keep_rows": 100,
            "safe_prune_candidate_rows": 5,
            "review_or_blocked_rows": 0,
            "other_rows": 0,
        },
        "totals_by_category": [
            {
                "cleanup_category": "linked_keep",
                "row_count": 100,
                "candidate_action": CATEGORY_ACTIONS["linked_keep"],
            },
            {
                "cleanup_category": "dangling_db_only_candidate",
                "row_count": 5,
                "candidate_action": CATEGORY_ACTIONS["dangling_db_only_candidate"],
            },
        ],
        "summary_dimensions": [
            {
                "cleanup_category": "dangling_db_only_candidate",
                "run_type": "static",
                "link_state": "dangling_static_run",
                "artifact_type": "dep_snapshot",
                "age_bucket": "90d+",
                "host_path_presence": "blank_host",
                "static_run_id_shape": "numeric_run_id",
                "row_count": 5,
                "created_min": None,
                "created_max": None,
            }
        ],
        "top_run_ids_by_category": {
            "dangling_db_only_candidate": [{"run_id": "42", "count": 5}],
        },
        "path_probe": None,
        "static_diagnostics_summary": {
            "distinct_static_run_count": 4,
            "distinct_recovered_package_count": 3,
            "runs_with_recovered_manifest_context": 3,
            "complete_core_bundle_run_count": 2,
            "partial_core_bundle_run_count": 2,
            "runs_with_duplicate_artifact_types": 1,
            "primary_reason_counts": {
                "file_present_db_detached": 8,
                "legacy_mirror_only_with_file": 2,
            },
            "cleanup_category_counts": {
                "static_file_present_detached_review": 8,
                "static_legacy_overlap_file_present_review": 2,
            },
            "blocked_session_count": 1,
            "blocked_registry_rows": 10,
            "blocked_sessions": ["20260430-all-full"],
            "candidate_session_count": 0,
            "candidate_registry_rows": 0,
            "recommended_candidate_order": [],
        },
    }
    text = format_text_report(data)
    assert "## Summary" in text
    assert "safe_prune_candidate_rows=5" in text
    assert "cleanup candidates (read-only)" in text
    assert "linked_keep" in text
    assert "dangling_db_only_candidate" in text
    assert "dep_snapshot" in text
    assert "42\t5" in text
    assert "Static dangling focus" in text
    assert "detached runs: 4 (recovered packages=3)" in text
    assert "recovered manifest context: 3 run(s)" in text
    assert "core bundle status: complete=2 partial=2 duplicates=1" in text
    assert (
        "cleanup categories: static_file_present_detached_review=8, static_legacy_overlap_file_present_review=2"
        in text
    )
    assert "blocked session stamps: 20260430-all-full" in text
    assert "artifact_registry.session_stamp is now the preferred static session marker" in text
    assert "prune_artifact_registry_dangling.py" in text
    assert "report_artifact_registry_static_detached.py" in text
    assert "prune_artifact_registry_static_detached.py" in text


def test_collect_cleanup_candidate_report_queries(monkeypatch: pytest.MonkeyPatch) -> None:
    returns: list[list[dict[str, object]]] = [
        [
            {
                "cleanup_category": "linked_keep",
                "run_type": "static",
                "link_state": "linked",
                "artifact_type": "static_report",
                "age_bucket": "0-7d",
                "host_path_presence": "host_path_set",
                "static_run_id_shape": "numeric_run_id",
                "row_count": 3,
                "created_min": None,
                "created_max": None,
            }
        ],
        [{"cleanup_category": "linked_keep", "run_id": "1", "cnt": 3}],
        [{"cleanup_category": "linked_keep", "row_count": 3}],
    ]

    def fake_run_sql(_sql: str, _params=None, **_kw):
        if not returns:
            return []
        return returns.pop(0)

    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.artifact_registry_cleanup_report._collect_static_dangling_summary",
        lambda *_a, **_k: {
            "summary": {
                "dangling_static_registry_rows": 0,
                "linked_static_registry_rows": 3,
                "distinct_static_run_count": 0,
                "distinct_recovered_package_count": 0,
                "runs_with_recovered_manifest_context": 0,
                "complete_core_bundle_run_count": 0,
                "partial_core_bundle_run_count": 0,
                "runs_with_duplicate_artifact_types": 0,
                "primary_reason_counts": {},
                "reason_flag_counts": {},
            }
        },
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.artifact_registry_cleanup_report._collect_static_session_retirement_summary",
        lambda *_a, **_k: {"summary": {"blocked_session_count": 0, "candidate_session_count": 0}},
    )

    out = collect_cleanup_candidate_report(fake_run_sql, path_sample_limit=0)
    assert out["summary_counts"]["total_rows"] == 3
    assert out["summary_counts"]["linked_keep_rows"] == 3
    assert out["summary_counts"]["safe_prune_candidate_rows"] == 0
    assert out["totals_by_category"][0]["row_count"] == 3
    assert out["summary_dimensions"][0]["artifact_type"] == "static_report"
    assert out["path_probe"] is None
    assert out["top_run_ids_by_category"]["linked_keep"][0]["run_id"] == "1"
    assert out["static_diagnostics_summary"]["linked_static_registry_rows"] == 3


def test_collect_cleanup_candidate_report_path_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    returns: list[list[dict[str, object]]] = [
        [],
        [],
        [
            {
                "artifact_id": 9,
                "cleanup_category": "dangling_old_export_first",
                "run_type": "static",
                "host_path": "/no/such/file/for_probe_test_artifact_registry",
            }
        ],
    ]

    def fake_run_sql(_sql: str, _params=None, **_kw):
        if not returns:
            return []
        return returns.pop(0)

    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.artifact_registry_cleanup_report._collect_static_dangling_summary",
        lambda *_a, **_k: {
            "summary": {
                "dangling_static_registry_rows": 1,
                "linked_static_registry_rows": 0,
                "distinct_static_run_count": 1,
                "distinct_recovered_package_count": 1,
                "runs_with_recovered_manifest_context": 1,
                "complete_core_bundle_run_count": 1,
                "partial_core_bundle_run_count": 0,
                "runs_with_duplicate_artifact_types": 0,
                "primary_reason_counts": {"file_present_db_detached": 1},
                "reason_flag_counts": {"missing_static_run": 1},
            }
        },
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.artifact_registry_cleanup_report._collect_static_session_retirement_summary",
        lambda *_a, **_k: {
            "summary": {
                "blocked_session_count": 1,
                "blocked_registry_rows": 1,
                "blocked_sessions": ["sess-a"],
            }
        },
    )

    out = collect_cleanup_candidate_report(fake_run_sql, path_sample_limit=5)
    assert out["path_probe"] is not None
    assert out["path_probe"]["sampled_rows"] == 1
    assert out["path_probe"]["host_path_exists_false"] >= 1
    assert out["static_diagnostics_summary"]["blocked_session_count"] == 1


def test_collect_cleanup_candidate_report_reclassifies_static_dangling_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    returns: list[list[dict[str, object]]] = [
        [
            {
                "cleanup_category": "linked_keep",
                "run_type": "static",
                "link_state": "linked",
                "artifact_type": "static_report",
                "age_bucket": "0-7d",
                "host_path_presence": "host_path_set",
                "static_run_id_shape": "numeric_run_id",
                "row_count": 3,
                "created_min": None,
                "created_max": None,
            },
            {
                "cleanup_category": "dangling_file_present_review",
                "run_type": "static",
                "link_state": "dangling_static_run",
                "artifact_type": "static_report",
                "age_bucket": "7-90d",
                "host_path_presence": "host_path_set",
                "static_run_id_shape": "numeric_run_id",
                "row_count": 99,
                "created_min": None,
                "created_max": None,
            },
        ],
        [
            {"cleanup_category": "linked_keep", "run_id": "1", "cnt": 3},
            {"cleanup_category": "dangling_file_present_review", "run_id": "1000", "cnt": 99},
        ],
    ]

    def fake_run_sql(_sql: str, _params=None, **_kw):
        if not returns:
            return []
        return returns.pop(0)

    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.artifact_registry_cleanup_report._collect_static_dangling_summary",
        lambda *_a, **_k: {
            "summary": {
                "dangling_static_registry_rows": 3,
                "linked_static_registry_rows": 3,
                "distinct_static_run_count": 2,
                "distinct_recovered_package_count": 1,
                "runs_with_recovered_manifest_context": 1,
                "complete_core_bundle_run_count": 1,
                "partial_core_bundle_run_count": 1,
                "runs_with_duplicate_artifact_types": 0,
                "primary_reason_counts": {
                    "file_present_db_detached": 1,
                    "legacy_mirror_only_file_missing": 1,
                    "truly_detached": 1,
                },
                "reason_flag_counts": {"missing_static_run": 3},
            },
            "static_dangling_rows": [
                {
                    "run_type": "static",
                    "link_state": "dangling_static_run",
                    "artifact_type": "static_report",
                    "age_bucket": "7-90d",
                    "host_path": "/tmp/present",
                    "created_at_utc": "2026-05-01 00:00:00",
                    "resolved_static_run_id": 1000,
                    "primary_reason": "file_present_db_detached",
                },
                {
                    "run_type": "static",
                    "link_state": "dangling_static_run",
                    "artifact_type": "static_report",
                    "age_bucket": "7-90d",
                    "host_path": "/tmp/missing",
                    "created_at_utc": "2026-05-02 00:00:00",
                    "resolved_static_run_id": 1001,
                    "primary_reason": "legacy_mirror_only_file_missing",
                },
                {
                    "run_type": "static",
                    "link_state": "dangling_static_run",
                    "artifact_type": "dep_snapshot",
                    "age_bucket": "7-90d",
                    "host_path": "/tmp/gone",
                    "created_at_utc": "2026-05-03 00:00:00",
                    "resolved_static_run_id": 1002,
                    "primary_reason": "truly_detached",
                },
            ],
            "static_dangling_runs": [
                {
                    "resolved_static_run_id": "1000",
                    "row_count": 1,
                    "dominant_primary_reason": "file_present_db_detached",
                },
                {
                    "resolved_static_run_id": "1001",
                    "row_count": 1,
                    "dominant_primary_reason": "legacy_mirror_only_file_missing",
                },
                {
                    "resolved_static_run_id": "1002",
                    "row_count": 1,
                    "dominant_primary_reason": "truly_detached",
                },
            ],
        },
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.artifact_registry_cleanup_report._collect_static_session_retirement_summary",
        lambda *_a, **_k: {
            "summary": {
                "blocked_session_count": 1,
                "blocked_registry_rows": 1,
                "blocked_sessions": ["sess-a"],
            }
        },
    )

    out = collect_cleanup_candidate_report(fake_run_sql, path_sample_limit=0)
    categories = {row["cleanup_category"] for row in out["totals_by_category"]}
    assert "static_file_present_detached_review" in categories
    assert "static_legacy_overlap_missing_file" in categories
    assert "static_truly_detached_candidate" in categories
    assert "dangling_file_present_review" not in categories
    assert out["top_run_ids_by_category"]["static_truly_detached_candidate"][0]["run_id"] == "1002"
    assert (
        out["static_diagnostics_summary"]["cleanup_category_counts"][
            "static_truly_detached_candidate"
        ]
        == 1
    )


def test_collect_cleanup_candidate_report_skips_static_diagnostics_for_dynamic_filter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    returns: list[list[dict[str, object]]] = [
        [],
        [],
        [],
    ]

    def fake_run_sql(_sql: str, _params=None, **_kw):
        if not returns:
            return []
        return returns.pop(0)

    out = collect_cleanup_candidate_report(
        fake_run_sql, run_type_filter="dynamic", path_sample_limit=0
    )
    assert out["static_diagnostics_summary"] is None


def test_script_help_is_safe_without_pythonpath(assert_safe_script_help) -> None:
    assert_safe_script_help("scripts/db/report_artifact_registry_cleanup_candidates.py", timeout=15)
