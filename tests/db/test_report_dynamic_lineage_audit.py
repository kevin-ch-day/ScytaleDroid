from __future__ import annotations

import csv
from pathlib import Path

from scripts.db import report_dynamic_lineage_audit as report
from scytaledroid.DynamicAnalysis import research_cohort_runtime, tracker_scope


def test_classify_lineage_state_boundaries() -> None:
    assert (
        report.classify_lineage_state(
            active_valid_runs=2,
            legacy_valid_runs=0,
            db_active_sessions=2,
            db_historical_sessions=0,
            installed_version_code="100",
            active_version_code="100",
        )
        == "current_build_observed"
    )
    assert (
        report.classify_lineage_state(
            active_valid_runs=0,
            legacy_valid_runs=2,
            db_active_sessions=0,
            db_historical_sessions=2,
            installed_version_code="101",
            active_version_code="100",
        )
        == "current_build_stale"
    )
    assert (
        report.classify_lineage_state(
            active_valid_runs=0,
            legacy_valid_runs=3,
            db_active_sessions=0,
            db_historical_sessions=3,
            installed_version_code="",
            active_version_code="100",
        )
        == "historical_local_only"
    )
    assert (
        report.classify_lineage_state(
            active_valid_runs=0,
            legacy_valid_runs=0,
            db_active_sessions=1,
            db_historical_sessions=0,
            installed_version_code="",
            active_version_code="100",
        )
        == "current_build_db_only"
    )
    assert (
        report.classify_lineage_state(
            active_valid_runs=0,
            legacy_valid_runs=0,
            db_active_sessions=0,
            db_historical_sessions=2,
            installed_version_code="",
            active_version_code="100",
        )
        == "historical_db_only"
    )
    assert (
        report.classify_lineage_state(
            active_valid_runs=0,
            legacy_valid_runs=0,
            db_active_sessions=0,
            db_historical_sessions=0,
            installed_version_code="",
            active_version_code="",
        )
        == "no_evidence_anywhere"
    )


def test_generate_report_includes_dataset_apps_without_runs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        research_cohort_runtime,
        "active_research_cohort_packages",
        lambda preferred_key=None: ("com.example.current", "com.example.empty"),
    )
    monkeypatch.setattr(
        report,
        "_scan_dynamic_runs",
        lambda package_filter=None: [
            {
                "run_id": "run-current-1",
                "package_name": "com.example.current",
                "app_label": "Current App",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "version_code": "200",
                "base_apk_sha256": "sha-current",
                "started_at": "2026-06-19T10:00:00+00:00",
                "ended_at": "2026-06-19T10:05:00+00:00",
                "dynamic_domains": {"api.example.com"},
                "service_keys": {"first_party_api"},
                "signal_keys": {"first_party_platform"},
            }
        ],
    )
    monkeypatch.setattr(
        report,
        "_load_app_profiles",
        lambda packages: {
            "com.example.current": {"display_name": "Current App", "profile_key": "research"},
            "com.example.empty": {"display_name": "Empty App", "profile_key": "research"},
        },
    )
    monkeypatch.setattr(
        report, "_load_installed_version_code", lambda package_name, device_serial=None: ""
    )
    monkeypatch.setattr(
        report,
        "_load_db_dynamic_lineage_context",
        lambda packages: {
            "com.example.current": {
                "db_active_sessions": 1,
                "db_historical_sessions": 0,
                "db_total_sessions": 1,
            },
            "com.example.empty": {
                "db_active_sessions": 0,
                "db_historical_sessions": 0,
                "db_total_sessions": 0,
            },
        },
    )
    monkeypatch.setattr(
        tracker_scope,
        "resolve_active_package_identity",
        lambda package_name: (
            ("200", "sha-current") if package_name == "com.example.current" else (None, None)
        ),
    )

    def _scoped_counts(
        package_name: str,
        runs: list[dict],
        *,
        cfg: object | None = None,
        resolve_tracker_run_identity_fn,
        active_identity_fn=None,
    ):
        if package_name == "com.example.current":
            return {
                "baseline_countable": 1,
                "baseline_extra": 0,
                "interactive_countable": 0,
                "interactive_extra": 0,
                "legacy_valid": 0,
                "legacy_builds": 0,
                "technical_valid_total": 1,
                "technical_valid_active": 1,
                "active_version_code": "200",
                "active_base_sha": "sha-current",
            }
        return {
            "baseline_countable": 0,
            "baseline_extra": 0,
            "interactive_countable": 0,
            "interactive_extra": 0,
            "legacy_valid": 0,
            "legacy_builds": 0,
            "technical_valid_total": 0,
            "technical_valid_active": 0,
            "active_version_code": "",
            "active_base_sha": "",
        }

    monkeypatch.setattr(tracker_scope, "build_scoped_dataset_counts", _scoped_counts)

    summary = report.generate_report(output_dir=tmp_path)

    assert summary["apps_total"] == 2
    assert summary["lineage_state_counts"] == {
        "current_build_observed": 1,
        "no_evidence_anywhere": 1,
    }

    with (tmp_path / "per_app_lineage_summary.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert {row["package_name"] for row in rows} == {"com.example.current", "com.example.empty"}
    empty_row = next(row for row in rows if row["package_name"] == "com.example.empty")
    assert empty_row["app_label"] == "Empty App"
    assert empty_row["lineage_state"] == "no_evidence_anywhere"
    assert empty_row["top_recommendation"] == "collect baseline evidence"


def test_generate_report_marks_stale_when_installed_build_drift_exists(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(
        research_cohort_runtime,
        "active_research_cohort_packages",
        lambda preferred_key=None: ("com.example.stale",),
    )
    monkeypatch.setattr(
        report,
        "_scan_dynamic_runs",
        lambda package_filter=None: [
            {
                "run_id": "legacy-1",
                "package_name": "com.example.stale",
                "app_label": "Stale App",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "version_code": "199",
                "base_apk_sha256": "sha-legacy",
                "started_at": "2026-06-18T10:00:00+00:00",
                "ended_at": "2026-06-18T10:05:00+00:00",
                "dynamic_domains": {"legacy.example.com"},
                "service_keys": {"legacy_service"},
                "signal_keys": {"legacy_signal"},
            }
        ],
    )
    monkeypatch.setattr(
        report,
        "_load_app_profiles",
        lambda packages: {
            "com.example.stale": {"display_name": "Stale App", "profile_key": "research"},
        },
    )
    monkeypatch.setattr(
        report, "_load_installed_version_code", lambda package_name, device_serial=None: "201"
    )
    monkeypatch.setattr(
        report,
        "_load_db_dynamic_lineage_context",
        lambda packages: {
            "com.example.stale": {
                "db_active_sessions": 0,
                "db_historical_sessions": 1,
                "db_total_sessions": 1,
            },
        },
    )
    monkeypatch.setattr(
        tracker_scope,
        "resolve_active_package_identity",
        lambda package_name: ("200", "sha-current"),
    )
    monkeypatch.setattr(
        tracker_scope,
        "build_scoped_dataset_counts",
        lambda package_name, runs, *, cfg=None, resolve_tracker_run_identity_fn, active_identity_fn=None: {
            "baseline_countable": 0,
            "baseline_extra": 0,
            "interactive_countable": 0,
            "interactive_extra": 0,
            "legacy_valid": 1,
            "legacy_builds": 1,
            "technical_valid_total": 1,
            "technical_valid_active": 0,
            "active_version_code": "200",
            "active_base_sha": "sha-current",
        },
    )

    summary = report.generate_report(output_dir=tmp_path, device_serial="ZY22JK89DR")

    assert summary["lineage_state_counts"] == {"current_build_stale": 1}
    with (tmp_path / "per_app_lineage_summary.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    row = rows[0]
    assert row["package_name"] == "com.example.stale"
    assert row["lineage_state"] == "current_build_stale"
    assert row["installed_version_code"] == "201"
    assert row["active_version_code"] == "200"
    assert row["top_recommendation"] == "refresh harvest/static for installed build"


def test_generate_report_distinguishes_historical_db_only_from_empty(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(
        research_cohort_runtime,
        "active_research_cohort_packages",
        lambda preferred_key=None: ("com.example.history", "com.example.empty"),
    )
    monkeypatch.setattr(report, "_scan_dynamic_runs", lambda package_filter=None: [])
    monkeypatch.setattr(
        report,
        "_load_app_profiles",
        lambda packages: {
            "com.example.history": {"display_name": "History App", "profile_key": "research"},
            "com.example.empty": {"display_name": "Empty App", "profile_key": "research"},
        },
    )
    monkeypatch.setattr(
        report, "_load_installed_version_code", lambda package_name, device_serial=None: ""
    )
    monkeypatch.setattr(
        report,
        "_load_db_dynamic_lineage_context",
        lambda packages: {
            "com.example.history": {
                "db_active_sessions": 0,
                "db_historical_sessions": 5,
                "db_total_sessions": 5,
            },
            "com.example.empty": {
                "db_active_sessions": 0,
                "db_historical_sessions": 0,
                "db_total_sessions": 0,
            },
        },
    )
    monkeypatch.setattr(
        tracker_scope, "resolve_active_package_identity", lambda package_name: ("100", "sha-active")
    )
    monkeypatch.setattr(
        tracker_scope,
        "build_scoped_dataset_counts",
        lambda package_name, runs, *, cfg=None, resolve_tracker_run_identity_fn, active_identity_fn=None: {
            "baseline_countable": 0,
            "baseline_extra": 0,
            "interactive_countable": 0,
            "interactive_extra": 0,
            "legacy_valid": 0,
            "legacy_builds": 0,
            "technical_valid_total": 0,
            "technical_valid_active": 0,
            "active_version_code": "100",
            "active_base_sha": "sha-active",
        },
    )

    summary = report.generate_report(output_dir=tmp_path)

    assert summary["lineage_state_counts"] == {
        "historical_db_only": 1,
        "no_evidence_anywhere": 1,
    }
    with (tmp_path / "per_app_lineage_summary.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    history_row = next(row for row in rows if row["package_name"] == "com.example.history")
    assert history_row["lineage_state"] == "historical_db_only"
    assert history_row["db_historical_sessions"] == "5"
    assert (
        history_row["top_recommendation"]
        == "treat as historical-only until current-build evidence is collected"
    )


def test_delta_row_reports_current_vs_legacy_sets() -> None:
    row = report._delta_row(
        package_name="com.example.app",
        app_label="Example App",
        active_version_code="200",
        legacy_version_codes={"198", "199"},
        current_domains={"current.example.com", "shared.example.com"},
        legacy_domains={"legacy.example.com", "shared.example.com"},
        current_services={"current_service", "shared_service"},
        legacy_services={"legacy_service", "shared_service"},
        current_signals={"current_signal", "shared_signal"},
        legacy_signals={"legacy_signal", "shared_signal"},
    )

    assert row["current_only_domain_count"] == 1
    assert row["legacy_only_domain_count"] == 1
    assert row["current_only_service_count"] == 1
    assert row["legacy_only_service_count"] == 1
    assert row["current_only_signal_count"] == 1
    assert row["legacy_only_signal_count"] == 1
    assert row["legacy_version_codes"] == "198,199"
