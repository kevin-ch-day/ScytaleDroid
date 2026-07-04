from __future__ import annotations

from types import SimpleNamespace

from scripts.db import report_dynamic_live_operational_state as report


def test_summarize_prepared_view_surfaces_drift_and_candidates() -> None:
    prepared = SimpleNamespace(
        row_models=[
            SimpleNamespace(
                package_name="bbc.mobile.news.ww",
                display_name="BBC News",
                live_build_drift=True,
                live_observed_version_code="10007091",
                live_expected_version_code="10007090",
                live_expected_version_name="1.0.7",
                live_static_run_id="6001",
                lineage_state="current_build_observed",
                need_baseline=0,
                need_interactive=1,
                baseline_countable=3,
                baseline_extra=2,
                baseline_low_signal_supplemental=0,
                interactive_countable=3,
                interactive_extra=0,
                interactive_low_signal_supplemental=0,
            ),
            SimpleNamespace(
                package_name="com.facebook.katana",
                display_name="Facebook",
                live_build_drift=False,
                lineage_state="current_build_observed",
                need_baseline=0,
                need_interactive=3,
                baseline_countable=3,
                baseline_extra=0,
                baseline_low_signal_supplemental=0,
                interactive_countable=1,
                interactive_extra=0,
                interactive_low_signal_supplemental=0,
            ),
            SimpleNamespace(
                package_name="com.whatsapp",
                display_name="WhatsApp",
                live_build_drift=False,
                lineage_state="current_build_observed",
                need_baseline=0,
                need_interactive=2,
                baseline_countable=3,
                baseline_extra=0,
                baseline_low_signal_supplemental=0,
                interactive_countable=2,
                interactive_extra=1,
                interactive_low_signal_supplemental=0,
            ),
            SimpleNamespace(
                package_name="com.linkedin.android",
                display_name="LinkedIn",
                live_build_drift=False,
                lineage_state="historical_db_only",
                need_baseline=3,
                need_interactive=4,
                baseline_countable=0,
                baseline_extra=0,
                baseline_low_signal_supplemental=0,
                interactive_countable=0,
                interactive_extra=0,
                interactive_low_signal_supplemental=0,
            ),
        ],
        current_build_ready_count=0,
        current_build_in_progress_count=2,
        current_build_review_count=0,
        current_build_db_only_count=0,
        historical_local_only_app_count=0,
        historical_db_only_app_count=1,
        no_evidence_anywhere_count=0,
        mixed_identity_app_count=0,
        dataset_apps_total=4,
        expected_runs=28,
        dataset_valid_runs_total=12,
        evidence_summary={"quota_runs_counted": 12, "apps_satisfied": 0},
    )

    summary = report.summarize_prepared_view(
        prepared=prepared,
        cohort_label="Research Dataset Beta",
        cohort_key="research_dataset_beta",
        device_serial="ZY22JK89DR",
        device_label="moto g 5G 2024 · ZY22JK89DR",
        candidate_limit=2,
        queue_status_label_fn=lambda row: (
            "refresh"
            if row.live_build_drift
            else (
                "interactive" if row.need_interactive > 0 and row.need_baseline <= 0 else "baseline"
            )
        ),
        baseline_label_fn=lambda row: f"{row.baseline_countable}/3",
        interactive_label_fn=lambda row: f"{row.interactive_countable}/4",
        recommended_reason_fn=lambda row: (
            "installed build differs from newest static plan"
            if row.live_build_drift
            else (
                "baseline complete, interactive runs needed"
                if row.need_baseline <= 0 and row.need_interactive > 0
                else "baseline runs needed"
            )
        ),
    )

    assert summary["queue_summary"]["drifted_apps"] == 1
    assert summary["drift_apps"][0]["app"] == "BBC News"
    assert summary["drift_apps"][0]["installed_build"] == "10007091"
    assert "no longer live-current" in summary["drift_apps"][0]["evidence_scope"]
    assert len(summary["capture_candidates"]) == 2
    assert summary["capture_candidates"][0]["app"] == "WhatsApp"
    assert summary["capture_candidates"][0]["next_action"] == "interactive"
    assert summary["capture_candidates"][1]["app"] == "Facebook"
    assert summary["freeze_guidance"]["mode"] == "capture_non_drift_or_freeze_build_scoped"


def test_summarize_prepared_view_requires_device_before_live_current_guidance() -> None:
    prepared = SimpleNamespace(
        row_models=[
            SimpleNamespace(
                package_name="com.whatsapp",
                display_name="WhatsApp",
                live_build_drift=False,
                lineage_state="current_build_observed",
                need_baseline=0,
                need_interactive=2,
                baseline_countable=3,
                baseline_extra=0,
                baseline_low_signal_supplemental=0,
                interactive_countable=2,
                interactive_extra=1,
                interactive_low_signal_supplemental=0,
            )
        ],
        current_build_ready_count=0,
        current_build_in_progress_count=1,
        current_build_review_count=0,
        current_build_db_only_count=0,
        historical_local_only_app_count=0,
        historical_db_only_app_count=0,
        no_evidence_anywhere_count=0,
        mixed_identity_app_count=0,
        dataset_apps_total=1,
        expected_runs=7,
        dataset_valid_runs_total=5,
        evidence_summary={"quota_runs_counted": 5, "apps_satisfied": 0},
    )

    summary = report.summarize_prepared_view(
        prepared=prepared,
        cohort_label="Research Dataset Beta",
        cohort_key="research_dataset_beta",
        device_serial=None,
        device_label="none",
        candidate_limit=2,
        queue_status_label_fn=lambda row: "interactive",
        baseline_label_fn=lambda row: f"{row.baseline_countable}/3",
        interactive_label_fn=lambda row: f"{row.interactive_countable}/4",
        recommended_reason_fn=lambda _row: "baseline complete, interactive runs needed",
    )

    assert summary["device"]["live_drift_checked"] is False
    assert summary["freeze_guidance"]["mode"] == "select_device_first"
    assert "Select a device" in summary["freeze_guidance"]["summary"]


def test_summarize_prepared_view_reports_empty_queue_explicitly() -> None:
    prepared = SimpleNamespace(
        row_models=[],
        current_build_ready_count=0,
        current_build_in_progress_count=0,
        current_build_review_count=0,
        current_build_db_only_count=0,
        historical_local_only_app_count=0,
        historical_db_only_app_count=0,
        no_evidence_anywhere_count=0,
        mixed_identity_app_count=0,
        dataset_apps_total=0,
        expected_runs=0,
        dataset_valid_runs_total=0,
        evidence_summary={},
    )

    summary = report.summarize_prepared_view(
        prepared=prepared,
        cohort_label="Research Dataset Beta",
        cohort_key="research_dataset_beta",
        device_serial=None,
        device_label="none",
        candidate_limit=2,
        queue_status_label_fn=lambda _row: "baseline",
        baseline_label_fn=lambda _row: "0/3",
        interactive_label_fn=lambda _row: "0/4",
        recommended_reason_fn=lambda _row: "baseline runs needed",
    )

    assert summary["freeze_guidance"]["mode"] == "empty_queue"
    assert "No dataset apps were resolved" in summary["freeze_guidance"]["summary"]
