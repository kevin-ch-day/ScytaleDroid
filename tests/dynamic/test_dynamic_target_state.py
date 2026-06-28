from __future__ import annotations

from scytaledroid.DynamicAnalysis.services.dynamic_target_state import derive_dynamic_target_state

from tests.dynamic._guided_run_state_support import make_dataset_state, make_recent_summary


def test_dynamic_target_state_marks_historical_only_when_only_legacy_evidence_exists() -> None:
    state = make_dataset_state(
        "com.twitter.android",
        historical_valid_runs=3,
        historical_build_count=1,
        local_evidence_dir_count=3,
    )

    target = derive_dynamic_target_state(
        package_name="com.twitter.android",
        state=state,
        db_historical_sessions=3,
        has_identity_mismatch=False,
    )

    assert target.study_status == "historical_only"
    assert target.publication_status == "historical_candidate"
    assert target.capture_status == "allowed"


def test_dynamic_target_state_marks_qa_review_when_latest_current_build_run_is_invalid() -> None:
    state = make_dataset_state(
        "com.cnn.mobile.android.phone",
        valid_runs=5,
        baseline_valid_runs=3,
        interactive_valid_runs=2,
        quota_met=True,
        active_version_code="19127521",
    )
    latest = make_recent_summary(
        ended_at="2026-06-20T10:00:00Z",
        run_profile="interaction_scripted",
        interaction_level="scripted",
        valid=False,
        invalid_reason_code="PCAP_MISSING",
        pcap_failure_detail="PCAP_DEVICE_FILE_MISSING",
        run_id="cnn-run-1",
        status_label="INVALID:PCAP_MISSING",
    )

    target = derive_dynamic_target_state(
        package_name="com.cnn.mobile.android.phone",
        state=state,
        latest_recent=latest,
        db_active_sessions=1,
        has_identity_mismatch=False,
    )

    assert target.study_status == "qa_review"
    assert target.capture_status == "blocked_qa_review"
    assert target.publication_status == "ready_after_qa"
    assert target.latest_invalid_reason == "PCAP_MISSING"
    assert target.latest_pcap_failure_detail == "PCAP_DEVICE_FILE_MISSING"


def test_dynamic_target_state_marks_drifted_live_device_as_refresh_block() -> None:
    state = make_dataset_state(
        "com.cnn.mobile.android.phone",
        valid_runs=5,
        baseline_valid_runs=3,
        interactive_valid_runs=2,
        quota_met=True,
        active_version_code="19127521",
    )

    target = derive_dynamic_target_state(
        package_name="com.cnn.mobile.android.phone",
        state=state,
        live_build_drift=True,
        db_active_sessions=1,
    )

    assert target.live_device_status == "drifted"
    assert target.capture_status == "blocked_refresh_required"
    assert target.publication_status == "historical_candidate"
