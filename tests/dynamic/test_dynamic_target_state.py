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


def test_dynamic_target_state_allows_more_collection_when_latest_invalid_but_quota_incomplete() -> None:
    state = make_dataset_state(
        "org.telegram.messenger",
        valid_runs=4,
        baseline_valid_runs=3,
        interactive_valid_runs=1,
        quota_met=False,
        active_version_code="69222",
    )
    latest = make_recent_summary(
        ended_at="2026-07-09T04:00:00Z",
        run_profile="interaction_manual",
        interaction_level="manual",
        messaging_activity="voice_call",
        valid=False,
        invalid_reason_code="INSUFFICIENT_DURATION",
        run_id="telegram-aborted-call",
        status_label="INVALID:INSUFFICIENT_DURATION",
    )

    target = derive_dynamic_target_state(
        package_name="org.telegram.messenger",
        state=state,
        latest_recent=latest,
        db_active_sessions=4,
        has_identity_mismatch=False,
    )

    assert target.study_status == "in_progress"
    assert target.capture_status == "allowed"
    assert target.publication_status == "not_ready"
    assert target.latest_invalid_reason == "INSUFFICIENT_DURATION"


def test_dynamic_target_state_keeps_review_when_latest_invalid_and_baseline_incomplete() -> None:
    state = make_dataset_state(
        "com.google.android.apps.messaging",
        valid_runs=1,
        baseline_valid_runs=0,
        interactive_valid_runs=1,
        quota_met=False,
        active_version_code="123",
    )
    latest = make_recent_summary(
        ended_at="2026-07-09T04:00:00Z",
        run_profile="baseline_connected",
        interaction_level="minimal",
        valid=False,
        invalid_reason_code="PCAP_MISSING",
        run_id="messaging-failed-baseline",
        status_label="INVALID:PCAP_MISSING",
    )

    target = derive_dynamic_target_state(
        package_name="com.google.android.apps.messaging",
        state=state,
        latest_recent=latest,
        db_active_sessions=1,
        has_identity_mismatch=False,
    )

    assert target.study_status == "qa_review"
    assert target.capture_status == "blocked_qa_review"


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
