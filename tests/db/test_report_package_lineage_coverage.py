"""Pure action-classification tests for the package lineage coverage report."""

from __future__ import annotations

from scripts.db import report_apk_lineage_availability as report


def test_missing_bytes_in_missing_root_recommends_restore() -> None:
    action = report._recommended_action(
        bytes_available=False,
        static_qualifying=0,
        dynamic_sessions=10,
        dynamic_unlinked=10,
        availability_state="MISSING_RESTORABLE_ROOT",
        app_version_present=True,
    )

    assert action == "restore_artifacts"


def test_available_dynamic_gap_recommends_analysis() -> None:
    action = report._recommended_action(
        bytes_available=True,
        static_qualifying=0,
        dynamic_sessions=3,
        dynamic_unlinked=3,
        availability_state="AVAILABLE_CANONICAL_ONLY",
        app_version_present=True,
    )

    assert action == "analyze_available_hash"


def test_exact_static_with_unlinked_dynamic_recommends_link_preview() -> None:
    action = report._recommended_action(
        bytes_available=True,
        static_qualifying=1,
        dynamic_sessions=3,
        dynamic_unlinked=3,
        availability_state="AVAILABLE_RECORDED_AND_CANONICAL",
        app_version_present=True,
    )

    assert action == "link_repair_preview_available"


def test_same_version_hash_change_promotes_review_action() -> None:
    packages = [
        {
            "recommended_actions": ["covered"],
            "recommended_action": "covered",
            "hashes": [
                {
                    "version_code": "1",
                    "version_name": "1.0",
                    "base_apk_sha256": "a" * 64,
                    "artifact_set_hash": "c" * 64,
                },
                {
                    "version_code": "1",
                    "version_name": "1.0",
                    "base_apk_sha256": "b" * 64,
                    "artifact_set_hash": "d" * 64,
                },
            ],
        }
    ]

    report._annotate_lineage_review_actions(packages)

    assert packages[0]["same_version_hash_changed_review"] is True
    assert "same_version_hash_changed_review" in packages[0]["recommended_actions"]
    assert packages[0]["recommended_action"] == "same_version_hash_changed_review"


def test_recovery_action_maps_missing_old_root_to_restore_old_root() -> None:
    from scripts.db import report_dynamic_static_recovery_plan as recovery

    action = recovery._recovery_action(
        {
            "recommended_action": "restore_artifacts",
            "recorded_storage_root": "/missing/old/root",
            "recorded_storage_root_exists": False,
            "canonical_store_file_available": False,
        },
        static_exact_coverage=0,
    )

    assert action == "restore_old_root"


def test_recovery_action_static_coverage_wins() -> None:
    from scripts.db import report_dynamic_static_recovery_plan as recovery

    action = recovery._recovery_action(
        {"recommended_action": "restore_artifacts"},
        static_exact_coverage=1,
    )

    assert action == "already_covered_refresh_report"


def test_static_target_dynamic_gap_missing_old_root_is_blocked() -> None:
    from scripts.db import report_static_analysis_targets as targets

    byte_status = targets._byte_status(
        recorded_exists=False,
        canonical_exists=False,
        recorded_root_exists=False,
        recorded_location_known=True,
    )
    status = targets._target_status(
        exact_static=0,
        byte_status=byte_status,
        split_status="unknown_until_bytes_restored",
        dynamic_unlinked=5,
        same_version_hash_drift=False,
    )
    reason = targets._target_reason(
        exact_static=0,
        byte_status=byte_status,
        dynamic_sessions=5,
        dynamic_unlinked=5,
        same_version_hash_drift=False,
    )

    assert byte_status == "missing_old_root"
    assert status == "blocked_missing_bytes"
    assert reason == "dynamic_static_gap"


def test_static_target_exact_static_with_unlinked_dynamic_is_link_preview() -> None:
    from scripts.db import report_static_analysis_targets as targets

    status = targets._target_status(
        exact_static=1,
        byte_status="available_canonical",
        split_status="install_set_known",
        dynamic_unlinked=2,
        same_version_hash_drift=False,
    )

    assert status == "link_repair_preview_available"


def test_static_target_static_covered_recorded_only_rebuilds_store() -> None:
    from scripts.db import report_static_analysis_targets as targets

    status = targets._target_status(
        exact_static=1,
        byte_status="available_recorded",
        split_status="install_set_known",
        dynamic_unlinked=0,
        same_version_hash_drift=False,
    )

    assert status == "rebuild_canonical_store"
