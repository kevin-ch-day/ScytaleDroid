from __future__ import annotations

from scytaledroid.DeviceAnalysis.harvest.models import ArtifactPlan, InventoryRow, PackagePlan
from scytaledroid.DeviceAnalysis.harvest.stale_replan import (
    STALE_REPLAN_FAILURE_OUTCOMES,
    STALE_REPLAN_SUCCESS_OUTCOMES,
    build_stale_replan_details,
    classify_stale_replan_outcome,
    is_failed_stale_replan_outcome,
    is_successful_stale_replan_outcome,
)


def _plan(*, skip_reason: str | None = None, version_code: str = "1") -> PackagePlan:
    inventory = InventoryRow(
        raw={},
        package_name="com.example.app",
        app_label="Example App",
        installer="com.android.vending",
        category=None,
        primary_path="/data/app/com.example.app/base.apk",
        profile_key="TEST_PROFILE",
        profile=None,
        version_name="1.0",
        version_code=version_code,
        apk_paths=["/data/app/com.example.app/base.apk"],
        split_count=1,
    )
    return PackagePlan(
        inventory=inventory,
        artifacts=[
            ArtifactPlan(
                source_path="/data/app/com.example.app/base.apk",
                artifact="base",
                file_name=f"com_example_app_{version_code}__base.apk",
                is_split_member=False,
            )
        ],
        total_paths=1,
        skip_reason=skip_reason,
    )


def test_classify_stale_replan_outcome_prefers_skip_and_version_change() -> None:
    assert classify_stale_replan_outcome(refreshed_plan=_plan(skip_reason="no_paths"), drift_reasons=()) == (
        "path_stale_package_no_longer_accessible"
    )
    assert classify_stale_replan_outcome(
        refreshed_plan=_plan(skip_reason="policy_non_root"),
        drift_reasons=("refreshed_skip:policy_non_root",),
    ) == "path_stale_blocked_before_pull"
    assert classify_stale_replan_outcome(
        refreshed_plan=_plan(),
        drift_reasons=("version_code_changed",),
    ) == "path_stale_package_updated_since_inventory"
    assert classify_stale_replan_outcome(
        refreshed_plan=_plan(),
        drift_reasons=("artifact_set_changed",),
    ) == "path_stale_package_paths_changed_since_inventory"


def test_stale_replan_outcome_sets_are_classified_consistently() -> None:
    for outcome in STALE_REPLAN_SUCCESS_OUTCOMES:
        assert is_successful_stale_replan_outcome(outcome) is True
        assert is_failed_stale_replan_outcome(outcome) is False
    for outcome in STALE_REPLAN_FAILURE_OUTCOMES:
        assert is_successful_stale_replan_outcome(outcome) is False
        assert is_failed_stale_replan_outcome(outcome) is True


def test_build_stale_replan_details_uses_refreshed_inventory_fields() -> None:
    details = build_stale_replan_details(
        refreshed_plan=_plan(version_code="2"),
        drift_reasons=("version_code_changed",),
    )

    assert details["refresh_failed"] is False
    assert details["refreshed_primary_path"] == "/data/app/com.example.app/base.apk"
    assert details["refreshed_version_code"] == "2"
    assert details["drift_reasons"] == ["version_code_changed"]
