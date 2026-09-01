from __future__ import annotations

from pathlib import Path

from scytaledroid.DeviceAnalysis.harvest import package_contract, planner
from scytaledroid.DeviceAnalysis.harvest.models import ArtifactResult, InventoryRow, PullResult


def _inventory(*, declared_split_count: int, paths: list[str]) -> InventoryRow:
    return InventoryRow(
        raw={
            "package_manager_split_names": ["base"]
            + [f"config.{index}" for index in range(1, declared_split_count)],
            "package_manager_split_count": declared_split_count,
        },
        package_name="com.example.app",
        app_label="Example",
        installer="com.android.vending",
        category="User",
        primary_path=paths[0],
        profile_key="SOCIAL",
        profile="Social",
        version_name="1.0",
        version_code="100",
        apk_paths=paths,
        split_count=len(paths),
    )


def _complete_pull_result(inventory: InventoryRow) -> PullResult:
    package_plan = planner.build_harvest_plan([inventory]).packages[0]
    result = PullResult(plan=package_plan)
    for artifact in package_plan.artifacts:
        result.ok.append(
            ArtifactResult(
                file_name=artifact.file_name,
                apk_id=None,
                dest_path=Path("/tmp") / artifact.file_name,
                source_path=artifact.source_path,
                sha256="a" * 64,
                artifact_label=artifact.artifact,
                is_base=not artifact.is_split_member,
            )
        )
    return result


def test_complete_pull_is_research_ineligible_when_inventory_omits_declared_split() -> None:
    inventory = _inventory(
        declared_split_count=3,
        paths=["/data/app/base.apk", "/data/app/split_config.en.apk"],
    )
    result = _complete_pull_result(inventory)

    package_contract.finalize_package_result(result, write_db_requested=False)

    assert result.comparison["matches_planned_artifacts"] is True
    assert result.comparison["inventory_paths_match_declared_splits"] is False
    assert result.capture_status == "partial"
    assert result.research_status == "ineligible"


def test_complete_pull_remains_clean_when_declared_and_path_counts_match() -> None:
    inventory = _inventory(
        declared_split_count=2,
        paths=["/data/app/base.apk", "/data/app/split_config.en.apk"],
    )
    result = _complete_pull_result(inventory)

    package_contract.finalize_package_result(result, write_db_requested=False)

    assert result.comparison["inventory_paths_match_declared_splits"] is True
    assert result.capture_status == "clean"
    assert result.research_status == "pending_audit"
