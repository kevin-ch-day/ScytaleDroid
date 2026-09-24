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
                canonical_store_path=f"data/store/apk/sha256/aa/{'a' * 64}.apk",
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
    assert result.comparison["canonical_store_complete"] is True
    assert result.comparison["canonical_durability_status"] == "ok"
    assert result.capture_status == "clean"
    assert result.research_status == "pending_audit"


def test_finalize_blocks_research_when_canonical_store_path_missing() -> None:
    inventory = _inventory(
        declared_split_count=1,
        paths=["/data/app/base.apk"],
    )
    result = _complete_pull_result(inventory)
    result.ok[0].canonical_store_path = None

    package_contract.finalize_package_result(result, write_db_requested=True)

    assert result.capture_status == "partial"
    assert result.persistence_status == "mirror_failed"
    assert result.research_status == "ineligible"
    assert "canonical_materialization_failed" in result.mirror_failure_reasons
    assert result.comparison["canonical_durability_status"] == "failed"


def test_finalize_blocks_research_when_canonical_error_present() -> None:
    from scytaledroid.DeviceAnalysis.harvest.models import (
        CANONICAL_MATERIALIZATION_FAILED,
        ArtifactError,
    )

    inventory = _inventory(
        declared_split_count=1,
        paths=["/data/app/base.apk"],
    )
    result = _complete_pull_result(inventory)
    result.errors.append(
        ArtifactError(
            source_path="/data/app/base.apk",
            reason=CANONICAL_MATERIALIZATION_FAILED,
            sha256="a" * 64,
            session_copy="/tmp/base.apk",
        )
    )

    package_contract.finalize_package_result(result, write_db_requested=True)

    assert result.capture_status == "partial"
    assert result.persistence_status == "mirror_failed"
    assert result.research_status == "ineligible"
