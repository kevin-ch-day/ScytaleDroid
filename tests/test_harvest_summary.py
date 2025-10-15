"""Unit tests for harvest summary helpers."""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scytaledroid.DeviceAnalysis.harvest import summary as harvest_summary
from scytaledroid.DeviceAnalysis.harvest.models import (
    ArtifactPlan,
    ArtifactResult,
    ArtifactError,
    HarvestPlan,
    InventoryRow,
    PackagePlan,
    PullResult,
    ScopeSelection,
)


def _inventory(package_name: str, label: str | None = None) -> InventoryRow:
    return InventoryRow(
        raw={},
        package_name=package_name,
        app_label=label or package_name,
        installer="com.android.vending",
        category=None,
        primary_path="/data/app",
        profile=None,
        version_name="1.0",
        version_code="1",
        apk_paths=[],
        split_count=0,
    )


def _build_sample_metrics() -> tuple[harvest_summary.HarvestRunMetrics, int]:
    inv_one = _inventory("com.test.one", "Test One")
    inv_two = _inventory("com.test.two", "Test Two")
    inv_three = _inventory("com.test.three", "Test Three")

    plan_one = PackagePlan(
        inventory=inv_one,
        artifacts=[
            ArtifactPlan(
                source_path="/data/app/com.test.one/base.apk",
                artifact="base",
                file_name="com_test_one_1__base.apk",
                is_split_member=False,
            )
        ],
        total_paths=1,
    )

    plan_two = PackagePlan(
        inventory=inv_two,
        artifacts=[],
        total_paths=0,
        skip_reason="policy_non_root",
    )

    plan_three = PackagePlan(
        inventory=inv_three,
        artifacts=[
            ArtifactPlan(
                source_path="/data/app/com.test.three/base.apk",
                artifact="base",
                file_name="com_test_three_1__base.apk",
                is_split_member=False,
            ),
            ArtifactPlan(
                source_path="/data/app/com.test.three/split.apk",
                artifact="split",
                file_name="com_test_three_1__split.apk",
                is_split_member=True,
            ),
        ],
        total_paths=2,
    )

    harvest_plan = HarvestPlan(
        packages=[plan_one, plan_two, plan_three],
        policy_filtered={},
        failures=[],
    )

    result_one = PullResult(plan=plan_one)
    result_one.ok.append(
        ArtifactResult(
            file_name="com_test_one_1__base.apk",
            apk_id=101,
            dest_path=Path("/tmp/com_test_one_1__base.apk"),
            source_path="/data/app/com.test.one/base.apk",
        )
    )

    result_two = PullResult(plan=plan_two)
    result_two.skipped.append("policy_non_root")

    result_three = PullResult(plan=plan_three)
    result_three.ok.append(
        ArtifactResult(
            file_name="com_test_three_1__base.apk",
            apk_id=201,
            dest_path=Path("/tmp/com_test_three_1__base.apk"),
            source_path="/data/app/com.test.three/base.apk",
        )
    )
    result_three.ok.append(
        ArtifactResult(
            file_name="com_test_three_1__split.apk",
            apk_id=None,
            dest_path=Path("/tmp/com_test_three_1__split.apk"),
            source_path="/data/app/com.test.three/split.apk",
            status="cached",
        )
    )
    result_three.errors.append(
        ArtifactError(
            source_path="/data/app/com.test.three/split.apk",
            reason="permission denied",
        )
    )
    result_three.skipped.append("dedupe_sha256")

    selection = ScopeSelection(
        label="Test scope",
        packages=[inv_one, inv_two, inv_three],
        kind="custom",
        metadata={},
    )

    harvest_result = harvest_summary._build_harvest_result(
        harvest_plan,
        [result_one, result_two, result_three],
        selection,
        serial="SER123",
        run_timestamp="20240101-000000",
        guard_brief=None,
    )

    metrics = harvest_summary.HarvestRunMetrics.from_run(
        harvest_plan, harvest_result, [result_one, result_two, result_three]
    )

    return metrics, metrics.artifacts_failed


def test_harvest_run_metrics_tracks_success_and_skips() -> None:
    """HarvestRunMetrics should aggregate package/artifact level outcomes."""

    metrics, pull_errors = _build_sample_metrics()

    assert metrics.total_packages == 3
    assert metrics.blocked_packages == 1
    assert metrics.executed_packages == 2
    assert metrics.planned_artifacts == 3
    assert metrics.artifacts_written == 2
    assert metrics.artifacts_failed == pull_errors == 1
    assert metrics.packages_with_writes == 2
    assert metrics.packages_with_errors == 1
    assert metrics.packages_failed == 0
    assert metrics.packages_with_partial_errors == 1
    assert metrics.packages_successful == 1
    assert metrics.packages_skipped_runtime == 0
    assert metrics.preflight_skips == {"policy_non_root": 1}
    assert metrics.runtime_skips == {"dedupe_sha256": 1}
    assert metrics.dedupe_skips == 1
    assert metrics.runtime_skip_total == 1
    assert metrics.artifact_status_excluding_written["cached"] == 1


def test_harvest_highlights_surface_key_states() -> None:
    """Highlights helper should summarise the most important signals."""

    metrics, pull_errors = _build_sample_metrics()
    highlights = harvest_summary._harvest_highlights(metrics, pull_errors)

    rendered = {f"{level}:{message}" for level, message in highlights}
    assert "success:1 package harvested cleanly" in rendered
    assert "warn:1 package finished with partial errors" in rendered
    assert "warn:1 runtime skip (top: Duplicate artifact)" in rendered
    assert "warn:1 artifact error encountered" in rendered
