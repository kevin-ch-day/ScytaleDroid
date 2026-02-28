from collections import Counter
from pathlib import Path

from scytaledroid.DeviceAnalysis.harvest.models import (
    ArtifactPlan,
    HarvestPlan,
    InventoryRow,
    PackagePlan,
    ScopeSelection,
)
from scytaledroid.DeviceAnalysis.harvest.summary import HarvestRunMetrics
from scytaledroid.DeviceAnalysis.harvest.views import (
    render_harvest_summary_structured,
    render_scope_overview,
)


def _dummy_selection() -> ScopeSelection:
    raw = {
        "package_name": "com.example.app",
        "app_label": "Example",
        "installer": "play",
        "category": "social",
        "primary_path": "/data/app/com.example.app/base.apk",
        "profile_key": "SOCIAL",
        "profile": "social",
        "version_code": "1",
        "version_name": "1.0",
        "apk_paths": ["/data/app/com.example.app/base.apk"],
        "split_count": 1,
    }
    inv = InventoryRow(
        raw=raw,
        package_name="com.example.app",
        app_label="Example",
        installer="play",
        category="social",
        profile="social",
        profile_key="SOCIAL",
        primary_path="/data/app/com.example.app/base.apk",
        apk_paths=["/data/app/com.example.app/base.apk"],
        split_count=1,
        version_code="1",
        version_name="1.0",
    )
    pkg_plan = PackagePlan(
        inventory=inv,
        artifacts=[
            ArtifactPlan(
                "/data/app/com.example.app/base.apk",
                "com_example_app_1__base.apk",
                "base.apk",
                False,
            )
        ],
        total_paths=1,
    )
    return ScopeSelection(label="Test Scope", packages=[inv], kind="test", metadata={"candidate_count": 1}), HarvestPlan(
        packages=[pkg_plan], policy_filtered={}, failures=[]
    )


def test_render_scope_overview(capsys):
    selection, plan = _dummy_selection()
    render_scope_overview(selection=selection, plan=plan, is_rooted=False, include_system_partitions=False)
    out = capsys.readouterr().out
    assert "APK Harvest · RUN START" in out
    assert "[RUN] Scope" in out
    assert "Test Scope" in out


def test_render_harvest_summary_structured(capsys):
    metrics = HarvestRunMetrics(
        total_packages=1,
        blocked_packages=0,
        executed_packages=1,
        planned_artifacts=1,
        artifacts_written=1,
        artifacts_failed=0,
        artifact_status_counter=None,  # type: ignore[arg-type]
        packages_with_writes=1,
        packages_with_errors=0,
        packages_failed=0,
        packages_skipped_runtime=0,
        runtime_skips=Counter(),
        runtime_notes=Counter(),
        preflight_skips={},
    )
    render_harvest_summary_structured(
        selection_label="Test Scope",
        metrics=metrics,
        pull_mode="inventory",
        output_root=str(Path("/tmp/output")),
        preflight_skips={},
        runtime_skips={},
        policy_filtered={},
        session_stamp="RUN-123",
    )
    out = capsys.readouterr().out
    assert "APK Harvest · RUN SUMMARY" in out
    assert "[RUN] Scope" in out
    assert "planned=1" in out or "planned=1  written=1" in out
    assert "/tmp/output" in out
