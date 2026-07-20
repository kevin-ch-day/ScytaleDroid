from __future__ import annotations

from pathlib import Path

import pytest
from tests.device_analysis._harvest_runner_support import (
    isolate_storage_contract,
    make_artifact_plan,
    make_inventory_row,
    make_package_plan,
    patch_runner_common,
)

pytestmark = [pytest.mark.unit]


@pytest.fixture(autouse=True)
def _isolate_storage_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    isolate_storage_contract(tmp_path, monkeypatch)


def test_execute_harvest_stops_early_when_device_becomes_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from scytaledroid.Database.db_utils import diagnostics
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.harvest.models import ArtifactError

    patch_runner_common(monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path, with_storage_root=False)

    calls: list[str] = []

    def _fake_pull(**kwargs):
        calls.append(kwargs["source_path"])
        return ArtifactError(source_path=kwargs["source_path"], reason="device_unavailable")

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)

    def _plan(package_name: str):
        return make_package_plan(
            inventory=make_inventory_row(
                package_name=package_name,
                app_label=package_name,
                primary_path=f"/data/app/{package_name}/base.apk",
                apk_paths=[f"/data/app/{package_name}/base.apk"],
                profile_key=None,
            ),
            artifacts=[
                make_artifact_plan(
                    source_path=f"/data/app/{package_name}/base.apk",
                    artifact="base",
                    file_name=f"{package_name.replace('.', '_')}__base.apk",
                )
            ],
            total_paths=1,
        )

    results = runner.execute_harvest(
        serial="SERIAL123",
        adb_path="adb",
        dest_root=tmp_path / "SERIAL123" / "20260328",
        session_stamp="20260328",
        plans=[_plan("com.example.one"), _plan("com.example.two")],
        config=object(),
        pull_mode="inventory",
    )

    assert len(results) == 1
    assert results[0].errors[0].reason == "device_unavailable"
    assert calls == ["/data/app/com.example.one/base.apk"]
    assert "ADB device unavailable; stopping harvest early." in capsys.readouterr().out


def test_print_progress_line_separates_reviewed_eligible_attempted_and_blocked(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.harvest.models import PullResult

    result = PullResult(
        plan=make_package_plan(
            inventory=make_inventory_row(
                package_name="com.example.progress",
                app_label="Progress App",
                primary_path="/data/app/com.example.progress/base.apk",
                apk_paths=["/data/app/com.example.progress/base.apk"],
                profile_key=None,
            ),
            artifacts=[],
            total_paths=1,
        )
    )
    runner._print_progress_line(
        result,
        {
            "packages_total": 578,
            "packages_reviewed": 120,
            "packages_eligible": 152,
            "packages_attempted": 31,
            "packages_harvested": 28,
            "packages_skipped": 89,
            "packages_runtime_skipped": 3,
            "packages_replanned": 2,
            "packages_replan_recovered": 1,
            "packages_replan_failed": 1,
            "packages_partial": 0,
            "packages_failed": 0,
            "packages_drifted": 3,
        },
        package_index=31,
        package_total=152,
        force=True,
    )
    out = capsys.readouterr().out
    assert "reviewed 120/578" in out
    assert "eligible 152" in out
    assert "attempted 31" in out
    assert "resolved 28" in out
    assert "blocked before pull 89" in out
    assert "replanned 2 (recovered 1, failed 1)" in out
    assert "blocked reviewed" not in out


def test_update_package_outcome_tolerates_legacy_pull_result_without_replan_fields() -> None:
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.harvest.models import PullResult

    result = PullResult(
        plan=make_package_plan(
            inventory=make_inventory_row(
                package_name="com.example.legacyresult",
                app_label="Legacy Result",
                primary_path="/data/app/com.example.legacyresult/base.apk",
                apk_paths=["/data/app/com.example.legacyresult/base.apk"],
                profile_key=None,
            ),
            artifacts=[],
            total_paths=1,
        ),
        capture_status="clean",
    )
    delattr(result, "stale_replan_required")
    delattr(result, "stale_replan_outcome")

    stats = {
        "packages_reviewed": 0,
        "packages_attempted": 0,
        "packages_harvested": 0,
        "packages_runtime_skipped": 0,
        "packages_path_stale": 0,
        "packages_replanned": 0,
        "packages_replan_success": 0,
        "packages_replan_failed": 0,
        "packages_replan_recovered": 0,
        "packages_drifted": 0,
        "packages_partial": 0,
        "packages_failed": 0,
        "packages_clean": 0,
        "packages_mirror_failed": 0,
    }

    runner._update_package_outcome(stats, result)

    assert stats["packages_reviewed"] == 1
    assert stats["packages_attempted"] == 1
    assert stats["packages_clean"] == 1
    assert stats["packages_path_stale"] == 0
    assert stats["packages_replanned"] == 0
    assert stats["packages_replan_recovered"] == 0
