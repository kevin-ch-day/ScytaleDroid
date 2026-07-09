from __future__ import annotations

from scytaledroid.DeviceAnalysis.harvest import runner
from scytaledroid.DeviceAnalysis.harvest.models import ArtifactPlan, InventoryRow, PackagePlan
from scytaledroid.Utils.DisplayUtils import colors


def _package_plan() -> PackagePlan:
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
    inventory = InventoryRow(
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
    return PackagePlan(
        inventory=inventory,
        artifacts=[ArtifactPlan(inventory.primary_path or "", "artifact.apk", "artifact.apk", False)],
        total_paths=1,
    )


def test_package_footer_suppresses_pure_apk_library_hits_in_simple_mode(monkeypatch, capsys) -> None:
    monkeypatch.setenv("SCYTALEDROID_HARVEST_SIMPLE", "1")

    runner._print_package_footer(
        _package_plan(),
        {"saved": 0, "skipped": 4, "errors": 0, "bytes": 0, "library_hits": 4},
        1,
        1,
        compact_mode=True,
    )

    assert capsys.readouterr().out == ""


def test_package_footer_renders_apk_library_hits_as_reuse_not_warning(monkeypatch, capsys) -> None:
    monkeypatch.setenv("SCYTALEDROID_HARVEST_SIMPLE", "0")
    monkeypatch.setenv("SCYTALEDROID_HARVEST_QUIET", "0")

    runner._print_package_footer(
        _package_plan(),
        {"saved": 0, "skipped": 4, "errors": 0, "bytes": 0, "library_hits": 4},
        1,
        1,
        compact_mode=True,
    )

    out = colors.strip(capsys.readouterr().out)
    assert "[WARN]" not in out
    assert "reused 4/4 from APK library" in out
    assert "errors 0" in out
