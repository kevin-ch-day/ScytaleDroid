import re
from types import SimpleNamespace

from scytaledroid.DeviceAnalysis.inventory.views import print_inventory_run_summary_from_result
from scytaledroid.Utils.DisplayUtils import colors


def _fake_result():
    rows = [
        {
            "package_name": "com.example.app",
            "primary_path": "/data/app/com.example.app/base.apk",
            "split_count": 1,
            "source": "Play Store",
            "owner_role": "User",
        },
        {
            "package_name": "com.android.systemui",
            "primary_path": "/system/systemui.apk",
            "split_count": 1,
            "owner_role": "System",
        },
    ]
    delta = SimpleNamespace(new_count=0, removed_count=0, updated_count=0)
    return SimpleNamespace(
        snapshot_path="data/state/device/inventory.json",
        snapshot_id=11,
        rows=rows,
        synced_app_definitions=2,
        elapsed_seconds=5.0,
        delta=delta,
        first_snapshot=False,
        fallback_used=True,
    )


def test_print_inventory_run_summary_from_result(capsys):
    result = _fake_result()
    print_inventory_run_summary_from_result(result)
    out = colors.strip(capsys.readouterr().out)
    assert "Refresh Inventory · RUN SUMMARY" in out
    assert "[RUN] Snapshot" in out
    assert "data/state/device/inventory.json" in out
    assert "Snapshot ID" in out
    assert "11" in out
    assert re.search(r"Packages\s*:\s*2", out)
    assert re.search(r"Split APK packages\s*:\s*0", out)
    assert "Scan duration" in out and "05s" in out
    assert re.search(r"Avg rate\s*:\s*0.40 pkg/s", out)
    assert re.search(r"Fallback mode\s*:\s*enabled", out)
    assert "Delta vs previous" in out
    assert "updated=0" in out
    assert re.search(r"User apps \(candidates\)\s*:\s*1", out)


def test_inventory_summary_field_order_is_stable(capsys):
    result = _fake_result()
    print_inventory_run_summary_from_result(result)
    out = colors.strip(capsys.readouterr().out)

    expected_order = [
        "Snapshot",
        "Snapshot ID",
        "Packages",
        "Split APK packages",
        "Avg rate",
        "Fallback mode",
        "User apps (candidates)",
        "Delta vs previous",
        "Scan duration",
    ]
    positions = [out.find(token) for token in expected_order]
    assert all(pos >= 0 for pos in positions)
    assert positions == sorted(positions)
