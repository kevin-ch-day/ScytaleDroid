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
    assert "Inventory Sync · RUN SUMMARY" in out
    assert "[RUN] Snapshot path: data/state/device/inventory.json" in out
    assert "[RUN] Snapshot id: 11" in out
    assert re.search(r"Packages\s*:\s*2", out)
    assert re.search(r"Split packages\s*:\s*0", out)
    assert "Duration: 05s" in out
    assert "Avg rate: 0.40 pkg/s" in out
    assert "Fallback mode: enabled" in out
    assert "Delta vs previous" in out
    assert "updated=0" in out
    assert "User apps (candidates): 1" in out


def test_inventory_summary_field_order_is_stable(capsys):
    result = _fake_result()
    print_inventory_run_summary_from_result(result)
    out = colors.strip(capsys.readouterr().out)

    expected_order = [
        "[RUN] Snapshot path:",
        "[RUN] Snapshot id:",
        "Packages:",
        "Split packages:",
        "Duration:",
        "Avg rate:",
        "Fallback mode:",
        "Delta vs previous:",
        "User apps (candidates):",
    ]
    positions = [out.find(token) for token in expected_order]
    assert all(pos >= 0 for pos in positions)
    assert positions == sorted(positions)
