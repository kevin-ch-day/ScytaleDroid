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
        rows=rows,
        synced_app_definitions=2,
        elapsed_seconds=5.0,
        delta=delta,
        first_snapshot=False,
    )


def test_print_inventory_run_summary_from_result(capsys):
    result = _fake_result()
    print_inventory_run_summary_from_result(result)
    out = colors.strip(capsys.readouterr().out)
    assert "Inventory Sync · RUN SUMMARY" in out
    assert "[RUN] Snapshot" in out
    assert re.search(r"Packages\s*:\s*2", out)
    assert "Delta vs previous" in out
    assert "[RESULT] User apps" in out or "User apps (candidates)" in out
