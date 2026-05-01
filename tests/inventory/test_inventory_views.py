import re
from types import SimpleNamespace

from scytaledroid.DeviceAnalysis.inventory import views
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
        serial="ZY22JK89DR",
        snapshot_path="data/state/device/inventory.json",
        snapshot_id=11,
        rows=rows,
        previous_total=2,
        synced_app_definitions=2,
        elapsed_seconds=5.0,
        delta=delta,
        first_snapshot=False,
        fallback_used=True,
    )


def test_print_inventory_run_summary_from_result(capsys):
    result = _fake_result()
    views.snapshot_io.get_inventory_retention_status = lambda _serial: {
        "policy_keep_last": 5,
        "db_snapshots": 5,
        "fs_snapshots": 2,
    }
    print_inventory_run_summary_from_result(result)
    out = colors.strip(capsys.readouterr().out)
    assert "Refresh inventory · summary" in out
    assert "Snapshot ID" in out
    assert "11" in out
    assert re.search(r"Packages\s*:\s*2", out)
    assert re.search(r"Split APK packages\s*:\s*0", out)
    assert "Duration" in out and "5s" in out
    assert "Delta vs previous" in out
    assert "updated=0" in out
    assert "data/state/device/inventory.json" not in out
    assert "Retention: 5 kept (DB 5, FS 2)" in out
    assert "Refresh inventory complete" in out and "snapshot 11" in out
    assert "2 packages on this snapshot" in out


def test_inventory_summary_field_order_is_stable(capsys):
    result = _fake_result()
    views.snapshot_io.get_inventory_retention_status = lambda _serial: {
        "policy_keep_last": 5,
        "db_snapshots": 5,
        "fs_snapshots": 2,
    }
    print_inventory_run_summary_from_result(result)
    out = colors.strip(capsys.readouterr().out)
    lines = [line.rstrip() for line in out.splitlines() if line.strip()]

    expected_prefixes = [
        "[RUN] Snapshot ID",
        "[RUN] Packages",
        "[RUN] Duration",
        "[RESULT] Delta vs previous",
        "[RESULT] Split APK packages",
    ]
    positions = []
    for prefix in expected_prefixes:
        for index, line in enumerate(lines):
            if line.startswith(prefix):
                positions.append(index)
                break
        else:
            raise AssertionError(f"missing line with prefix: {prefix}")
    assert positions == sorted(positions)


def test_print_inventory_run_summary_labels_metadata_only_changes(capsys):
    result = _fake_result()
    views.snapshot_io.get_inventory_retention_status = lambda _serial: {
        "policy_keep_last": 5,
        "db_snapshots": 5,
        "fs_snapshots": 2,
    }
    result.delta = SimpleNamespace(new_count=0, removed_count=0, updated_count=21)
    print_inventory_run_summary_from_result(result)

    out = colors.strip(capsys.readouterr().out)
    assert "metadata_changed=21" in out
    assert "(package set unchanged)" in out
    assert "(identical to previous snapshot)" not in out
