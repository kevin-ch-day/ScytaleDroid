from datetime import UTC, datetime

from scytaledroid.DeviceAnalysis.inventory.diagnostics import compute_inventory_metrics
from scytaledroid.DeviceAnalysis.inventory.models import (
    InventoryDelta,
    InventorySnapshot,
    PackageRecord,
)


def test_inventory_delta_counts():
    prev = InventorySnapshot(
        device_serial="ABC",
        created_at=datetime.now(UTC),
        mode_key="baseline",
        packages=[
            PackageRecord(
                package_name="com.example.keep",
                label="Keep",
                install_source="Play Store",
                role="User",
                partition="Data (/data)",
                is_split=False,
                metadata={"version": "1"},
            ),
            PackageRecord(
                package_name="com.example.remove",
                label="Remove",
                install_source="Play Store",
                role="User",
                partition="Data (/data)",
                is_split=False,
                metadata={"version": "1"},
            ),
        ],
    )
    curr = InventorySnapshot(
        device_serial="ABC",
        created_at=datetime.now(UTC),
        mode_key="baseline",
        packages=[
            PackageRecord(
                package_name="com.example.keep",
                label="Keep",
                install_source="Play Store",
                role="User",
                partition="Data (/data)",
                is_split=False,
                metadata={"version": "2"},  # updated
            ),
            PackageRecord(
                package_name="com.example.new",
                label="New",
                install_source="Sideload",
                role="User",
                partition="Data (/data)",
                is_split=True,
                metadata={"version": "1"},
            ),
        ],
    )

    delta = InventoryDelta.from_snapshots(curr, prev)
    summary = delta.summary_counts()
    assert summary["new"] == 1
    assert summary["removed"] == 1
    assert summary["updated"] == 1


def test_compute_inventory_metrics_from_result():
    # Mimic a runner result with rows + delta + elapsed_seconds
    class DummyDelta:
        new_count = 1
        removed_count = 0
        updated_count = 2

    class DummyResult:
        def __init__(self):
            self.rows = [
                {
                    "package_name": "com.user.one",
                    "owner_role": "User",
                    "source": "Play Store",
                    "primary_path": "/data/app/one/base.apk",
                    "split_count": 1,
                },
                {
                    "package_name": "com.system.core",
                    "owner_role": "System",
                    "source": "Unknown",
                    "primary_path": "/system/app/core/base.apk",
                    "split_count": 2,
                },
                {
                    "package_name": "com.vendor.mod",
                    "owner_role": "Vendor",
                    "source": "Unknown",
                    "primary_path": "/vendor/app/mod/base.apk",
                    "split_count": 1,
                },
            ]
            self.delta = DummyDelta()
            self.elapsed_seconds = 125  # 2m 05s

    metrics = compute_inventory_metrics(DummyResult())
    assert metrics.total_packages == 3
    assert metrics.split_apk_packages == 1  # one entry has split_count=2
    assert metrics.user_scope_candidates == 1  # only /data path
    assert metrics.by_install_source.get("Play Store") == 1
    assert metrics.by_role.get("System") == 1
    assert metrics.by_partition.get("System (/system, /system_ext)") == 1
    assert metrics.delta_new == 1
    assert metrics.delta_updated == 2
    assert metrics.scan_duration == "02m 05s"
