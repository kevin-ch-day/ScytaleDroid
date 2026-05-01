from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from scytaledroid.DeviceAnalysis.inventory import db_sync
from scytaledroid.DeviceAnalysis.inventory import progress
from scytaledroid.DeviceAnalysis.inventory.snapshot_io import _prune_inventory_files
from scytaledroid.Utils.DisplayUtils import colors


def test_sync_app_definitions_skips_numeric_only_package(monkeypatch) -> None:
    batches: list[list[tuple[str, str | None]]] = []

    def _bulk(rows: list[tuple[str, str | None]]) -> int:
        batches.append(list(rows))
        return len(rows)

    monkeypatch.setattr(db_sync, "bulk_ensure_app_definitions", _bulk)

    rows = [
        {"package_name": "20260204", "app_label": "Bad Token"},
        {"package_name": "com.example.valid", "app_label": "Valid App"},
    ]

    synced = db_sync.sync_app_definitions(rows)

    assert synced == 1
    assert batches == [[("com.example.valid", "Valid App")]]


def test_render_snapshot_block_uses_labeled_lines_and_compact_non_root_warning(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        progress,
        "_FALLBACK_WARNED_KEYS",
        set(),
    )
    monkeypatch.setattr(progress.colors, "colors_enabled", lambda: False)
    monkeypatch.setattr(
        progress,
        "INVENTORY_STALE_SECONDS",
        24 * 60 * 60,
    )

    meta = SimpleNamespace(
        captured_at=None,
        snapshot_id=26,
        package_count=546,
    )

    progress.render_snapshot_block(
        meta,
        mode="baseline",
        serial="ZY22JK89DR",
        allow_fallbacks=True,
    )

    out = colors.strip(capsys.readouterr().out)
    assert "Refresh inventory" in out
    assert "Device       : ZY22JK89DR" in out
    assert "Previous snap: 26" in out
    assert "Inventory    : none" in out
    assert "Last sync    : never" in out
    assert "Packages     : —" in out
    assert "Mode         : baseline" in out
    assert "Non-root collection active; harvest remains policy-filtered." in out
    assert "Next: ADB package dump" in out


def test_render_snapshot_block_formats_last_sync_age(monkeypatch, capsys) -> None:
    monkeypatch.setattr(progress.colors, "colors_enabled", lambda: False)
    monkeypatch.setattr(
        progress,
        "INVENTORY_STALE_SECONDS",
        24 * 60 * 60,
    )

    captured = datetime.now(UTC) - timedelta(minutes=48, seconds=17)
    meta = SimpleNamespace(
        captured_at=captured,
        snapshot_id=42,
        package_count=546,
    )

    progress.render_snapshot_block(
        meta,
        mode="baseline",
        serial="ZY22JK89DR",
        allow_fallbacks=False,
    )

    out = colors.strip(capsys.readouterr().out)
    assert "Inventory    : FRESH" in out
    assert "Last sync    : " in out and "ago" in out


def test_prune_inventory_files_keeps_last_n_snapshots(tmp_path, monkeypatch):
    serial = "TESTSERIAL"
    inv_dir = tmp_path / serial / "inventory"
    inv_dir.mkdir(parents=True, exist_ok=True)

    stamps = [
        "20260101-000001",
        "20260101-000002",
        "20260101-000003",
        "20260101-000004",
        "20260101-000005",
        "20260101-000006",
        "20260101-000007",
    ]
    for ts in stamps:
        (inv_dir / f"inventory_{ts}.json").write_text("{}", encoding="utf-8")
        (inv_dir / f"inventory_{ts}.meta.json").write_text("{}", encoding="utf-8")
    (inv_dir / "latest.json").write_text("{}", encoding="utf-8")
    (inv_dir / "latest.meta.json").write_text("{}", encoding="utf-8")

    import scytaledroid.DeviceAnalysis.inventory.snapshot_io as mod

    monkeypatch.setattr(mod, "_STATE_ROOT", tmp_path)

    before, deleted = _prune_inventory_files(serial, keep_last=5)
    assert before == 7
    assert deleted == 2

    remaining = sorted(
        [
            p.name
            for p in inv_dir.glob("inventory_*.json")
            if p.name.endswith(".json") and not p.name.endswith(".meta.json") and p.name != "latest.json"
        ]
    )
    assert remaining == [f"inventory_{ts}.json" for ts in stamps[-5:]]
