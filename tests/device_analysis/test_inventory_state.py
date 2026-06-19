from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from scytaledroid.DeviceAnalysis.inventory import db_sync
from scytaledroid.DeviceAnalysis.inventory import progress
from scytaledroid.DeviceAnalysis.inventory import snapshot_io
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
    assert "Current snapshot · before run" in out
    assert "Device       : ZY22JK89DR" in out
    assert "Previous snap: 26" in out
    assert "Inventory    : none" in out
    assert "Last sync    : never" in out
    assert "Packages     : —" in out
    assert "Mode         : full device" in out
    assert "Policy       : Non-root paths (harvest/filtering may omit system APK paths)" in out
    assert "This run: ADB package inventory" in out


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
    assert "Mode         : full device" in out


def test_render_snapshot_block_uses_expanded_day_hour_minute_age(monkeypatch, capsys) -> None:
    monkeypatch.setattr(progress.colors, "colors_enabled", lambda: False)
    monkeypatch.setattr(
        progress,
        "INVENTORY_STALE_SECONDS",
        24 * 60 * 60,
    )

    captured = datetime.now(UTC) - timedelta(days=1, hours=2, minutes=49)
    meta = SimpleNamespace(
        captured_at=captured,
        snapshot_id=57,
        package_count=578,
    )

    progress.render_snapshot_block(
        meta,
        mode="baseline",
        serial="ZY22JK89DR",
        allow_fallbacks=True,
    )

    out = colors.strip(capsys.readouterr().out)
    assert "Inventory    : STALE" in out
    assert "Last sync    : 1 Day 2 hrs 49 mins ago" in out
    assert "Mode         : full device" in out


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


def test_persist_snapshot_round_trips_fast_mode_fidelity_metadata(tmp_path, monkeypatch):
    serial = "TESTSERIAL"

    class _Txn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    class _Engine:
        def transaction(self):
            return _Txn()

    class _Session:
        def __enter__(self):
            return _Engine()

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(snapshot_io, "_STATE_ROOT", tmp_path)
    monkeypatch.setattr(snapshot_io.inventory_meta, "_state_root", lambda: tmp_path)
    monkeypatch.setattr(snapshot_io, "database_session", lambda: _Session())
    monkeypatch.setattr(snapshot_io.inventory_repo, "create_snapshot", lambda *args, **kwargs: 77)
    monkeypatch.setattr(
        snapshot_io.inventory_repo,
        "replace_packages",
        lambda snapshot_id, _serial, rows: len(rows) if snapshot_id == 77 else 0,
    )
    monkeypatch.setattr(snapshot_io, "_enforce_inventory_retention", lambda *_args, **_kwargs: None)

    rows = [
        {
            "package_name": "com.example.userapp",
            "version_code": "42",
            "version_name": None,
            "primary_path": "/data/app/~~abc/com.example.userapp/base.apk",
            "apk_paths": [
                "/data/app/~~abc/com.example.userapp/base.apk",
                "/data/app/~~abc/com.example.userapp/split_config.en.apk",
            ],
            "split_count": 2,
            "path_fidelity": "pm_path",
        },
        {
            "package_name": "com.vendor.blocked",
            "version_code": "1",
            "version_name": None,
            "primary_path": "/vendor/app/Blocked/Blocked.apk",
            "apk_paths": ["/vendor/app/Blocked/Blocked.apk"],
            "split_count": 1,
            "path_fidelity": "bulk_base_only",
        },
    ]
    stats = SimpleNamespace(
        collection_mode="bulk",
        identity_source="pm_list_show_versioncode",
        identity_quality="strict",
        path_enriched_packages=1,
        bulk_identity_only_packages=1,
    )

    persisted = snapshot_io.persist_snapshot(
        serial,
        rows,
        package_list_hash="abc123",
        package_signature_hash="def456",
        build_fingerprint="fingerprint",
        collection_stats=stats,
    )

    payload = snapshot_io.load_latest_inventory(serial)
    meta = snapshot_io.load_latest_snapshot_meta(serial)

    assert persisted.snapshot_id == 77
    assert payload is not None
    assert payload["snapshot_id"] == 77
    assert payload["collection_mode"] == "bulk"
    assert payload["identity_source"] == "pm_list_show_versioncode"
    assert payload["identity_quality"] == "strict"
    assert payload["path_enriched_packages"] == 1
    assert payload["bulk_identity_only_packages"] == 1
    assert [row["path_fidelity"] for row in payload["packages"]] == ["pm_path", "bulk_base_only"]
    assert meta is not None
    assert meta.snapshot_id == 77
    assert meta.collection_mode == "bulk"
    assert meta.identity_source == "pm_list_show_versioncode"
    assert meta.identity_quality == "strict"
    assert meta.path_enriched_packages == 1
    assert meta.bulk_identity_only_packages == 1
