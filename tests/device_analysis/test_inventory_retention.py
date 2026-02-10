from __future__ import annotations

from scytaledroid.DeviceAnalysis.inventory.snapshot_io import _prune_inventory_files


def test_prune_inventory_files_keeps_last_n_snapshots(tmp_path, monkeypatch):
    # Build fake state dir: data/state/<serial>/inventory
    serial = "TESTSERIAL"
    inv_dir = tmp_path / serial / "inventory"
    inv_dir.mkdir(parents=True, exist_ok=True)

    # Create 7 timestamp snapshots, each with .json and .meta.json.
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

    # Monkeypatch module constant root to our tmp directory.
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
    # Keep only last 5 stamps.
    assert remaining == [f"inventory_{ts}.json" for ts in stamps[-5:]]
