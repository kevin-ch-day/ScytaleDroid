from __future__ import annotations

from pathlib import Path

from scytaledroid.DeviceAnalysis import report


def test_generate_device_report_bootstraps_inventory_with_fast_mode(
    monkeypatch,
    tmp_path: Path,
) -> None:
    calls: dict[str, object] = {}
    payloads = iter(
        [
            None,
            {"packages": [], "package_count": 0},
        ]
    )

    monkeypatch.setattr(report, "_get_device_entry", lambda _serial: {"serial": "SER123"})
    monkeypatch.setattr(report.adb_devices, "build_device_summary", lambda _entry: {"serial": "SER123"})
    monkeypatch.setattr(report.device_service, "fetch_raw_inventory", lambda _serial: next(payloads))
    monkeypatch.setattr(report.prompt_utils, "prompt_yes_no", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        report.device_service,
        "sync_inventory",
        lambda serial, **kwargs: calls.update({"serial": serial, **kwargs}),
    )
    monkeypatch.setattr(
        report,
        "_write_report",
        lambda _serial, _summary, _payload: tmp_path / "device_report.md",
    )
    monkeypatch.setattr(report.prompt_utils, "press_enter_to_continue", lambda *args, **kwargs: None)
    monkeypatch.setattr(report.table_utils, "render_key_value_pairs", lambda *args, **kwargs: None)
    monkeypatch.setattr(report.table_utils, "render_table", lambda *args, **kwargs: None)
    monkeypatch.setattr(report, "_profile_guidance", lambda _packages: [])

    report.generate_device_report("SER123")

    assert calls["serial"] == "SER123"
    assert calls["mode"] == "bulk"


def test_write_report_includes_inventory_snapshot_section(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(report.app_config, "OUTPUT_DIR", str(tmp_path))

    summary = {"serial": "SER123", "model": "Test Device"}
    payload = {
        "package_count": 1,
        "packages": [
            {
                "package_name": "com.example.app",
                "app_label": "Example",
                "version_code": "1",
                "category": "Unknown",
                "source": "Play Store",
                "profile_name": "Social",
                "primary_path": "/data/app/base.apk",
                "split_count": 1,
            }
        ],
        "snapshot_id": 53,
        "generated_at": "2026-06-12T12:00:00Z",
        "collection_mode": "bulk",
        "identity_quality": "strict",
        "path_enriched_packages": 1,
        "bulk_identity_only_packages": 0,
    }

    path = report._write_report("SER123", summary, payload)
    text = path.read_text(encoding="utf-8")

    assert "## Inventory Snapshot" in text
    assert "| Snapshot ID | 53 |" in text
    assert "| Inventory mode | fast |" in text
    assert "| Identity quality | strict |" in text
    assert "| Path fidelity | enriched=1  bulk_only=0 |" in text
