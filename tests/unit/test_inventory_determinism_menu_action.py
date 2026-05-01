from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Database.db_utils import menu_actions


def test_inventory_determinism_menu_action_writes_strict_artifact(monkeypatch, tmp_path: Path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(menu_actions.prompt_utils, "prompt_text", lambda *args, **kwargs: "SER123")
    monkeypatch.setattr(menu_actions.prompt_utils, "press_enter_to_continue", lambda: None)

    def fake_run_sql(query: str, params=None, fetch=None, **_kwargs):
        q = " ".join(query.split()).lower()
        if "from device_inventory_snapshots" in q and "where device_serial" not in q and "limit 1" in q:
            return ("SER123",)
        if "from device_inventory_snapshots" in q and "where device_serial=%s" in q:
            return [(11,), (10,)]
        if "from device_inventory_snapshots" in q and "where snapshot_id = %s" in q:
            snapshot_id = int(params[0])
            return {
                "snapshot_id": snapshot_id,
                "device_serial": "SER123",
                "package_count": 1,
                "package_list_hash": "abc",
                "package_signature_hash": "sig",
                "scope_hash": "scope",
                "captured_at": f"2026-02-16T00:00:{snapshot_id:02d}Z",
            }
        if "from device_inventory" in q and "where snapshot_id = %s" in q:
            return [
                {
                    "package_name": "com.example.app",
                    "version_code": "100",
                    "app_label": "Example",
                    "version_name": "1.0.0",
                    "installer": "com.android.vending",
                    "primary_path": "/data/app/base.apk",
                    "split_count": 1,
                    "extras": json.dumps({"signer_cert_digest": "deadbeef"}),
                    "apk_paths": json.dumps(["/data/app/base.apk"]),
                }
            ]
        raise AssertionError(f"Unhandled SQL in test stub: {query}")

    monkeypatch.setattr(menu_actions.core_q, "run_sql", fake_run_sql)

    menu_actions.run_inventory_determinism_comparator()

    artifacts = list((tmp_path / "output" / "audit" / "comparators" / "inventory_guard").glob("*/diff.json"))
    assert artifacts, "expected comparator artifact to be written"
    payload = json.loads(artifacts[0].read_text(encoding="utf-8"))
    assert payload["compare_type"] == "inventory_guard"
    assert payload["result"]["pass"] is True
    assert payload["result"]["diff_counts"]["disallowed"] == 0
    assert payload["allowed_diff_fields"] == [
        "left.timestamp_utc",
        "right.timestamp_utc",
        "left.run_id",
        "right.run_id",
    ]
