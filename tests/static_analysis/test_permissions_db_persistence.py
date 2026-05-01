from __future__ import annotations

import importlib.util
from pathlib import Path

from scytaledroid.Database.db_func.permissions import permission_dicts as permission_dicts_db


_MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "scytaledroid"
    / "StaticAnalysis"
    / "persistence"
    / "permissions_db.py"
)
_SPEC = importlib.util.spec_from_file_location("test_permissions_db_module", _MODULE_PATH)
assert _SPEC and _SPEC.loader
permissions_db = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(permissions_db)


def test_insert_queue_defaults_optional_placeholders(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake_insert_permission_queue(params):
        captured.update(dict(params))
        return None

    monkeypatch.setattr(permission_dicts_db.intel_db, "insert_permission_queue", _fake_insert_permission_queue)

    permission_dicts_db.insert_queue(
        {
            "permission_string": "android.permission.TEST",
            "queue_action": "aosp_promote",
        }
    )

    assert captured["permission_string"] == "android.permission.TEST"
    assert captured["queue_action"] == "aosp_promote"
    assert "proposed_bucket" in captured and captured["proposed_bucket"] is None
    assert "proposed_classification" in captured and captured["proposed_classification"] is None
    assert "status" in captured and captured["status"] == "queued"


def test_persist_declared_permissions_enqueues_aosp_missing_without_bucket(monkeypatch) -> None:
    queue_calls: list[dict[str, object]] = []
    unknown_calls: list[dict[str, object]] = []

    monkeypatch.setattr(permission_dicts_db, "fetch_aosp_entries", lambda *_a, **_k: {})
    monkeypatch.setattr(permission_dicts_db, "fetch_oem_entries", lambda *_a, **_k: {})
    monkeypatch.setattr(permission_dicts_db, "fetch_vendor_prefix_rules", lambda *_a, **_k: [])
    monkeypatch.setattr(permission_dicts_db, "upsert_unknown", lambda payload: unknown_calls.append(dict(payload)))
    monkeypatch.setattr(permission_dicts_db, "insert_queue", lambda payload: queue_calls.append(dict(payload)))

    counts = permissions_db.persist_declared_permissions(
        package_name="pkg.example",
        version_name="1.0",
        version_code="1",
        target_sdk=35,
        sha256="abc",
        artifact_label="base.apk",
        declared=("android.permission.DOWNLOAD_WITHOUT_NOTIFICATION",),
        custom_declared=(),
    )

    assert counts["unknown"] == 1
    assert len(unknown_calls) == 1
    assert len(queue_calls) == 1
    assert queue_calls[0]["permission_string"] == "android.permission.DOWNLOAD_WITHOUT_NOTIFICATION"
    assert "proposed_bucket" in queue_calls[0] and queue_calls[0]["proposed_bucket"] is None
    assert "proposed_classification" in queue_calls[0] and queue_calls[0]["proposed_classification"] is None
