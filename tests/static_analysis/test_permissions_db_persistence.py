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

    monkeypatch.setattr(
        permission_dicts_db.intel_db, "insert_permission_queue", _fake_insert_permission_queue
    )

    permission_dicts_db.insert_queue(
        {
            "permission_string": "android.permission.TEST",
            "queue_action": "aosp_promote",
        }
    )

    assert captured["permission_string"] == "android.permission.TEST"
    assert captured["queue_action"] == "defer"
    assert "proposed_bucket" in captured and captured["proposed_bucket"] is None
    assert "proposed_classification" in captured and captured["proposed_classification"] is None
    assert "status" in captured and captured["status"] == "queued"


def test_persist_declared_permissions_enqueues_aosp_missing_without_bucket(monkeypatch) -> None:
    queue_calls: list[dict[str, object]] = []
    unknown_calls: list[dict[str, object]] = []

    monkeypatch.setattr(permission_dicts_db, "fetch_aosp_entries", lambda *_a, **_k: {})
    monkeypatch.setattr(permission_dicts_db, "fetch_oem_entries", lambda *_a, **_k: {})
    monkeypatch.setattr(permission_dicts_db, "fetch_vendor_prefix_rules", lambda *_a, **_k: [])
    monkeypatch.setattr(
        permission_dicts_db, "upsert_unknown", lambda payload: unknown_calls.append(dict(payload))
    )
    monkeypatch.setattr(
        permission_dicts_db, "insert_queue", lambda payload: queue_calls.append(dict(payload))
    )

    counts = permissions_db.persist_declared_permissions(
        package_name="pkg.example",
        version_name="1.0",
        version_code="1",
        target_sdk=35,
        sha256="abc",
        artifact_label="base.apk",
        declared=("android.permission.DOWNLOAD_WITHOUT_NOTIFICATION",),
        custom_declared=(),
        database_mutation_authorized=True,
    )

    assert counts["unknown"] == 1
    assert len(unknown_calls) == 1
    assert len(queue_calls) == 1
    assert queue_calls[0]["permission_string"] == "android.permission.DOWNLOAD_WITHOUT_NOTIFICATION"
    assert queue_calls[0].get("queue_action") == "defer"
    assert "proposed_bucket" in queue_calls[0] and queue_calls[0]["proposed_bucket"] is None
    assert (
        "proposed_classification" in queue_calls[0]
        and queue_calls[0]["proposed_classification"] is None
    )


def test_persist_declared_permissions_keeps_definition_without_matching_request(
    monkeypatch,
) -> None:
    unknown_calls: list[dict[str, object]] = []
    queue_calls: list[dict[str, object]] = []

    monkeypatch.setattr(permission_dicts_db, "fetch_aosp_entries", lambda *_a, **_k: {})
    monkeypatch.setattr(permission_dicts_db, "fetch_oem_entries", lambda *_a, **_k: {})
    monkeypatch.setattr(permission_dicts_db, "fetch_vendor_prefix_rules", lambda *_a, **_k: [])
    monkeypatch.setattr(
        permission_dicts_db,
        "upsert_unknown",
        lambda payload: unknown_calls.append(dict(payload)),
    )
    monkeypatch.setattr(
        permission_dicts_db,
        "insert_queue",
        lambda payload: queue_calls.append(dict(payload)),
    )

    counts = permissions_db.persist_declared_permissions(
        package_name="com.example.owner",
        version_name="1.0",
        version_code="1",
        target_sdk=35,
        sha256="a" * 64,
        artifact_label="base.apk",
        declared=(),
        custom_declared=("com.example.owner.permission.SYNC",),
        database_mutation_authorized=True,
    )

    assert counts == {"aosp": 0, "oem": 0, "app_defined": 1, "unknown": 0}
    assert unknown_calls == [
        {
            "permission_string": "com.example.owner.permission.SYNC",
            "triage_status": "app_defined",
            "notes": None,
            "example_package_name": "com.example.owner",
            "example_sample_id": None,
        }
    ]
    assert queue_calls == []

    contract = (
        Path(__file__).resolve().parents[2] / "docs" / "database" / "permission_intel_contract.md"
    ).read_text(encoding="utf-8")
    normalized_contract = " ".join(contract.split())
    assert "`permissions.declared` is the legacy report field" in normalized_contract
    assert "`permissions.custom` contains exact `<permission>` definitions" in normalized_contract
    assert "`REQUESTED` or `DEFINED`" in normalized_contract


def test_permission_both_defined_and_requested_is_counted_once(monkeypatch) -> None:
    requested_permission = "COM.EXAMPLE.OWNER.PERMISSION.SYNC"
    defined_permission = "com.example.owner.permission.sync"
    unknown_calls: list[dict[str, object]] = []
    monkeypatch.setattr(permission_dicts_db, "fetch_aosp_entries", lambda *_a, **_k: {})
    monkeypatch.setattr(permission_dicts_db, "fetch_oem_entries", lambda *_a, **_k: {})
    monkeypatch.setattr(permission_dicts_db, "fetch_vendor_prefix_rules", lambda *_a, **_k: [])
    monkeypatch.setattr(
        permission_dicts_db,
        "upsert_unknown",
        lambda payload: unknown_calls.append(dict(payload)),
    )
    monkeypatch.setattr(permission_dicts_db, "insert_queue", lambda _payload: None)

    counts = permissions_db.persist_declared_permissions(
        package_name="com.example.owner",
        version_name="1.0",
        version_code="1",
        target_sdk=35,
        sha256="a" * 64,
        artifact_label="base.apk",
        declared=(requested_permission, requested_permission),
        custom_declared=(defined_permission,),
        database_mutation_authorized=True,
    )

    assert counts == {"aosp": 0, "oem": 0, "app_defined": 1, "unknown": 0}
    assert len(unknown_calls) == 1
    assert unknown_calls[0]["permission_string"] == defined_permission
    assert unknown_calls[0]["triage_status"] == "app_defined"


def test_ordinary_persist_does_not_mutate_permission_intel(monkeypatch) -> None:
    unknown_calls: list[dict[str, object]] = []
    queue_calls: list[dict[str, object]] = []
    oem_calls: list[str] = []
    monkeypatch.delenv("SCYTALEDROID_PERMISSION_INTEL_MUTATION_AUTHORIZED", raising=False)
    monkeypatch.setattr(permission_dicts_db, "fetch_aosp_entries", lambda *_a, **_k: {})
    monkeypatch.setattr(
        permission_dicts_db,
        "fetch_oem_entries",
        lambda *_a, **_k: {"vendor.example.permission.FOO": {"permission_string": "vendor.example.permission.FOO"}},
    )
    monkeypatch.setattr(permission_dicts_db, "fetch_vendor_prefix_rules", lambda *_a, **_k: [])
    monkeypatch.setattr(
        permission_dicts_db, "upsert_unknown", lambda payload: unknown_calls.append(dict(payload))
    )
    monkeypatch.setattr(
        permission_dicts_db, "insert_queue", lambda payload: queue_calls.append(dict(payload))
    )
    monkeypatch.setattr(permission_dicts_db, "update_oem_seen", lambda name: oem_calls.append(name))

    counts = permissions_db.persist_declared_permissions(
        package_name="com.example.app",
        version_name="1.0",
        version_code="1",
        target_sdk=35,
        sha256="a" * 64,
        artifact_label="base.apk",
        declared=(
            "android.permission.DOWNLOAD_WITHOUT_NOTIFICATION",
            "vendor.example.permission.FOO",
            "not a token",
        ),
        custom_declared=("com.example.app.permission.SYNC",),
    )

    assert counts["unknown"] == 2
    assert counts["oem"] == 1
    assert counts["app_defined"] == 1
    assert unknown_calls == []
    assert queue_calls == []
    assert oem_calls == []


def test_persist_permissions_to_db_defaults_to_read_only_intel(monkeypatch) -> None:
    unknown_calls: list[dict[str, object]] = []
    monkeypatch.delenv("SCYTALEDROID_PERMISSION_INTEL_MUTATION_AUTHORIZED", raising=False)
    monkeypatch.setattr(permission_dicts_db, "fetch_aosp_entries", lambda *_a, **_k: {})
    monkeypatch.setattr(permission_dicts_db, "fetch_oem_entries", lambda *_a, **_k: {})
    monkeypatch.setattr(permission_dicts_db, "fetch_vendor_prefix_rules", lambda *_a, **_k: [])
    monkeypatch.setattr(
        permission_dicts_db, "upsert_unknown", lambda payload: unknown_calls.append(dict(payload))
    )
    monkeypatch.setattr(permission_dicts_db, "insert_queue", lambda _payload: unknown_calls.append({"queue": True}))
    monkeypatch.setattr(permission_dicts_db, "update_oem_seen", lambda _name: unknown_calls.append({"oem": True}))

    report = type(
        "Report",
        (),
        {
            "manifest": type(
                "Manifest",
                (),
                {"package_name": "com.example.app", "version_name": "1", "version_code": "1", "target_sdk": 35},
            )(),
            "hashes": {"sha256": "a" * 64},
            "file_name": "base.apk",
            "permissions": type(
                "Perms",
                (),
                {
                    "declared": ("android.permission.DOWNLOAD_WITHOUT_NOTIFICATION",),
                    "custom": (),
                },
            )(),
        },
    )()

    counts = permissions_db.persist_permissions_to_db(report)
    assert counts["unknown"] == 1
    assert unknown_calls == []


def test_env_opt_in_authorizes_permission_intel_mutation(monkeypatch) -> None:
    unknown_calls: list[dict[str, object]] = []
    queue_calls: list[dict[str, object]] = []
    oem_calls: list[str] = []
    monkeypatch.setenv("SCYTALEDROID_PERMISSION_INTEL_MUTATION_AUTHORIZED", "1")
    monkeypatch.setattr(permission_dicts_db, "fetch_aosp_entries", lambda *_a, **_k: {})
    monkeypatch.setattr(
        permission_dicts_db,
        "fetch_oem_entries",
        lambda *_a, **_k: {
            "vendor.example.permission.FOO": {"permission_string": "vendor.example.permission.FOO"}
        },
    )
    monkeypatch.setattr(permission_dicts_db, "fetch_vendor_prefix_rules", lambda *_a, **_k: [])
    monkeypatch.setattr(
        permission_dicts_db, "upsert_unknown", lambda payload: unknown_calls.append(dict(payload))
    )
    monkeypatch.setattr(
        permission_dicts_db, "insert_queue", lambda payload: queue_calls.append(dict(payload))
    )
    monkeypatch.setattr(permission_dicts_db, "update_oem_seen", lambda name: oem_calls.append(name))

    counts = permissions_db.persist_declared_permissions(
        package_name="com.example.app",
        version_name="1.0",
        version_code="1",
        target_sdk=35,
        sha256="a" * 64,
        artifact_label="base.apk",
        declared=(
            "android.permission.DOWNLOAD_WITHOUT_NOTIFICATION",
            "vendor.example.permission.FOO",
            "not a token",
        ),
        custom_declared=("com.example.app.permission.SYNC",),
    )

    assert counts["unknown"] == 2
    assert counts["oem"] == 1
    assert counts["app_defined"] == 1
    assert any(call["triage_status"] == "malformed" for call in unknown_calls)
    assert any(call["triage_status"] == "app_defined" for call in unknown_calls)
    assert any(call["triage_status"] == "aosp_missing" for call in unknown_calls)
    assert queue_calls[0]["permission_string"] == "android.permission.DOWNLOAD_WITHOUT_NOTIFICATION"
    assert oem_calls == ["vendor.example.permission.FOO"]
