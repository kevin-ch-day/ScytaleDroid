from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Database.db_core import permission_intel
from scytaledroid.Database.tools.permission_intel_phase1_common import (
    PHASE1_TABLES,
    write_phase1_artifact,
)


def test_permission_intel_resolve_config_requires_dedicated_namespace(monkeypatch):
    monkeypatch.setattr(permission_intel.db_config, "resolve_db_config_from_root", lambda _root: (None, None))
    try:
        permission_intel.resolve_config()
    except RuntimeError as exc:
        assert "Dedicated permission-intel DB is not configured" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected RuntimeError")


def test_permission_intel_resolve_config_uses_dedicated_namespace(monkeypatch):
    monkeypatch.setattr(
        permission_intel.db_config,
        "resolve_db_config_from_root",
        lambda _root: (
            {
                "engine": "mysql",
                "host": "localhost",
                "port": 3306,
                "user": "perm_user",
                "password": "",
                "database": "android_permission_intel",
                "charset": "utf8mb4",
            },
            "env:SCYTALEDROID_PERMISSION_INTEL_DB_URL",
        ),
    )

    cfg, source, fallback = permission_intel.resolve_config()

    assert fallback is False
    assert source == "env:SCYTALEDROID_PERMISSION_INTEL_DB_URL"
    assert cfg["database"] == "android_permission_intel"


def test_permission_intel_describe_target(monkeypatch):
    monkeypatch.setattr(
        permission_intel,
        "resolve_config",
        lambda: (
            {
                "engine": "mysql",
                "host": "localhost",
                "port": 3306,
                "user": "perm_user",
                "database": "android_permission_intel",
            },
            "env:SCYTALEDROID_PERMISSION_INTEL_DB_*",
            False,
        ),
    )

    summary = permission_intel.describe_target()

    assert summary["database"] == "android_permission_intel"
    assert summary["source"] == "env:SCYTALEDROID_PERMISSION_INTEL_DB_*"
    assert summary["compatibility_mode"] is False


def test_permission_intel_latest_governance_snapshot(monkeypatch):
    monkeypatch.setattr(
        permission_intel,
        "run_sql",
        lambda *args, **kwargs: ("gov_v1", "abc123", 1828),
    )

    version, sha, row_count = permission_intel.latest_governance_snapshot()

    assert version == "gov_v1"
    assert sha == "abc123"
    assert row_count == 1828


def test_permission_intel_latest_governance_loaded_at(monkeypatch):
    monkeypatch.setattr(
        permission_intel,
        "run_sql",
        lambda *args, **kwargs: ("2026-04-28 22:00:00",),
    )

    loaded_at = permission_intel.latest_governance_loaded_at("gov_v1")

    assert loaded_at == "2026-04-28 22:00:00"


def test_permission_intel_fetch_aosp_permission_catalog_rows(monkeypatch):
    monkeypatch.setattr(
        permission_intel,
        "run_sql",
        lambda *args, **kwargs: [
            ("android.permission.CAMERA", "dangerous", 1, None),
            ("android.permission.READ_CONTACTS", "dangerous", 1, None),
        ],
    )

    rows = permission_intel.fetch_aosp_permission_catalog_rows()

    assert rows == [
        ("android.permission.CAMERA", "dangerous", 1, None),
        ("android.permission.READ_CONTACTS", "dangerous", 1, None),
    ]


def test_permission_intel_fetch_aosp_permission_dict_rows_case_insensitive(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_run_sql(query, params=None, **kwargs):
        captured["query"] = query
        captured["params"] = params
        return [("android.permission.CAMERA", "CAMERA", "dangerous", 0, 0, 0, 0, 1, None)]

    monkeypatch.setattr(permission_intel, "run_sql", _fake_run_sql)

    rows = permission_intel.fetch_aosp_permission_dict_rows(
        ["ANDROID.PERMISSION.CAMERA"],
        case_insensitive=True,
    )

    assert "LOWER(constant_value)" in str(captured["query"])
    assert captured["params"] == ("android.permission.camera",)
    assert rows[0][0] == "android.permission.CAMERA"


def test_permission_intel_intel_table_exists(monkeypatch):
    monkeypatch.setattr(permission_intel, "run_sql", lambda *args, **kwargs: (1,))

    assert permission_intel.intel_table_exists("permission_signal_catalog") is True


def test_permission_intel_fetch_signal_catalog_rows(monkeypatch):
    monkeypatch.setattr(
        permission_intel,
        "run_sql",
        lambda *args, **kwargs: [
            {
                "signal_key": "camera",
                "display_name": "Camera access",
                "description": "Apps requesting camera capture capabilities.",
                "default_weight": 1.0,
                "default_band": "high",
                "stage": "declared",
            }
        ],
    )

    rows = permission_intel.fetch_signal_catalog_rows()

    assert rows[0]["signal_key"] == "camera"


def test_no_app_facing_direct_permission_intel_run_sql_calls() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    app_root = repo_root / "scytaledroid"
    allowed_prefixes = {
        "Database/db_core/permission_intel.py",
        "Database/tools/",
        "Database/db_queries/",
    }
    offenders: list[str] = []
    for path in app_root.rglob("*.py"):
        rel = path.relative_to(app_root).as_posix()
        if any(rel == prefix or rel.startswith(prefix) for prefix in allowed_prefixes):
            continue
        text = path.read_text(encoding="utf-8")
        if "permission_intel.run_sql(" in text or "intel_db.run_sql(" in text:
            offenders.append(rel)
    assert offenders == []


def test_write_phase1_artifact_writes_expected_payload(tmp_path: Path) -> None:
    out_path = tmp_path / "artifacts" / "phase1_validate.json"
    results = [
        {"table": "android_permission_dict_aosp", "source_count": 1, "target_count": 1, "match": True}
    ]

    written = write_phase1_artifact(
        out_path,
        command="permission_intel_phase1_validate",
        source_db="scytaledroid_droid_intel_db_dev",
        target_db="android_permission_intel",
        status="completed",
        failed=False,
        results=results,
    )

    assert written == out_path
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "v1"
    assert payload["command"] == "permission_intel_phase1_validate"
    assert payload["source_db"] == "scytaledroid_droid_intel_db_dev"
    assert payload["target_db"] == "android_permission_intel"
    assert payload["status"] == "completed"
    assert payload["failed"] is False
    assert payload["phase1_tables"] == list(PHASE1_TABLES)
    assert payload["results"] == results
    assert payload["generated_at_utc"].endswith("Z")
