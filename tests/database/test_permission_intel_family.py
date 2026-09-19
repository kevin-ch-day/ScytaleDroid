from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Database.db_core import permission_intel
from scytaledroid.Database.tools.permission_intel_phase1_common import (
    PHASE1_TABLES,
    write_phase1_artifact,
)


def test_permission_intel_resolve_config_requires_dedicated_namespace(monkeypatch):
    monkeypatch.setattr(
        permission_intel.db_config, "resolve_db_config_from_root", lambda _root: (None, None)
    )
    try:
        permission_intel.resolve_config()
    except RuntimeError as exc:
        assert "Dedicated permission-intel DB is not configured" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected RuntimeError")


def test_permission_intel_db_available_reflects_resolve(monkeypatch):
    monkeypatch.setattr(
        permission_intel.db_config, "resolve_db_config_from_root", lambda _root: (None, None)
    )
    assert permission_intel.is_permission_intel_configured() is False
    assert permission_intel.permission_intel_db_available() is False

    monkeypatch.setattr(
        permission_intel.db_config,
        "resolve_db_config_from_root",
        lambda _root: ({"engine": "mysql", "database": "android_permission_intel"}, "env:test"),
    )
    assert permission_intel.is_permission_intel_configured() is True
    assert permission_intel.permission_intel_db_available() is True


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
    # Historical invalid-token rows remain stored but are not current permission truth.


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

    assert "LOWER(constant_value)" not in str(captured["query"])
    assert "constant_value_norm IN" in str(captured["query"])
    assert "lifecycle_status IS NULL OR lifecycle_status <> 'invalid_token'" in str(
        captured["query"]
    )
    assert captured["params"] == ("android.permission.camera",)
    assert rows[0][0] == "android.permission.CAMERA"


def test_current_interpretation_uses_deployed_evidence_surfaces(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_run_sql(query, params=None, **kwargs):
        captured["query"] = query
        captured["params"] = params
        captured["kwargs"] = kwargs
        return []

    monkeypatch.setattr(permission_intel, "run_sql", _fake_run_sql)
    rows = permission_intel.fetch_current_permission_interpretation_rows(
        ["android.permission.CAMERA"]
    )
    sql = str(captured["query"])
    assert rows == []
    assert "android_permission_v1_current_permission" in sql
    assert "api_permission_declaration_conflict" in sql
    assert "GROUP BY permission_id" in sql
    assert "COUNT(c.conflict_id)" not in sql
    assert "BINARY sp.canonical_permission" not in sql
    assert "android_permission_v1_1_" not in sql
    assert "SELECT %s AS lookup_token_norm" in sql
    assert "FROM android_permission_dict_aosp\n                 WHERE" not in sql
    assert "android_permission_dict_oem" in sql
    assert "android_permission_meta_oem_vendor" in sql
    assert captured["params"] == ("android.permission.camera",)
    assert captured["kwargs"]["read_only"] is True


def test_oem_lookup_requires_resolved_vendor_and_exact_token(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_run_sql(query, params=None, **kwargs):
        captured["query"] = query
        captured["params"] = params
        return []

    monkeypatch.setattr(permission_intel, "run_sql", _fake_run_sql)
    permission_intel.fetch_oem_permission_dict_rows(["vendor.example.permission.ACCESS"])
    sql = str(captured["query"])
    assert "INNER JOIN android_permission_meta_oem_vendor" in sql
    assert "BINARY o.permission_string IN" in sql
    assert captured["params"] == ("vendor.example.permission.ACCESS",)


def test_oem_catalog_rows_require_protection_and_resolved_vendor(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_run_sql(query, params=None, **kwargs):
        captured["query"] = query
        captured["kwargs"] = kwargs
        return []

    monkeypatch.setattr(permission_intel, "run_sql", _fake_run_sql)
    permission_intel.fetch_oem_permission_catalog_rows()
    sql = str(captured["query"])
    assert "INNER JOIN android_permission_meta_oem_vendor" in sql
    assert "TRIM(o.protection_level)" in sql
    assert captured["kwargs"]["read_only"] is True


def test_aosp_catalog_rows_filter_protection_in_sql(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_run_sql(query, params=None, **kwargs):
        captured["query"] = query
        captured["kwargs"] = kwargs
        return []

    monkeypatch.setattr(permission_intel, "run_sql", _fake_run_sql)
    permission_intel.fetch_aosp_permission_catalog_rows()
    sql = str(captured["query"])
    assert "TRIM(protection_level)" in sql
    assert "COALESCE(lifecycle_status" not in sql
    assert captured["kwargs"]["read_only"] is True


def test_permission_intel_intel_table_exists(monkeypatch):
    calls: list[int] = []

    def _run_sql(*args, **kwargs):
        calls.append(1)
        return (1,)

    monkeypatch.setattr(permission_intel, "run_sql", _run_sql)
    permission_intel._INTEL_TABLES_PRESENT.clear()

    assert permission_intel.intel_table_exists("permission_signal_catalog") is True
    assert permission_intel.intel_table_exists("permission_signal_catalog") is True
    assert calls == [1]


def test_fetch_vendor_prefix_rules_is_process_cached(monkeypatch):
    from scytaledroid.Database.db_func.permissions import permission_dicts as permission_dicts_db

    calls: list[int] = []

    def _rows():
        calls.append(1)
        return [(1, "com.samsung.", "prefix")]

    monkeypatch.setattr(permission_dicts_db.intel_db, "fetch_vendor_prefix_rule_rows", _rows)
    permission_dicts_db.fetch_vendor_prefix_rules.cache_clear()
    first = permission_dicts_db.fetch_vendor_prefix_rules()
    second = permission_dicts_db.fetch_vendor_prefix_rules()
    assert calls == [1]
    assert first == second
    assert first[0]["namespace_prefix"] == "com.samsung."
    permission_dicts_db.fetch_vendor_prefix_rules.cache_clear()


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
        {
            "table": "android_permission_dict_aosp",
            "source_count": 1,
            "target_count": 1,
            "match": True,
        }
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
