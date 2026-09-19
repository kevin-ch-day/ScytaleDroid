from __future__ import annotations

from pathlib import Path

import pytest
from scytaledroid.Database.db_core import permission_intel


def test_unknown_submission_rejects_blank_and_unsupported_status() -> None:
    with pytest.raises(permission_intel.PermissionIntelSubmissionError, match="blank"):
        permission_intel.validate_unknown_submission(
            {"permission_string": "android.permission.TEST", "triage_status": ""}
        )
    with pytest.raises(permission_intel.PermissionIntelSubmissionError, match="unsupported"):
        permission_intel.validate_unknown_submission(
            {"permission_string": "android.permission.TEST", "triage_status": "invented"}
        )


def test_queue_submission_requires_source_identity() -> None:
    with pytest.raises(permission_intel.PermissionIntelSubmissionError, match="requested_by"):
        permission_intel.validate_queue_submission(
            {
                "permission_string": "android.permission.TEST",
                "triage_status": "aosp_missing",
                "queue_action": "defer",
                "status": "queued",
                "source_system": "static-analysis",
            }
        )


def test_v1_lookup_is_binary_and_uses_deployed_views(monkeypatch) -> None:
    calls: list[str] = []
    params_seen: list[object] = []

    def fake_run_sql(sql, params=None, **kwargs):
        calls.append(sql)
        params_seen.append(params)
        if "android_permission_v1_catalog_release" in sql:
            return [
                {
                    "catalog_release_id": "release",
                    "schema_contract_id": permission_intel.SUPPORTED_V1_SCHEMA_CONTRACT,
                    "schema_contract_version": permission_intel.SUPPORTED_V1_SCHEMA_VERSION,
                    "compatibility_floor": permission_intel.SUPPORTED_V1_SCHEMA_VERSION,
                    "schema_contract_release_status": permission_intel.SUPPORTED_V1_SCHEMA_RELEASE_STATUS,
                    "catalog_digest": "a" * 64,
                    "catalog_release_status": "ACCEPTED",
                    "catalog_import_status": "IMPORTED",
                    "import_receipt_count": 1,
                    "exhaustive_scope": 0,
                    "accepted_at_utc": "2026-08-30 00:00:00",
                }
            ]
        return [
            {
                "canonical_permission": "android.permission.INTERNET",
                "compatibility_protection_expression": "normal",
                "protection_base": "normal",
            }
        ]

    monkeypatch.setattr(permission_intel, "run_sql", fake_run_sql)
    rows = permission_intel.fetch_v1_permission_rows(["android.permission.INTERNET"])
    assert rows[0]["reference_mode"] == permission_intel.V1_REFERENCE_MODE
    assert rows[0]["scope_complete"] is False
    assert permission_intel.V1_SCYTALEDROID_PERMISSION_VIEW in calls[1]
    assert permission_intel.V1_CURRENT_PERMISSION_VIEW in calls[1]
    assert "android_permission_v1_1_" not in calls[1]
    assert "BINARY sp.canonical_permission IN" in calls[1]
    assert "authority_class IN" in calls[1]
    assert "'AOSP_HIDDEN'" in calls[1]
    assert "sp.catalog_release_id = %s" in calls[1]
    assert params_seen[1] == (
        "android.permission.INTERNET",
        "release",
        "a" * 64,
    )


def test_v1_lookup_rejects_surrounding_whitespace_before_gate(monkeypatch) -> None:
    monkeypatch.setattr(
        permission_intel,
        "fetch_v1_catalog_gate",
        lambda: pytest.fail("invalid exact token must fail before catalog lookup"),
    )
    with pytest.raises(ValueError, match="surrounding whitespace"):
        permission_intel.fetch_v1_permission_rows([" android.permission.INTERNET"])


def test_v1_full_catalog_is_limited_to_accepted_aosp_authorities(monkeypatch) -> None:
    calls: list[str] = []
    params_seen: list[object] = []

    def fake_run_sql(sql, params=None, **kwargs):
        calls.append(sql)
        params_seen.append(params)
        if "android_permission_v1_catalog_release" in sql:
            return [
                {
                    "catalog_release_id": "release",
                    "schema_contract_id": permission_intel.SUPPORTED_V1_SCHEMA_CONTRACT,
                    "schema_contract_version": permission_intel.SUPPORTED_V1_SCHEMA_VERSION,
                    "compatibility_floor": permission_intel.SUPPORTED_V1_SCHEMA_VERSION,
                    "schema_contract_release_status": permission_intel.SUPPORTED_V1_SCHEMA_RELEASE_STATUS,
                    "catalog_digest": "a" * 64,
                    "catalog_release_status": "ACCEPTED",
                    "catalog_import_status": "IMPORTED",
                    "import_receipt_count": 1,
                    "exhaustive_scope": 0,
                    "accepted_at_utc": "2026-08-30 00:00:00",
                }
            ]
        return []

    monkeypatch.setattr(permission_intel, "run_sql", fake_run_sql)

    permission_intel.fetch_v1_permission_catalog_rows()

    assert "'AOSP_PUBLIC', 'AOSP_HIDDEN', 'AOSP_INTERNAL', 'AOSP_MODULE'" in calls[1]
    assert permission_intel.V1_SCYTALEDROID_PERMISSION_VIEW in calls[1]
    assert "android_permission_v1_1_" not in calls[1]
    assert "ORDER BY BINARY" not in calls[1]
    assert "BINARY p.canonical_permission" not in calls[1]
    assert "p.canonical_permission = sp.canonical_permission" in calls[1]
    assert params_seen[1] == ("release", "a" * 64)


@pytest.mark.parametrize("rows", [[], [{}, {}]])
def test_v1_gate_requires_exactly_one_catalog(monkeypatch, rows) -> None:
    monkeypatch.setattr(
        permission_intel,
        "run_sql",
        lambda *args, **kwargs: rows,
    )
    with pytest.raises(RuntimeError, match="exactly one"):
        permission_intel.fetch_v1_catalog_gate()


def test_v1_gate_rejects_schema_version_drift(monkeypatch) -> None:
    monkeypatch.setattr(
        permission_intel,
        "run_sql",
        lambda *args, **kwargs: [
            {
                "schema_contract_id": permission_intel.SUPPORTED_V1_SCHEMA_CONTRACT,
                "schema_contract_version": "1.0.1",
                "compatibility_floor": permission_intel.SUPPORTED_V1_SCHEMA_VERSION,
                "schema_contract_release_status": permission_intel.SUPPORTED_V1_SCHEMA_RELEASE_STATUS,
            }
        ],
    )
    with pytest.raises(RuntimeError, match="version interval"):
        permission_intel.fetch_v1_catalog_gate()


def test_interpretation_surfaces_are_tracked_and_not_freeze_targets() -> None:
    assert permission_intel.V1_SCYTALEDROID_PERMISSION_VIEW in permission_intel.INTERPRETATION_SURFACES
    assert permission_intel.V1_CURRENT_PERMISSION_VIEW in permission_intel.INTERPRETATION_SURFACES
    assert "android_permission_v1_1_scytaledroid_permission" not in permission_intel.INTERPRETATION_SURFACES
    overlap = set(permission_intel.INTERPRETATION_SURFACES) & set(permission_intel.MANAGED_TABLES)
    assert overlap == set()


def test_scytale_permission_intel_never_writes_obs_sample() -> None:
    source = permission_intel.__file__
    assert source is not None
    text = Path(source).read_text(encoding="utf-8").lower()
    assert "insert into android_permission_obs_sample" not in text


def test_v1_interpretation_rejects_duplicates_and_unsupported_contract(monkeypatch) -> None:
    gate = {
        "catalog_release_id": "release",
        "schema_contract_id": permission_intel.SUPPORTED_V1_SCHEMA_CONTRACT,
        "schema_contract_version": permission_intel.SUPPORTED_V1_SCHEMA_VERSION,
        "compatibility_floor": permission_intel.SUPPORTED_V1_SCHEMA_VERSION,
        "schema_contract_release_status": permission_intel.SUPPORTED_V1_SCHEMA_RELEASE_STATUS,
        "catalog_digest": "a" * 64,
        "catalog_release_status": "ACCEPTED",
        "catalog_import_status": "IMPORTED",
        "import_receipt_count": 1,
        "accepted_at_utc": "2026-09-08 00:00:00",
    }

    def duplicate(sql, *args, **kwargs):
        if "android_permission_v1_catalog_release" in sql:
            return [gate]
        return [
            {
                "canonical_permission": "android.permission.INTERNET",
                "interpretation_contract_version": "1.1.0-draft",
            },
            {
                "canonical_permission": "android.permission.INTERNET",
                "interpretation_contract_version": "1.1.0-draft",
            },
        ]

    monkeypatch.setattr(permission_intel, "run_sql", duplicate)
    with pytest.raises(RuntimeError, match="duplicate identity"):
        permission_intel.fetch_v1_permission_rows(["android.permission.INTERNET"])

    def unsupported(sql, *args, **kwargs):
        if "android_permission_v1_catalog_release" in sql:
            return [gate]
        return [
            {
                "canonical_permission": "android.permission.INTERNET",
                "interpretation_contract_version": "2.0.0",
            }
        ]

    monkeypatch.setattr(permission_intel, "run_sql", unsupported)
    with pytest.raises(RuntimeError, match="interpretation contract"):
        permission_intel.fetch_v1_permission_rows(["android.permission.INTERNET"])
