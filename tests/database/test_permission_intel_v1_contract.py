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


def test_v1_lookup_is_binary_and_shadow_only(monkeypatch) -> None:
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
        return [{"canonical_permission": "android.permission.INTERNET"}]

    monkeypatch.setattr(permission_intel, "run_sql", fake_run_sql)
    rows = permission_intel.fetch_v1_permission_rows(["android.permission.INTERNET"])
    assert rows[0]["reference_mode"] == "SHADOW_READ_ONLY"
    assert rows[0]["scope_complete"] is False
    assert "BINARY canonical_permission IN" in calls[1]
    assert "authority_class IN" in calls[1]
    assert "catalog_release_id = %s" in calls[1]
    assert params_seen[1] == (
        "android.permission.INTERNET",
        "release",
        "a" * 64,
    )


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

    assert "authority_class IN ('AOSP_PUBLIC', 'AOSP_INTERNAL', 'AOSP_MODULE')" in calls[1]
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


def test_scytale_permission_intel_never_writes_obs_sample() -> None:
    source = permission_intel.__file__
    assert source is not None
    text = Path(source).read_text(encoding="utf-8").lower()
    assert "insert into android_permission_obs_sample" not in text
