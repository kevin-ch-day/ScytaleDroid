from __future__ import annotations

import pytest
from scytaledroid.Database.db_func.permissions import (
    current_interpretation,
    permission_dicts,
)
from scytaledroid.Database.db_func.permissions.current_interpretation import (
    interpret_permission_row,
)


def test_scytale_guard_preserves_identity_condition_and_conflict_safety() -> None:
    conditioned = interpret_permission_row(
        "android.permission.DETECT_SCREEN_RECORDING",
        {
            "canonical_permission": "android.permission.DETECT_SCREEN_RECORDING",
            "authority_class": "AOSP_HIDDEN",
            "feature_dependency": "screen.recording.flag",
            "catalog_protection": "signature|role",
        },
    )
    assert conditioned.identifier_recognition == "EXACT_ACCEPTED_CANONICAL"
    assert conditioned.declaration_state == "CONDITIONED"
    assert conditioned.feature_dependency == "screen.recording.flag"

    conflict = interpret_permission_row(
        "android.permission.GET_INTENT_SENDER_INTENT",
        {
            "canonical_permission": "android.permission.GET_INTENT_SENDER_INTENT",
            "authority_class": "AOSP_HIDDEN",
            "feature_dependency": "virtual.device.flag",
            "unresolved_conflict_count": 1,
            "catalog_protection": "signature|role",
        },
    )
    assert conflict.platform_authority_accepted is True
    assert conflict.protection_result is None

    accepted_application = interpret_permission_row(
        "android.permission.HOST_DEFINED_EXAMPLE",
        {
            "canonical_permission": "android.permission.HOST_DEFINED_EXAMPLE",
            "authority_class": "APPLICATION_DEFINED",
        },
    )
    assert accepted_application.authority_scope == "THIRD_PARTY_APPLICATION_DEFINED"
    assert accepted_application.platform_authority_accepted is False


def test_scytale_exact_catalog_identity_rejects_nonexact_fact_lifecycle() -> None:
    token = "android.permission.CAMERA"
    mismatched_fact = interpret_permission_row(
        token,
        {
            "canonical_permission": token,
            "authority_class": "AOSP_PUBLIC",
            "catalog_lifecycle": "active",
            "catalog_protection": "dangerous",
            "fact_permission_string": "ANDROID.PERMISSION.CAMERA",
            "fact_scope": "removed_api",
            "fact_lifecycle": "historical",
        },
    )
    exact_fact = interpret_permission_row(
        token,
        {
            "canonical_permission": token,
            "authority_class": "AOSP_PUBLIC",
            "catalog_lifecycle": "active",
            "catalog_protection": "dangerous",
            "fact_permission_string": token,
            "fact_scope": "removed_api",
            "fact_lifecycle": "historical",
        },
    )

    assert mismatched_fact.authority_scope == "AOSP_PLATFORM"
    assert mismatched_fact.declaration_state == "UNCONDITIONAL"
    assert mismatched_fact.protection_result == "dangerous"
    assert exact_fact.authority_scope == "HISTORICAL_PLATFORM"
    assert exact_fact.declaration_state == "NOT_APPLICABLE"
    assert exact_fact.protection_result is None


def test_scytale_guard_rejects_legacy_membership_as_platform_authority() -> None:
    launcher = interpret_permission_row(
        "com.android.launcher.permission.READ_SETTINGS",
        {
            "fact_permission_string": "com.android.launcher.permission.READ_SETTINGS",
            "fact_scope": "permission_definition",
            "fact_source_type": "aosp_package_manifest",
            "defining_package": "com.android.launcher",
            "legacy_source_type": "aosp_package_manifest",
        },
    )
    provider = interpret_permission_row(
        "com.android.email.permission.ACCESS_PROVIDER",
        {
            "fact_permission_string": "com.android.email.permission.ACCESS_PROVIDER",
            "fact_scope": "provider_permission",
            "fact_source_type": "aosp_package_manifest",
        },
    )
    baidu = interpret_permission_row(
        "android.permission.BAIDU_LOCATION_SERVICE",
        {
            "fact_permission_string": "android.permission.BAIDU_LOCATION_SERVICE",
            "fact_scope": "permission_definition",
            "fact_source_type": "sdk_vendor_docs",
            "anomaly_class": "vendor_namespace_in_android",
        },
    )
    provisional = interpret_permission_row(
        "android.permission.PREVENT_POWER_KEY",
        {
            "legacy_source_type": "queue_apply_shell",
            "legacy_source_family": "aosp_sparse_queue_apply_shell",
            "concept_status": "provisional",
        },
    )
    assert launcher.authority_scope == "AOSP_PACKAGE_DEFINED"
    assert provider.identifier_kind == "PROVIDER_PERMISSION"
    assert provider.authority_scope == "AOSP_PROVIDER_ACL"
    assert baidu.authority_scope == "SDK_INTEGRATION_CUSTOM_PERMISSION"
    assert provisional.evidence_state == "PROVISIONAL_SEED_ONLY"
    c2d = interpret_permission_row(
        "android.permission.C2D_MESSAGE",
        {
            "fact_scope": "custom_permission_pattern",
            "fact_source_type": "android_public_docs",
            "fact_lifecycle": "historical",
        },
    )
    assert c2d.authority_scope == "UNKNOWN"
    assert c2d.declaration_state == "NO_DECLARATION"
    assert c2d.evidence_state == "INSUFFICIENT"
    assert not any(
        item.platform_authority_accepted for item in (launcher, provider, baidu, provisional, c2d)
    )


def test_scytale_requires_definition_scope_and_resolved_oem_relationship() -> None:
    source_only = interpret_permission_row(
        "vendor.example.permission.ACCESS",
        {
            "fact_permission_string": "vendor.example.permission.ACCESS",
            "fact_scope": "provider_permission",
            "fact_source_type": "sdk_vendor_docs",
        },
    )
    unresolved_oem = interpret_permission_row(
        "vendor.example.permission.ACCESS",
        {
            "fact_permission_string": "vendor.example.permission.ACCESS",
            "fact_scope": "permission_definition",
            "oem_permission_string": "vendor.example.permission.ACCESS",
            "oem_vendor_id": None,
        },
    )
    resolved_oem = interpret_permission_row(
        "vendor.example.permission.ACCESS",
        {
            "fact_permission_string": "vendor.example.permission.ACCESS",
            "fact_scope": "permission_definition",
            "oem_permission_string": "vendor.example.permission.ACCESS",
            "oem_vendor_id": 7,
            "resolved_oem_vendor_id": 7,
        },
    )
    padded_definition = interpret_permission_row(
        " vendor.example.permission.ACCESS",
        {
            "fact_permission_string": "vendor.example.permission.ACCESS",
            "fact_scope": "permission_definition",
            "fact_source_type": "sdk_vendor_docs",
        },
    )
    assert source_only.evidence_state == "INSUFFICIENT"
    assert unresolved_oem.authority_scope == "UNKNOWN"
    assert resolved_oem.authority_scope == "OEM_OR_VENDOR"
    assert resolved_oem.evidence_state == "SOURCE_BACKED_DEFINITION"
    assert padded_definition.authority_scope == "UNKNOWN"
    assert padded_definition.evidence_state == "INSUFFICIENT"


def test_scytale_rejects_conflicting_rows_for_one_requested_token(monkeypatch) -> None:
    token = "vendor.example.permission.ACCESS"
    monkeypatch.setattr(
        current_interpretation.permission_intel,
        "fetch_current_permission_interpretation_rows",
        lambda _values: [
            {"lookup_token_norm": token.lower(), "fact_scope": "permission_definition"},
            {"lookup_token_norm": token.lower(), "fact_scope": "provider_permission"},
        ],
    )
    with pytest.raises(RuntimeError, match="conflicting Permission Intel evidence"):
        current_interpretation.fetch_current_interpretations([token])


def test_scytale_does_not_collapse_padded_and_clean_lookup_keys(monkeypatch) -> None:
    clean = "android.permission.CAMERA"
    padded = f" {clean}"
    monkeypatch.setattr(
        current_interpretation.permission_intel,
        "fetch_current_permission_interpretation_rows",
        lambda _values: [
            {
                "lookup_token_norm": clean.lower(),
                "canonical_permission": clean,
                "authority_class": "AOSP_PUBLIC",
            },
            {"lookup_token_norm": padded.lower()},
        ],
    )
    decisions = current_interpretation.fetch_current_interpretations([clean, padded])
    assert decisions[clean].identifier_recognition == "EXACT_ACCEPTED_CANONICAL"
    assert decisions[padded].identifier_recognition == "UNRESOLVED_IDENTIFIER"


def test_scytale_legacy_entry_and_scalar_adapters_fail_closed(monkeypatch) -> None:
    camera = interpret_permission_row(
        "android.permission.CAMERA",
        {
            "canonical_permission": "android.permission.CAMERA",
            "authority_class": "AOSP_PUBLIC",
            "catalog_protection": "dangerous",
            "legacy_name": "CAMERA",
        },
    )
    conflict = interpret_permission_row(
        "android.permission.DEVICE_POWER",
        {
            "canonical_permission": "android.permission.DEVICE_POWER",
            "authority_class": "AOSP_HIDDEN",
            "feature_dependency": "bluetooth.flag",
            "unresolved_conflict_count": 1,
            "catalog_protection": "signature|module|role",
            "legacy_name": "DEVICE_POWER",
        },
    )
    baidu = interpret_permission_row(
        "android.permission.BAIDU_LOCATION_SERVICE",
        {
            "fact_permission_string": "android.permission.BAIDU_LOCATION_SERVICE",
            "fact_scope": "permission_definition",
            "fact_source_type": "sdk_vendor_docs",
            "anomaly_class": "vendor_namespace_in_android",
            "legacy_name": "BAIDU_LOCATION_SERVICE",
        },
    )
    decisions = {
        camera.token: camera,
        conflict.token: conflict,
        baidu.token: baidu,
        "android.permission.DETECT_SCREEN_RECORDING": interpret_permission_row(
            "android.permission.DETECT_SCREEN_RECORDING",
            {
                "canonical_permission": "android.permission.DETECT_SCREEN_RECORDING",
                "authority_class": "AOSP_HIDDEN",
                "feature_dependency": "screen.recording.flag",
                "catalog_protection": "normal",
                "legacy_name": "DETECT_SCREEN_RECORDING",
            },
        ),
    }
    monkeypatch.setattr(
        permission_dicts,
        "fetch_current_interpretations",
        lambda values: {value: decisions[value] for value in values},
    )

    entries = permission_dicts.fetch_aosp_entries(list(decisions))
    assert set(entries) == {
        "android.permission.CAMERA",
        "android.permission.DEVICE_POWER",
        "android.permission.DETECT_SCREEN_RECORDING",
    }
    protection = permission_dicts.fetch_aosp_protection_map(
        [
            "CAMERA",
            "DEVICE_POWER",
            "DETECT_SCREEN_RECORDING",
            "BAIDU_LOCATION_SERVICE",
        ]
    )
    assert protection == {
        "CAMERA": "dangerous",
        "DEVICE_POWER": None,
        "DETECT_SCREEN_RECORDING": None,
    }
