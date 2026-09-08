from __future__ import annotations

from scytaledroid.Database.db_func.permissions import permission_dicts
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


def test_scytale_guard_rejects_legacy_membership_as_platform_authority() -> None:
    launcher = interpret_permission_row(
        "com.android.launcher.permission.READ_SETTINGS",
        {
            "fact_scope": "permission_definition",
            "fact_source_type": "aosp_package_manifest",
            "defining_package": "com.android.launcher",
            "legacy_source_type": "aosp_package_manifest",
        },
    )
    provider = interpret_permission_row(
        "com.android.email.permission.ACCESS_PROVIDER",
        {
            "fact_scope": "provider_permission",
            "fact_source_type": "aosp_package_manifest",
        },
    )
    baidu = interpret_permission_row(
        "android.permission.BAIDU_LOCATION_SERVICE",
        {
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
    assert c2d.authority_scope == "THIRD_PARTY_APPLICATION_DEFINED"
    assert not any(
        item.platform_authority_accepted
        for item in (launcher, provider, baidu, provisional, c2d)
    )


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
