from __future__ import annotations

from scytaledroid.StaticAnalysis.modules.permissions import catalog


def _install_yaml_paths(tmp_path, monkeypatch) -> None:
    source = tmp_path / "framework_permissions.yaml"
    source.write_text(
        "- name: android.permission.INTERNET\n"
        "  protection: normal\n"
        "  source: legacy_fixture\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(catalog, "_default_catalog_paths", lambda: (source,))
    catalog.load_permission_catalog.cache_clear()


def _stub_permission_intel_reads(monkeypatch, *, v1_rows=None, aosp_rows=None, oem_rows=None) -> None:
    from scytaledroid.Database.db_core import permission_intel

    monkeypatch.setattr(permission_intel, "is_permission_intel_configured", lambda: True)
    if v1_rows is not None:
        monkeypatch.setattr(permission_intel, "fetch_v1_permission_catalog_rows", lambda: v1_rows)
    if aosp_rows is not None:
        monkeypatch.setattr(permission_intel, "fetch_aosp_permission_catalog_rows", lambda: aosp_rows)
    if oem_rows is not None:
        monkeypatch.setattr(permission_intel, "fetch_oem_permission_catalog_rows", lambda: oem_rows)


def test_unknown_conditional_protection_remains_explicit(monkeypatch) -> None:
    _stub_permission_intel_reads(
        monkeypatch,
        v1_rows=[
            {
                "canonical_permission": "android.permission.DEVICE_POWER",
                "accepted_platform_release": "37",
                "compatibility_protection_expression": None,
                "declaration_state": "MULTIPLE_FEATURE_DEPENDENT_ALTERNATIVES",
                "applicability_state": "REQUIRES_BUILD_CONFIGURATION_EVIDENCE",
                "protection_state": "UNKNOWN_REQUIRES_BUILD_CONFIGURATION",
            }
        ],
        aosp_rows=[],
        oem_rows=[],
    )
    entries, version = catalog._load_db_catalog()  # noqa: SLF001
    descriptor = entries["android.permission.DEVICE_POWER"]
    assert version == "1"
    assert descriptor.protection == ()
    assert descriptor.guard_strength() == "unknown"
    assert descriptor.source == "permission_intel_v1"
    assert descriptor.declaration_state == "MULTIPLE_FEATURE_DEPENDENT_ALTERNATIVES"
    assert descriptor.applicability_state == "REQUIRES_BUILD_CONFIGURATION_EVIDENCE"
    assert descriptor.protection_state == "UNKNOWN_REQUIRES_BUILD_CONFIGURATION"


def test_interpretation_state_is_retained_in_snapshots() -> None:
    descriptor = catalog.PermissionDescriptor(
        name="android.permission.MANAGE_CONTACTS",
        protection=(),
        source="permission_intel_v1",
        declaration_state="NO_DECLARATION_REVISION",
        applicability_state="NO_DECLARATION_APPLICABILITY_EVIDENCE",
        protection_state="UNKNOWN_NO_CURRENT_DECLARATION",
    )
    permissions = catalog.PermissionCatalog(
        entries={descriptor.name: descriptor}, version="1", case_sensitive=True
    )
    row = permissions.to_snapshot([descriptor.name])[descriptor.name]
    assert row["declaration_state"] == "NO_DECLARATION_REVISION"
    assert row["protection_state"] == "UNKNOWN_NO_CURRENT_DECLARATION"
    assert row["guard_strength"] == "unknown"


def test_yaml_fallback_when_permission_intel_not_configured(tmp_path, monkeypatch) -> None:
    from scytaledroid.Database.db_core import permission_intel

    monkeypatch.delenv("SCYTALEDROID_PERMISSION_INTEL_V1_SHADOW_MODE", raising=False)
    monkeypatch.setattr(permission_intel, "is_permission_intel_configured", lambda: False)
    monkeypatch.setattr(
        permission_intel,
        "fetch_v1_permission_catalog_rows",
        lambda: (_ for _ in ()).throw(AssertionError("candidate DB must not be read")),
    )
    _install_yaml_paths(tmp_path, monkeypatch)

    authoritative = catalog.load_permission_catalog()
    assert authoritative.describe("android.permission.INTERNET").source == "legacy_fixture"
    assert catalog.load_permission_catalog_shadow() is None


def test_analysis_catalog_prefers_deployed_permission_intel(tmp_path, monkeypatch) -> None:
    _stub_permission_intel_reads(
        monkeypatch,
        v1_rows=[
            {
                "canonical_permission": "android.permission.INTERNET",
                "accepted_platform_release": 37,
                "compatibility_protection_expression": "dangerous",
                "lifecycle": "declared_in_accepted_release",
            }
        ],
        aosp_rows=[],
        oem_rows=[],
    )
    _install_yaml_paths(tmp_path, monkeypatch)

    loaded = catalog.load_permission_catalog()
    assert loaded.guard_strength("android.permission.INTERNET") == "dangerous"
    assert loaded.describe("android.permission.INTERNET").source == "permission_intel_v1"


def test_candidate_compare_only_is_separate_diagnostic(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SCYTALEDROID_PERMISSION_INTEL_V1_SHADOW_MODE", "COMPARE_ONLY")
    _stub_permission_intel_reads(
        monkeypatch,
        v1_rows=[
            {
                "canonical_permission": "android.permission.INTERNET",
                "accepted_platform_release": 37,
                "compatibility_protection_expression": "dangerous",
                "declaration_state": "SINGLE_UNCONDITIONAL_DECLARATION",
                "applicability_state": "UNCONDITIONAL",
                "protection_state": "DECLARED_IN_ACCEPTED_SOURCE_SCOPE",
            }
        ],
        aosp_rows=[],
        oem_rows=[],
    )
    _install_yaml_paths(tmp_path, monkeypatch)

    loaded = catalog.load_permission_catalog()
    candidate = catalog.load_permission_catalog_shadow()

    assert loaded.guard_strength("android.permission.INTERNET") == "dangerous"
    assert candidate is not None
    assert candidate.guard_strength("android.permission.INTERNET") == "dangerous"
    assert candidate.describe("android.permission.INTERNET").source == "permission_intel_v1"


def test_yaml_fallback_when_permission_intel_read_fails(tmp_path, monkeypatch) -> None:
    from scytaledroid.Database.db_core import permission_intel

    monkeypatch.setenv("SCYTALEDROID_PERMISSION_INTEL_V1_SHADOW_MODE", "COMPARE_ONLY")
    monkeypatch.setattr(permission_intel, "is_permission_intel_configured", lambda: True)

    def _boom():
        raise RuntimeError("candidate unavailable")

    monkeypatch.setattr(permission_intel, "fetch_v1_permission_catalog_rows", _boom)
    monkeypatch.setattr(permission_intel, "fetch_aosp_permission_catalog_rows", _boom)
    monkeypatch.setattr(permission_intel, "fetch_oem_permission_catalog_rows", _boom)
    _install_yaml_paths(tmp_path, monkeypatch)

    loaded = catalog.load_permission_catalog()
    assert catalog.load_permission_catalog_shadow() is None
    assert loaded.guard_strength("android.permission.INTERNET") == "weak"
    assert loaded.describe("android.permission.INTERNET").source == "legacy_fixture"


def test_v1_internal_group_and_background_flow_into_descriptor(monkeypatch) -> None:
    _stub_permission_intel_reads(
        monkeypatch,
        v1_rows=[
            {
                "canonical_permission": "android.permission.READ_FRAME_BUFFER",
                "accepted_platform_release": 37,
                "compatibility_protection_expression": "internal|signature",
                "protection_base": "internal",
                "permission_group": None,
                "background_permission": None,
                "authority_class": "AOSP_HIDDEN",
                "lifecycle": "declared_in_accepted_release",
            },
            {
                "canonical_permission": "android.permission.ACCESS_FINE_LOCATION",
                "accepted_platform_release": 37,
                "compatibility_protection_expression": "dangerous",
                "permission_group": "LOCATION",
                "background_permission": "android.permission.ACCESS_BACKGROUND_LOCATION",
                "authority_class": "AOSP_PUBLIC",
                "feature_dependency": "android.hardware.location.gps",
                "lifecycle": "declared_in_accepted_release",
            },
        ],
        aosp_rows=[],
        oem_rows=[],
    )
    entries, version = catalog._load_db_catalog()  # noqa: SLF001
    assert version == "2"
    internal = entries["android.permission.READ_FRAME_BUFFER"]
    assert internal.protection == ("internal", "signature")
    assert internal.guard_strength() == "signature"
    assert internal.authority_class == "AOSP_HIDDEN"
    location = entries["android.permission.ACCESS_FINE_LOCATION"]
    assert location.permission_group == "LOCATION"
    assert location.background_permission == "android.permission.ACCESS_BACKGROUND_LOCATION"
    assert location.feature_dependency == "android.hardware.location.gps"
    snapshot = catalog.PermissionCatalog(entries=entries, version=version).to_snapshot(
        [location.name]
    )[location.name]
    assert snapshot["permission_group"] == "LOCATION"
    assert snapshot["background_permission"] == "android.permission.ACCESS_BACKGROUND_LOCATION"
    assert snapshot["authority_class"] == "AOSP_PUBLIC"
    assert snapshot["feature_dependency"] == "android.hardware.location.gps"


def test_v1_permission_group_shortens_and_drops_undefined(monkeypatch) -> None:
    _stub_permission_intel_reads(
        monkeypatch,
        v1_rows=[
            {
                "canonical_permission": "android.permission.health.READ_HEART_RATE",
                "compatibility_protection_expression": "dangerous",
                "permission_group": "android.permission-group.HEALTH",
                "authority_class": "AOSP_MODULE",
            },
            {
                "canonical_permission": "android.permission.CAMERA",
                "compatibility_protection_expression": "dangerous",
                "permission_group": "android.permission-group.UNDEFINED",
                "background_permission": "android.permission.BACKGROUND_CAMERA",
                "authority_class": "AOSP_PUBLIC",
            },
        ],
        aosp_rows=[],
        oem_rows=[],
    )
    entries, _version = catalog._load_db_catalog()  # noqa: SLF001
    health = entries["android.permission.health.READ_HEART_RATE"]
    assert health.permission_group == "HEALTH"
    camera = entries["android.permission.CAMERA"]
    assert camera.permission_group is None
    assert camera.background_permission == "android.permission.BACKGROUND_CAMERA"


def test_aosp_dict_supplement_fills_protected_names_missing_from_v1(monkeypatch) -> None:
    _stub_permission_intel_reads(
        monkeypatch,
        v1_rows=[
            {
                "canonical_permission": "android.permission.INTERNET",
                "compatibility_protection_expression": "normal",
            }
        ],
        aosp_rows=[
            ("android.permission.INTERNET", "normal", 1, None),
            ("android.permission.BOOT_COMPLETED", "normal", 1, None),
            ("android.permission.ACCESS_ADSERVICES_TOPICS", None, 33, None),
        ],
        oem_rows=[
            ("com.samsung.android.knox.permission.KNOX_CUSTOM_SETTING", "signature"),
        ],
    )
    entries, version = catalog._load_db_catalog()  # noqa: SLF001
    assert version == "3"
    assert entries["android.permission.INTERNET"].source == "permission_intel_v1"
    assert entries["android.permission.BOOT_COMPLETED"].source == "permission_intel_aosp_dict"
    assert entries["android.permission.BOOT_COMPLETED"].guard_strength() == "weak"
    assert "android.permission.ACCESS_ADSERVICES_TOPICS" not in entries
    knox = entries["com.samsung.android.knox.permission.KNOX_CUSTOM_SETTING"]
    assert knox.source == "permission_intel_oem_dict"
    assert knox.guard_strength() == "signature"


def test_merge_protection_levels_keeps_apk_values_and_fills_catalog_gaps() -> None:
    loaded = catalog.PermissionCatalog(
        entries={
            "android.permission.CAMERA": catalog.PermissionDescriptor(
                name="android.permission.CAMERA",
                protection=("dangerous", "instant"),
                source="permission_intel_v1",
            ),
            "android.permission.INTERNET": catalog.PermissionDescriptor(
                name="android.permission.INTERNET",
                protection=("normal",),
                source="permission_intel_v1",
            ),
        },
        version="2",
    )
    merged = loaded.merge_protection_levels(
        ["android.permission.CAMERA", "android.permission.INTERNET", "com.example.CUSTOM"],
        existing={"android.permission.CAMERA": ("normal",)},
    )
    assert merged["android.permission.CAMERA"] == ("normal",)
    assert merged["android.permission.INTERNET"] == ("normal",)
    assert "com.example.CUSTOM" not in merged


def test_candidate_shadow_mode_rejects_unknown_values(monkeypatch) -> None:
    monkeypatch.setenv("SCYTALEDROID_PERMISSION_INTEL_V1_SHADOW_MODE", "AUTHORITATIVE")
    try:
        catalog.load_permission_catalog_shadow()
    except ValueError as exc:
        assert "LEGACY_ONLY" in str(exc)
        assert "COMPARE_ONLY" in str(exc)
    else:
        raise AssertionError("unknown shadow mode must fail closed")
