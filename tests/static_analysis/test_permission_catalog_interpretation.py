from __future__ import annotations

from scytaledroid.StaticAnalysis.modules.permissions import catalog


def _legacy_catalog(tmp_path, monkeypatch) -> catalog.PermissionCatalog:
    source = tmp_path / "framework_permissions.yaml"
    source.write_text(
        "- name: android.permission.INTERNET\n"
        "  protection: normal\n"
        "  source: legacy_fixture\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(catalog, "_default_catalog_paths", lambda: (source,))
    catalog.load_permission_catalog.cache_clear()
    return catalog.load_permission_catalog()


def test_unknown_conditional_protection_remains_explicit(monkeypatch) -> None:
    from scytaledroid.Database.db_core import permission_intel

    monkeypatch.setattr(
        permission_intel,
        "fetch_v1_permission_catalog_rows",
        lambda: [
            {
                "canonical_permission": "android.permission.DEVICE_POWER",
                "accepted_platform_release": "37",
                "compatibility_protection_expression": None,
                "declaration_state": "MULTIPLE_FEATURE_DEPENDENT_ALTERNATIVES",
                "applicability_state": "REQUIRES_BUILD_CONFIGURATION_EVIDENCE",
                "protection_state": "UNKNOWN_REQUIRES_BUILD_CONFIGURATION",
            }
        ],
    )
    entries, version = catalog._load_db_catalog()  # noqa: SLF001
    descriptor = entries["android.permission.DEVICE_POWER"]
    assert version == "1"
    assert descriptor.protection == ()
    assert descriptor.guard_strength() == "unknown"
    assert descriptor.declaration_state == "MULTIPLE_FEATURE_DEPENDENT_ALTERNATIVES"
    assert descriptor.applicability_state == "REQUIRES_BUILD_CONFIGURATION_EVIDENCE"
    assert descriptor.protection_state == "UNKNOWN_REQUIRES_BUILD_CONFIGURATION"


def test_interpretation_state_is_retained_in_snapshots() -> None:
    descriptor = catalog.PermissionDescriptor(
        name="android.permission.MANAGE_CONTACTS",
        protection=(),
        source="permission_intel_v1_1_shadow",
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


def test_candidate_disabled_preserves_authoritative_legacy_without_db_read(
    tmp_path, monkeypatch
) -> None:
    from scytaledroid.Database.db_core import permission_intel

    monkeypatch.delenv("SCYTALEDROID_PERMISSION_INTEL_V1_SHADOW_MODE", raising=False)
    monkeypatch.setattr(
        permission_intel,
        "fetch_v1_permission_catalog_rows",
        lambda: (_ for _ in ()).throw(AssertionError("candidate DB must not be read")),
    )

    authoritative = _legacy_catalog(tmp_path, monkeypatch)
    assert authoritative.describe("android.permission.INTERNET").source == "legacy_fixture"
    assert catalog.load_permission_catalog_shadow() is None


def test_candidate_compare_only_is_separate_from_authoritative_legacy(
    tmp_path, monkeypatch
) -> None:
    from scytaledroid.Database.db_core import permission_intel

    monkeypatch.setenv("SCYTALEDROID_PERMISSION_INTEL_V1_SHADOW_MODE", "COMPARE_ONLY")
    monkeypatch.setattr(
        permission_intel,
        "fetch_v1_permission_catalog_rows",
        lambda: [
            {
                "canonical_permission": "android.permission.INTERNET",
                "accepted_platform_release": 37,
                "compatibility_protection_expression": "dangerous",
                "declaration_state": "SINGLE_UNCONDITIONAL_DECLARATION",
                "applicability_state": "UNCONDITIONAL",
                "protection_state": "DECLARED_IN_ACCEPTED_SOURCE_SCOPE",
            }
        ],
    )

    authoritative = _legacy_catalog(tmp_path, monkeypatch)
    candidate = catalog.load_permission_catalog_shadow()

    assert authoritative.guard_strength("android.permission.INTERNET") == "weak"
    assert candidate is not None
    assert candidate.guard_strength("android.permission.INTERNET") == "dangerous"
    assert candidate.describe("android.permission.INTERNET").source == (
        "permission_intel_v1_1_shadow"
    )
    assert catalog.load_permission_catalog() is authoritative


def test_candidate_compare_only_absence_does_not_suppress_legacy(
    tmp_path, monkeypatch
) -> None:
    from scytaledroid.Database.db_core import permission_intel

    monkeypatch.setenv("SCYTALEDROID_PERMISSION_INTEL_V1_SHADOW_MODE", "COMPARE_ONLY")
    monkeypatch.setattr(
        permission_intel,
        "fetch_v1_permission_catalog_rows",
        lambda: (_ for _ in ()).throw(RuntimeError("candidate unavailable")),
    )
    monkeypatch.setattr(permission_intel, "is_permission_intel_configured", lambda: True)

    authoritative = _legacy_catalog(tmp_path, monkeypatch)
    assert catalog.load_permission_catalog_shadow() is None
    assert authoritative.guard_strength("android.permission.INTERNET") == "weak"


def test_candidate_shadow_mode_rejects_unknown_values(monkeypatch) -> None:
    monkeypatch.setenv("SCYTALEDROID_PERMISSION_INTEL_V1_SHADOW_MODE", "AUTHORITATIVE")
    try:
        catalog.load_permission_catalog_shadow()
    except ValueError as exc:
        assert "LEGACY_ONLY" in str(exc)
        assert "COMPARE_ONLY" in str(exc)
    else:
        raise AssertionError("unknown shadow mode must fail closed")
