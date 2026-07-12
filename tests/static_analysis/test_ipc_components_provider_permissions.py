from __future__ import annotations

from xml.etree import ElementTree

from scytaledroid.StaticAnalysis.core.findings import Badge
from scytaledroid.StaticAnalysis.core.manifest_utils import (
    build_manifest_evidence,
    collect_exported_components,
)
from scytaledroid.StaticAnalysis.detectors.components import (
    _build_metrics,
    _classify_component,
    iter_manifest_components,
)
from scytaledroid.StaticAnalysis.detectors.provider_acl import (
    _collect_providers as collect_acl_providers,
)
from scytaledroid.StaticAnalysis.modules.storage_surface import (
    _collect_providers as collect_storage_providers,
)


def _manifest(body: str) -> ElementTree.Element:
    return ElementTree.fromstring(
        f"""
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.example">
            <permission
                android:name="com.example.READ"
                android:protectionLevel="signature" />
            <permission
                android:name="com.example.WRITE"
                android:protectionLevel="signature" />
            <application>
                {body}
            </application>
        </manifest>
        """
    )


def _manifest_with_target(body: str, *, target_sdk: int | None) -> ElementTree.Element:
    uses_sdk = (
        f'<uses-sdk android:targetSdkVersion="{target_sdk}" />'
        if target_sdk is not None
        else ""
    )
    return ElementTree.fromstring(
        f"""
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.example">
            {uses_sdk}
            <application>
                {body}
            </application>
        </manifest>
        """
    )


def test_exported_provider_read_write_permissions_are_recognized_as_guard() -> None:
    components = tuple(
        iter_manifest_components(
            _manifest(
                """
                <provider
                    android:name="com.example.Provider"
                    android:authorities="com.example.provider"
                    android:exported="true"
                    android:readPermission="com.example.READ"
                    android:writePermission="com.example.WRITE" />
                """
            )
        )
    )

    provider = components[0]
    finding = _classify_component(
        provider,
        protection_levels={
            "com.example.READ": ("signature",),
            "com.example.WRITE": ("signature",),
        },
        catalog={},
    )
    metrics = _build_metrics(
        components,
        None,
        protection_levels={
            "com.example.READ": ("signature",),
            "com.example.WRITE": ("signature",),
        },
        catalog={},
    )

    assert finding is not None
    assert finding.status is Badge.INFO
    assert finding.title == "Exported provider gated by com.example.READ (protectionLevel=signature); com.example.WRITE (protectionLevel=signature)"
    assert metrics["exported_with_permission"] == 1
    assert metrics["exported_without_permission"] == 0
    assert metrics["permission_guard_strength"] == {"strong": 1}


def test_exported_provider_without_base_read_or_write_permission_still_fails() -> None:
    components = tuple(
        iter_manifest_components(
            _manifest(
                """
                <provider
                    android:name="com.example.OpenProvider"
                    android:authorities="com.example.open"
                    android:exported="true" />
                """
            )
        )
    )

    finding = _classify_component(
        components[0],
        protection_levels={},
        catalog={},
    )

    assert finding is not None
    assert finding.status is Badge.FAIL
    assert "without permission" in finding.title


def test_disabled_exported_component_is_not_counted_as_effective_export() -> None:
    manifest = _manifest_with_target(
        """
        <activity
            android:name="com.example.DisabledActivity"
            android:enabled="false"
            android:exported="true" />
        <activity
            android:name="com.example.EnabledActivity"
            android:exported="true" />
        """,
        target_sdk=35,
    )

    components = tuple(iter_manifest_components(manifest))
    metrics = _build_metrics(components, None, protection_levels={}, catalog={})
    summary = collect_exported_components(manifest)
    evidence = build_manifest_evidence(manifest)

    assert metrics["components_exported"] == 1
    assert summary.activities == ("com.example.EnabledActivity",)
    disabled = next(
        row for row in evidence if row["name"] == "com.example.DisabledActivity"
    )
    assert disabled["exported_explicit"] is True
    assert disabled["exported_effective"] is False
    assert disabled["export_reason"] == "component_disabled"


def test_legacy_provider_without_exported_defaults_to_exported() -> None:
    manifest = _manifest_with_target(
        """
        <provider
            android:name="com.example.LegacyProvider"
            android:authorities="com.example.legacy" />
        """,
        target_sdk=16,
    )

    components = tuple(iter_manifest_components(manifest))
    finding = _classify_component(
        components[0],
        protection_levels={},
        catalog={},
    )
    summary = collect_exported_components(manifest)
    evidence = build_manifest_evidence(manifest)

    assert components[0].exported is True
    assert finding is not None
    assert finding.status is Badge.FAIL
    assert summary.providers == ("com.example.LegacyProvider",)
    assert evidence[0]["exported_effective"] is True
    assert evidence[0]["export_reason"] == "provider_default_true_legacy_sdk"


def test_modern_provider_without_exported_defaults_private() -> None:
    manifest = _manifest_with_target(
        """
        <provider
            android:name="com.example.ModernProvider"
            android:authorities="com.example.modern" />
        """,
        target_sdk=35,
    )

    components = tuple(iter_manifest_components(manifest))
    summary = collect_exported_components(manifest)
    evidence = build_manifest_evidence(manifest)

    assert components[0].exported is False
    assert summary.providers == tuple()
    assert evidence[0]["exported_effective"] is False
    assert evidence[0]["export_reason"] == "provider_default_false"


def test_provider_acl_parser_uses_legacy_exported_default_and_enabled_state() -> None:
    manifest = _manifest_with_target(
        """
        <provider
            android:name="com.example.LegacyProvider"
            android:authorities="com.example.legacy" />
        <provider
            android:name="com.example.DisabledProvider"
            android:authorities="com.example.disabled"
            android:enabled="false"
            android:exported="true" />
        """,
        target_sdk=16,
    )

    providers = {provider.name: provider for provider in collect_acl_providers(manifest)}

    assert providers["com.example.LegacyProvider"].exported is True
    assert providers["com.example.LegacyProvider"].export_reason == (
        "provider_default_true_legacy_sdk"
    )
    assert providers["com.example.DisabledProvider"].exported is False
    assert providers["com.example.DisabledProvider"].export_reason == "component_disabled"


def test_storage_surface_provider_parser_uses_effective_exported_state() -> None:
    manifest = _manifest_with_target(
        """
        <provider
            android:name="com.example.LegacyProvider"
            android:authorities="com.example.legacy" />
        <provider
            android:name="com.example.DisabledProvider"
            android:authorities="com.example.disabled"
            android:enabled="false"
            android:exported="true" />
        """,
        target_sdk=16,
    )

    providers = {provider.name: provider for provider in collect_storage_providers(manifest)}

    assert providers["com.example.LegacyProvider"].exported is True
    assert providers["com.example.LegacyProvider"].enabled is True
    assert providers["com.example.DisabledProvider"].exported is False
    assert providers["com.example.DisabledProvider"].enabled is False
