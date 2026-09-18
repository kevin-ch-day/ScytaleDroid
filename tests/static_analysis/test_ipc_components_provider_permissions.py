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


def test_application_permission_is_inherited_by_components_without_explicit_guard() -> None:
    manifest = ElementTree.fromstring(
        """
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.example">
            <permission android:name="com.example.APP" android:protectionLevel="signature" />
            <application android:permission="com.example.APP">
                <activity android:name="com.example.InheritedActivity" android:exported="true" />
                <service android:name="com.example.InheritedService" android:exported="true" />
                <receiver android:name="com.example.InheritedReceiver" android:exported="true" />
                <provider
                    android:name="com.example.InheritedProvider"
                    android:authorities="com.example.inherited"
                    android:exported="true" />
                <activity
                    android:name="com.example.OverrideActivity"
                    android:exported="true"
                    android:permission="com.example.OVERRIDE" />
            </application>
        </manifest>
        """
    )
    components = {component.name: component for component in iter_manifest_components(manifest)}
    levels = {"com.example.APP": ("signature",), "com.example.OVERRIDE": ("signature",)}

    inherited = _classify_component(
        components["com.example.InheritedActivity"],
        protection_levels=levels,
        catalog={},
    )
    override = _classify_component(
        components["com.example.OverrideActivity"],
        protection_levels=levels,
        catalog={},
    )
    provider = _classify_component(
        components["com.example.InheritedProvider"],
        protection_levels=levels,
        catalog={},
    )

    assert components["com.example.InheritedActivity"].permission == "com.example.APP"
    assert components["com.example.InheritedService"].permission == "com.example.APP"
    assert components["com.example.InheritedReceiver"].permission == "com.example.APP"
    assert components["com.example.InheritedProvider"].permission == "com.example.APP"
    assert components["com.example.OverrideActivity"].permission == "com.example.OVERRIDE"
    assert inherited is not None and inherited.status is Badge.INFO
    assert override is not None and "com.example.OVERRIDE" in override.title
    assert provider is not None and provider.status is Badge.INFO


def test_provider_unprotected_write_is_exposed_when_only_read_is_guarded() -> None:
    components = tuple(
        iter_manifest_components(
            _manifest(
                """
                <provider
                    android:name="com.example.ReadOnlyGuard"
                    android:authorities="com.example.readonly"
                    android:exported="true"
                    android:readPermission="com.example.READ" />
                """
            )
        )
    )
    finding = _classify_component(
        components[0],
        protection_levels={"com.example.READ": ("signature",)},
        catalog={},
    )
    acl = {provider.name: provider for provider in collect_acl_providers(_manifest(
        """
        <provider
            android:name="com.example.ReadOnlyGuard"
            android:authorities="com.example.readonly"
            android:exported="true"
            android:readPermission="com.example.READ" />
        """
    ))}
    from scytaledroid.StaticAnalysis.detectors.provider_acl import _classify_provider

    acl_finding = _classify_provider(
        acl["com.example.ReadOnlyGuard"],
        protection_levels={"com.example.READ": ("signature",)},
        catalog={},
    )
    assert finding is not None
    assert finding.status is Badge.FAIL
    assert "unprotected write" in finding.title
    assert acl["com.example.ReadOnlyGuard"].read_permission == "com.example.READ"
    assert acl["com.example.ReadOnlyGuard"].write_permission is None
    assert acl_finding is not None
    assert "unprotected write" in acl_finding.title


def test_provider_unprotected_read_is_exposed_when_only_write_is_guarded() -> None:
    components = tuple(
        iter_manifest_components(
            _manifest(
                """
                <provider
                    android:name="com.example.WriteOnlyGuard"
                    android:authorities="com.example.writeonly"
                    android:exported="true"
                    android:writePermission="com.example.WRITE" />
                """
            )
        )
    )
    finding = _classify_component(
        components[0],
        protection_levels={"com.example.WRITE": ("signature",)},
        catalog={},
    )
    assert finding is not None
    assert finding.status is Badge.FAIL
    assert "unprotected read" in finding.title


def test_provider_general_permission_protects_both_directions() -> None:
    components = tuple(
        iter_manifest_components(
            _manifest(
                """
                <provider
                    android:name="com.example.GeneralGuard"
                    android:authorities="com.example.general"
                    android:exported="true"
                    android:permission="com.example.READ" />
                """
            )
        )
    )
    finding = _classify_component(
        components[0],
        protection_levels={"com.example.READ": ("signature",)},
        catalog={},
    )
    assert components[0].read_permission == "com.example.READ"
    assert components[0].write_permission == "com.example.READ"
    assert finding is not None
    assert finding.status is Badge.INFO


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
