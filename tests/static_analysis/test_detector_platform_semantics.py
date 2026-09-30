from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree

from scytaledroid.StaticAnalysis.core.findings import Badge, SeverityLevel
from scytaledroid.StaticAnalysis.core.models import (
    ManifestFlags,
    ManifestSummary,
    PermissionSummary,
)
from scytaledroid.StaticAnalysis.detectors.correlation.network import (
    network_snapshot_from_metrics,
    policy_from_payload,
)
from scytaledroid.StaticAnalysis.detectors.manifest import (
    ManifestBaselineDetector,
    _classify_custom_permissions,
)
from scytaledroid.StaticAnalysis.detectors.network import (
    _cleartext_policy_state,
    _filter_http_matches,
    _nsc_allows_cleartext,
    _summarise_surface,
)
from scytaledroid.StaticAnalysis.detectors.storage import _build_findings
from scytaledroid.StaticAnalysis.modules.network_security.models import (
    DomainPolicy,
    NetworkSecurityPolicy,
)
from scytaledroid.StaticAnalysis.modules.network_security.parser import (
    extract_network_security_policy,
)


def _context(target_sdk: int) -> SimpleNamespace:
    return SimpleNamespace(
        apk_path=Path("dummy.apk"),
        manifest_root=ElementTree.fromstring("<manifest><application /></manifest>"),
        manifest_summary=ManifestSummary(package_name="com.example", target_sdk=str(target_sdk)),
        manifest_flags=ManifestFlags(allow_backup=True, request_legacy_external_storage=True),
        permissions=PermissionSummary(),
        permission_catalog={},
        network_security_policy=None,
    )


def test_cleartext_default_depends_on_target_and_explicit_policy() -> None:
    assert _nsc_allows_cleartext(None, "api.example.org", target_sdk=27) is True
    assert _nsc_allows_cleartext(None, "api.example.org", target_sdk=28) is False
    assert _nsc_allows_cleartext(
        None, "api.example.org", target_sdk=35, uses_cleartext_traffic=True
    ) is True
    assert _nsc_allows_cleartext(
        NetworkSecurityPolicy.empty(),
        "api.example.org",
        target_sdk=35,
        uses_cleartext_traffic=True,
    ) is True
    assert _nsc_allows_cleartext(
        None, "api.example.org", target_sdk=38, uses_cleartext_traffic=True
    ) is False
    policy = NetworkSecurityPolicy(
        source_path="res/xml/network.xml",
        base_cleartext=None,
        debug_overrides_cleartext=None,
        trust_user_certificates=False,
        domain_policies=(
            DomainPolicy(
                domains=("example.org",),
                include_subdomains=True,
                cleartext_permitted=True,
                user_certificates_allowed=False,
            ),
            DomainPolicy(
                domains=("secure.example.org",),
                include_subdomains=True,
                cleartext_permitted=False,
                user_certificates_allowed=False,
            ),
        ),
    )
    assert _nsc_allows_cleartext(policy, "api.example.org", target_sdk=35) is True
    assert _nsc_allows_cleartext(policy, "api.secure.example.org", target_sdk=35) is False
    assert _nsc_allows_cleartext(policy, "other.org", target_sdk=35) is False


def test_cleartext_policy_uncertainty_stays_out_of_viable_endpoint_count() -> None:
    assert _cleartext_policy_state(None, "api.example.org") == "unknown"
    missing_config = NetworkSecurityPolicy(
        source_path="res/xml/missing.xml",
        base_cleartext=None,
        debug_overrides_cleartext=None,
        trust_user_certificates=False,
    )
    assert _cleartext_policy_state(
        missing_config, "api.example.org", target_sdk=35
    ) == "unknown"
    unresolved = SimpleNamespace(host="api.example.org", url="http://api.example.org")
    allowed, blocked, allowlisted, unknown = _filter_http_matches(
        (unresolved,), missing_config, target_sdk=35
    )
    assert allowed == ()
    assert blocked == ()
    assert allowlisted == ()
    assert unknown == (unresolved,)
    metrics, status = _summarise_surface(
        (), (), {}, ManifestFlags(), unresolved_matches=(unresolved,)
    )
    assert status == "review"
    assert metrics["surface"]["counts"]["http"] == 0
    assert metrics["surface"]["http_literals_policy_unknown"] == 1


def test_nsc_include_subdomains_applies_to_each_domain_rule() -> None:
    raw_xml = b'''<network-security-config>
      <base-config cleartextTrafficPermitted="false" />
      <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">wide.test</domain>
        <domain includeSubdomains="false">exact.test</domain>
        <trust-anchors><certificates src="user" /></trust-anchors>
        <pin-set expiration="2030-01-01"><pin digest="SHA-256">abc=</pin></pin-set>
      </domain-config>
    </network-security-config>'''
    apk = SimpleNamespace(get_file=lambda _path: raw_xml)
    policy = extract_network_security_policy(
        apk, manifest_reference="@xml/network_security_config"
    )
    assert len(policy.domain_policies) == 2
    assert all(domain.user_certificates_allowed for domain in policy.domain_policies)
    assert policy.domain_policies[0].pinned_certificates[0]["expiration"] == "2030-01-01"
    assert policy.domain_policies[0].pinned_certificates[0]["pins"] == [
        {"digest": "SHA-256", "value": "abc="}
    ]
    restored = policy_from_payload(policy.to_dict())
    assert restored.domain_policies[0].pinned_certificates == policy.domain_policies[0].pinned_certificates
    assert restored.domain_policies[0].trust_anchors == ("user",)
    assert network_snapshot_from_metrics(None, restored).pinned_domains == (
        "exact.test", "wide.test"
    )
    assert _cleartext_policy_state(policy, "api.wide.test", target_sdk=35) == "allowed"
    assert _cleartext_policy_state(policy, "exact.test", target_sdk=35) == "allowed"
    assert _cleartext_policy_state(policy, "api.exact.test", target_sdk=35) == "blocked"


def test_nsc_parser_accepts_decoded_android_namespaced_attributes() -> None:
    raw_xml = b'''<network-security-config xmlns:android="http://schemas.android.com/apk/res/android">
      <base-config android:cleartextTrafficPermitted="true" />
    </network-security-config>'''
    apk = SimpleNamespace(get_file=lambda _path: raw_xml)
    policy = extract_network_security_policy(apk, manifest_reference="@xml/network")
    assert policy.base_cleartext is True


def test_nsc_parser_decodes_binary_xml_and_retains_raw_hash(monkeypatch) -> None:
    from scytaledroid.StaticAnalysis.modules.network_security import parser

    class BinaryPrinter:
        def __init__(self, raw: bytes) -> None:
            assert raw == b"\x03\x00\x08\x00compiled"

        def is_valid(self) -> bool:
            return True

        def get_buff(self) -> bytes:
            return b'<network-security-config><base-config cleartextTrafficPermitted="true" /></network-security-config>'

    monkeypatch.setattr(parser, "AXMLPrinter", BinaryPrinter)
    apk = SimpleNamespace(get_file=lambda _path: b"\x03\x00\x08\x00compiled")
    policy = extract_network_security_policy(apk, manifest_reference="@xml/network")
    assert policy.parse_valid is True
    assert policy.base_cleartext is True
    assert len(policy.raw_xml_hash or "") == 64
    restored = policy_from_payload(policy.to_dict())
    assert restored.parse_valid is True


def test_unreadable_nsc_remains_unknown_even_with_target_default() -> None:
    apk = SimpleNamespace(get_file=lambda _path: b"<network-security-config")
    policy = extract_network_security_policy(apk, manifest_reference="@xml/network")
    assert policy.parse_valid is False
    assert len(policy.raw_xml_hash or "") == 64
    assert _cleartext_policy_state(policy, "api.example.org", target_sdk=35) == "unknown"
    restored = policy_from_payload(policy.to_dict())
    assert _cleartext_policy_state(restored, "api.example.org", target_sdk=35) == "unknown"


def test_backup_and_modern_legacy_flag_are_observations() -> None:
    context = _context(35)
    manifest_findings = {
        finding.finding_id: finding
        for finding in ManifestBaselineDetector().run(context).findings
    }
    storage_findings = {
        finding.finding_id: finding for finding in _build_findings(context, ())
    }
    for finding_id in ("manifest_backup_enabled", "manifest_legacy_external_storage"):
        finding = manifest_findings[finding_id]
        assert finding.status is Badge.INFO
        assert finding.severity_gate is SeverityLevel.P2
    for finding_id in ("storage_allow_backup", "storage_legacy_external"):
        finding = storage_findings[finding_id]
        assert finding.status is Badge.INFO
        assert finding.severity_gate is SeverityLevel.P2

    legacy_context = _context(29)
    legacy = {
        finding.finding_id: finding
        for finding in ManifestBaselineDetector().run(legacy_context).findings
    }["manifest_legacy_external_storage"]
    assert legacy.status is Badge.WARN
    assert legacy.severity_gate is SeverityLevel.P1


def test_numeric_custom_permission_is_not_weak_in_manifest_summary() -> None:
    buckets = _classify_custom_permissions(
        {
            "com.example.SIGNATURE": {"protection_levels": ("0x00000002",)},
            "com.example.NORMAL": {"protection_levels": ("0x00000000",)},
            "com.example.DEFAULT_NORMAL": {"protection_levels": ()},
        }
    )
    assert buckets["strong"] == ("com.example.SIGNATURE",)
    assert buckets["weak"] == ("com.example.DEFAULT_NORMAL", "com.example.NORMAL")


def test_manifest_export_summary_excludes_unknown_and_directionally_guarded_provider() -> None:
    context = _context(35)
    context.manifest_root = ElementTree.fromstring(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        '<application>'
        '<provider android:name="com.example.Guarded" android:exported="true" '
        'android:readPermission="com.example.SIGNATURE" '
        'android:writePermission="com.example.SIGNATURE" />'
        '<activity android:name="com.example.Unknown" android:exported="true" '
        'android:permission="com.example.UNRESOLVED" />'
        '<service android:name="com.example.Open" android:exported="true" />'
        '</application></manifest>'
    )
    context.permissions = PermissionSummary(
        protection_levels={"com.example.SIGNATURE": ("signature",)}
    )
    result = ManifestBaselineDetector().run(context)
    summary = result.metrics["component_guard_summary"]
    assert summary["signature_exports"] == ("com.example.Guarded",)
    assert summary["unknown_exports"] == ("com.example.Unknown",)
    assert summary["weak_exports"] == ("com.example.Open",)
    aggregate = next(
        finding for finding in result.findings
        if finding.finding_id == "manifest_exported_weak_guards"
    )
    assert aggregate.status is Badge.INFO
    assert aggregate.severity_gate is SeverityLevel.P2
