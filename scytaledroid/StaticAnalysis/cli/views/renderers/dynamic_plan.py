"""Dynamic plan and baseline JSON renderers."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
from typing import Mapping, Sequence

from scytaledroid.Config import app_config
from scytaledroid.Utils.evidence_store import filesystem_safe_slug

from scytaledroid.StaticAnalysis.core import ManifestFlags, StaticAnalysisReport


def _build_modernization_guidance(
    report: StaticAnalysisReport,
    string_payload: Mapping[str, object],
) -> list[str]:
    """Return modernization recommendations for manifest/network settings."""

    flags = getattr(report, "manifest_flags", ManifestFlags())
    guidance: list[str] = []

    aggregates = string_payload.get("aggregates") if isinstance(string_payload, Mapping) else {}

    if getattr(flags, "request_legacy_external_storage", False):
        guidance.append("  - Migrate file access to scoped storage APIs (MediaStore, SAF) or app-private directories.")
        guidance.append("    Once migration is complete remove `android:requestLegacyExternalStorage=\"true\"` from <application>.")

    uses_cleartext = getattr(flags, "uses_cleartext_traffic", False)
    network_config_present = bool(getattr(flags, "network_security_config", None))

    if uses_cleartext:
        http_hosts: list[tuple[str, int]] = []
        if isinstance(aggregates, Mapping):
            roots = aggregates.get("endpoint_roots")
            if isinstance(roots, Sequence):
                for entry in roots:
                    if not isinstance(entry, Mapping):
                        continue
                    schemes = entry.get("schemes") if isinstance(entry.get("schemes"), Mapping) else {}
                    http_count = int(schemes.get("http", 0) or 0)
                    if http_count <= 0:
                        continue
                    root = str(entry.get("root_domain") or "").strip()
                    if not root:
                        continue
                    http_hosts.append((root, http_count))
            if not http_hosts:
                clear_entries = aggregates.get("endpoint_cleartext")
                if isinstance(clear_entries, Sequence):
                    seen: set[str] = set()
                    for entry in clear_entries:
                        if not isinstance(entry, Mapping):
                            continue
                        root = str(entry.get("root_domain") or "").strip()
                        if not root or root in seen:
                            continue
                        seen.add(root)
                        http_hosts.append((root, 1))

        http_hosts.sort(key=lambda item: (-item[1], item[0]))
        host_names = [host for host, _ in http_hosts[:3]]

        if not http_hosts:
            guidance.append("  - Remove `android:usesCleartextTraffic=\"true\"`; no HTTP endpoints were detected.")
        else:
            guidance.append("  - Provide a network security config that blocks cleartext by default and explicitly")
            guidance.append("    allows only the required HTTP domains while migrating remaining traffic to HTTPS.")
            guidance.append("    res/xml/network_security_config.xml:")
            guidance.append("      <network-security-config>")
            guidance.append("          <base-config cleartextTrafficPermitted=\"false\" />")
            for host in host_names:
                guidance.append("          <domain-config cleartextTrafficPermitted=\"true\">")
                guidance.append(f"              <domain includeSubdomains=\"true\">{host}</domain>")
                guidance.append("          </domain-config>")
            if not host_names:
                guidance.append("          <!-- add <domain> entries for the domains that must remain on HTTP -->")
            guidance.append("      </network-security-config>")
            guidance.append("    Reference the config from <application android:networkSecurityConfig=\"@xml/network_security_config\"/>.")
            if not network_config_present:
                guidance.append("    (No existing networkSecurityConfig was detected in the manifest.)")

    return guidance


def write_baseline_json(
    payload: Mapping[str, object],
    *,
    package: str,
    profile: str,
    scope: str,
) -> Path:
    """Persist payload to the baseline reports directory."""

    base_dir = Path(app_config.DATA_DIR) / "static_analysis" / "baseline"
    base_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    safe_package = filesystem_safe_slug(package)
    safe_profile = filesystem_safe_slug(profile)
    safe_scope = filesystem_safe_slug(scope)
    filename = f"{safe_package}-{safe_profile}-{safe_scope}-{timestamp}.json"
    path = base_dir / filename
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    return path


def _extract_domains(string_payload: Mapping[str, object]) -> tuple[list[str], list[str]]:
    aggregates = string_payload.get("aggregates", {}) if isinstance(string_payload, Mapping) else {}
    samples = string_payload.get("samples", {}) if isinstance(string_payload, Mapping) else {}
    domains: set[str] = set()
    cleartext_domains: set[str] = set()

    if isinstance(aggregates, Mapping):
        endpoint_roots = aggregates.get("endpoint_roots")
        if isinstance(endpoint_roots, Sequence):
            for entry in endpoint_roots:
                if not isinstance(entry, Mapping):
                    continue
                root = str(entry.get("root_domain") or "").strip()
                if not root:
                    continue
                domains.add(root)
                schemes = entry.get("schemes") if isinstance(entry.get("schemes"), Mapping) else {}
                if str(schemes.get("http") or "0").isdigit() and int(schemes.get("http") or 0) > 0:
                    cleartext_domains.add(root)
        endpoint_clear = aggregates.get("endpoint_cleartext")
        if isinstance(endpoint_clear, Sequence):
            for entry in endpoint_clear:
                if not isinstance(entry, Mapping):
                    continue
                root = str(entry.get("root_domain") or "").strip()
                if root:
                    domains.add(root)
                    cleartext_domains.add(root)

    if isinstance(samples, Mapping):
        for bucket in samples.values():
            if not isinstance(bucket, Sequence):
                continue
            for entry in bucket:
                if not isinstance(entry, Mapping):
                    continue
                root = str(entry.get("root_domain") or "").strip()
                if root:
                    domains.add(root)
                    scheme = str(entry.get("scheme") or "").lower()
                    if scheme == "http":
                        cleartext_domains.add(root)

    return sorted(domains), sorted(cleartext_domains)


def _high_value_permissions(declared: Sequence[str]) -> list[str]:
    high_value = {
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.READ_PHONE_STATE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.PACKAGE_USAGE_STATS",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
    }
    return sorted({perm for perm in declared if perm in high_value})


def build_dynamic_plan(
    report: StaticAnalysisReport,
    payload: Mapping[str, object],
) -> Mapping[str, object]:
    metadata = payload.get("app", {}) if isinstance(payload, Mapping) else {}
    baseline = payload.get("baseline", {}) if isinstance(payload, Mapping) else {}
    string_payload = baseline.get("string_analysis", {}) if isinstance(baseline, Mapping) else {}
    webview_summary = baseline.get("webview") if isinstance(baseline, Mapping) else None

    exported = report.exported_components
    permissions = report.permissions
    domains, cleartext_domains = _extract_domains(string_payload)
    declared = sorted(set(permissions.declared))
    dangerous = sorted(set(permissions.dangerous))
    high_value = _high_value_permissions(declared)

    suggested_probes: list[str] = []
    if exported.total() > 0:
        suggested_probes.append("exported_components_probe")
    if high_value:
        suggested_probes.append("high_value_permission_probe")
    if report.manifest_flags.uses_cleartext_traffic or cleartext_domains:
        suggested_probes.append("network_cleartext_observation")
    if webview_summary:
        suggested_probes.append("webview_observation")

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "package_name": metadata.get("package"),
        "version_name": metadata.get("version_name"),
        "version_code": metadata.get("version_code"),
        "hashes": metadata.get("hashes"),
        "exported_components": {
            "activities": list(exported.activities),
            "services": list(exported.services),
            "receivers": list(exported.receivers),
            "providers": list(exported.providers),
            "total": exported.total(),
        },
        "permissions": {
            "declared": declared,
            "dangerous": dangerous,
            "high_value": high_value,
        },
        "network_targets": {
            "domains": domains,
            "cleartext_domains": cleartext_domains,
        },
        "risk_flags": {
            "debuggable": report.manifest_flags.debuggable,
            "allow_backup": report.manifest_flags.allow_backup,
            "uses_cleartext_traffic": report.manifest_flags.uses_cleartext_traffic,
            "request_legacy_external_storage": report.manifest_flags.request_legacy_external_storage,
            "network_security_config": report.manifest_flags.network_security_config,
            "webview": webview_summary,
        },
        "suggested_probes": suggested_probes,
    }


def write_dynamic_plan_json(
    plan: Mapping[str, object],
    *,
    package: str,
    profile: str,
    scope: str,
) -> Path:
    base_dir = Path(app_config.DATA_DIR) / "static_analysis" / "dynamic_plan"
    base_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    safe_package = filesystem_safe_slug(package)
    safe_profile = filesystem_safe_slug(profile)
    safe_scope = filesystem_safe_slug(scope)
    filename = f"{safe_package}-{safe_profile}-{safe_scope}-{timestamp}.json"
    path = base_dir / filename
    with path.open("w", encoding="utf-8") as handle:
        json.dump(plan, handle, indent=2, sort_keys=True)
    return path


__all__ = [
    "build_dynamic_plan",
    "write_baseline_json",
    "write_dynamic_plan_json",
    "_build_modernization_guidance",
]
