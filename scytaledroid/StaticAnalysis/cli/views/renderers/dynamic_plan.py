"""Dynamic plan and baseline JSON renderers."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.StaticAnalysis.core import ManifestFlags, StaticAnalysisReport
from scytaledroid.Utils.evidence_store import filesystem_safe_slug

PLAN_SCHEMA_VERSION = "v1"


def _normalize_domain(value: object) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    raw = raw.strip(" \t\r\n\"'()[]{}<>")
    raw = raw.rstrip(").,;")
    if raw.startswith("*."):
        raw = raw[2:]
    if "%" in raw or " " in raw:
        return ""
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0]
    raw = raw.split("?", 1)[0]
    raw = raw.split("#", 1)[0]
    if ":" in raw:
        host, maybe_port = raw.rsplit(":", 1)
        if maybe_port.isdigit():
            raw = host
    if "." not in raw or ".." in raw:
        return ""
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
    if any(ch not in allowed for ch in raw):
        return ""
    if raw.startswith(".") or raw.endswith(".") or raw.startswith("-") or raw.endswith("-"):
        return ""
    return raw


def _validate_plan_schema(plan: Mapping[str, object]) -> None:
    """Fail fast if the plan is missing required keys/types.

    Empty arrays are acceptable; missing fields are not.
    """

    required_top = ("plan_schema_version", "schema_version", "generated_at", "run_identity", "network_targets")
    missing = [key for key in required_top if key not in plan]
    if missing:
        raise RuntimeError(f"dynamic plan schema missing required keys: {', '.join(missing)}")

    if plan.get("plan_schema_version") != PLAN_SCHEMA_VERSION:
        raise RuntimeError(f"dynamic plan schema_version unsupported: {plan.get('plan_schema_version')}")

    identity = plan.get("run_identity")
    if not isinstance(identity, Mapping):
        raise RuntimeError("dynamic plan run_identity must be an object")
    identity_fields = (
        "base_apk_sha256",
        "artifact_set_hash",
        "run_signature",
        "run_signature_version",
        "identity_valid",
        "identity_error_reason",
    )
    missing_ident = [field for field in identity_fields if field not in identity]
    if missing_ident:
        raise RuntimeError(f"dynamic plan run_identity missing fields: {', '.join(missing_ident)}")

    network = plan.get("network_targets")
    if not isinstance(network, Mapping):
        raise RuntimeError("dynamic plan network_targets must be an object")
    net_fields = ("domains", "cleartext_domains", "domain_sources", "domain_sources_note")
    missing_net = [field for field in net_fields if field not in network]
    if missing_net:
        raise RuntimeError(f"dynamic plan network_targets missing fields: {', '.join(missing_net)}")
    for field in ("domains", "cleartext_domains", "domain_sources"):
        if not isinstance(network.get(field), list):
            raise RuntimeError(f"dynamic plan network_targets.{field} must be an array")
    if not isinstance(network.get("domain_sources_note"), str):
        raise RuntimeError("dynamic plan network_targets.domain_sources_note must be a string")


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
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_package = filesystem_safe_slug(package)
    safe_profile = filesystem_safe_slug(profile)
    safe_scope = filesystem_safe_slug(scope)
    filename = f"{safe_package}-{safe_profile}-{safe_scope}-{timestamp}.json"
    path = base_dir / filename
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, default=str)
    return path


def _extract_domains(string_payload: Mapping[str, object]) -> tuple[list[str], list[str]]:
    aggregates = string_payload.get("aggregates", {}) if isinstance(string_payload, Mapping) else {}
    samples = string_payload.get("selected_samples") if isinstance(string_payload, Mapping) else None
    if not samples:
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


def _extract_nsc_domains(report: StaticAnalysisReport) -> tuple[list[str], list[str]]:
    metadata = report.metadata or {}
    bundle = metadata.get("repro_bundle") if isinstance(metadata, Mapping) else None
    if isinstance(bundle, Mapping):
        nsc_payload = bundle.get("network_security_config")
    else:
        nsc_payload = None
    if not isinstance(nsc_payload, Mapping):
        nsc_payload = metadata.get("network_security_config")

    nsc_domains: set[str] = set()
    nsc_cleartext: set[str] = set()
    if isinstance(nsc_payload, Mapping):
        domain_policies = nsc_payload.get("domain_policies")
        if isinstance(domain_policies, Sequence):
            for entry in domain_policies:
                if not isinstance(entry, Mapping):
                    continue
                domains = entry.get("domains")
                if not isinstance(domains, Sequence):
                    continue
                cleartext = bool(entry.get("cleartext_permitted"))
                for domain in domains:
                    value = str(domain or "").strip()
                    if not value:
                        continue
                    nsc_domains.add(value)
                    if cleartext:
                        nsc_cleartext.add(value)
    return sorted(nsc_domains), sorted(nsc_cleartext)


def _merge_domain_sources(
    *,
    string_domains: Sequence[str],
    nsc_domains: Sequence[str],
) -> tuple[list[str], list[dict[str, object]]]:
    sources: dict[str, set[str]] = {}
    for domain in string_domains:
        sources.setdefault(domain, set()).add("strings")
    for domain in nsc_domains:
        sources.setdefault(domain, set()).add("nsc")
    merged_domains = sorted(sources)
    domain_sources = [
        {"domain": domain, "sources": sorted(list(tags))}
        for domain, tags in sorted(sources.items())
    ]
    return merged_domains, domain_sources


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
    *,
    static_run_id: int | None = None,
    schema_version: str | None = None,
    batch_id: str | None = None,
) -> Mapping[str, object]:
    metadata = payload.get("app", {}) if isinstance(payload, Mapping) else {}
    baseline = payload.get("baseline", {}) if isinstance(payload, Mapping) else {}
    string_payload = baseline.get("string_analysis", {}) if isinstance(baseline, Mapping) else {}
    webview_summary = baseline.get("webview") if isinstance(baseline, Mapping) else None

    exported = report.exported_components
    permissions = report.permissions
    string_domains_raw, string_cleartext_raw = _extract_domains(string_payload)
    nsc_domains_raw, nsc_cleartext_raw = _extract_nsc_domains(report)
    string_domains = sorted({d for d in (_normalize_domain(item) for item in string_domains_raw) if d})
    string_cleartext = sorted({d for d in (_normalize_domain(item) for item in string_cleartext_raw) if d})
    nsc_domains = sorted({d for d in (_normalize_domain(item) for item in nsc_domains_raw) if d})
    nsc_cleartext = sorted({d for d in (_normalize_domain(item) for item in nsc_cleartext_raw) if d})
    domains, domain_sources = _merge_domain_sources(
        string_domains=string_domains,
        nsc_domains=nsc_domains,
    )
    cleartext_domains = sorted(set(string_cleartext).union(nsc_cleartext))
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

    # Contract note: the plan JSON is the "static snapshot" consumed by dynamic runs.
    # Keep a dedicated schema version so we can evolve the plan format without relying
    # on DB schema versions or implicit assumptions.
    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    plan = {
        "plan_schema_version": PLAN_SCHEMA_VERSION,
        "schema_version": schema_version,
        "generated_at": generated_at,
        "batch_id": batch_id,
        "package_name": metadata.get("package"),
        "version_name": metadata.get("version_name"),
        "version_code": metadata.get("version_code"),
        "hashes": metadata.get("hashes"),
        "run_identity": {
            "base_apk_sha256": metadata.get("base_apk_sha256"),
            "artifact_set_hash": metadata.get("artifact_set_hash"),
            "run_signature": metadata.get("run_signature"),
            "run_signature_version": metadata.get("run_signature_version"),
            # Convenience join pointer (not part of the identity tuple).
            "static_run_id": static_run_id,
            "identity_valid": metadata.get("identity_valid"),
            "identity_error_reason": metadata.get("identity_error_reason"),
        },
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
            "domain_sources": domain_sources,
            "domain_sources_note": "Sources are advisory signals (strings, nsc) and are not ground truth.",
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
    if static_run_id is not None:
        plan["static_run_id"] = static_run_id
    _validate_plan_schema(plan)
    return plan


def write_dynamic_plan_json(
    plan: Mapping[str, object],
    *,
    package: str,
    profile: str,
    scope: str,
    static_run_id: int | None = None,
) -> Path:
    _validate_plan_schema(plan)
    base_dir = Path(app_config.DATA_DIR) / "static_analysis" / "dynamic_plan"
    base_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_package = filesystem_safe_slug(package)
    safe_profile = filesystem_safe_slug(profile)
    safe_scope = filesystem_safe_slug(scope)
    run_segment = f"-sr{static_run_id}" if static_run_id is not None else ""
    filename = f"{safe_package}-{safe_profile}-{safe_scope}{run_segment}-{timestamp}.json"
    path = base_dir / filename
    with path.open("w", encoding="utf-8") as handle:
        json.dump(plan, handle, indent=2, sort_keys=True, default=str)
    return path


__all__ = [
    "build_dynamic_plan",
    "write_baseline_json",
    "write_dynamic_plan_json",
    "_build_modernization_guidance",
]
