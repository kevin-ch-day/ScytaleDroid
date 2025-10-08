"""Canonical view model builders for static analysis reports."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, MutableMapping, Sequence

from scytaledroid.Config import app_config

from ..core import Finding, SeverityLevel, StaticAnalysisReport
from ..detectors.permissions import PermissionsProfileDetector
from ..modules.permissions.rules import SENSITIVITY_WEIGHTS, SPECIAL_ACCESS_PERMISSIONS


_DEFAULT_TIME_FORMAT = "%Y-%m-%d %H:%M"


def build_report_view(report: StaticAnalysisReport) -> Mapping[str, Any]:
    """Return a canonical presentation payload for *report*."""

    manifest = report.manifest
    metadata = report.metadata or {}

    app_name = _pick_first(
        metadata.get("app_label"),
        manifest.app_label,
        manifest.package_name,
        report.file_name,
        default="—",
    )
    package_name = _pick_first(
        manifest.package_name,
        metadata.get("package_name"),
        default="—",
    )
    version_name = _pick_first(
        manifest.version_name,
        metadata.get("version_name"),
        default="—",
    )
    version_code = _pick_first(
        manifest.version_code,
        metadata.get("version_code"),
        default="—",
    )
    main_activity = _pick_first(manifest.main_activity, default="—")

    severity_counts = _count_severity(report.findings)
    badge, badge_class = _determine_badge(severity_counts)

    integrity_profiles = _extract_integrity_profiles(report)
    package_profile = integrity_profiles.get("package", {})
    artifact_profile = integrity_profiles.get("artifact", {})
    integrity_card = integrity_profiles.get("integrity", {})

    topology = _build_topology_payload(package_profile, artifact_profile, integrity_card)
    signing = _build_signing_payload(package_profile)

    permission_entries = _collect_permission_rows(report)

    network_payload = _build_network_payload(report)
    indicator_payload = _build_indicator_payload(network_payload)

    secrets_payload = _collect_secret_rows(report)

    risk_payload = _compute_risk_model(
        permission_entries,
        secrets_payload,
        network_payload,
        report,
    )

    timestamp_utc = _format_generated_timestamp(report.generated_at)
    toolchain = _normalise_toolchain(metadata.get("toolchain"))

    view: MutableMapping[str, Any] = {
        "app": {
            "name": app_name,
            "package": package_name,
            "version_name": version_name,
            "version_code": version_code,
            "main_activity": main_activity or "—",
        },
        "identity": {
            "size_bytes": report.file_size,
            "size_human": _human_size(report.file_size),
            "hashes": {
                "md5": report.hashes.get("md5") or "—",
                "sha1": report.hashes.get("sha1") or "—",
                "sha256": report.hashes.get("sha256") or "—",
            },
        },
        "artifact": {
            "label": metadata.get("artifact") or report.file_name,
            "role": artifact_profile.get("role") or artifact_profile.get("role_label") or "—",
        },
        "result": {
            "badge": badge,
            "badge_class": badge_class,
            "p0": severity_counts.get("P0", 0),
            "p1": severity_counts.get("P1", 0),
            "p2": severity_counts.get("P2", 0),
        },
        "topology": topology,
        "signing": signing,
        "permissions": permission_entries,
        "indicators": indicator_payload,
        "network": network_payload,
        "secrets": secrets_payload,
        "risk": risk_payload,
        "run": {
            "profile": metadata.get("run_profile") or report.scan_profile or "quick",
            "verbosity": metadata.get("run_verbosity") or "summary",
            "evidence_limit": metadata.get("evidence_limit") or metadata.get("run_evidence_limit") or "—",
            "toolchain": toolchain,
            "timestamp_utc": timestamp_utc,
            "seed": metadata.get("run_id") or "—",
            "version": f"{app_config.APP_VERSION} ({app_config.APP_RELEASE})",
        },
    }

    return view


def _pick_first(*candidates: Any, default: str = "") -> Any:
    for value in candidates:
        if isinstance(value, str) and value.strip():
            return value
        if value not in (None, "") and not isinstance(value, str):
            return value
    return default


def _count_severity(findings: Sequence[Finding]) -> MutableMapping[str, int]:
    counts: MutableMapping[str, int] = {level.value: 0 for level in SeverityLevel}
    for finding in findings:
        if not isinstance(finding, Finding):
            continue
        counts.setdefault(finding.severity_gate.value, 0)
        counts[finding.severity_gate.value] += 1
    return counts


def _determine_badge(counts: Mapping[str, int]) -> tuple[str, str]:
    if counts.get("P0", 0):
        return "FAIL", "fail"
    if counts.get("P1", 0):
        return "WARN", "warn"
    return "OK", "ok"


def _extract_integrity_profiles(report: StaticAnalysisReport) -> Mapping[str, Mapping[str, Any]]:
    profiles: MutableMapping[str, Mapping[str, Any]] = {}
    for result in report.detector_results:
        if result.section_key != "integrity":
            continue
        metrics = result.metrics or {}
        presentation = metrics.get("presentation")
        if isinstance(presentation, Mapping):
            for key in ("package", "artifact", "integrity"):
                payload = presentation.get(key)
                if isinstance(payload, Mapping):
                    profiles[key] = dict(payload)
        break
    return profiles


def _build_topology_payload(
    package_profile: Mapping[str, Any],
    artifact_profile: Mapping[str, Any],
    integrity_card: Mapping[str, Any],
) -> Mapping[str, Any]:
    modules = {"base": False, "config": []}

    role = str(artifact_profile.get("role") or "").lower()
    modules["base"] = role in {"base", "feature"}

    module_counts = package_profile.get("module_counts")
    if isinstance(module_counts, Mapping):
        configs = module_counts.get("configs")
        if isinstance(configs, Mapping):
            categories = configs.get("categories")
            if isinstance(categories, Mapping):
                for key, value in sorted(categories.items()):
                    try:
                        count = int(value)
                    except (TypeError, ValueError):
                        continue
                    if count:
                        label = "lang" if key == "locale" else key
                        modules.setdefault("config", []).append(f"{label}={count}")

    payload_inventory = package_profile.get("payload_inventory")
    dex_count = None
    resource_asset_count = None
    if isinstance(payload_inventory, Mapping):
        try:
            dex_count = int(payload_inventory.get("dex", 0))
        except (TypeError, ValueError):
            dex_count = 0
        try:
            resource_asset_count = int(payload_inventory.get("resources", 0))
        except (TypeError, ValueError):
            resource_asset_count = 0

    if dex_count is None:
        try:
            dex_count = int(integrity_card.get("multi_dex_total", 0))
        except (TypeError, ValueError):
            dex_count = 0

    if resource_asset_count is None:
        resource_asset_count = 0

    return {
        "modules": modules,
        "dex_count": dex_count,
        "resource_asset_count": resource_asset_count,
        "delivery": package_profile.get("delivery") or "—",
        "install_requirements": package_profile.get("install_requirements") or [],
    }


def _build_signing_payload(package_profile: Mapping[str, Any]) -> Mapping[str, Any]:
    signing = package_profile.get("signing")
    if not isinstance(signing, Mapping):
        return {
            "v2": False,
            "v3": False,
            "v4": False,
            "debug": False,
        }
    schemes = signing.get("schemes") if isinstance(signing.get("schemes"), Mapping) else {}
    return {
        "v2": bool(schemes.get("v2")),
        "v3": bool(schemes.get("v3")),
        "v4": bool(schemes.get("v4")),
        "debug": bool(signing.get("debug_cert")),
        "consistency": signing.get("consistency_state"),
    }


def _collect_permission_rows(report: StaticAnalysisReport) -> list[Mapping[str, Any]]:
    declared = tuple(sorted(report.permissions.declared))

    metrics = _lookup_detector_metrics(report, PermissionsProfileDetector.section_key)
    dangerous = set(metrics.get("dangerous_permissions", ()))
    signature = set(metrics.get("signature_permissions", ()))
    privileged = set(metrics.get("privileged_permissions", ()))
    special = set(metrics.get("special_access_permissions", ()))
    custom = set(metrics.get("custom_permissions", ()))

    entries: list[MutableMapping[str, Any]] = []

    for name in declared:
        display_name, namespace = _format_permission_name(name)
        weight = SENSITIVITY_WEIGHTS.get(name, 10)
        if name in special:
            weight = max(weight, 80)
        if name in privileged:
            weight = max(weight, 75)
        if name in dangerous:
            weight = max(weight, 60)
        if name in signature:
            weight = max(weight, 50)
        if name in SPECIAL_ACCESS_PERMISSIONS:
            weight = max(weight, 70)
        band = _risk_band(weight)
        entries.append(
            {
                "name": name,
                "display_name": display_name,
                "namespace": namespace,
                "risk": band,
                "weight": weight,
                "is_custom": name in custom,
            }
        )

    entries.sort(key=lambda entry: (-entry["weight"], entry["display_name"]))
    return entries


def _risk_band(weight: int) -> str:
    if weight >= 80:
        return "High"
    if weight >= 60:
        return "Medium"
    return "Low"


def _build_network_payload(report: StaticAnalysisReport) -> Mapping[str, Any]:
    metrics = _lookup_detector_metrics(report, "network_surface")
    surface = metrics.get("surface") if isinstance(metrics.get("surface"), Mapping) else {}
    counts = surface.get("counts") if isinstance(surface, Mapping) else {}

    http_count = _safe_int(counts, "http")
    https_count = _safe_int(counts, "https")
    ws_count = _safe_int(counts, "ws")

    hosts_payload: dict[str, list[str]] = {}
    host_inventory = surface.get("hosts") if isinstance(surface, Mapping) else {}
    if isinstance(host_inventory, Mapping):
        for scheme, values in host_inventory.items():
            if not isinstance(values, Iterable):
                continue
            hosts_payload[scheme] = sorted({str(value) for value in values if value})

    host_hashes_csv = "—"
    host_hashes = metrics.get("Host hashes")
    if isinstance(host_hashes, Mapping):
        flattened: list[str] = []
        for values in host_hashes.values():
            if not isinstance(values, Iterable):
                continue
            flattened.extend(str(value) for value in values if value)
        if flattened:
            host_hashes_csv = ", ".join(sorted(flattened))

    manifest_flags = report.manifest_flags
    uses_cleartext = manifest_flags.uses_cleartext_traffic
    nsc = manifest_flags.network_security_config or "—"

    tls_notes = metrics.get("TLS overrides") if isinstance(metrics.get("TLS overrides"), Mapping) else {}
    pinning = "Yes" if tls_notes and tls_notes.get("Certificate pinning") else "—"

    return {
        "http_count": http_count,
        "https_count": https_count,
        "ws_count": ws_count,
        "uses_cleartext": _bool_to_label(uses_cleartext),
        "nsc": nsc,
        "pinning": pinning,
        "hosts": hosts_payload,
        "host_hashes_csv": host_hashes_csv,
        "urls": surface.get("urls") if isinstance(surface.get("urls"), Mapping) else {},
    }


def _build_indicator_payload(network_payload: Mapping[str, Any]) -> Mapping[str, Any]:
    hosts = []
    host_inventory = network_payload.get("hosts")
    if isinstance(host_inventory, Mapping):
        for scheme in ("https", "http"):
            values = host_inventory.get(scheme, ())
            if isinstance(values, Iterable):
                hosts.extend(str(value) for value in values if value)
    hosts = sorted(dict.fromkeys(hosts))

    return {
        "hosts": hosts,
        "ips": [],
        "urls": [],
        "ws": [],
        "emails": [],
        "uris": [],
        "paths": [],
        "interesting": [],
    }


def _collect_secret_rows(report: StaticAnalysisReport) -> list[Mapping[str, Any]]:
    entries: list[MutableMapping[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for finding in report.findings:
        if "secret" not in (finding.tags or ()):  # type: ignore[arg-type]
            continue
        severity = finding.severity_gate.value
        if severity not in {SeverityLevel.P0.value, SeverityLevel.P1.value}:
            continue
        pointer = finding.evidence[0] if finding.evidence else None
        location = pointer.location if pointer else "—"
        value_hash = pointer.hash_short if pointer else None
        if not value_hash:
            hashes = finding.metrics.get("hashes") if isinstance(finding.metrics, Mapping) else []
            if isinstance(hashes, Sequence) and hashes:
                value_hash = f"#h:{str(hashes[0])[:12]}"
        value_hash = value_hash or "#h:unknown"
        dedupe_key = (location, value_hash)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        pattern_name = finding.metrics.get("pattern") if isinstance(finding.metrics, Mapping) else None
        entries.append(
            {
                "type": pattern_name or finding.title or "secret",
                "location": location,
                "value_hash": value_hash,
                "severity": severity,
            }
        )

    entries.sort(key=lambda entry: (entry["severity"], entry["type"]))
    return entries


def _compute_risk_model(
    permissions: Sequence[Mapping[str, Any]],
    secrets: Sequence[Mapping[str, Any]],
    network: Mapping[str, Any],
    report: StaticAnalysisReport,
) -> Mapping[str, Any]:
    score = 0
    factors: list[str] = []

    p0_secret_count = sum(1 for entry in secrets if entry.get("severity") == SeverityLevel.P0.value)
    p1_secret_count = sum(1 for entry in secrets if entry.get("severity") == SeverityLevel.P1.value)
    secret_score = min(75, p0_secret_count * 45 + p1_secret_count * 25)
    if secret_score:
        score += secret_score
        if p0_secret_count:
            factors.append("P0 secrets")
        elif p1_secret_count:
            factors.append("P1 secrets")

    uses_cleartext = report.manifest_flags.uses_cleartext_traffic is True
    http_count = network.get("http_count") or 0
    if uses_cleartext and http_count:
        declared = set(report.permissions.declared)
        if "android.permission.INTERNET" in declared:
            score += 20
            factors.append("cleartext traffic")

    high_risk_permissions = sum(1 for entry in permissions if entry.get("risk") == "High")
    if high_risk_permissions:
        perm_score = min(20, high_risk_permissions * 5)
        score += perm_score
        factors.append("high-risk permissions")

    score = min(score, 100)

    if score >= 70:
        band = "High"
    elif score >= 40:
        band = "Medium"
    else:
        band = "Low"

    return {
        "score": score,
        "band": band,
        "top_factors": factors[:5],
    }


def _format_generated_timestamp(timestamp: str | None) -> str:
    if not timestamp:
        return datetime.now(timezone.utc).strftime(_DEFAULT_TIME_FORMAT)
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc).strftime(_DEFAULT_TIME_FORMAT)
    return parsed.astimezone(timezone.utc).strftime(_DEFAULT_TIME_FORMAT)


def _normalise_toolchain(payload: Any) -> Mapping[str, str]:
    default = {"androguard": "—", "aapt2": "—", "apksigner": "—"}
    if not isinstance(payload, Mapping):
        return default
    result = dict(default)
    for key in default:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            result[key] = value
    return result


def _human_size(num_bytes: int) -> str:
    if num_bytes <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(num_bytes)
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} TB"


def _format_permission_name(name: str) -> tuple[str, str]:
    if name.startswith("android.permission."):
        return name.split(".")[-1], "android.permission"
    if "." in name:
        namespace, _, remainder = name.rpartition(".")
        return remainder or name, namespace
    return name, "custom"


def _bool_to_label(value: Any) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return "—"


def _lookup_detector_metrics(report: StaticAnalysisReport, section_key: str) -> Mapping[str, Any]:
    for result in report.detector_results:
        if result.section_key == section_key:
            return result.metrics or {}
    return {}


def _safe_int(mapping: Mapping[str, Any] | None, key: str) -> int:
    if not isinstance(mapping, Mapping):
        return 0
    try:
        return int(mapping.get(key, 0))
    except (TypeError, ValueError):
        return 0


__all__ = ["build_report_view"]

