"""Text renderer for baseline static-analysis output."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
import json
import re
from pathlib import Path
from textwrap import fill
from typing import Mapping, MutableMapping, Sequence

from scytaledroid.Config import app_config

from ..core import StaticAnalysisReport

_WIDTH = 78

def _short_number(value: int) -> str:
    try:
        n = int(value)
    except Exception:
        return str(value)
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}m"
    if n >= 1_000:
        return f"{n/1_000:.1f}k"
    return str(n)
_HASH_ORDER = ("md5", "sha1", "sha256")
_SEVERITY_ORDER = ("High", "Medium", "Low", "Info")
_SEVERITY_TOKENS = {"High": "H", "Medium": "M", "Low": "L", "Info": "I"}
_STRING_BUCKET_TITLES = {
    "endpoints": "Endpoints & Hosts (top)",
    "api_keys": "API Keys & Tokens",
    "analytics_ids": "Analytics IDs",
    "cloud_refs": "Cloud References",
    "ipc": "IPC & Permissions",
    "uris": "URIs / Paths",
    "flags": "Feature Flags",
    "certs": "Certs / Pinning",
    "high_entropy": "High-Entropy Strings",
}
_STRING_BUCKET_ORDER = (
    "endpoints",
    "http_cleartext",
    "api_keys",
    "analytics_ids",
    "cloud_refs",
    "ipc",
    "uris",
    "flags",
    "certs",
    "high_entropy",
)


@dataclass(frozen=True)
class BaselineFinding:
    """Structured baseline finding entry for display and JSON."""

    finding_id: str
    severity: str
    title: str
    pointer: str
    fix: str
    evidence: Mapping[str, str]


def _wrap_lines(text: str, *, indent: int = 2, subsequent_indent: int | None = None) -> list[str]:
    initial = " " * indent
    subsequent = " " * (subsequent_indent if subsequent_indent is not None else indent)
    return fill(text, width=_WIDTH, initial_indent=initial, subsequent_indent=subsequent).splitlines()


def _clean_bool(value: bool | None) -> str:
    if value is None:
        return "absent"
    return "true" if value else "false"


def _manifest_flag_lines(report: StaticAnalysisReport) -> list[str]:
    flags = report.manifest_flags
    lines = [
        f"  debuggable={_clean_bool(flags.debuggable)}  allowBackup={_clean_bool(flags.allow_backup)}",
        f"  usesCleartextTraffic={_clean_bool(flags.uses_cleartext_traffic)}  requestLegacyExternalStorage={_clean_bool(flags.request_legacy_external_storage)}",
    ]
    if flags.network_security_config:
        lines.extend(
            _wrap_lines(
                f"networkSecurityConfig: {flags.network_security_config}",
                indent=2,
                subsequent_indent=4,
            )
        )
    return lines[:5]


def _export_counts(report: StaticAnalysisReport) -> Mapping[str, int]:
    exported = report.exported_components
    return {
        "activities": len(exported.activities),
        "services": len(exported.services),
        "receivers": len(exported.receivers),
        "providers": len(exported.providers),
    }


def _permission_payload(report: StaticAnalysisReport) -> Mapping[str, object]:
    declared = sorted(set(report.permissions.declared))
    dangerous = sorted(set(report.permissions.dangerous))
    custom = sorted(set(report.permissions.custom))
    signature = sorted(set(declared) - set(dangerous) - set(custom))
    return {
        "declared": declared,
        "dangerous": dangerous,
        "signature": signature,
        "custom": custom,
        "counts": {
            "dangerous": len(dangerous),
            "signature": len(signature),
            "custom": len(custom),
        },
    }


def _baseline_findings(
    report: StaticAnalysisReport,
    exports: Mapping[str, int],
    string_data: Mapping[str, object],
    *,
    nsc: Mapping[str, object],
) -> tuple[list[BaselineFinding], Counter[str]]:
    findings: list[BaselineFinding] = []
    totals: Counter[str] = Counter()

    def add(
        severity: str,
        finding_id: str,
        title: str,
        pointer: str,
        fix: str,
        evidence: Mapping[str, str],
    ) -> None:
        totals[severity] += 1
        findings.append(
            BaselineFinding(
                finding_id=finding_id,
                severity=severity,
                title=title,
                pointer=pointer,
                fix=fix,
                evidence=dict(evidence),
            )
        )

    flags = report.manifest_flags
    if flags.debuggable:
        add(
            "Medium",
            "BASE-001",
            "android:debuggable enabled",
            "AndroidManifest.xml: android:debuggable",
            "Disable debuggable for release builds.",
            {"file": "AndroidManifest.xml", "detail": "android:debuggable"},
        )
    if flags.allow_backup:
        add(
            "Low",
            "BASE-001",
            "allowBackup is enabled",
            "AndroidManifest.xml: android:allowBackup",
            "Review backup policy or disable allowBackup.",
            {"file": "AndroidManifest.xml", "detail": "android:allowBackup"},
        )
    if flags.uses_cleartext_traffic:
        add(
            "Medium",
            "BASE-004",
            "usesCleartextTraffic allows HTTP",
            "AndroidManifest.xml: usesCleartextTraffic",
            "Enforce HTTPS or tighten cleartext policy.",
            {"file": "AndroidManifest.xml", "detail": "usesCleartextTraffic"},
        )
    if flags.request_legacy_external_storage:
        add(
            "Low",
            "BASE-006",
            "Legacy external storage requested",
            "AndroidManifest.xml: requestLegacyExternalStorage",
            "Target scoped storage or justify legacy flag.",
            {"file": "AndroidManifest.xml", "detail": "requestLegacyExternalStorage"},
        )

    nsc_path = str(nsc.get("source") or "network_security_config")
    if nsc.get("debug_overrides"):
        add(
            "Medium",
            "BASE-004",
            "NSC debug-overrides trust user CAs",
            nsc_path,
            "Exclude debug overrides from release network security config.",
            {"file": nsc_path, "detail": "debug-overrides"},
        )
    if nsc.get("user_certs"):
        add(
            "Medium",
            "BASE-004",
            "Network security config trusts user-added CAs",
            nsc_path,
            "Restrict trust anchors to system CAs in release builds.",
            {"file": nsc_path, "detail": "user certificates"},
        )
    domains = nsc.get("cleartext_domains") or ()
    if domains:
        pointer = f"{nsc_path}: cleartext domains"
        add(
            "Low",
            "BASE-004",
            "Per-domain cleartext exemptions present",
            pointer,
            "Review cleartext exemptions and enforce TLS.",
            {"file": nsc_path, "detail": "cleartext domains"},
        )

    if exports.get("providers"):
        add(
            "Medium",
            "BASE-002",
            "Exported content providers without explicit permissions",
            "AndroidManifest.xml: <provider>",
            "Restrict provider exposure or enforce read/write permissions.",
            {"file": "AndroidManifest.xml", "detail": "exported provider"},
        )
    if exports.get("activities") or exports.get("services") or exports.get("receivers"):
        add(
            "Low",
            "BASE-002",
            "Exported components detected",
            "AndroidManifest.xml: exported components",
            "Review exported components and add permissions.",
            {"file": "AndroidManifest.xml", "detail": "exported component"},
        )

    string_counts = string_data.get("counts", {}) if isinstance(string_data, Mapping) else {}
    samples_payload = string_data.get("samples", {}) if isinstance(string_data, Mapping) else {}
    if string_counts.get("api_keys"):
        sample = (samples_payload.get("api_keys") or [{}])[0]
        pointer = sample.get("src", "dex strings")
        detail = sample.get("value") or sample.get("value_masked") or "api key"
        add(
            "Medium",
            "BASE-005",
            "Credential-like strings detected",
            pointer,
            "Rotate keys and remove hard-coded credentials.",
            {"dex_sid": pointer, "detail": detail},
        )
    if string_counts.get("endpoints"):
        sample = (samples_payload.get("endpoints") or [{}])[0]
        pointer = sample.get("src", "dex strings")
        detail = sample.get("value") or sample.get("value_masked") or "endpoint"
        add(
            "Low",
            "BASE-005",
            "Endpoint literals present",
            pointer,
            "Validate endpoints and prefer configuration-driven hosts.",
            {"dex_sid": pointer, "detail": detail},
        )
    if string_counts.get("high_entropy"):
        sample = (samples_payload.get("high_entropy") or [{}])[0]
        pointer = sample.get("src", "dex strings")
        detail = sample.get("value") or sample.get("value_masked") or "high-entropy"
        add(
            "Medium",
            "BASE-005",
            "High-entropy strings suggest secrets",
            pointer,
            "Audit code for embedded secrets and rotate if necessary.",
            {"dex_sid": pointer, "detail": detail},
        )

    ordered = sorted(
        findings,
        key=lambda item: (
            _SEVERITY_ORDER.index(item.severity) if item.severity in _SEVERITY_ORDER else len(_SEVERITY_ORDER),
            item.finding_id,
            item.title,
        ),
    )
    return ordered, totals


def _extract_nsc(report: StaticAnalysisReport) -> Mapping[str, object]:
    metadata = report.metadata or {}
    bundle = metadata.get("repro_bundle") if isinstance(metadata, Mapping) else None
    if isinstance(bundle, Mapping):
        nsc_payload = bundle.get("network_security_config")
    else:
        nsc_payload = None
    if not isinstance(nsc_payload, Mapping):
        nsc_payload = metadata.get("network_security_config")
    source = None
    debug = False
    user_certs = False
    cleartext_domains: list[str] = []
    if isinstance(nsc_payload, Mapping):
        source = nsc_payload.get("source_path")
        debug = bool(nsc_payload.get("debug_overrides_cleartext"))
        user_certs = bool(nsc_payload.get("trust_user_certificates"))
        domains = nsc_payload.get("domain_policies")
        if isinstance(domains, Sequence):
            for entry in domains:
                if not isinstance(entry, Mapping):
                    continue
                domains_list = entry.get("domains")
                cleartext = entry.get("cleartext_permitted")
                if cleartext:
                    if isinstance(domains_list, Sequence):
                        cleartext_domains.extend(str(value) for value in domains_list if value)
    return {
        "source": source,
        "debug_overrides": debug,
        "user_certs": user_certs,
        "cleartext_domains": tuple(sorted(set(cleartext_domains))),
    }


def _app_metadata(report: StaticAnalysisReport, *, signer: str | None, split_count: int) -> Mapping[str, object]:
    manifest = report.manifest
    hashes = dict(sorted(report.hashes.items()))
    ordered_hashes: MutableMapping[str, str] = {}
    for key in _HASH_ORDER:
        if key in hashes:
            ordered_hashes[key] = hashes.pop(key)
    for key in sorted(hashes):
        ordered_hashes[key] = hashes[key]
    metadata: MutableMapping[str, object] = {
        "package": manifest.package_name or "unknown",
        "version_name": manifest.version_name or "—",
        "version_code": manifest.version_code,
        "min_sdk": manifest.min_sdk,
        "target_sdk": manifest.target_sdk,
        "signer": signer,
        "splits": split_count,
        "hashes": ordered_hashes,
    }
    return metadata


def _render_hash_lines(hashes: Mapping[str, str]) -> list[str]:
    """Render cryptographic hashes as a compact, aligned list."""

    if not hashes:
        return []

    label_map = {
        "md5": "MD5",
        "sha1": "SHA-1",
        "sha256": "SHA-256",
    }
    lines = ["Hashes"]
    for key in ("md5", "sha1", "sha256"):
        value = hashes.get(key)
        if not value:
            continue
        label = label_map.get(key, key.upper())
        # Two-space indent; pad label to align colons
        lines.append(f"  {label:<8}: {value}")
    return lines


def _normalise_string_data(raw: Mapping[str, object]) -> Mapping[str, object]:
    counts_payload = raw.get("counts") if isinstance(raw, Mapping) else {}
    samples_payload = raw.get("samples") if isinstance(raw, Mapping) else {}
    extra_counts_payload = raw.get("extra_counts") if isinstance(raw, Mapping) else {}
    aggregates_payload = raw.get("aggregates") if isinstance(raw, Mapping) else {}
    counts = {bucket: int(counts_payload.get(bucket, 0)) for bucket in _STRING_BUCKET_ORDER}
    samples: MutableMapping[str, list[Mapping[str, object]]] = {}
    if isinstance(samples_payload, Mapping):
        for bucket in _STRING_BUCKET_ORDER:
            entries = samples_payload.get(bucket)
            if isinstance(entries, Sequence):
                normalised: list[Mapping[str, object]] = []
                for entry in entries:
                    if not isinstance(entry, Mapping):
                        continue
                    normalised.append(
                        {
                            "value": entry.get("value"),
                            "value_masked": entry.get("value_masked"),
                            "src": entry.get("src"),
                            "tag": entry.get("tag"),
                            "sha256": entry.get("sha256"),
                            "finding_type": entry.get("finding_type"),
                            "provider": entry.get("provider"),
                            "risk_tag": entry.get("risk_tag"),
                            "confidence": entry.get("confidence"),
                            "scheme": entry.get("scheme"),
                            "root_domain": entry.get("root_domain"),
                            "resource_name": entry.get("resource_name"),
                            "source_type": entry.get("source_type"),
                            "sample_hash": entry.get("sample_hash"),
                        }
                    )
                if normalised:
                    samples[bucket] = normalised
    extra_counts = {}
    if isinstance(extra_counts_payload, Mapping):
        extra_counts = {str(k): int(extra_counts_payload.get(k, 0)) for k in extra_counts_payload}
    aggregates = aggregates_payload if isinstance(aggregates_payload, Mapping) else {}
    options_payload = raw.get("options") if isinstance(raw, Mapping) else {}
    options = options_payload if isinstance(options_payload, Mapping) else {}
    return {
        "counts": counts,
        "samples": samples,
        "extra_counts": extra_counts,
        "aggregates": aggregates,
        "options": options,
    }


def _string_lines(string_payload: Mapping[str, object]) -> list[str]:
    lines = ["String Analysis"]
    counts = string_payload.get("counts", {}) if isinstance(string_payload, Mapping) else {}
    extra = string_payload.get("extra_counts", {}) if isinstance(string_payload, Mapping) else {}
    aggregates = string_payload.get("aggregates", {}) if isinstance(string_payload, Mapping) else {}
    options = string_payload.get("options", {}) if isinstance(string_payload, Mapping) else {}

    try:
        sample_limit = max(int(options.get("max_samples", 2)), 1)
    except Exception:
        sample_limit = 2
    cleartext_only = bool(options.get("cleartext_only")) if isinstance(options, Mapping) else False

    def _count_value(key: str, *, source: Mapping[str, object] | None = None) -> int:
        mapping = source if source is not None else counts
        return int(mapping.get(key, 0)) if isinstance(mapping, Mapping) else 0

    totals_line1 = "  ".join(
        (
            f"endpoints={_short_number(_count_value('endpoints'))}",
            f"http_cleartext={_short_number(_count_value('http_cleartext'))}",
            f"https={_short_number(_count_value('https', source=extra))}",
            f"ip_private={_short_number(_count_value('ip_private', source=extra))}",
        )
    )
    totals_line2 = "  ".join(
        (
            f"analytics_ids={_short_number(_count_value('analytics_ids'))}",
            f"api_keys={_short_number(_count_value('api_keys'))}",
            f"cloud_refs={_short_number(_count_value('cloud_refs'))}",
            f"entropy_hi={_short_number(_count_value('entropy_high', source=extra) or _count_value('high_entropy'))}",
        )
    )
    lines.append("  Totals")
    lines.extend(_wrap_lines(totals_line1, indent=4, subsequent_indent=6))
    lines.extend(_wrap_lines(totals_line2, indent=4, subsequent_indent=6))

    endpoint_roots = []
    if isinstance(aggregates, Mapping):
        roots = aggregates.get("endpoint_roots")
        if isinstance(roots, Sequence):
            endpoint_roots = [item for item in roots if isinstance(item, Mapping)]

    if endpoint_roots:
        lines.append("")
        lines.append("  Endpoints (top by host root)")
        if cleartext_only:
            allowed_hosts = {
                str(entry.get("root_domain"))
                for entry in aggregates.get("endpoint_cleartext", [])
                if isinstance(entry, Mapping) and entry.get("root_domain")
            }
            filtered_roots = [
                item
                for item in endpoint_roots
                if not allowed_hosts or str(item.get("root_domain")) in allowed_hosts
            ]
        else:
            filtered_roots = endpoint_roots
        top = filtered_roots[: max(3, sample_limit)]
        for item in top:
            root = str(item.get("root_domain") or "(unknown)")
            total = int(item.get("total", 0))
            schemes = item.get("schemes") if isinstance(item.get("schemes"), Mapping) else {}
            parts = []
            for scheme, count in sorted(schemes.items() if isinstance(schemes, Mapping) else []):
                parts.append(f"{scheme}={int(count)}")
            detail = f"{root} ×{total}"
            if parts:
                detail += "   (" + ", ".join(parts) + ")"
            lines.extend(_wrap_lines(detail, indent=4, subsequent_indent=6))
        remaining = len(filtered_roots) - len(top)
        if remaining > 0:
            lines.append(f"    (+{remaining} more)")

    clear_samples = []
    if isinstance(aggregates, Mapping):
        clear_entries = aggregates.get("endpoint_cleartext")
        if isinstance(clear_entries, Sequence):
            clear_samples = [entry for entry in clear_entries if isinstance(entry, Mapping)]

    if clear_samples:
        lines.append("")
        lines.append("  Cleartext (http://) — non-local (first 10)")
        top_clear = clear_samples[:10]
        for entry in top_clear:
            url = str(entry.get("value") or "(unknown)")
            src = str(entry.get("src") or "string")
            preview = url if len(url) <= 70 else f"{url[:67]}…"
            detail = f"{preview}              Src: {src}"
            lines.extend(_wrap_lines(detail, indent=4, subsequent_indent=6))
        remaining = len(clear_samples) - len(top_clear)
        if remaining > 0:
            lines.append(f"    (+{remaining} more)")

    api_payload = []
    if isinstance(aggregates, Mapping):
        api_entries = aggregates.get("api_keys_high")
        if isinstance(api_entries, Sequence):
            api_payload = [entry for entry in api_entries if isinstance(entry, Mapping)]

    if api_payload:
        lines.append("")
        lines.append("  API Keys & Tokens (high-confidence)")

        def _api_label(provider: str | None, token_type: str | None) -> str:
            provider_key = (provider or "").lower()
            token_key = (token_type or "").lower()
            mapping = {
                ("google", "google_api_key"): "GoogleAPI",
                ("aws", "aws_access_key"): "AWS AKID",
                ("aws", "aws_secret"): "AWS Secret",
                ("stripe", "stripe"): "Stripe",
                ("stripe", None): "Stripe",
                ("slack", "slack"): "Slack",
                ("github", "github"): "GitHub",
                ("twilio", "twilio"): "Twilio",
            }
            if token_key == "jwt":
                return "JWT"
            for (prov, token), label in mapping.items():
                if provider_key == prov and (token is None or token_key == token):
                    return label
            return provider.capitalize() if provider else "Token"

        for entry in api_payload[:sample_limit]:
            provider = entry.get("provider")
            token_type = entry.get("token_type")
            label = _api_label(provider, token_type)
            masked = str(entry.get("masked") or "(hidden)")
            src = str(entry.get("src") or "string")
            confidence = entry.get("confidence")
            suffix = f" (confidence {confidence})" if confidence and confidence != "high" else ""
            detail = f"{label:<10} {masked}              Src: {src}{suffix}"
            lines.extend(_wrap_lines(detail, indent=4, subsequent_indent=6))
        remaining = len(api_payload) - min(len(api_payload), sample_limit)
        if remaining > 0:
            lines.append(f"    (+{remaining} more)")

    cloud_payload = []
    if isinstance(aggregates, Mapping):
        cloud_entries = aggregates.get("cloud_refs")
        if isinstance(cloud_entries, Sequence):
            cloud_payload = [entry for entry in cloud_entries if isinstance(entry, Mapping)]

    if cloud_payload:
        lines.append("")
        lines.append("  Cloud References")
        for entry in cloud_payload[:sample_limit]:
            provider = str(entry.get("provider") or "cloud")
            service = str(entry.get("service") or "").strip()
            label = f"{provider}:{service}" if service else provider
            resource = entry.get("resource")
            region = entry.get("region")
            src = str(entry.get("src") or "string")
            parts = [label]
            if resource:
                parts.append(f"bucket={resource}")
            if region:
                parts.append(f"region={region}")
            detail = "  ".join(parts) + f"        Src: {src}"
            lines.extend(_wrap_lines(detail, indent=4, subsequent_indent=6))
        remaining = len(cloud_payload) - min(len(cloud_payload), sample_limit)
        if remaining > 0:
            lines.append(f"    (+{remaining} more)")

    analytics_payload: list[tuple[str, list[Mapping[str, object]], int]] = []
    if isinstance(aggregates, Mapping):
        analytics_entries = aggregates.get("analytics_ids")
        if isinstance(analytics_entries, Mapping):
            for vendor, entries in analytics_entries.items():
                if not isinstance(entries, Sequence):
                    continue
                vendor_entries: list[Mapping[str, object]] = []
                total_ids = 0
                for entry in entries:
                    if not isinstance(entry, Mapping):
                        continue
                    ids = entry.get("ids")
                    if not isinstance(ids, Sequence):
                        continue
                    normalised_ids = [str(identifier) for identifier in ids if identifier]
                    vendor_entries.append(
                        {
                            "ids": normalised_ids,
                            "src": str(entry.get("src") or "string"),
                            "count": int(entry.get("count", len(normalised_ids))),
                        }
                    )
                    total_ids += len(normalised_ids)
                if vendor_entries:
                    analytics_payload.append((str(vendor), vendor_entries, total_ids))

    if analytics_payload:
        lines.append("")
        lines.append("  Analytics IDs (by vendor)")
        analytics_payload.sort(key=lambda item: (-item[2], item[0]))
        vendor_limit = max(sample_limit, 3)
        shown_vendors = analytics_payload[:vendor_limit]
        for vendor, entries, _total_ids in shown_vendors:
            all_ids = sorted({identifier for entry in entries for identifier in entry.get("ids", [])})
            if not all_ids:
                continue
            display_ids = all_ids[:sample_limit]
            primary_src = entries[0].get("src") or "string"
            detail = f"{vendor}: {', '.join(display_ids)}       Src: {primary_src}"
            lines.extend(_wrap_lines(detail, indent=4, subsequent_indent=6))
            remaining_ids = len(all_ids) - len(display_ids)
            if remaining_ids > 0:
                lines.append(f"    (+{remaining_ids} more IDs)")
            extra_sources = len({entry.get("src") for entry in entries if entry.get("src")}) - 1
            if extra_sources > 0:
                lines.append(
                    "    (+{count} more source{suffix})".format(
                        count=extra_sources,
                        suffix="s" if extra_sources != 1 else "",
                    )
                )
        remaining_vendors = len(analytics_payload) - len(shown_vendors)
        if remaining_vendors > 0:
            lines.append(f"    (+{remaining_vendors} more)")

    entropy_samples = []
    if isinstance(aggregates, Mapping):
        entropy_entries = aggregates.get("entropy_high_samples")
        if isinstance(entropy_entries, Sequence):
            entropy_samples = [entry for entry in entropy_entries if isinstance(entry, Mapping)]

    if entropy_samples:
        total_entropy = _count_value("entropy_high", source=extra) or len(entropy_samples)
        lines.append("")
        lines.append("  High-Entropy Strings")
        shown = min(len(entropy_samples), max(2, sample_limit))
        try:
            min_entropy = float(options.get("min_entropy", 5.5))
        except Exception:
            min_entropy = 5.5
        lines.append(
            f"    {shown} samples shown (entropy ≥{min_entropy:.2f}); +{max(total_entropy - shown, 0)} more total"
        )
        for entry in entropy_samples[:shown]:
            masked = str(entry.get("masked") or "(hidden)")
            src = str(entry.get("src") or "string")
            detail = f"      {masked}                         Src: {src}"
            lines.extend(_wrap_lines(detail, indent=6, subsequent_indent=8))

    return lines


def _finding_lines(findings: Sequence[BaselineFinding], totals: Counter[str]) -> list[str]:
    lines = ["Findings (baseline)"]
    if not findings:
        lines.append("  (none)")
        return lines

    for finding in findings:
        token = _SEVERITY_TOKENS.get(finding.severity, "I")
        lines.append(f"  {token} {finding.finding_id}  {finding.title}")
        pointer_lines = _wrap_lines(finding.pointer, indent=4, subsequent_indent=6)
        lines.extend(pointer_lines)
        fix_lines = _wrap_lines(f"Fix: {finding.fix}", indent=4, subsequent_indent=6)
        lines.extend(fix_lines)
    return lines


def _severity_summary_lines(totals: Counter[str]) -> list[str]:
    lines = ["", "Summary (severity)"]
    lines.append(
        "  High: {H}   Medium: {M}   Low: {L}   Info: {I}".format(
            H=totals.get("High", 0),
            M=totals.get("Medium", 0),
            L=totals.get("Low", 0),
            I=totals.get("Info", 0),
        )
    )
    return lines


def render_app_result(
    report: StaticAnalysisReport,
    *,
    signer: str | None,
    split_count: int,
    string_data: Mapping[str, object],
    duration_seconds: float,
) -> tuple[list[str], Mapping[str, object], Counter[str]]:
    """Return printable lines, JSON payload, and severity totals."""

    exports = _export_counts(report)
    permissions = _permission_payload(report)
    nsc = _extract_nsc(report)
    string_payload = _normalise_string_data(string_data)
    findings, finding_totals = _baseline_findings(report, exports, string_payload, nsc=nsc)

    metadata = _app_metadata(report, signer=signer, split_count=split_count)
    hashes = metadata["hashes"]

    lines: list[str] = ["Summary"]
    # Package
    lines.append(f"Package    : {metadata['package']}")
    # Version (use em dash separator when present)
    version_line = metadata.get("version_name", "—")
    version_code = metadata.get("version_code")
    if isinstance(version_line, str):
        version_line = version_line.replace(" - ", " — ")
    if version_code:
        version_line = f"{version_line} ({version_code})"
    lines.append(f"Version    : {version_line}")

    # SDKs (separate lines for readability)
    lines.append(f"Min SDK   : {metadata.get('min_sdk') or '—'}")
    lines.append(f"Target SDK: {metadata.get('target_sdk') or '—'}")

    # Splits
    lines.append(f"Splits     : {split_count}")
    lines.extend(_render_hash_lines(hashes))

    lines.append("")
    lines.append("Manifest Flags")
    lines.extend(_manifest_flag_lines(report))

    lines.append("")
    lines.append("Exported Components (no permission / weak ACL)")
    counts_line = (
        "  Activities: {activities}   Services: {services}   Receivers: {receivers}   Providers: {providers}".format(
            **exports
        )
    )
    lines.append(counts_line)

    lines.append("")
    lines.append("Permissions (declared)")
    declared = list(permissions["declared"]) if isinstance(permissions.get("declared"), Sequence) else []
    if declared:
        head = declared[:20]
        declared_text = ", ".join(head)
        lines.extend(_wrap_lines(declared_text, indent=2, subsequent_indent=4))
        remaining = len(declared) - len(head)
        if remaining > 0:
            lines.append(f"    (+{remaining} more)")
    else:
        lines.append("  —")
    counts = permissions["counts"]
    lines.append(
        f"  Counts: dangerous={counts['dangerous']}  signature={counts['signature']}  custom={counts['custom']}"
    )

    lines.append("")
    lines.extend(_string_lines(string_payload))

    lines.append("")
    lines.extend(_finding_lines(findings, finding_totals))

    lines.extend(_severity_summary_lines(finding_totals))

    # Optional extras: attach NSC + WebView summaries when present
    webview_summary = None
    try:
        lookup = {res.section_key: res for res in report.detector_results}
        web = lookup.get("webview")
        if web and isinstance(web.metrics, Mapping) and web.metrics:
            # compact: only nonzero metrics
            compact = {k: v for k, v in web.metrics.items() if isinstance(v, (int, float)) and v}
            if compact:
                webview_summary = compact
    except Exception:
        webview_summary = None

    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "app": metadata,
        "baseline": {
            "manifest_flags": {
                "debuggable": report.manifest_flags.debuggable,
                "allow_backup": report.manifest_flags.allow_backup,
                "uses_cleartext_traffic": report.manifest_flags.uses_cleartext_traffic,
                "request_legacy_external_storage": report.manifest_flags.request_legacy_external_storage,
                "network_security_config": report.manifest_flags.network_security_config,
            },
            "exports": exports,
            "permissions": permissions,
            "nsc": nsc,
            "webview": webview_summary,
            "string_analysis": string_payload,
            "findings": [
                {
                    "id": finding.finding_id,
                    "severity": finding.severity,
                    "title": finding.title,
                    "evidence": dict(finding.evidence),
                    "fix": finding.fix,
                }
                for finding in findings
            ],
        },
        "duration_seconds": round(duration_seconds, 2),
    }

    return lines, payload, finding_totals


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
    safe_package = re.sub(r"[^A-Za-z0-9_.-]", "_", package)
    safe_profile = re.sub(r"[^A-Za-z0-9_.-]", "_", profile)
    safe_scope = re.sub(r"[^A-Za-z0-9_.-]", "_", scope)
    filename = f"{safe_package}-{safe_profile}-{safe_scope}-{timestamp}.json"
    path = base_dir / filename
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    return path


__all__ = ["render_app_result", "write_baseline_json"]
