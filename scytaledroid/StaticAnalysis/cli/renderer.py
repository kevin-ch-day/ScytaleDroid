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
    if not hashes:
        return []
    parts = [f"{key} {value}" for key, value in hashes.items()]
    text = "Hashes  : " + "  ".join(parts)
    return _wrap_lines(text, indent=2, subsequent_indent=4)


def _normalise_string_data(raw: Mapping[str, object]) -> Mapping[str, object]:
    counts_payload = raw.get("counts") if isinstance(raw, Mapping) else {}
    samples_payload = raw.get("samples") if isinstance(raw, Mapping) else {}
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
                        }
                    )
                if normalised:
                    samples[bucket] = normalised
    return {"counts": counts, "samples": samples}


def _string_lines(string_payload: Mapping[str, object]) -> list[str]:
    lines = ["String Analysis (DEX first; then resources/assets)", "  Totals"]
    counts = string_payload.get("counts", {}) if isinstance(string_payload, Mapping) else {}
    totals = "  ".join(f"{bucket}={counts.get(bucket, 0)}" for bucket in _STRING_BUCKET_ORDER)
    lines.extend(_wrap_lines(totals, indent=4, subsequent_indent=6))

    samples_payload = string_payload.get("samples", {}) if isinstance(string_payload, Mapping) else {}
    if isinstance(samples_payload, Mapping):
        for bucket in _STRING_BUCKET_ORDER:
            if bucket not in _STRING_BUCKET_TITLES:
                continue
            entries = samples_payload.get(bucket)
            if not entries:
                continue
            lines.append(f"  {_STRING_BUCKET_TITLES[bucket]}")
            top_entries = list(entries)[:3]
            for sample in top_entries:
                if not isinstance(sample, Mapping):
                    continue
                value = sample.get("value") or sample.get("value_masked") or "(value hidden)"
                src = sample.get("src", "string")
                tag = sample.get("tag")
                detail = f"{value}  Src: {src}"
                if tag:
                    detail += f"  Tag: {tag}"
                lines.extend(_wrap_lines(detail, indent=4, subsequent_indent=6))
            remaining = len(entries) - len(top_entries)
            if remaining > 0:
                lines.append(f"    (+{remaining} more)")
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
    lines.append(f"  Package : {metadata['package']}")
    version_line = metadata.get("version_name", "—")
    version_code = metadata.get("version_code")
    if version_code:
        version_line = f"{version_line} ({version_code})"
    lines.append(f"  Version : {version_line}")
    sdk_line = f"min={metadata.get('min_sdk') or '—'}  target={metadata.get('target_sdk') or '—'}"
    lines.append(f"  SDKs    : {sdk_line}")
    signer_value = metadata.get("signer")
    if isinstance(signer_value, str) and signer_value:
        short = f"{signer_value[:6]}…{signer_value[-4:]}" if len(signer_value) > 10 else signer_value
        lines.append(f"  Signer  : SHA256 {short}")
    lines.append(f"  Splits  : {split_count}")
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
    declared_text = ", ".join(permissions["declared"]) if permissions["declared"] else "—"
    lines.extend(_wrap_lines(declared_text, indent=2, subsequent_indent=4))
    counts = permissions["counts"]
    lines.append(
        f"  Counts: dangerous={counts['dangerous']}  signature={counts['signature']}  custom={counts['custom']}"
    )

    lines.append("")
    lines.extend(_string_lines(string_payload))

    lines.append("")
    lines.extend(_finding_lines(findings, finding_totals))

    lines.extend(_severity_summary_lines(finding_totals))

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
