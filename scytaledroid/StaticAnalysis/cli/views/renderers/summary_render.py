"""File: scytaledroid/StaticAnalysis/cli/renderer.py

Text renderer for baseline static-analysis output.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, MutableMapping, Sequence
from datetime import datetime, timezone
from textwrap import fill

from scytaledroid.StaticAnalysis.modules.string_analysis import (
    BUCKET_LABELS,
    BUCKET_METADATA,
    BUCKET_ORDER,
)
from scytaledroid.Utils.DisplayUtils import severity as severity_utils

from ....core import StaticAnalysisReport
from .dynamic_plan import (
    _build_modernization_guidance,
    build_dynamic_plan,
    write_baseline_json,
    write_dynamic_plan_json,
)
from .diagnostics_render import summarise_masvs_inline as _summarise_masvs_inline
from .exploratory import render_exploratory_summary
from .findings_render import (
    BaselineFinding,
    finding_lines as _finding_lines,
    severity_summary_lines as _severity_summary_lines,
)
from .permissions_payload import permission_payload
from .permissions_renderer import render_declared_permissions

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
_STRING_BUCKET_TITLES = {key: meta.label for key, meta in BUCKET_METADATA.items()}


def _normalise_baseline_severity(value: object) -> str:
    return severity_utils.format_severity_label(value, default="Info")


def _detector_severity_map(report: StaticAnalysisReport) -> Mapping[str, str]:
    lookup: MutableMapping[str, str] = {}
    try:
        results = getattr(report, "detector_results", None) or ()
    except Exception:
        results = ()
    for result in results:
        findings = getattr(result, "findings", None) or ()
        for finding in findings:
            finding_id = getattr(finding, "finding_id", None) or getattr(finding, "id", None)
            if not finding_id:
                continue
            severity = None
            severity = severity or severity_utils.format_severity_label(
                getattr(finding, "severity", ""), default=""
            )
            severity = severity or severity_utils.format_severity_label(
                getattr(finding, "severity_label", ""), default=""
            )
            metrics = getattr(finding, "metrics", None)
            if isinstance(metrics, Mapping):
                severity = severity or severity_utils.format_severity_label(
                    metrics.get("severity", ""), default=""
                )
                severity = severity or severity_utils.format_severity_label(
                    metrics.get("severity_level", ""), default=""
                )
            if not severity:
                gate = getattr(getattr(finding, "severity_gate", None), "value", None)
                if gate is not None:
                    severity = severity_utils.format_severity_label(gate, default="")
            if severity:
                lookup.setdefault(str(finding_id), severity)
    return lookup


def _wrap_lines(text: str, *, indent: int = 2, subsequent_indent: int | None = None) -> list[str]:
    initial = " " * indent
    subsequent = " " * (subsequent_indent if subsequent_indent is not None else indent)
    return fill(text, width=_WIDTH, initial_indent=initial, subsequent_indent=subsequent).splitlines()


def _clean_bool(value: bool | None) -> str:
    if value is None:
        return "absent"
    return "true" if value else "false"


def _bucket_label(bucket: str) -> str:
    return BUCKET_LABELS.get(bucket, bucket.replace("_", " ").title())


def _preview_text(value: object, *, limit: int = 70) -> str:
    text = str(value)
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _analytics_summary_lines(report: StaticAnalysisReport) -> list[str]:
    indicators = getattr(report, "analysis_indicators", {}) or {}
    workload = getattr(report, "workload_profile", {}) or {}
    if not indicators and not workload:
        return []

    label_map = {
        "novelty_index": "Novelty index",
        "severity_entropy": "Severity entropy",
        "category_entropy": "Category entropy",
        "masvs_coverage_ratio": "MASVS coverage",
    }

    lines = ["Analytics Highlights"]
    for key in ("novelty_index", "severity_entropy", "category_entropy", "masvs_coverage_ratio"):
        if key in indicators:
            value = indicators[key]
            lines.append(f"  {label_map.get(key, key.replace('_', ' ').title())}: {value}")

    summary = workload.get("summary") if isinstance(workload, Mapping) else {}
    if isinstance(summary, Mapping):
        throughput = summary.get("findings_per_second")
        if throughput:
            lines.append(f"  Findings/sec: {throughput}")
        p90 = summary.get("p90_duration_sec")
        if p90:
            lines.append(f"  P90 detector runtime: {p90}s")
    return lines


def _build_analytics_payload(report: StaticAnalysisReport) -> Mapping[str, object]:
    payload: dict[str, object] = {}
    matrices = getattr(report, "analysis_matrices", {})
    if isinstance(matrices, Mapping) and matrices:
        payload["matrices"] = matrices
    indicators = getattr(report, "analysis_indicators", {})
    if isinstance(indicators, Mapping) and indicators:
        payload["indicators"] = indicators
    workload = getattr(report, "workload_profile", {})
    if isinstance(workload, Mapping) and workload:
        payload["workload"] = workload
    return payload


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


def _baseline_findings(
    report: StaticAnalysisReport,
    exports: Mapping[str, int],
    string_data: Mapping[str, object],
    *,
    nsc: Mapping[str, object],
) -> tuple[list[BaselineFinding], Counter[str]]:
    findings: list[BaselineFinding] = []
    totals: Counter[str] = Counter()
    severity_lookup = _detector_severity_map(report)

    def add(
        severity: str,
        finding_id: str,
        title: str,
        pointer: str,
        fix: str,
        evidence: Mapping[str, str],
    ) -> None:
        effective_severity = severity_lookup.get(str(finding_id)) or _normalise_baseline_severity(severity)
        totals[effective_severity] += 1
        findings.append(
            BaselineFinding(
                finding_id=finding_id,
                severity=effective_severity,
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
    # Gated cleartext: require manifest flag + code-path HTTP endpoint
    def _code_http_present() -> bool:
        try:
            samples = string_data.get("selected_samples") if isinstance(string_data, Mapping) else None
            if not samples:
                samples = string_data.get("samples", {}) if isinstance(string_data, Mapping) else {}
            http_samples = (samples.get("http_cleartext") or []) + (samples.get("endpoints") or [])
            for s in http_samples:
                st = str(s.get("source_type") or "").lower()
                if st in {"code", "dex", "native"}:
                    return True
            return False
        except Exception:
            return False
    if flags.uses_cleartext_traffic and _code_http_present():
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
    samples_payload = string_data.get("selected_samples") if isinstance(string_data, Mapping) else None
    if not samples_payload:
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
        # Only raise when we have code-path evidence or explicit cleartext
        endpoint_samples = samples_payload.get("endpoints") or []
        has_code_path = False
        for s in endpoint_samples:
            source_type = str(s.get("source_type") or "").lower()
            if source_type in {"code", "dex", "native"}:
                has_code_path = True
                break
        has_cleartext = bool(string_counts.get("http_cleartext"))
        if has_code_path or has_cleartext:
            sample = (endpoint_samples or [{}])[0]
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


def _extract_react_native(report: StaticAnalysisReport) -> Mapping[str, object] | None:
    try:
        lookup = {res.section_key: res for res in report.detector_results}
        result = lookup.get("react_native")
    except Exception:
        result = None
    if not result or not isinstance(result.metrics, Mapping):
        return None
    metrics = result.metrics
    if not metrics.get("rn_detected"):
        return None
    return {
        "detected": True,
        "bundles": int(metrics.get("bundles", 0)),
        "native_libs": int(metrics.get("native_libs", 0)),
        "namespaces": int(metrics.get("namespaces", 0)),
        "hermes": bool(metrics.get("hermes")),
        "fabric": bool(metrics.get("fabric")),
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
    extra_meta = report.metadata if isinstance(report.metadata, Mapping) else {}
    metadata: MutableMapping[str, object] = {
        "package": manifest.package_name or "unknown",
        "version_name": manifest.version_name or "—",
        "version_code": manifest.version_code,
        "min_sdk": manifest.min_sdk,
        "target_sdk": manifest.target_sdk,
        "signer": signer,
        "splits": split_count,
        "hashes": ordered_hashes,
        "base_apk_sha256": extra_meta.get("base_apk_sha256"),
        "artifact_set_hash": extra_meta.get("artifact_set_hash"),
        "run_signature": extra_meta.get("run_signature"),
        "run_signature_version": extra_meta.get("run_signature_version"),
        "identity_valid": extra_meta.get("identity_valid"),
        "identity_error_reason": extra_meta.get("identity_error_reason"),
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
    samples_payload = raw.get("selected_samples") if isinstance(raw, Mapping) else None
    if not samples_payload:
        samples_payload = raw.get("samples") if isinstance(raw, Mapping) else {}
    selected_payload = raw.get("selected_samples") if isinstance(raw, Mapping) else {}
    selection_params_payload = raw.get("selection_params") if isinstance(raw, Mapping) else None
    extra_counts_payload = raw.get("extra_counts") if isinstance(raw, Mapping) else {}
    noise_counts_payload = raw.get("noise_counts") if isinstance(raw, Mapping) else {}
    regex_skipped_payload = raw.get("regex_skipped") if isinstance(raw, Mapping) else 0
    aggregates_payload = raw.get("aggregates") if isinstance(raw, Mapping) else {}
    counts = {bucket: int(counts_payload.get(bucket, 0)) for bucket in BUCKET_ORDER}
    def _normalise_samples(payload: object) -> MutableMapping[str, list[Mapping[str, object]]]:
        normalised_samples: MutableMapping[str, list[Mapping[str, object]]] = {}
        if not isinstance(payload, Mapping):
            return normalised_samples
        for bucket in BUCKET_ORDER:
            entries = payload.get(bucket)
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
                    normalised_samples[bucket] = normalised
        return normalised_samples

    samples = _normalise_samples(samples_payload)
    selected_samples = _normalise_samples(selected_payload)
    extra_counts = {}
    if isinstance(extra_counts_payload, Mapping):
        extra_counts = {str(k): int(extra_counts_payload.get(k, 0)) for k in extra_counts_payload}
    noise_counts = {}
    if isinstance(noise_counts_payload, Mapping):
        noise_counts = {str(k): int(noise_counts_payload.get(k, 0)) for k in noise_counts_payload}
    try:
        regex_skipped = int(regex_skipped_payload or 0)
    except Exception:
        regex_skipped = 0
    aggregates = aggregates_payload if isinstance(aggregates_payload, Mapping) else {}
    structured_payload = raw.get("structured") if isinstance(raw, Mapping) else {}
    structured = dict(structured_payload) if isinstance(structured_payload, Mapping) else {}
    options_payload = raw.get("options") if isinstance(raw, Mapping) else {}
    options = options_payload if isinstance(options_payload, Mapping) else {}
    selection_params = (
        dict(selection_params_payload)
        if isinstance(selection_params_payload, Mapping)
        else None
    )

    buckets_struct = structured.get("buckets")
    if isinstance(buckets_struct, Mapping):
        normalised_buckets: MutableMapping[str, Mapping[str, object]] = {}
        for key, value in buckets_struct.items():
            normalised_buckets[key] = dict(value) if isinstance(value, Mapping) else {}
        structured["buckets"] = normalised_buckets
        http_struct = normalised_buckets.get("http_cleartext")
        if isinstance(http_struct, MutableMapping):
            total = int(counts.get("http_cleartext", http_struct.get("total", 0)))
            unique = int(http_struct.get("unique_values", 0))
            if total <= 0:
                unique = 0
                total = 0
            else:
                if __debug__:
                    assert unique <= total
                unique = min(unique, total)
            http_struct["total"] = total
            http_struct["unique_values"] = unique
            counts["http_cleartext"] = total

    return {
        "counts": counts,
        "samples": samples,
        "selected_samples": selected_samples,
        "selection_params": selection_params,
        "extra_counts": extra_counts,
        "noise_counts": noise_counts,
        "regex_skipped": regex_skipped,
        "aggregates": aggregates,
        "structured": structured,
        "options": options,
    }


def _string_lines(string_payload: Mapping[str, object], *, verbose_output: bool) -> list[str]:
    lines = ["String Analysis"]
    counts = string_payload.get("counts", {}) if isinstance(string_payload, Mapping) else {}
    extra = string_payload.get("extra_counts", {}) if isinstance(string_payload, Mapping) else {}
    aggregates = string_payload.get("aggregates", {}) if isinstance(string_payload, Mapping) else {}
    structured = string_payload.get("structured", {}) if isinstance(string_payload, Mapping) else {}
    options = string_payload.get("options", {}) if isinstance(string_payload, Mapping) else {}
    noise_counts = string_payload.get("noise_counts", {}) if isinstance(string_payload, Mapping) else {}
    try:
        regex_skipped = int(string_payload.get("regex_skipped", 0))
    except Exception:
        regex_skipped = 0

    try:
        sample_limit = max(int(options.get("max_samples", 2)), 1)
    except Exception:
        sample_limit = 2
    if not verbose_output:
        sample_limit = min(sample_limit, 5)
    cleartext_only = bool(options.get("cleartext_only")) if isinstance(options, Mapping) else False

    def _count_value(key: str, *, source: Mapping[str, object] | None = None) -> int:
        mapping = source if source is not None else counts
        return int(mapping.get(key, 0)) if isinstance(mapping, Mapping) else 0

    bucket_totals = [
        (bucket, int(counts.get(bucket, 0)))
        for bucket in BUCKET_ORDER
        if int(counts.get(bucket, 0))
    ]
    bucket_totals.sort(key=lambda item: (-item[1], BUCKET_ORDER.index(item[0])))

    lines.append("  Totals (by bucket)")
    if bucket_totals:
        total_limit = max(sample_limit, 6)
        structured_buckets: Mapping[str, Mapping[str, object]] = {}
        if isinstance(structured, Mapping):
            buckets_data = structured.get("buckets")
            if isinstance(buckets_data, Mapping):
                structured_buckets = {
                    key: value
                    for key, value in buckets_data.items()
                    if isinstance(value, Mapping)
                }
        for bucket, total in bucket_totals[:total_limit]:
            label = _bucket_label(bucket)
            summary = structured_buckets.get(bucket)
            unique = int(summary.get("unique_values", total)) if summary else total
            detail = f"{label:<24} {total}"
            if summary and unique and unique != total:
                detail += f" (unique {unique})"
            lines.append(f"    {detail}")
        remaining = len(bucket_totals) - min(len(bucket_totals), total_limit)
        if remaining > 0:
            lines.append(f"    (+{remaining} more buckets)")
    else:
        lines.append("    (no string buckets detected)")

    extra_pairs = []
    for key, label in (
        ("https", "https"),
        ("ip_private", "ip_private"),
        ("ip_public", "ip_public"),
        ("localhost", "localhost"),
        ("ws", "ws"),
        ("wss", "wss"),
        ("entropy_high", "entropy_high"),
    ):
        value = _count_value(key, source=extra)
        if value:
            extra_pairs.append(f"{label}={_short_number(value)}")
    if extra_pairs:
        lines.append("")
        lines.append("  Extra counters")
        lines.extend(_wrap_lines("  ".join(extra_pairs), indent=4, subsequent_indent=6))

    if regex_skipped or noise_counts:
        noise_pairs = []
        if regex_skipped:
            noise_pairs.append(f"regex_skipped={_short_number(regex_skipped)}")
        if isinstance(noise_counts, Mapping):
            for key, value in sorted(
                noise_counts.items(), key=lambda item: (-int(item[1]), str(item[0]))
            )[:6]:
                try:
                    count = int(value)
                except Exception:
                    continue
                if count:
                    noise_pairs.append(f"{key}={_short_number(count)}")
        if noise_pairs:
            lines.append("")
            lines.append("  Noise gate")
            lines.extend(
                _wrap_lines("  ".join(noise_pairs), indent=4, subsequent_indent=6)
            )

    structured_buckets: Mapping[str, Mapping[str, object]] = {}
    if isinstance(structured, Mapping):
        buckets_data = structured.get("buckets")
        if isinstance(buckets_data, Mapping):
            structured_buckets = {
                key: value
                for key, value in buckets_data.items()
                if isinstance(value, Mapping)
            }

    def _bucket_priority(key: str) -> int:
        meta = BUCKET_METADATA.get(key)
        return meta.priority if meta else 0

    def _bucket_highlight(key: str) -> bool:
        meta = BUCKET_METADATA.get(key)
        return meta.highlight if meta else True

    sorted_bucket_keys = sorted(
        structured_buckets.keys(),
        key=lambda key: (
            -_bucket_priority(key),
            -int(structured_buckets[key].get("total", 0)),
            key,
        ),
    )

    # Avoid duplicate rendering for buckets that have dedicated sections below
    # (endpoints roots, cleartext list, high-entropy samples, analytics IDs).
    _skip_detailed_buckets = {"endpoints", "http_cleartext", "high_entropy", "analytics_ids"}
    highlight_keys = [
        key for key in sorted_bucket_keys if _bucket_highlight(key) and key not in _skip_detailed_buckets
    ]
    additional_keys = [key for key in sorted_bucket_keys if key not in highlight_keys]

    for bucket in highlight_keys:
        summary = structured_buckets[bucket]
        top_values = summary.get("top_values")
        if not isinstance(top_values, Sequence) or not top_values:
            continue
        total = int(summary.get("total", 0))
        unique = int(summary.get("unique_values", 0))
        source_types = summary.get("source_types") if isinstance(summary.get("source_types"), Mapping) else {}
        if isinstance(source_types, Mapping):
            source_breakdown = [
                (str(name), int(value))
                for name, value in source_types.items()
                if int(value)
            ]
            source_breakdown.sort(key=lambda item: (-item[1], item[0]))
        else:
            source_breakdown = []
        header = f"  {_bucket_label(bucket)} (total={total}, unique={unique})"
        if source_breakdown:
            header += "  sources: " + ", ".join(
                f"{name}={value}" for name, value in source_breakdown[:2]
            )
        lines.append("")
        lines.append(header)
        value_limit = max(sample_limit, 3) if bucket == "endpoints" else sample_limit
        shown_values = top_values[:value_limit]
        for entry in shown_values:
            example = entry.get("example") if isinstance(entry.get("example"), Mapping) else {}
            display_value = entry.get("value")
            if bucket in {"api_keys", "high_entropy"} and isinstance(example, Mapping):
                masked = example.get("masked")
                if masked:
                    display_value = masked
            preview = _preview_text(display_value or "(empty)")
            count = int(entry.get("count", 0))
            parts = [f"{preview} ×{count}"]
            sources_list = entry.get("sources") if isinstance(entry.get("sources"), Sequence) else []
            source_total = int(entry.get("source_total", len(sources_list))) if entry.get("source_total") is not None else len(sources_list)
            if sources_list:
                src_preview = ", ".join(str(src) for src in sources_list[:2])
                extra_sources = max(source_total - len(sources_list[:2]), 0)
                if extra_sources:
                    src_preview += f" (+{extra_sources} more)"
                parts.append(f"Src: {src_preview}")
            tags_list = entry.get("tags") if isinstance(entry.get("tags"), Sequence) else []
            if tags_list:
                parts.append("Tags: " + ", ".join(str(tag) for tag in tags_list[:2]))
            providers_list = entry.get("providers") if isinstance(entry.get("providers"), Sequence) else []
            if providers_list:
                parts.append("Providers: " + ", ".join(str(p) for p in providers_list[:2]))
            risks_list = entry.get("risk_tags") if isinstance(entry.get("risk_tags"), Sequence) else []
            if risks_list:
                parts.append("Risk: " + ", ".join(str(r) for r in risks_list[:2]))
            confidence = example.get("confidence") if isinstance(example, Mapping) else None
            if confidence and confidence not in {"high", "High"}:
                parts.append(f"Confidence: {confidence}")
            detail = "  ".join(parts)
            lines.extend(_wrap_lines(detail, indent=6, subsequent_indent=8))
        remaining_values = len(top_values) - len(shown_values)
        if remaining_values > 0:
            lines.append(f"      (+{remaining_values} more values)")

    if additional_keys:
        lines.append("")
        lines.append("  Additional buckets")
        for bucket in additional_keys:
            if bucket in _skip_detailed_buckets:
                # Already rendered via dedicated sections below; show compact summary only
                pass
            summary = structured_buckets[bucket]
            total = int(summary.get("total", 0))
            unique = int(summary.get("unique_values", 0))
            lines.append(
                f"    {_bucket_label(bucket)}: total={total}, unique={unique}"
            )

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
        # Suppress boilerplate/documentary domains using string noise policy
        try:
            from scytaledroid.StaticAnalysis.modules.string_analysis.allowlist import (
                DEFAULT_POLICY_ROOT as _POLICY_ROOT,
            )
            from scytaledroid.StaticAnalysis.modules.string_analysis.allowlist import (
                load_noise_policy as _load_policy,
            )

            policy = _load_policy(_POLICY_ROOT)
            doc_hosts = policy.hosts_documentary
            filtered_roots = [
                item
                for item in filtered_roots
                if (
                    str(item.get("root_domain") or "").lower() not in doc_hosts
                    or any(
                        source in {"dex", "code", "native"}
                        for source in item.get("source_types", [])
                        if isinstance(source, str)
                    )
                )
            ]
        except Exception:
            pass
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
            preview = _preview_text(url, limit=70)
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
        if not verbose_output:
            api_payload = [entry for entry in api_payload if str(entry.get("confidence") or "").lower() == "high"]
        if not api_payload:
            pass
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


def render_app_result(
    report: StaticAnalysisReport,
    *,
    signer: str | None,
    split_count: int,
    string_data: Mapping[str, object],
    duration_seconds: float,
    verbose_output: bool = False,
) -> tuple[list[str], Mapping[str, object], Counter[str]]:
    """Return printable lines, JSON payload, and severity totals."""

    exports = _export_counts(report)
    permissions = permission_payload(report)
    nsc = _extract_nsc(report)
    rn_payload = _extract_react_native(report)
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

    if rn_payload:
        lines.append("")
        lines.append("React Native")
        lines.append("  Detected : yes")
        lines.append(f"  Bundles  : {rn_payload.get('bundles', 0)}")
        lines.append(f"  Native   : {rn_payload.get('native_libs', 0)} libs")
        lines.append(f"  Hermes   : {_clean_bool(rn_payload.get('hermes'))}")
        lines.append(f"  Fabric   : {_clean_bool(rn_payload.get('fabric'))}")

    lines.append("")
    lines.append("Exported Components (no permission / weak ACL)")
    counts_line = (
        "  Activities: {activities}   Services: {services}   Receivers: {receivers}   Providers: {providers}".format(
            **exports
        )
    )
    lines.append(counts_line)

    lines.append("")
    render_declared_permissions(lines, permissions, _wrap_lines, verbose_output=verbose_output)

    lines.append("")
    lines.extend(_string_lines(string_payload, verbose_output=verbose_output))

    lines.append("")
    lines.extend(_finding_lines(findings))

    analytics_lines = _analytics_summary_lines(report)
    if analytics_lines:
        lines.append("")
        lines.extend(analytics_lines)

    modernization_lines = _build_modernization_guidance(report, string_payload)
    if modernization_lines:
        lines.append("")
        lines.append("Modernization Recommendations")
        lines.extend(modernization_lines)

    # Inline MASVS summary derived from detector results
    try:
        summary = _summarise_masvs_inline(report)
        lines.append("")
        lines.append("MASVS Summary")
        table_rows: list[str] = []
        for area in ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE"):
            data = summary.get(area) or {}
            counts_map = data.get("counts") if isinstance(data.get("counts"), Mapping) else {}
            high = counts_map.get("High", 0)
            medium = counts_map.get("Medium", 0)
            low = counts_map.get("Low", 0)
            info = counts_map.get("Info", 0)
            status = "PASS"
            quality = data.get("quality") if isinstance(data.get("quality"), Mapping) else {}
            coverage_status = quality.get("coverage_status") if isinstance(quality, Mapping) else None
            if coverage_status == "no_data":
                status = "NO DATA"
            elif high:
                status = "FAIL"
            elif medium:
                status = "WARN"
            worst = data.get("worst") if isinstance(data.get("worst"), Mapping) else None
            if worst:
                worst_display = (
                    f"{worst.get('score', 0):.1f}/"
                    f"{worst.get('band') or '?'} {worst.get('identifier') or ''}"
                ).strip()
            else:
                worst_display = "—"
            avg = data.get("average")
            avg_display = f"{avg:.1f}" if isinstance(avg, (int, float)) else "—"
            bands_map = data.get("bands") if isinstance(data.get("bands"), Counter) else {}
            order = ("Critical", "High", "Medium", "Low", "None")
            band_parts = [
                f"{label[0]}:{int(bands_map[label])}"
                for label in order
                if bands_map.get(label)
            ]
            band_display = ", ".join(band_parts) if band_parts else "—"
            risk_value = quality.get("risk_index") if isinstance(quality, Mapping) else None
            if isinstance(risk_value, (int, float)):
                risk_display = f"{risk_value:>5.1f}"
            else:
                risk_display = "  —  "
            coverage = quality.get("cvss_coverage") if isinstance(quality, Mapping) else None
            if isinstance(coverage, (int, float)):
                coverage_display = f"{coverage * 100:>5.0f}%"
            else:
                coverage_display = "  —  "
            basis_display = "   —   "
            components = quality.get("risk_components") if isinstance(quality, Mapping) else None
            if isinstance(components, Mapping):
                inputs = components.get("inputs") if isinstance(components.get("inputs"), Mapping) else None
                if isinstance(inputs, Mapping):
                    sev = inputs.get("severity_density_norm")
                    band_val = inputs.get("cvss_band_score")
                    intensity = inputs.get("cvss_intensity")
                    if all(isinstance(val, (int, float)) for val in (sev, band_val, intensity)):
                        basis_display = f"S{sev:.2f}/B{band_val:.2f}/I{intensity:.2f}"
            row = (
                f"{area.title():<9}  {high:<4}  {medium:<4}  {low:<4}  {info:<4}  {status:<5}  "
                f"{risk_display:<6} {basis_display:<15} {coverage_display:<7} {worst_display:<18} {avg_display:<4} {band_display}"
            )
            table_rows.append(row)
        for header in [
            "Area       High  Med   Low   Info  Status  Risk   Basis           CVSS%  Worst CVSS         Avg  Bands"
        ]:
            lines.append(header)
        lines.extend(table_rows)
    except Exception:
        pass

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
        "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
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
            "react_native": rn_payload,
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

    analytics_payload = _build_analytics_payload(report)
    if analytics_payload:
        payload["analytics"] = analytics_payload

    return lines, payload, finding_totals


__all__ = [
    "render_app_result",
    "render_exploratory_summary",
    "write_baseline_json",
    "build_dynamic_plan",
    "write_dynamic_plan_json",
]
