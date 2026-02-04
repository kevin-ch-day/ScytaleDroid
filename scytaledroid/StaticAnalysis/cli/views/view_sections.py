"""Section rendering utilities for static-analysis CLI."""

from __future__ import annotations

import copy
import textwrap
from collections.abc import Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from typing import Any

from ...core import StaticAnalysisReport
from ...core.findings import Badge, DetectorResult, EvidencePointer, Finding, SeverityLevel
from ..core.cli_options import ScanDisplayOptions
from ..core.ui_glyphs import GlyphSet


@dataclass(frozen=True)
class SectionDefinition:
    """Static metadata describing a rendered section."""

    key: str
    title: str


SECTION_DEFINITIONS: tuple[SectionDefinition, ...] = (
    SectionDefinition("integrity", "Integrity & Identity"),
    SectionDefinition("manifest_hygiene", "Manifest Hygiene"),
    SectionDefinition("permissions", "Permissions Profile"),
    SectionDefinition("ipc_components", "IPC Components"),
    SectionDefinition("provider_acl", "Provider ACL"),
    SectionDefinition("network_surface", "Network Surface & TLS"),
    SectionDefinition("domain_verification", "Domain Verification"),
    SectionDefinition("secrets", "Secrets & Credentials"),
    SectionDefinition("storage_backup", "Storage & Backup"),
    SectionDefinition("webview", "WebView"),
    SectionDefinition("crypto_hygiene", "Cryptography"),
    SectionDefinition("dynamic_loading", "Dynamic Analysis"),
    SectionDefinition("file_io_sinks", "File I/O"),
    SectionDefinition("interaction_risks", "User Interaction"),
    SectionDefinition("sdk_inventory", "SDK Inventory"),
    SectionDefinition("react_native", "React Native"),
    SectionDefinition("native_jni", "Native / JNI"),
    SectionDefinition("obfuscation", "Obfuscation / Anti-Analysis"),
    SectionDefinition("correlation_findings", "Findings (P0/P1)"),
)

SECTION_TITLES: tuple[str, ...] = tuple(definition.title for definition in SECTION_DEFINITIONS)


_RESET = "\x1b[0m"
_BADGE_COLOURS = {
    "OK": "32",
    "INFO": "34",
    "WARN": "33",
    "FAIL": "31",
    "SKIPPED": "90",
}


def render_sections(
    report: StaticAnalysisReport,
    *,
    options: ScanDisplayOptions,
    glyphs: GlyphSet,
    artifact_label: str,
    artifact_index: int,
    artifact_total: int,
    package_cache: MutableMapping[tuple[str, str, str], Mapping[str, Any]],
) -> list[str]:
    """Render detector results in a deterministic section order."""

    if options.verbosity == "summary":
        return []

    integrity_result, package_profile, artifact_profile, integrity_card = (
        extract_integrity_profiles(report)
    )

    role = str((artifact_profile or {}).get("role") or "").lower()
    is_base = role == "base"

    if not is_base:
        if options.verbosity in {"detail", "debug"} and integrity_result:
            return [
                _render_split_summary_line(
                    artifact_label=artifact_label,
                    integrity_result=integrity_result,
                    integrity_card=integrity_card,
                    package_profile=package_profile,
                    glyphs=glyphs,
                )
            ]
        return []

    package_key = _package_key(report)
    if package_profile and package_key not in package_cache:
        package_cache[package_key] = copy.deepcopy(package_profile)
    if package_key in package_cache:
        package_profile = package_cache[package_key]

    lines: list[str] = []
    topology_lines = _render_application_topology(
        report=report,
        integrity_result=integrity_result,
        package_profile=package_profile,
        artifact_profile=artifact_profile,
        glyphs=glyphs,
        options=options,
        artifact_label=artifact_label,
        artifact_index=artifact_index,
        artifact_total=artifact_total,
    )
    if topology_lines:
        lines.extend(topology_lines)
        lines.append("")

    if integrity_result:
        integrity_lines = _render_integrity_card(
            SectionDefinition("integrity", "Integrity & Identity"),
            integrity_result,
            glyphs,
            options,
            package_profile=package_profile,
            artifact_profile=artifact_profile,
            integrity_card=integrity_card,
        )
        if integrity_lines:
            lines.extend(integrity_lines)
            lines.append("")

    findings_lines = _render_findings_table(report.findings, glyphs)
    if findings_lines:
        lines.extend(findings_lines)

    if lines and not lines[-1]:
        lines.pop()
    return lines


def render_stub_sections() -> list[str]:
    """Return placeholder lines for every analysis section."""

    return []


def extract_integrity_profiles(
    report: StaticAnalysisReport,
) -> tuple[
    DetectorResult | None,
    Mapping[str, Any] | None,
    Mapping[str, Any] | None,
    Mapping[str, Any] | None,
]:
    """Return the integrity detector result and presentation profiles."""

    lookup = {result.section_key: result for result in report.detector_results}
    integrity_result = lookup.get("integrity")
    presentation = _extract_presentation_payload(integrity_result)
    package_profile = presentation.get("package")
    artifact_profile = presentation.get("artifact")
    integrity_card = presentation.get("integrity")
    return integrity_result, package_profile, artifact_profile, integrity_card


def _render_application_topology(
    *,
    report: StaticAnalysisReport,
    integrity_result: DetectorResult | None,
    package_profile: Mapping[str, Any] | None,
    artifact_profile: Mapping[str, Any] | None,
    glyphs: GlyphSet,
    options: ScanDisplayOptions,
    artifact_label: str,
    artifact_index: int,
    artifact_total: int,
) -> list[str]:
    if not isinstance(package_profile, Mapping):
        return []

    if package_profile.get("_topology_printed"):
        return []

    manifest = report.manifest
    package_name = manifest.package_name or "—"
    version_name = manifest.version_name or "—"
    version_code = manifest.version_code or ""
    version_display = f"{version_name} ({version_code})" if version_code else version_name
    delivery = _safe_str(package_profile, "delivery")

    lines: list[str] = ["Application Topology", glyphs.rule * glyphs.line_width]
    lines.append(f"Package: {package_name:<30} Version: {version_display}")
    lines.append(f"Delivery: {delivery}")
    lines.append("")

    lines.append("Modules (tree)")
    lines.extend(_render_modules_tree(package_profile, glyphs))
    lines.append("")

    lines.append("Install requirements")
    lines.extend(_render_install_requirements(package_profile, glyphs))
    lines.append("")

    lines.append("Signing (package-scope)")
    lines.extend(_render_signing_summary(package_profile, glyphs))
    lines.append("")

    lines.append("Payload inventory (package-scope)")
    lines.extend(_render_payload_inventory(package_profile, glyphs))
    lines.append("")

    lines.append("Scan plan (this artifact)")
    lines.extend(
        _render_scan_plan(
            artifact_profile,
            glyphs,
        )
    )
    lines.append("")

    evidence_limit = options.evidence_limit
    evidence_lines = _render_evidence_block(
        integrity_result.evidence if integrity_result else tuple(),
        glyphs=glyphs,
        limit=evidence_limit,
    )
    lines.append(f"Evidence (≤{evidence_limit})")
    if evidence_lines:
        lines.extend(evidence_lines)
    else:
        lines.append("  —")

    duration = integrity_result.duration_sec if integrity_result else 0.0
    status = integrity_result.status if integrity_result else Badge.SKIPPED
    # Suppress timing to keep output compact; status is still shown.
    lines.append(f"Status: {format_badge(status, glyphs)}")
    if isinstance(package_profile, dict):
        package_profile["_topology_printed"] = True
    return lines


def _render_split_summary_line(
    *,
    artifact_label: str,
    integrity_result: DetectorResult,
    integrity_card: Mapping[str, Any] | None,
    package_profile: Mapping[str, Any] | None,
    glyphs: GlyphSet,
) -> str:
    badge = format_badge(integrity_result.status, glyphs)
    size_bytes = _safe_int(integrity_card, "size_bytes")
    size_mb = size_bytes / (1024 * 1024) if size_bytes else 0.0
    hashes = integrity_card.get("hashes", {}) if isinstance(integrity_card, Mapping) else {}
    sha256 = _format_hash(hashes.get("sha256"))

    schemes = []
    signing_profile = package_profile.get("signing") if isinstance(package_profile, Mapping) else {}
    scheme_flags = signing_profile.get("schemes") if isinstance(signing_profile, Mapping) else {}
    for name in ("v2", "v3", "v4"):
        if scheme_flags.get(name):
            schemes.append(name)
    signer_text = ",".join(schemes) if schemes else "—"

    label = artifact_label or _safe_str(integrity_card, "role_label")
    return (
        f"{badge} {label} | size {size_mb:.1f}MB | signer {signer_text} | sha256 {sha256}"
    )


def _render_integrity_card(
    definition: SectionDefinition,
    result: DetectorResult | None,
    glyphs: GlyphSet,
    options: ScanDisplayOptions,
    *,
    package_profile: Mapping[str, Any] | None,
    artifact_profile: Mapping[str, Any] | None,
    integrity_card: Mapping[str, Any] | None,
) -> list[str]:
    lines = [definition.title, glyphs.rule * glyphs.line_width]

    if result is None:
        lines.extend(_render_missing_section(glyphs))
        return lines

    size_bytes = _safe_int(integrity_card, "size_bytes")
    multi_dex_total = _safe_int(integrity_card, "multi_dex_total")
    role_label = _safe_str(integrity_card, "role_label")

    sdk_info = integrity_card.get("sdk", {}) if isinstance(integrity_card, Mapping) else {}
    hashes = integrity_card.get("hashes", {}) if isinstance(integrity_card, Mapping) else {}

    lines.append("Measures")
    lines.append(
        "  Size:  {size:.1f} MB         Multi-dex: {multi_dex}          Split role: {role}".format(
            size=size_bytes / (1024 * 1024) if size_bytes else 0.0,
            multi_dex=multi_dex_total or "—",
            role=role_label or "—",
        )
    )
    lines.append(
        "  SDK:   min {min_sdk} {arrow} target {target_sdk} (compile {compile_sdk})".format(
            min_sdk=_safe_value(sdk_info, "min"),
            target_sdk=_safe_value(sdk_info, "target"),
            compile_sdk=_safe_value(sdk_info, "compile"),
            arrow=glyphs.arrow_right,
        )
    )
    lines.append(
        "  Hashes: MD5  {md5}   SHA1 {sha1}   SHA256 {sha256}".format(
            md5=_format_hash(hashes.get("md5")),
            sha1=_format_hash(hashes.get("sha1")),
            sha256=_format_hash(hashes.get("sha256")),
        )
    )
    lines.append("")

    lines.append("Policy conformance")
    signing = package_profile.get("signing") if package_profile else {}
    schemes = signing.get("schemes") if isinstance(signing, Mapping) else {}
    v2 = _glyph_from_bool(glyphs, schemes.get("v2"))
    v3 = _glyph_from_bool(glyphs, schemes.get("v3"))
    v4 = _glyph_from_bool(glyphs, schemes.get("v4"))
    debug_glyph = _glyph_from_bool(glyphs, signing.get("debug_cert"))
    lines.append(f"  Signing: v2={v2}  v3={v3}  v4={v4}     Debug cert: {debug_glyph}")
    consistency = _glyph_from_bool(glyphs, signing.get("consistency_state"))
    lines.append(f"  Split signature consistency: {consistency}")
    split_awareness = glyphs.check if (package_profile or {}).get("module_counts") else "—"
    lines.append(f"  Split awareness: {split_awareness} (module topology recognized)")

    if result.notes:
        lines.append("")
        lines.append("Notes")
        lines.extend(_render_notes(result.notes, glyphs))

    evidence_lines = _render_evidence_block(result.evidence, glyphs=glyphs, limit=options.evidence_limit)
    if evidence_lines:
        lines.append("")
        lines.append(f"Evidence (≤{options.evidence_limit})")
        lines.extend(evidence_lines)

    lines.append("")
    lines.append(f"Status: {format_badge(result.status, glyphs)}")
    return lines


def _render_findings_table(
    findings: Sequence[Finding],
    glyphs: GlyphSet,
) -> list[str]:
    relevant = [
        finding
        for finding in findings
        if finding.severity_gate in {SeverityLevel.P0, SeverityLevel.P1}
    ]
    lines = ["Findings (P0/P1)", glyphs.rule * glyphs.line_width]

    if not relevant:
        lines.append("None recorded.")
        return lines

    order = {SeverityLevel.P0: 0, SeverityLevel.P1: 1}
    relevant.sort(key=lambda item: (order.get(item.severity_gate, 99), item.title.lower()))

    for index, finding in enumerate(relevant):
        lines.append(f"{finding.severity_gate.value} {glyphs.bullet} {finding.title}")
        because = finding.because.strip() if finding.because else "—"
        lines.append(f"    Because: {because}")

        evidence_lines = _render_evidence_block(
            finding.evidence,
            glyphs=glyphs,
            limit=2,
        )
        if evidence_lines:
            lines.append("    Evidence:")
            for entry in evidence_lines:
                lines.append("    " + entry.lstrip())

        lines.append(f"    MASVS: {finding.category_masvs.value}")
        remediate = finding.remediate.strip() if finding.remediate else ""
        if remediate:
            lines.append(f"    Remediate: {remediate}")

        if index != len(relevant) - 1:
            lines.append("")

    if lines and not lines[-1]:
        lines.pop()
    return lines


def _render_network_card(
    definition: SectionDefinition,
    result: DetectorResult | None,
    glyphs: GlyphSet,
    options: ScanDisplayOptions,
) -> list[str]:
    lines = [definition.title, glyphs.rule * glyphs.line_width]
    if result is None:
        lines.extend(_render_missing_section(glyphs))
        return lines

    metrics = result.metrics or {}
    endpoints = metrics.get("Endpoints", "http=0  https=0")
    policy = metrics.get("Policy", "usesCleartextTraffic=—  NSC=—  Pinning=—")

    lines.append("Endpoints")
    lines.append(f"  {endpoints}")
    lines.append("")

    lines.append("Trust & Policy")
    lines.append(f"  {policy}")

    host_hashes = metrics.get("Host hashes")
    if isinstance(host_hashes, Mapping):
        lines.append("  Host hashes:")
        for scheme, values in sorted(host_hashes.items()):
            if isinstance(values, Sequence) and not isinstance(values, (str, bytes)):
                value_str = ", ".join(str(entry) for entry in values)
            else:
                value_str = str(values)
            lines.append(f"    {scheme}: {value_str or '—'}")

    overrides = metrics.get("TLS overrides")
    if isinstance(overrides, Mapping):
        lines.append("  TLS overrides:")
        for label, values in overrides.items():
            if isinstance(values, Sequence) and not isinstance(values, (str, bytes)):
                value_str = ", ".join(str(entry) for entry in values)
            else:
                value_str = str(values)
            lines.append(f"    {label}: {value_str}")

    evidence_lines = _render_evidence_block(result.evidence, glyphs=glyphs, limit=options.evidence_limit)
    if evidence_lines:
        lines.append("")
        lines.append(f"Evidence (≤{options.evidence_limit})")
        lines.extend(evidence_lines)

    if result.notes:
        lines.append("")
        lines.append("Notes")
        lines.extend(_render_notes(result.notes, glyphs))

    lines.append("")
    lines.append(f"Status: {format_badge(result.status, glyphs)}")
    return lines


def _render_secrets_card(
    definition: SectionDefinition,
    result: DetectorResult | None,
    glyphs: GlyphSet,
    options: ScanDisplayOptions,
) -> list[str]:
    lines = [definition.title, glyphs.rule * glyphs.line_width]
    if result is None:
        lines.extend(_render_missing_section(glyphs))
        return lines

    metrics = result.metrics or {}
    if metrics:
        lines.extend(_render_metrics(metrics))

    if result.notes:
        lines.append("Notes")
        lines.extend(_render_notes(result.notes, glyphs))

    evidence_lines = _render_evidence_block(result.evidence, glyphs=glyphs, limit=options.evidence_limit)
    if evidence_lines:
        lines.append(f"Evidence (≤{options.evidence_limit})")
        lines.extend(evidence_lines)

    lines.append(f"Status: {format_badge(result.status, glyphs)}")
    return lines


def _render_generic_section(
    definition: SectionDefinition,
    result: DetectorResult | None,
    glyphs: GlyphSet,
    options: ScanDisplayOptions,
) -> list[str]:
    lines = [definition.title, glyphs.rule * glyphs.line_width]

    if result is None:
        lines.extend(_render_missing_section(glyphs))
        return lines

    metrics = result.metrics or {}
    if metrics:
        lines.extend(_render_metrics(metrics))

    evidence_lines = _render_evidence_block(result.evidence, glyphs=glyphs, limit=options.evidence_limit)
    if evidence_lines:
        lines.append(f"Evidence (≤{options.evidence_limit})")
        lines.extend(evidence_lines)

    if result.notes:
        lines.append("Notes")
        lines.extend(_render_notes(result.notes, glyphs))

    if result.findings and options.show_findings:
        lines.append("Findings")
        for finding in result.findings[: options.finding_limit]:
            lines.append(f"  - {finding.title} ({finding.severity_gate.value})")

    lines.append(f"Status: {format_badge(result.status, glyphs)}")
    return lines


def _render_missing_section(glyphs: GlyphSet, reason: str = "Detector not executed.") -> list[str]:
    return [
        f"Reason: {reason}",
        f"Status: {format_badge(Badge.SKIPPED, glyphs)}",
    ]


def _render_metrics(metrics: Mapping[str, Any], indent: str = "") -> list[str]:
    lines: list[str] = []
    for key, value in metrics.items():
        label = str(key)
        if isinstance(value, Mapping):
            lines.append(f"{indent}{label}:")
            lines.extend(_render_metrics(value, indent + "  "))
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            lines.append(f"{indent}{label}:")
            for entry in value:
                lines.append(f"{indent}  {entry}")
        else:
            lines.append(f"{indent}{label}: {value}")
    return lines


def _render_modules_tree(
    package_profile: Mapping[str, Any] | None,
    glyphs: GlyphSet,
) -> list[str]:
    lines: list[str] = []
    modules = package_profile.get("module_counts") if isinstance(package_profile, Mapping) else {}
    feature_info = modules.get("features", {}) if isinstance(modules, Mapping) else {}
    config_info = modules.get("configs", {}) if isinstance(modules, Mapping) else {}

    lines.append("  base")
    feature_count = _safe_int(feature_info, "count")
    config_count = _safe_int(config_info, "count")

    if feature_count:
        feature_line = _format_feature_summary(feature_info)
        connector = glyphs.branch if config_count else glyphs.branch_last
        lines.append(f"  {connector} feature ({feature_count})         {feature_line}")
    if config_count:
        connector = glyphs.branch_last
        config_line = _format_config_summary(config_info)
        lines.append(f"  {connector} config ({config_count})          {config_line}")
    return lines


def _render_install_requirements(
    package_profile: Mapping[str, Any] | None,
    glyphs: GlyphSet,
) -> list[str]:
    requirements = []
    if isinstance(package_profile, Mapping):
        requirements = package_profile.get("install_requirements", [])
    if not requirements:
        return ["  —"]

    lines: list[str] = []
    for entry in requirements:
        label = entry.get("label", "—")
        state = entry.get("state")
        glyph = _glyph_from_bool(glyphs, state == "present") if isinstance(state, str) else _glyph_from_bool(glyphs, state)
        descriptor = "present in scan set" if state == "present" or state is True else "absent in scan set"
        lines.append(f"  {label}: {glyph} {descriptor}")
    return lines


def _render_signing_summary(
    package_profile: Mapping[str, Any] | None,
    glyphs: GlyphSet,
) -> list[str]:
    signing = package_profile.get("signing") if isinstance(package_profile, Mapping) else {}
    schemes = signing.get("schemes") if isinstance(signing, Mapping) else {}

    v2 = _glyph_from_bool(glyphs, schemes.get("v2"))
    v3 = _glyph_from_bool(glyphs, schemes.get("v3"))
    v4 = _glyph_from_bool(glyphs, schemes.get("v4"))
    debug_cert = signing.get("debug_cert") if isinstance(signing, Mapping) else None
    consistency_state = signing.get("consistency_state") if isinstance(signing, Mapping) else None
    signer_sets = signing.get("signer_sets") if isinstance(signing, Mapping) else None
    artifact_total = signing.get("artifact_total") if isinstance(signing, Mapping) else None

    debug_glyph = _glyph_from_bool(glyphs, debug_cert)
    consistency_glyph = _glyph_from_bool(glyphs, consistency_state)
    sets_display = signer_sets if signer_sets not in (None, "") else "—"
    total_display = artifact_total if artifact_total not in (None, "") else "—"

    detail_suffix = ""
    if sets_display != "—" and total_display != "—":
        detail_suffix = f" ({sets_display} signer set(s) across {total_display} artifact(s))"

    return [
        f"  Schemes: v2={v2}  v3={v3}  v4={v4}      Debug cert: {debug_glyph}",
        f"  Split signer consistency: {consistency_glyph}{detail_suffix}",
    ]


def _render_payload_inventory(
    package_profile: Mapping[str, Any] | None,
    glyphs: GlyphSet,
) -> list[str]:
    inventory = package_profile.get("payload_inventory") if isinstance(package_profile, Mapping) else {}
    dex = _safe_int(inventory, "dex")
    native = _safe_int(inventory, "native")
    resources = _safe_int(inventory, "resources")
    max_value = max(dex, native, resources, 1)

    lines = [
        f"  Code (dex): {dex:<4} {glyphs.bar(dex, max_value)}         Native (.so): {native or '—'}",
        f"  Resources/assets: {resources or '—'}  {glyphs.bar(resources, max_value)}",
    ]
    notable = inventory.get("notable") if isinstance(inventory, Mapping) else None
    if isinstance(notable, Sequence) and not isinstance(notable, (str, bytes)) and notable:
        joined = ", ".join(str(entry) for entry in notable)
        lines.append(f"  Notable: {joined}")
    return lines


def _render_scan_plan(
    artifact_profile: Mapping[str, Any] | None,
    glyphs: GlyphSet,
) -> list[str]:
    if not isinstance(artifact_profile, Mapping):
        return ["  Role: —", "  Depth: —", "  Cross-refs: —", "  Coverage notes: —"]

    role = artifact_profile.get("role", "—")
    scan_plan = artifact_profile.get("scan_plan") if isinstance(artifact_profile, Mapping) else {}
    depth = scan_plan.get("depth", "—") if isinstance(scan_plan, Mapping) else "—"
    cross_refs = scan_plan.get("cross_refs", "—") if isinstance(scan_plan, Mapping) else "—"
    coverage = scan_plan.get("coverage", "—") if isinstance(scan_plan, Mapping) else "—"

    return [
        f"  Role: {role}",
        f"  Depth: {depth}     Cross-refs: {cross_refs}",
        f"  Coverage notes: {coverage}",
    ]


def _render_evidence_block(
    evidence: Sequence[EvidencePointer],
    *,
    glyphs: GlyphSet,
    limit: int,
) -> list[str]:
    if limit <= 0:
        return []

    seen: set[tuple[str, str | None]] = set()
    deduped: list[EvidencePointer] = []
    for pointer in evidence:
        key = (pointer.location, pointer.hash_short)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(pointer)

    if not deduped:
        return []

    effective_limit = min(max(limit, 1), 2)
    pointers = deduped[:effective_limit]

    lines: list[str] = []
    prefix = f"  {glyphs.pointer} "
    continuation_indent = "  " + " " * len(glyphs.pointer) + " "
    wrap_width = max(20, glyphs.line_width - len(prefix))

    for pointer in pointers:
        base = pointer.location
        if pointer.hash_short:
            base = f"{base}  {pointer.hash_short}"

        wrapped = textwrap.wrap(
            base,
            width=wrap_width,
            break_long_words=False,
            break_on_hyphens=False,
        )
        if not wrapped:
            wrapped = [base]

        lines.append(prefix + wrapped[0])
        for segment in wrapped[1:]:
            lines.append(continuation_indent + segment)
    remaining = len(deduped) - len(pointers)
    if remaining > 0:
        lines.append(f"  (+{remaining} more)")
    return lines


def _render_notes(notes: Sequence[str], glyphs: GlyphSet) -> list[str]:
    return [f"  {glyphs.bullet} {note}" for note in notes]


def _format_feature_summary(info: Mapping[str, Any]) -> str:
    modes = info.get("install_modes") if isinstance(info, Mapping) else {}
    segments = []
    for key in ("install-time", "on-demand", "unknown"):
        value = modes.get(key, 0) if isinstance(modes, Mapping) else 0
        segments.append(f"{key}: {value}")
    return "   ".join(segments)


def _format_config_summary(info: Mapping[str, Any]) -> str:
    categories = info.get("categories") if isinstance(info, Mapping) else {}
    ordered = ("abi", "density", "language", "other")
    segments = []
    for key in ordered:
        value = categories.get(key, 0) if isinstance(categories, Mapping) else 0
        if value:
            segments.append(f"{key}: {value}")
    return "   ".join(segments) or "—"


def _package_key(report: StaticAnalysisReport) -> tuple[str, str, str]:
    manifest = report.manifest
    return (
        manifest.package_name or "",
        manifest.version_name or "",
        manifest.version_code or "",
    )


def _extract_presentation_payload(result: DetectorResult | None) -> Mapping[str, Mapping[str, Any]]:
    metrics = result.metrics if result else {}
    presentation = metrics.get("presentation") if isinstance(metrics, Mapping) else {}
    if not isinstance(presentation, Mapping):
        return {}
    payload: dict[str, Mapping[str, Any]] = {}
    for key in ("package", "artifact", "integrity"):
        value = presentation.get(key)
        if isinstance(value, Mapping):
            payload[key] = dict(value)
    return payload


def format_badge(badge: Badge | str, glyphs: GlyphSet) -> str:
    if isinstance(badge, Badge):
        value = badge.value
    else:
        try:
            value = Badge(badge).value
        except ValueError:
            value = str(badge)

    key = value.upper()
    colour_code = _BADGE_COLOURS.get(key)
    if glyphs.use_color and colour_code:
        coloured = f"\x1b[{colour_code}m{value}{_RESET}"
    else:
        coloured = value
    return f"[{coloured}]"


def _format_duration(seconds: float) -> str:
    try:
        value = float(seconds)
    except (TypeError, ValueError):
        value = 0.0
    if value < 0:
        value = 0.0
    return f"{value:.1f}s"


def _format_hash(value: Any) -> str:
    text = str(value) if value else "—"
    if not text or text == "—":
        return "—"
    if len(text) <= 12:
        return text
    return f"{text[:8]}…{text[-4:]}"


def _safe_str(mapping: Mapping[str, Any] | None, key: str) -> str:
    if not isinstance(mapping, Mapping):
        return "—"
    value = mapping.get(key)
    if value in (None, ""):
        return "—"
    return str(value)


def _safe_value(mapping: Mapping[str, Any] | None, key: str) -> str:
    if not isinstance(mapping, Mapping):
        return "—"
    value = mapping.get(key)
    if value in (None, ""):
        return "—"
    return str(value)


def _safe_int(mapping: Mapping[str, Any] | None, key: str) -> int:
    if not isinstance(mapping, Mapping):
        return 0
    value = mapping.get(key)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _glyph_from_bool(glyphs: GlyphSet, value: Any) -> str:
    if value is True:
        return glyphs.check
    if value is False:
        return glyphs.cross
    return "—"


__all__ = [
    "SectionDefinition",
    "SECTION_DEFINITIONS",
    "SECTION_TITLES",
    "format_badge",
    "render_sections",
    "render_stub_sections",
    "extract_integrity_profiles",
]