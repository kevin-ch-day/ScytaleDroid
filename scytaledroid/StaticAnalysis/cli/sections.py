"""Section rendering utilities for static-analysis CLI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ..core.findings import Badge, DetectorResult, EvidencePointer
from .options import ScanDisplayOptions


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
    SectionDefinition("native_jni", "Native / JNI"),
    SectionDefinition("obfuscation", "Obfuscation / Anti-Analysis"),
    SectionDefinition("correlation_findings", "Findings (P0/P1)"),
)

SECTION_TITLES: tuple[str, ...] = tuple(definition.title for definition in SECTION_DEFINITIONS)


def render_sections(
    results: Sequence[DetectorResult],
    *,
    options: ScanDisplayOptions,
) -> list[str]:
    """Render detector results in a deterministic section order."""

    lookup = {result.section_key: result for result in results}
    lines: list[str] = []
    for definition in SECTION_DEFINITIONS:
        section_lines = _render_section(definition, lookup.get(definition.key), options)
        lines.extend(section_lines)
    if lines:
        lines.pop()  # remove trailing blank line for tidy output
    return lines


def render_stub_sections() -> list[str]:
    """Return placeholder lines for every analysis section."""

    return render_sections(tuple(), options=ScanDisplayOptions())


def _render_section(
    definition: SectionDefinition,
    result: DetectorResult | None,
    options: ScanDisplayOptions,
) -> list[str]:
    lines = [definition.title, "-" * len(definition.title)]
    if result is None:
        lines.append("Status: [skipped]")
        lines.append("")
        return lines

    metric_lines = _render_metrics(result.metrics)
    if metric_lines:
        lines.extend(metric_lines)

    evidence_lines = _render_evidence(result.evidence, options.evidence_limit)
    if evidence_lines:
        lines.extend(evidence_lines)

    if result.notes:
        lines.extend(_render_notes(result.notes))

    lines.append(f"Timing: {_format_duration(result.duration_sec)}")
    lines.append(f"Status: {_format_badge(result.status)}")

    if options.verbosity == "debug" and result.raw_debug:
        lines.append("Debug:")
        for debug_line in result.raw_debug.splitlines():
            lines.append(f"  {debug_line}")

    lines.append("")
    return lines


def _render_metrics(metrics: Mapping[str, object]) -> list[str]:
    if not metrics:
        return []

    lines: list[str] = []
    for key, value in metrics.items():
        label = str(key)
        if isinstance(value, Mapping):
            lines.append(f"{label}:")
            nested = _render_metrics(value)
            for nested_line in nested:
                lines.append(f"  {nested_line}")
            continue

        if isinstance(value, (list, tuple)):
            lines.append(f"{label}:")
            for entry in value:
                for sub_line in str(entry).splitlines():
                    lines.append(f"  {sub_line}")
            continue

        for sub_line in str(value).splitlines():
            lines.append(f"{label}: {sub_line}")
    return lines


def _render_evidence(
    evidence: Sequence[EvidencePointer],
    limit: int,
) -> list[str]:
    if not evidence:
        return []

    limit = max(0, limit)
    pointers = list(evidence[:limit]) if limit else []
    lines: list[str] = []
    if pointers:
        lines.append("Evidence:")
        for pointer in pointers:
            hash_suffix = f"  {pointer.hash_short}" if pointer.hash_short else ""
            lines.append(f"  - {pointer.location}{hash_suffix}")
    remaining = len(evidence) - len(pointers)
    if remaining > 0:
        if not pointers:
            lines.append("Evidence:")
        lines.append(f"  (+{remaining} more)")
    return lines


def _render_notes(notes: Sequence[str]) -> list[str]:
    lines = ["Notes:"]
    for note in notes:
        lines.append(f"  - {note}")
    return lines


def _format_badge(badge: Badge | str) -> str:
    if isinstance(badge, Badge):
        value = badge.value
    else:
        try:
            value = Badge(badge).value
        except ValueError:
            value = str(badge)
    return f"[{value}]"


def _format_duration(seconds: float) -> str:
    try:
        value = float(seconds)
    except (TypeError, ValueError):
        value = 0.0
    if value < 0:
        value = 0.0
    return f"{value:.1f}s"


__all__ = [
    "SectionDefinition",
    "SECTION_DEFINITIONS",
    "SECTION_TITLES",
    "render_sections",
    "render_stub_sections",
]
