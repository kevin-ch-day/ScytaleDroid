"""Helpers for exporting analysis artefacts into human-readable reports."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.StaticAnalysis.core import (
    Finding,
    SeverityLevel,
    StaticAnalysisReport,
)

_SLUG_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")


def export_static_analysis_markdown(
    report: StaticAnalysisReport,
    *,
    source_path: Path | None = None,
    output_root: Path | None = None,
) -> Path:
    """Render *report* to a markdown file and return the created path."""

    lines = _build_static_markdown(report, source_path=source_path)

    root = Path(output_root or app_config.OUTPUT_DIR) / "reports" / "static_analysis"

    package = (
        report.manifest.package_name
        or str(report.metadata.get("package_name") or "artifact")
    )
    slug = _slugify(package)
    destination = root / slug
    destination.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    path = destination / f"static_analysis_{timestamp}.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _build_static_markdown(
    report: StaticAnalysisReport,
    *,
    source_path: Path | None = None,
) -> list[str]:
    now_label = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    metadata = report.metadata or {}
    manifest = report.manifest

    title = (
        metadata.get("app_label")
        or manifest.app_label
        or manifest.package_name
        or report.file_name
    )

    lines: list[str] = []
    lines.append(f"# Static Analysis Report — {title}")
    lines.append("")
    lines.append(f"Generated: {now_label}")
    lines.append(f"Analysis captured at: {report.generated_at}")
    if report.scan_profile:
        lines.append(f"Scan profile: {report.scan_profile}")
    if source_path:
        lines.append(f"Source JSON: {source_path.name}")
    lines.append("")

    lines.append("## Artifact Overview")
    lines.append("")
    overview_rows: list[tuple[str, str]] = [
        ("Package", manifest.package_name or metadata.get("package_name") or "Unknown"),
        (
            "Version",
            manifest.version_name
            or metadata.get("version_name")
            or manifest.version_code
            or metadata.get("version_code")
            or "Unknown",
        ),
        ("File", report.file_name),
        ("Size", _human_size(report.file_size)),
    ]

    for label in ("sha256", "sha1", "md5"):
        value = report.hashes.get(label)
        if value:
            overview_rows.append((label.upper(), value))

    lines.extend(_markdown_table(["Field", "Value"], overview_rows))
    lines.append("")

    lines.append("## Manifest Flags")
    lines.append("")
    flag_rows = [
        ("Debuggable", _format_flag(report.manifest_flags.debuggable)),
        ("Allow Backup", _format_flag(report.manifest_flags.allow_backup)),
        (
            "Uses Cleartext Traffic",
            _format_flag(report.manifest_flags.uses_cleartext_traffic),
        ),
        (
            "Request Legacy External Storage",
            _format_flag(report.manifest_flags.request_legacy_external_storage),
        ),
        (
            "Network Security Config",
            report.manifest_flags.network_security_config or "None",
        ),
        ("Full Backup Content", report.manifest_flags.full_backup_content or "None"),
    ]
    lines.extend(_markdown_table(["Flag", "Value"], flag_rows))
    lines.append("")

    lines.append("## Permission Summary")
    lines.append("")
    declared = sorted(set(report.permissions.declared))
    dangerous = sorted(set(report.permissions.dangerous))
    custom = sorted(set(report.permissions.custom))
    perm_rows = [
        ("Declared", str(len(declared))),
        ("Dangerous", str(len(dangerous))),
        ("Custom", str(len(custom))),
    ]
    lines.extend(_markdown_table(["Type", "Count"], perm_rows))

    if dangerous:
        lines.append("")
        lines.append("### Dangerous permissions")
        lines.append("")
        lines.extend(_bullet_list(dangerous, limit=12))
    if custom:
        lines.append("")
        lines.append("### Custom permissions")
        lines.append("")
        lines.extend(_bullet_list(custom, limit=12))

    lines.append("")
    lines.append("## Component Summary")
    lines.append("")
    component_rows = [
        (
            "Activities",
            str(len(report.components.activities)),
            str(len(report.exported_components.activities)),
        ),
        (
            "Services",
            str(len(report.components.services)),
            str(len(report.exported_components.services)),
        ),
        (
            "Broadcast Receivers",
            str(len(report.components.receivers)),
            str(len(report.exported_components.receivers)),
        ),
        (
            "Content Providers",
            str(len(report.components.providers)),
            str(len(report.exported_components.providers)),
        ),
    ]
    lines.extend(_markdown_table(["Component", "Declared", "Exported"], component_rows))

    if report.features:
        lines.append("")
        lines.append("### Declared features")
        lines.append("")
        lines.extend(_bullet_list(sorted(set(report.features)), limit=15))

    if report.libraries:
        lines.append("")
        lines.append("### Bundled libraries")
        lines.append("")
        lines.extend(_bullet_list(sorted(set(report.libraries)), limit=15))

    lines.append("")
    lines.append("## Findings")
    lines.append("")
    lines.extend(_render_findings(report.findings))

    metrics_block = _render_metrics(report.detector_metrics)
    if metrics_block:
        lines.append("")
        lines.append("## Detector Metrics")
        lines.append("")
        lines.extend(metrics_block)

    return lines


def _render_findings(findings: Sequence[Finding]) -> list[str]:
    if not findings:
        return ["No correlation findings were recorded."]

    ordered: list[str] = []
    severity_order = {
        SeverityLevel.P0: 0,
        SeverityLevel.P1: 1,
        SeverityLevel.P2: 2,
        SeverityLevel.NOTE: 3,
    }
    grouped: dict[SeverityLevel, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.severity_gate, []).append(finding)

    for severity in sorted(grouped, key=lambda level: severity_order.get(level, 99)):
        bucket = grouped[severity]
        bucket.sort(key=lambda f: (f.title.lower(), f.finding_id))
        ordered.append(f"### {severity.value} ({len(bucket)})")
        ordered.append("")
        for item in bucket:
            ordered.extend(_render_single_finding(item))
            ordered.append("")

    if ordered and ordered[-1] == "":
        ordered.pop()
    return ordered


def _render_single_finding(finding: Finding) -> list[str]:
    lines = [
        f"- **{finding.title}** (`{finding.finding_id}`) — status {finding.status.value}",
        f"  - Because: {finding.because}",
    ]
    if finding.remediate:
        lines.append(f"  - Remediate: {finding.remediate}")

    if finding.evidence:
        lines.append("  - Evidence:")
        for pointer in list(finding.evidence)[:5]:
            entry = f"    - {pointer.location}"
            if pointer.hash_short:
                entry += f" {pointer.hash_short}"
            lines.append(entry)
        if len(finding.evidence) > 5:
            lines.append(f"    - (+{len(finding.evidence) - 5} more)")

    if finding.tags:
        tags = ", ".join(sorted({tag for tag in finding.tags if tag}))
        if tags:
            lines.append(f"  - Tags: {tags}")

    if finding.metrics:
        metrics_parts = [
            f"{key}={finding.metrics[key]}" for key in sorted(finding.metrics.keys())
        ]
        if metrics_parts:
            lines.append(f"  - Metrics: {', '.join(metrics_parts)}")

    return lines


def _render_metrics(metrics: Mapping[str, object]) -> list[str]:
    if not metrics:
        return []

    rows = [(key, str(metrics[key])) for key in sorted(metrics.keys())]
    return _markdown_table(["Metric", "Value"], rows)


def _markdown_table(headers: Sequence[str], rows: Iterable[Sequence[str]]) -> list[str]:
    header_line = "| " + " | ".join(str(column) for column in headers) + " |"
    divider = "| " + " | ".join("---" for _ in headers) + " |"
    table_lines = [header_line, divider]
    for row in rows:
        table_lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return table_lines


def _bullet_list(items: Sequence[str], *, limit: int | None = None) -> list[str]:
    entries = [item for item in items if item]
    if limit is not None:
        shown = entries[:limit]
    else:
        shown = entries
    lines = [f"- {entry}" for entry in shown]
    if limit is not None and len(entries) > limit:
        lines.append(f"- (+{len(entries) - limit} more)")
    return lines or ["- None"]


def _format_flag(value: bool | None) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return "Unknown"


def _slugify(value: str) -> str:
    stripped = value.strip()
    slug = _SLUG_PATTERN.sub("_", stripped)
    return slug or "artifact"


def _human_size(size: int) -> str:
    threshold = 1024.0
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(max(size, 0))
    for unit in units:
        if value < threshold:
            return f"{value:.1f} {unit}"
        value /= threshold
    return f"{value:.1f} PB"


__all__ = ["export_static_analysis_markdown"]
