"""Progress and formatting helpers for static-analysis scans."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from importlib import metadata as importlib_metadata
from importlib.metadata import PackageNotFoundError
from shutil import which
from typing import Any, Mapping, MutableMapping, Sequence, TextIO

try:  # pragma: no cover - optional timezone data
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except Exception:  # pragma: no cover - Python < 3.9 or missing module
    ZoneInfo = None  # type: ignore[assignment]
    ZoneInfoNotFoundError = Exception  # type: ignore[assignment]

from scytaledroid.Config.app_config import APP_VERSION

from ..core import StaticAnalysisReport
from ..core.findings import Badge, DetectorResult, Finding
from ..core.repository import ArtifactGroup
from .glyphs import GlyphSet
from .options import ScanDisplayOptions, describe_cli_flags
from .sections import (
    SECTION_DEFINITIONS,
    extract_integrity_profiles,
    format_badge,
    render_sections,
)

_DEFAULT_TIMEZONE_LABEL = "America/Chicago"
if ZoneInfo is not None:
    try:
        _LOCAL_TIMEZONE = ZoneInfo(_DEFAULT_TIMEZONE_LABEL)
        _TIMEZONE_LABEL = _DEFAULT_TIMEZONE_LABEL
    except ZoneInfoNotFoundError:  # pragma: no cover - environment dependent
        _LOCAL_TIMEZONE = timezone.utc
        _TIMEZONE_LABEL = "UTC"
else:  # pragma: no cover - Python < 3.9 fallback
    _LOCAL_TIMEZONE = timezone.utc
    _TIMEZONE_LABEL = "UTC"
_SECTION_NAME_LOOKUP = {definition.key: definition.title for definition in SECTION_DEFINITIONS}


@dataclass
class ScanProgress:
    """Coordinates presentation of repository/group/app progress."""

    total_groups: int
    options: ScanDisplayOptions
    stream: TextIO = field(default_factory=lambda: sys.stdout)

    def __post_init__(self) -> None:  # pragma: no cover - simple attribute wiring
        self._severity_totals: Counter[str] = Counter()
        isatty = getattr(self.stream, "isatty", None)
        self._is_tty = bool(isatty()) if callable(isatty) else False
        encoding = (getattr(self.stream, "encoding", "") or "").lower()
        supports_unicode = self._is_tty and "utf" in encoding
        width = shutil.get_terminal_size(fallback=(100, 24)).columns
        width = max(60, min(width, 100))
        use_color = self._is_tty and not bool(os.environ.get("NO_COLOR"))
        self.glyphs = GlyphSet.for_tty(
            self._is_tty,
            supports_unicode=supports_unicode,
            use_color=use_color,
            line_width=width,
        )
        self._preface_packages: set[tuple[str, str, str]] = set()

    def now(self) -> datetime:
        return datetime.now(_LOCAL_TIMEZONE)

    # --- High-level banners -------------------------------------------------

    def announce_options(self) -> None:
        summary = describe_cli_flags(self.options)
        self._write(f"Options: {summary}")

    def print_repository_header(
        self,
        *,
        title: str,
        total_groups: int,
        total_artifacts: int,
        profile: str,
        verbosity: str,
        started: datetime,
    ) -> None:
        self._write()
        self._write(title)
        self._write("=" * len(title))
        self._write(
            f"Groups: {total_groups}    Artifacts: {total_artifacts}    Profile: {profile}    Verbosity: {verbosity}"
        )
        self._write(f"Started: {format_timestamp(started)}")
        self._write()

    def print_repository_summary(self, *, started: datetime, finished: datetime) -> None:
        duration = (finished - started).total_seconds()
        ordered_labels = ("P0", "P1", "P2", "NOTE")
        severity_line = "Severities: " + "   ".join(
            f"{label}={self._severity_totals.get(label, 0)}" for label in ordered_labels
        )

        self._write("Repository Summary")
        self._write("------------------")
        self._write(severity_line)
        self._write(f"Started:   {format_timestamp(started)}")
        self._write(f"Finished:  {format_timestamp(finished)}")
        self._write(f"Duration:  {format_duration(duration)}")
        self._write()

    # --- Group / artifact progress -----------------------------------------

    def start_group(
        self,
        *,
        index: int,
        package_name: str,
        version: str | None,
        category: str | None,
        artifact_count: int,
    ) -> None:
        category_text = category or "Uncategorised"
        version_text = version or "—"
        self._write(
            f"[{index}/{self.total_groups}] Package: {package_name}    Version: {version_text}    "
            f"Artifacts: {artifact_count}    Category: {category_text}"
        )

    def artifact_started(
        self,
        *,
        artifact_index: int,
        artifact_total: int,
        label: str,
    ) -> None:
        self._write(f"  {self.glyphs.arrow_right} Artifact {artifact_index}/{artifact_total}: {label}")

    def artifact_failed(self, label: str, message: str) -> None:
        badge = format_badge(Badge.FAIL, self.glyphs)
        self._write(f"    {badge} {label}: {message}")

    def artifact_completed(
        self,
        *,
        label: str,
        saved_path: str | None,
        findings: Sequence[Finding],
        duration_seconds: float | None,
        warning: str | None,
    ) -> Counter[str]:
        counter = Counter(finding.severity_gate.value for finding in findings)
        self._severity_totals.update(counter)

        if counter.get("P0"):
            badge = format_badge(Badge.FAIL, self.glyphs)
        elif counter.get("P1"):
            badge = format_badge(Badge.WARN, self.glyphs)
        else:
            badge = format_badge(Badge.OK, self.glyphs)

        parts = ["    ", badge, " ", label]
        if duration_seconds is not None and self.options.show_timings:
            parts.append(f" ({format_duration(duration_seconds)})")
        if saved_path:
            parts.append(f" {self.glyphs.arrow_right} {saved_path}")
        if warning:
            parts.append(f" — {warning}")

        self._write("".join(parts))
        return counter

    # --- Detailed artifact banners ----------------------------------------

    def print_group_header(self, *, index: int, group: ArtifactGroup) -> None:
        category = group.category or "Uncategorised"
        artifact_count = len(group.artifacts)
        package = group.package_name or "—"
        self.start_group(
            index=index,
            package_name=package,
            version=group.version_display,
            category=category,
            artifact_count=artifact_count,
        )

    def print_artifact_header(
        self,
        *,
        report: StaticAnalysisReport,
        artifact_label: str,
        artifact_index: int,
        artifact_total: int,
        category: str | None,
        started_at: datetime,
    ) -> None:
        metadata = report.metadata or {}
        manifest = report.manifest

        self._ensure_preface(report=report, started_at=started_at, artifact_label=artifact_label)

        name = metadata.get("app_label") or manifest.app_label or manifest.package_name or "—"
        package_name = manifest.package_name or metadata.get("package_name") or "—"
        version_name = manifest.version_name or metadata.get("version_name") or "—"
        version_code = manifest.version_code or metadata.get("version_code") or "—"
        version_line = (
            f"Version:    {version_name} ({version_code})"
            if version_code and version_code != "—"
            else f"Version:    {version_name}"
        )

        artifact_text = f"{artifact_label} ({artifact_index}/{artifact_total})"
        category_text = category or metadata.get("category") or "—"

        self._write()
        self._write("App")
        self._write("---")
        self._write(f"Name:       {name}")
        self._write(f"Package:    {package_name}")
        self._write(version_line)
        self._write(f"Artifact:   {artifact_text}")
        self._write(f"Category:   {category_text}")
        self._write(f"Started:    {format_timestamp(started_at)}")
        self._write()

    def print_artifact_summary(
        self,
        *,
        report: StaticAnalysisReport,
        runtime_seconds: float,
        finished_at: datetime,
        severity_counter: Mapping[str, int],
    ) -> None:
        _, package_profile, artifact_profile, _ = extract_integrity_profiles(report)
        role = str((artifact_profile or {}).get("role") or "").lower()
        if role != "base":
            return

        metadata = report.metadata or {}
        manifest = report.manifest

        app_name = (
            metadata.get("app_label")
            or manifest.app_label
            or manifest.package_name
            or "—"
        )
        package_name = manifest.package_name or metadata.get("package_name") or "—"
        version_name = manifest.version_name or metadata.get("version_name") or "—"
        version_code = manifest.version_code or metadata.get("version_code")
        version_segment = (
            f"{version_name} ({version_code})" if version_code else version_name
        )

        hashes = report.hashes or {}
        md5 = _short_digest(hashes.get("md5"))
        sha1 = _short_digest(hashes.get("sha1"))
        sha256 = hashes.get("sha256") or "—"

        self._write("Base APK Summary")
        self._write("----------------")
        self._write(f"App name:   {app_name}")
        self._write(f"Package:    {package_name}")
        self._write(f"Version:    {version_segment}")
        self._write("")
        self._write(f"MD5:        {md5}")
        self._write(f"SHA1:       {sha1}")
        self._write(f"SHA256:     {sha256}")
        self._write("")
        result_badge = self._result_badge(severity_counter)
        p0 = severity_counter.get("P0", 0)
        p1 = severity_counter.get("P1", 0)
        p2 = severity_counter.get("P2", 0)
        self._write(f"Result:     {result_badge}   P0={p0}   P1={p1}   P2={p2}")
        finished_text = f"{format_timestamp(finished_at)} ({_TIMEZONE_LABEL})"
        self._write(f"Finished:   {finished_text}")
        self._write()

    def render_artifact_view(
        self,
        *,
        report: StaticAnalysisReport,
        artifact_label: str,
        artifact_index: int,
        artifact_total: int,
        category: str | None,
        started_at: datetime,
        finished_at: datetime,
        runtime_seconds: float,
        severity_counter: Mapping[str, int],
        package_cache: MutableMapping[tuple[str, str, str], Mapping[str, Any]],
        printed_logs: set[str],
    ) -> None:
        if self.options.quiet:
            return

        self.print_artifact_summary(
            report=report,
            runtime_seconds=runtime_seconds,
            finished_at=finished_at,
            severity_counter=severity_counter,
        )

        metadata = report.metadata or {}
        if self.options.show_pipeline:
            summary_lines = _render_pipeline_summary(
                metadata.get("pipeline_summary"),
                glyphs=self.glyphs,
            )
            pipeline_lines = _render_pipeline_trace(
                metadata.get("pipeline_trace"),
                glyphs=self.glyphs,
            )
            groups = [group for group in (summary_lines, pipeline_lines) if group]
            if groups:
                for index, group in enumerate(groups):
                    for line in group:
                        self._write(line)
                    if index != len(groups) - 1:
                        self._write()
                self._write()

        if self.options.verbosity == "summary":
            return

        _, _, artifact_profile, _ = extract_integrity_profiles(report)
        role = str((artifact_profile or {}).get("role") or "").lower()
        is_base = role == "base"

        if is_base:
            self._ensure_preface(
                report=report,
                started_at=started_at,
                artifact_label=artifact_label,
            )

        section_lines = render_sections(
            report,
            options=self.options,
            glyphs=self.glyphs,
            artifact_label=artifact_label,
            artifact_index=artifact_index,
            artifact_total=artifact_total,
            package_cache=package_cache,
        )

        if section_lines:
            for line in section_lines:
                self._write(line)
            self._write()

        if self.options.verbosity == "debug":
            debug_lines = _render_debug_appendix(
                report=report,
                glyphs=self.glyphs,
                log_registry=printed_logs,
            )
            if debug_lines:
                for line in debug_lines:
                    self._write(line)
                self._write()

    # --- Internals ---------------------------------------------------------

    def _write(self, text: str = "") -> None:
        self.stream.write(text + "\n")

    def _rule_line(self, *, width: int | None = None) -> str:
        effective = width if width is not None else self.glyphs.line_width
        effective = max(1, min(effective, self.glyphs.line_width))
        return self.glyphs.rule * effective

    def _ensure_preface(
        self,
        *,
        report: StaticAnalysisReport,
        started_at: datetime,
        artifact_label: str,
    ) -> None:
        if self.options.quiet:
            return
        if self.options.verbosity not in {"detail", "debug"}:
            return

        manifest = report.manifest
        package_key = (
            manifest.package_name or "",
            manifest.version_name or "",
            manifest.version_code or "",
        )
        if package_key in self._preface_packages:
            return

        for line in _preface_lines(
            report=report,
            options=self.options,
            glyphs=self.glyphs,
            started_at=started_at,
            artifact_label=artifact_label,
        ):
            self._write(line)
        self._write()
        self._preface_packages.add(package_key)

    def _result_badge(self, counter: Mapping[str, int]) -> str:
        if counter.get("P0", 0):
            return format_badge(Badge.FAIL, self.glyphs)
        if counter.get("P1", 0):
            return format_badge(Badge.WARN, self.glyphs)
        if counter.get("P2", 0):
            return format_badge(Badge.INFO, self.glyphs)
        return format_badge(Badge.OK, self.glyphs)


def _summarise_timings(results: Sequence[DetectorResult], *, glyphs: GlyphSet) -> str:
    if not results:
        return ""

    entries = [
        (result.section_key, float(getattr(result, "duration_sec", 0.0) or 0.0))
        for result in results
        if isinstance(result, DetectorResult)
    ]
    entries = [(key, duration) for key, duration in entries if duration > 0]
    if not entries:
        return "—"

    entries.sort(key=lambda item: item[1], reverse=True)
    top_durations = entries[:4]
    max_duration = max(duration for _, duration in top_durations)

    parts: list[str] = []
    for key, duration in top_durations:
        label = _short_section_name(key)
        bar = glyphs.bar(duration, max_duration, width=6)
        segment = f"{label} {duration:.1f} {bar}".strip()
        parts.append(segment)

    remaining = entries[4:]
    if remaining:
        tail_total = sum(duration for _, duration in remaining)
        parts.append(f"misc {tail_total:.1f}")
    return " | ".join(parts)


def _short_section_name(key: str) -> str:
    title = _SECTION_NAME_LOOKUP.get(key, key)
    if not title:
        return key
    token = title.split()[0].lower()
    if key == "network_surface":
        return "network"
    if key == "domain_verification":
        return "domains"
    if key == "correlation_findings":
        return "findings"
    return token


def _interpret_counter(counter: Mapping[str, int]) -> str:
    if counter.get("P0", 0):
        return "Critical issues detected (P0 present)."
    if counter.get("P1", 0):
        return "High-risk findings require review (P1 present)."
    if counter.get("P2", 0):
        return "Hardening opportunities identified (P2 findings)."
    return "No critical findings; baseline checks passed."


def _render_debug_appendix(
    *,
    report: StaticAnalysisReport,
    glyphs: GlyphSet,
    log_registry: set[str],
) -> list[str]:
    metadata = report.metadata or {}
    log_path = metadata.get("androguard_log_path")
    lines: list[str] = ["Debug appendix", glyphs.rule * glyphs.line_width]
    sections_added = False

    tool_lines: list[str] = []
    if isinstance(log_path, str) and log_path and log_path not in log_registry:
        tool_lines.append(f"  Androguard log: {log_path}")
        log_registry.add(log_path)

    if tool_lines:
        lines.append("Tool logs")
        lines.extend(tool_lines)
        sections_added = True

    note_lines: list[str] = []
    for result in report.detector_results:
        if not result.notes:
            continue
        section = _SECTION_NAME_LOOKUP.get(result.section_key, result.section_key)
        for entry in result.notes:
            note_lines.append(f"  {section}: {entry}")

    if note_lines:
        if sections_added:
            lines.append("")
        lines.append("Detector notes")
        lines.extend(note_lines)
        sections_added = True

    if not sections_added:
        return []

    return lines


def _preface_lines(
    *,
    report: StaticAnalysisReport,
    options: ScanDisplayOptions,
    glyphs: GlyphSet,
    started_at: datetime,
    artifact_label: str,
) -> list[str]:
    legend_title = "Legend & Provenance"
    lines = [legend_title, glyphs.rule * glyphs.line_width]

    lines.append(
        "Badges: [OK] pass   [INFO] context   [WARN] needs review   [FAIL] defect   [skipped] unavailable"
    )
    bars_descriptor = "▏▎▍▌▋▊▉█ proportional" if glyphs.supports_unicode else "##### proportional"
    fallback_note = " (plain-text fallback: #####)" if glyphs.supports_unicode else ""
    lines.append(
        f"Glyphs: {glyphs.check} present   {glyphs.cross} missing   {glyphs.partial} partial   "
        f"{glyphs.xref} cross-ref    {glyphs.pointer} payload path"
    )
    lines.append(f"Bars:   {bars_descriptor}{fallback_note}")
    lines.append("")
    lines.append("Provenance")
    lines.append(
        "  Toolchain: "
        f"Androguard {_package_version('androguard')} • "
        f"aapt2 {_cli_version('aapt2', ['version'])} • "
        f"apksigner {_cli_version('apksigner', ['--version'])} • "
        f"strings {_cli_version('strings', ['--version'])}"
    )

    profile = (report.scan_profile or options.profile or "").capitalize()
    verbosity = (options.verbosity or "").capitalize()
    lines.append(
        "  ScytaleDroid Static Analysis: "
        f"{APP_VERSION}-alpha • Profile: {profile or '—'} • Verbosity: {verbosity or '—'}"
    )

    seed = _determinism_seed(report, artifact_label)
    lines.append(f"  Determinism seed: SHA256(pkg+ver+artifact)={seed}")
    lines.append(f"  Started: {format_timestamp(started_at)} ({_TIMEZONE_LABEL})")
    return lines


def _render_pipeline_summary(
    payload: object,
    *,
    glyphs: GlyphSet,
) -> list[str]:
    if not isinstance(payload, Mapping):
        return []

    lines: list[str] = ["Pipeline Summary", glyphs.rule * glyphs.line_width]

    total = payload.get("detector_total")
    executed = payload.get("detector_executed")
    skipped = payload.get("detector_skipped")
    counts: list[str] = []
    if isinstance(executed, int) and isinstance(total, int):
        counts.append(f"executed {executed}/{total}")
    if isinstance(skipped, int) and skipped:
        counts.append(f"skipped {skipped}")
    if counts:
        lines.append("Detectors: " + ", ".join(counts))

    total_duration = payload.get("total_duration_sec")
    if isinstance(total_duration, (int, float)):
        lines.append(f"Runtime: {format_duration(total_duration)} total")
        average = payload.get("average_duration_sec")
        if isinstance(average, (int, float)) and average > 0:
            lines.append(f"          {average:.2f}s average per executed detector")

    total_findings = payload.get("total_findings")
    severity_payload = payload.get("severity_counts")
    if isinstance(total_findings, int) and total_findings >= 0:
        severity_tokens: list[str] = []
        if isinstance(severity_payload, Mapping):
            for label in ("P0", "P1", "P2", "NOTE"):
                value = severity_payload.get(label)
                if isinstance(value, int) and value > 0:
                    severity_tokens.append(f"{label}={value}")
        detail = f" ({', '.join(severity_tokens)})" if severity_tokens else ""
        lines.append(f"Findings: {total_findings}{detail}")

    status_payload = payload.get("status_counts")
    if isinstance(status_payload, Mapping):
        status_tokens: list[str] = []
        for key in ("OK", "INFO", "WARN", "FAIL", "skipped"):
            value = status_payload.get(key)
            if isinstance(value, int) and value > 0:
                status_tokens.append(f"{key}={value}")
        if status_tokens:
            lines.append("Statuses: " + ", ".join(status_tokens))

    slowest_payload = payload.get("slowest_detectors")
    if isinstance(slowest_payload, Sequence):
        slow_lines: list[str] = []
        for item in slowest_payload:
            if not isinstance(item, Mapping):
                continue
            detector = str(item.get("detector") or "—")
            section = str(item.get("section") or "—")
            duration = item.get("duration_sec")
            try:
                duration_value = float(duration)
            except (TypeError, ValueError):
                continue
            slow_lines.append(
                f"  • {format_duration(duration_value)} — {section} [{detector}]"
            )
        if slow_lines:
            lines.append("Slowest detectors:")
            lines.extend(slow_lines)

    skipped_payload = payload.get("skipped_detectors")
    if isinstance(skipped_payload, Sequence):
        skipped_lines: list[str] = []
        for item in skipped_payload:
            if not isinstance(item, Mapping):
                continue
            detector = str(item.get("detector") or "—")
            section = str(item.get("section") or "—")
            reason = str(item.get("reason") or "unspecified")
            skipped_lines.append(f"  • {section} [{detector}] — {reason}")
        if skipped_lines:
            lines.append("Skipped detectors:")
            lines.extend(skipped_lines)

    failure_payload = payload.get("first_failure")
    if isinstance(failure_payload, Mapping):
        lines.append(
            "First failure: "
            + _format_pipeline_event(failure_payload, glyphs=glyphs)
        )

    warning_payload = payload.get("first_warning")
    if isinstance(warning_payload, Mapping):
        lines.append(
            "First warning: "
            + _format_pipeline_event(warning_payload, glyphs=glyphs)
        )

    compliance_lines = _render_masvs_overview(
        payload.get("masvs_compliance"),
        glyphs=glyphs,
    )
    if compliance_lines:
        if lines and lines[-1]:
            lines.append("")
        lines.extend(compliance_lines)

    return lines


def _render_masvs_overview(payload: object, *, glyphs: GlyphSet) -> list[str]:
    if not isinstance(payload, Mapping):
        return []

    lines: list[str] = ["MASVS Compliance", glyphs.rule * glyphs.line_width]

    overall_badge = format_badge(_badge_from_text(payload.get("status")), glyphs)
    score = payload.get("score")
    if isinstance(score, (int, float)):
        lines.append(f"Overall: {overall_badge} • score {score * 100:.0f}%")
    else:
        lines.append(f"Overall: {overall_badge}")

    categories = payload.get("categories")
    if not isinstance(categories, Sequence):
        return lines

    for entry in categories:
        if not isinstance(entry, Mapping):
            continue

        category = str(entry.get("category") or entry.get("name") or "—")
        badge = format_badge(_badge_from_text(entry.get("status")), glyphs)
        score_value = entry.get("score")
        if isinstance(score_value, (int, float)):
            score_text = f"{score_value * 100:.0f}%"
        else:
            score_text = "—"

        severity_payload = entry.get("severity_counts")
        severity_tokens: list[str] = []
        if isinstance(severity_payload, Mapping):
            for label in ("P0", "P1", "P2", "NOTE"):
                value = severity_payload.get(label)
                if isinstance(value, int) and value > 0:
                    severity_tokens.append(f"{label}={value}")

        detail = f" [{', '.join(severity_tokens)}]" if severity_tokens else ""
        lines.append(f"  {category:<12} {badge}  score {score_text}{detail}")

        highlight_lines = _render_masvs_highlights(entry.get("highlights"), glyphs=glyphs)
        for highlight in highlight_lines:
            lines.append(f"    {highlight}")

    return lines


def _render_masvs_highlights(payload: object, *, glyphs: GlyphSet) -> list[str]:
    if not isinstance(payload, Sequence) or isinstance(payload, (str, bytes)):
        return []

    lines: list[str] = []
    for index, entry in enumerate(payload):
        if index >= 2:
            break
        if not isinstance(entry, Mapping):
            continue

        severity = str(entry.get("severity") or entry.get("severity_gate") or "—")
        badge = format_badge(_badge_from_text(entry.get("status")), glyphs)
        title = str(entry.get("title") or "—")
        lines.append(f"{severity:<3} {badge} {title}")

        because = entry.get("because")
        if isinstance(because, str):
            text = because.strip()
            if text:
                lines.append(f"      Because: {text}")

    return lines


def _render_pipeline_trace(
    payload: object,
    *,
    glyphs: GlyphSet,
) -> list[str]:
    if isinstance(payload, Mapping):
        entries = [payload]
    elif isinstance(payload, Sequence) and not isinstance(payload, (str, bytes)):
        entries = list(payload)
    else:
        return []

    lines: list[str] = []
    header_printed = False

    for entry in entries:
        if not isinstance(entry, Mapping):
            continue

        if not header_printed:
            lines.append("Pipeline Trace")
            lines.append(glyphs.rule * glyphs.line_width)
            header_printed = True

        index = entry.get("index")
        try:
            index_text = f"{int(index):>2}."
        except (TypeError, ValueError):
            index_text = "--."

        section_key = str(entry.get("section") or "")
        section_title = _SECTION_NAME_LOOKUP.get(section_key, section_key or "—")
        detector = str(entry.get("detector") or "—")
        badge = format_badge(_badge_from_text(entry.get("status")), glyphs)

        try:
            duration_value = float(entry.get("duration", 0.0) or 0.0)
        except (TypeError, ValueError):
            duration_value = 0.0
        duration_text = format_duration(duration_value)

        line = f"{index_text} {badge} {section_title} [{detector}] {duration_text}"

        severity_payload = entry.get("severity")
        severity_tokens: list[str] = []
        if isinstance(severity_payload, Mapping):
            for label in ("P0", "P1", "P2", "NOTE"):
                value = severity_payload.get(label)
                try:
                    count = int(value)
                except (TypeError, ValueError):
                    continue
                if count:
                    severity_tokens.append(f"{label}={count}")

        if severity_tokens:
            line += " • " + ", ".join(severity_tokens)
        else:
            finding_count = entry.get("finding_count")
            if isinstance(finding_count, int) and finding_count:
                line += f" • findings={finding_count}"

        note_tokens: list[str] = []
        notes_payload = entry.get("notes")
        if isinstance(notes_payload, Sequence) and not isinstance(notes_payload, (str, bytes)):
            for note in notes_payload:
                text = str(note).strip()
                if text:
                    note_tokens.append(text)
        if note_tokens:
            line += " — " + "; ".join(note_tokens)

        lines.append(line)

        metrics_payload = entry.get("metrics")
        if isinstance(metrics_payload, Mapping):
            metric_parts: list[str] = []
            for key, value in metrics_payload.items():
                if key in {"skip_reason", "error"}:
                    continue
                metric_parts.append(f"{key}={value}")
            if metric_parts:
                lines.append(f"      metrics: {', '.join(metric_parts)}")

    return lines


def _format_pipeline_event(
    payload: Mapping[str, object],
    *,
    glyphs: GlyphSet,
) -> str:
    detector = str(payload.get("detector") or "—")
    section = str(payload.get("section") or "—")
    reason = str(payload.get("reason") or "unspecified")
    duration = payload.get("duration_sec")
    timing = ""
    try:
        value = float(duration)
        if value > 0:
            timing = f" ({format_duration(value)})"
    except (TypeError, ValueError):
        timing = ""

    bullet = getattr(glyphs, "bullet", "•")
    return f"{bullet} {section} [{detector}] — {reason}{timing}"


def _badge_from_text(value: object) -> Badge:
    if isinstance(value, Badge):
        return value
    if not isinstance(value, str):
        return Badge.INFO

    text = value.strip()
    if not text:
        return Badge.INFO

    for candidate in (text, text.upper(), text.lower(), text.capitalize()):
        try:
            return Badge(candidate)
        except ValueError:
            continue
    return Badge.INFO


def _determinism_seed(report: StaticAnalysisReport, artifact_label: str) -> str:
    manifest = report.manifest
    package = manifest.package_name or ""
    version_name = manifest.version_name or ""
    version_code = manifest.version_code or ""
    payload = "::".join((package, version_name, version_code, artifact_label))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return digest[:8]


def _package_version(name: str) -> str:
    try:
        version = importlib_metadata.version(name)
    except PackageNotFoundError:
        return "—"
    return version


def _cli_version(tool: str, args: Sequence[str]) -> str:
    path = which(tool)
    if not path:
        return "—"
    try:
        result = subprocess.run(
            [path, *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=1.0,
        )
    except Exception:  # pragma: no cover - environment dependent
        return "—"

    output = (result.stdout or result.stderr or "").strip()
    if not output:
        return "—"
    first_line = output.splitlines()[0]
    token = _extract_version_token(first_line)
    return token or "—"


def _extract_version_token(text: str) -> str:
    for chunk in text.replace("(", " ").replace(")", " ").split():
        if any(char.isdigit() for char in chunk):
            return chunk
    return text.strip()


def _short_digest(value: object | None) -> str:
    if not value:
        return "—"
    text = str(value)
    if len(text) <= 12:
        return text
    return f"{text[:8]}…{text[-4:]}"


def format_timestamp(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    local = dt.astimezone(_LOCAL_TIMEZONE)
    hour = local.hour % 12 or 12
    minute = local.minute
    am_pm = "AM" if local.hour < 12 else "PM"
    return f"{local.month}-{local.day}-{local.year} {hour}:{minute:02d} {am_pm}"


def format_duration(value: float | int | timedelta) -> str:
    if isinstance(value, timedelta):
        seconds = value.total_seconds()
    else:
        try:
            seconds = float(value)
        except (TypeError, ValueError):
            seconds = 0.0
    if seconds < 0:
        seconds = 0.0
    return f"{seconds:.1f}s"


__all__ = ["ScanProgress", "format_timestamp", "format_duration"]
