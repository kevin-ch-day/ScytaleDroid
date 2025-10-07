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
from typing import Mapping, Sequence, TextIO

from zoneinfo import ZoneInfo

from scytaledroid.Config.app_config import APP_VERSION

from ..core import StaticAnalysisReport
from ..core.findings import Badge, DetectorResult, Finding
from ..core.repository import ArtifactGroup
from .glyphs import GlyphSet
from .options import ScanDisplayOptions, describe_cli_flags
from .sections import SECTION_DEFINITIONS, format_badge

_CT = ZoneInfo("America/Chicago")
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
        self._preface_printed = False

    def now(self) -> datetime:
        return datetime.now(_CT)

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
        ordered_labels = ("P0", "P1", "P2")
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
        findings = report.findings
        categories_touched = sorted(
            {
                finding.category_masvs.value
                for finding in findings
                if getattr(finding, "category_masvs", None)
            }
        )

        self._write("Summary")
        self._write(self._rule_line())
        self._write(
            f"Severity counts:  P0={severity_counter.get('P0', 0)}   "
            f"P1={severity_counter.get('P1', 0)}   P2={severity_counter.get('P2', 0)}"
        )
        categories_line = ", ".join(categories_touched) if categories_touched else "—"
        self._write(f"Categories:       {categories_line}")
        self._write(f"Runtime:          {format_duration(runtime_seconds)}")
        self._write(f"Finished:         {format_timestamp(finished_at)}")
        self._write(f"Result:           {self._result_badge(severity_counter)}")

        timing_line = _summarise_timings(report.detector_results, glyphs=self.glyphs)
        if timing_line:
            self._write(f"Section timing (s): {timing_line}")

        interpretation = _interpret_counter(severity_counter)
        self._write(f"Interpretation: {interpretation}")
        self._write("Next steps:       —")
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
        if self._preface_printed or self.options.quiet:
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
        self._preface_printed = True

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
    lines.append(f"  Started: {format_timestamp(started_at)} (America/Chicago)")
    return lines


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


def format_timestamp(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    local = dt.astimezone(_CT)
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
