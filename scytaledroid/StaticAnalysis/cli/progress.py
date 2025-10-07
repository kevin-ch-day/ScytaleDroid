"""Progress and formatting helpers for static-analysis scans."""

from __future__ import annotations

import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Mapping, Sequence, TextIO

from zoneinfo import ZoneInfo

from ..core import StaticAnalysisReport
from ..core.findings import Finding
from ..core.repository import ArtifactGroup
from .options import ScanDisplayOptions, describe_cli_flags

_CT = ZoneInfo("America/Chicago")


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
        self._write(f"  → Artifact {artifact_index}/{artifact_total}: {label}")

    def artifact_failed(self, label: str, message: str) -> None:
        self._write(f"    [FAIL] {label}: {message}")

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
            badge = "[FAIL]"
        elif counter.get("P1"):
            badge = "[WARN]"
        else:
            badge = "[OK]"

        parts = ["    ", badge, " ", label]
        if duration_seconds is not None and self.options.show_timings:
            parts.append(f" ({format_duration(duration_seconds)})")
        if saved_path:
            parts.append(f" → {saved_path}")
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
    ) -> None:
        findings = report.findings
        severity_counter = Counter(finding.severity_gate.value for finding in findings)
        self._severity_totals.update(severity_counter)

        categories_touched = sorted(
            {
                finding.category_masvs.value
                for finding in findings
                if getattr(finding, "category_masvs", None)
            }
        )

        self._write("Summary")
        self._write("-------")
        self._write(
            f"Severity counts:  P0={severity_counter.get('P0', 0)}   "
            f"P1={severity_counter.get('P1', 0)}   P2={severity_counter.get('P2', 0)}"
        )
        categories_line = ", ".join(categories_touched) if categories_touched else "—"
        self._write(f"Categories:       {categories_line}")
        self._write(f"Runtime:          {format_duration(runtime_seconds)}")
        self._write(f"Finished:         {format_timestamp(finished_at)}")
        self._write(f"Result:           {self._result_badge(severity_counter)}")
        self._write("Next steps:       —")
        self._write()

    # --- Internals ---------------------------------------------------------

    def _write(self, text: str = "") -> None:
        self.stream.write(text + "\n")

    @staticmethod
    def _result_badge(counter: Mapping[str, int]) -> str:
        if counter.get("P0", 0):
            return "[ATTENTION REQUIRED] (P0 present)"
        if counter.get("P1", 0):
            return "[REVIEW] (P1 present)"
        return "[OK]"


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
