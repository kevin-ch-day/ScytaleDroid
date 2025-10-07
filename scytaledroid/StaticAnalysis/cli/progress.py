"""Progress rendering helpers for static-analysis runs."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from scytaledroid.Utils.DisplayUtils import status_messages

from ..core.findings import Finding, SeverityLevel
from .options import ScanDisplayOptions

_SEVERITY_ORDER: tuple[SeverityLevel, ...] = (
    SeverityLevel.P0,
    SeverityLevel.P1,
    SeverityLevel.P2,
    SeverityLevel.NOTE,
)


def _format_duration(seconds: float) -> str:
    if seconds < 0.001:
        return "<1 ms"
    if seconds < 1.0:
        return f"{seconds * 1000:.0f} ms"
    return f"{seconds:.2f} s"


def _severity_summary(findings: Sequence[Finding]) -> tuple[str, Counter[str]]:
    counter: Counter[str] = Counter()
    for finding in findings:
        counter[finding.severity.value] += 1
    if not counter:
        return "none recorded", counter

    ordered_parts: list[str] = []
    seen: set[str] = set()
    for level in _SEVERITY_ORDER:
        label = level.value
        count = counter.get(label, 0)
        if count:
            ordered_parts.append(f"{label}:{count}")
            seen.add(label)

    for label, count in sorted(counter.items()):
        if label in seen:
            continue
        ordered_parts.append(f"{label}:{count}")
        seen.add(label)

    return ", ".join(ordered_parts), counter


def _top_findings(findings: Sequence[Finding], limit: int) -> Iterable[str]:
    if limit <= 0:
        return []
    priority = {level.value: index for index, level in enumerate(_SEVERITY_ORDER)}
    sorted_findings = sorted(
        findings,
        key=lambda finding: (
            priority.get(finding.severity.value, len(priority)),
            finding.detector_id,
            finding.title,
        ),
    )
    lines: list[str] = []
    for finding in sorted_findings[:limit]:
        prefix = finding.severity.value
        title = finding.title or finding.summary
        lines.append(f"{prefix} · {title}")
    return lines


class ScanProgress:
    """Renders live feedback for static-analysis scans."""

    def __init__(self, *, total_groups: int, options: ScanDisplayOptions) -> None:
        self.total_groups = total_groups
        self.options = options

    def announce_options(self) -> None:
        if self.options.quiet:
            return
        print(status_messages.status(f"Display options: {self.options.describe()}", level="info"))

    def start_group(
        self,
        *,
        index: int,
        package_name: str,
        version: str,
        category: str | None,
        artifact_count: int,
    ) -> None:
        details = [f"[{index}/{self.total_groups}] {package_name} ({version})"]
        if category and not self.options.quiet:
            details.append(f"category: {category}")
        details.append(f"artifacts: {artifact_count}")
        level = "info"
        print(status_messages.status(" – ".join(details), level=level))

    def artifact_started(
        self,
        *,
        artifact_index: int,
        artifact_total: int,
        label: str,
    ) -> None:
        if self.options.quiet:
            return
        print(
            status_messages.status(
                f"  • [{artifact_index}/{artifact_total}] {label} → analysis started",
                level="info",
            )
        )

    def artifact_failed(self, label: str, message: str) -> None:
        print(status_messages.status(f"    ✖ {label}: {message}", level="error"))

    def artifact_completed(
        self,
        *,
        label: str,
        saved_path: Path | None,
        findings: Sequence[Finding],
        duration_seconds: float | None,
        warning: str | None,
    ) -> Counter[str]:
        if saved_path:
            destination = _format_saved_path(saved_path)
            print(status_messages.status(f"    ✓ {label}: report saved → {destination}", level="success"))
        else:
            print(status_messages.status(f"    ✓ {label}: report generated", level="success"))

        summary, counter = _severity_summary(findings)

        info_segments: list[str] = [f"findings: {summary}"]
        if self.options.show_timings and duration_seconds is not None:
            info_segments.append(f"duration: {_format_duration(duration_seconds)}")

        if not self.options.quiet:
            print(status_messages.status(f"      ↳ {'; '.join(info_segments)}", level="info"))

        if warning:
            print(status_messages.status(f"      warning: {warning}", level="warn"))

        if self.options.show_findings and not self.options.quiet and findings:
            for line in _top_findings(findings, self.options.finding_limit):
                print(status_messages.status(f"        • {line}", level="info"))

        return counter

    def artifact_warning(self, label: str, message: str) -> None:
        if self.options.quiet:
            return
        print(status_messages.status(f"    warning for {label}: {message}", level="warn"))


def _format_saved_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


__all__ = ["ScanProgress"]
