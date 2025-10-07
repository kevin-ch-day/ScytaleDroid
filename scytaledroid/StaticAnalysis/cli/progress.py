"""Progress and formatting helpers for static-analysis scans."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Sequence

from zoneinfo import ZoneInfo

from scytaledroid.Utils.DisplayUtils import status_messages

from ..core import StaticAnalysisReport
from ..core.findings import Finding
from ..core.repository import ArtifactGroup
from .options import ScanDisplayOptions

_CT = ZoneInfo("America/Chicago")


@dataclass
class ScanRunProgress:
    """Coordinates presentation of repository/group/app progress."""

    total_groups: int
    options: ScanDisplayOptions

    def __post_init__(self) -> None:
        self._severity_totals: Counter[str] = Counter()

    def now(self) -> datetime:
        return datetime.now(_CT)

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
        print()
        print(title)
        print("=" * len(title))
        print(
            f"Groups: {total_groups}    Artifacts: {total_artifacts}    Profile: {profile.title()}    Verbosity: {verbosity}"
        )
        print(f"Started: {format_timestamp(started)}")
        print()

    def print_group_header(self, *, index: int, group: ArtifactGroup) -> None:
        category = group.category or "Uncategorised"
        artifact_count = len(group.artifacts)
        print(f"[{index}/{self.total_groups}] Group: {category} — Apps: 1  Artifacts: {artifact_count}")

    def print_artifact_notice(
        self,
        *,
        package_name: str,
        label: str,
        artifact_index: int,
        artifact_total: int,
    ) -> None:
        print(f"→ Analyzing: {package_name} (artifact {artifact_index}/{artifact_total}: {label})")

    def print_artifact_failure(self, label: str, message: str) -> None:
        print(status_messages.status(f"    ✖ {label}: {message}", level="error"))

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
        if version_code and version_code != "—":
            version_line = f"Version:    {version_name} ({version_code})"
        else:
            version_line = f"Version:    {version_name}"

        artifact_text = f"{artifact_label} ({artifact_index}/{artifact_total})"
        category_text = category or metadata.get("category") or "—"

        print()
        print("App")
        print("---")
        print(f"Name:       {name}")
        print(f"Package:    {package_name}")
        print(version_line)
        print(f"Artifact:   {artifact_text}")
        print(f"Category:   {category_text}")
        print(f"Started:    {format_timestamp(started_at)}")
        print()

    def print_artifact_summary(
        self,
        *,
        report: StaticAnalysisReport,
        runtime_seconds: float,
        finished_at: datetime,
    ) -> None:
        findings = report.findings
        severity_counter = Counter(finding.severity.value for finding in findings)
        self._record_findings(findings)

        categories_touched = sorted(
            {finding.masvs_category.value for finding in findings if finding.masvs_category}
        )

        print("Summary")
        print("-------")
        print(
            f"Severity counts:  P0={severity_counter.get('P0', 0)}   "
            f"P1={severity_counter.get('P1', 0)}   P2={severity_counter.get('P2', 0)}"
        )
        print(
            "Categories:       " + (", ".join(categories_touched) if categories_touched else "—")
        )
        print(f"Runtime:          {format_seconds(runtime_seconds)}")
        print(f"Finished:         {format_timestamp(finished_at)}")
        print(f"Result:           {self._result_badge(severity_counter)}")
        print("Next steps:       —")
        print()

    def print_repository_summary(self, *, started: datetime, finished: datetime) -> None:
        duration = (finished - started).total_seconds()
        ordered_labels = ["P0", "P1", "P2"]
        severity_line = "Severities: " + "   ".join(
            f"{label}={self._severity_totals.get(label, 0)}" for label in ordered_labels
        )

        print("Repository Summary")
        print("------------------")
        print(severity_line)
        print(f"Started:   {format_timestamp(started)}")
        print(f"Finished:  {format_timestamp(finished)}")
        print(f"Duration:  {format_seconds(duration)}")
        print()

    def _record_findings(self, findings: Sequence[Finding]) -> None:
        self._severity_totals.update(finding.severity.value for finding in findings)

    @staticmethod
    def _result_badge(counter: Mapping[str, int]) -> str:
        if counter.get("P0", 0):
            return "[ATTENTION REQUIRED] (P0 present)"
        if counter.get("P1", 0):
            return "[REVIEW] (P1 present)"
        return "[OK]"


def format_timestamp(dt: datetime) -> str:
    local = dt.astimezone(_CT)
    hour = local.hour % 12 or 12
    minute = local.minute
    am_pm = "AM" if local.hour < 12 else "PM"
    return f"{local.month}-{local.day}-{local.year} {hour}:{minute:02d} {am_pm}"


def format_seconds(seconds: float) -> str:
    return f"{seconds:.1f}s"


__all__ = ["ScanRunProgress", "format_timestamp", "format_seconds"]
