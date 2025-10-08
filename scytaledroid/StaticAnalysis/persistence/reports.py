"""Persistence helpers for static analysis reports."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional

from scytaledroid.Config import app_config
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ..core import StaticAnalysisReport

if TYPE_CHECKING:  # pragma: no cover - imported for type checking only
    from ..reporting.view import build_report_view, save_html_report


REPORTS_DIR = Path(app_config.DATA_DIR) / "static_analysis" / "reports"


class ReportStorageError(Exception):
    """Raised when reports cannot be persisted or loaded."""


@dataclass(frozen=True)
class StoredReport:
    """Represents a report stored on disk."""

    path: Path
    report: StaticAnalysisReport


@dataclass(frozen=True)
class SavedReportPaths:
    """Represents the filesystem artefacts produced for a saved report."""

    json_path: Path
    html_path: Optional[Path]
    view: dict[str, object]


def save_report(report: StaticAnalysisReport) -> SavedReportPaths:
    """Persist *report* to disk and return the generated artefact paths."""

    from ..reporting.view import build_report_view, save_html_report

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    sha256 = report.hashes.get("sha256")
    filename = f"{sha256}.json" if sha256 else f"report_{report.generated_at}.json"
    path = REPORTS_DIR / filename

    view_payload = dict(build_report_view(report))
    payload = report.to_dict()
    payload["view"] = view_payload
    try:
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
    except OSError as exc:  # pragma: no cover - filesystem errors
        raise ReportStorageError(f"Unable to write report to {path}: {exc}") from exc

    html_path: Optional[Path]
    try:
        html_path = save_html_report(report, view_payload)
    except OSError as exc:  # pragma: no cover - filesystem errors
        log.warning(
            f"Failed to render HTML report for {path.name}: {exc}",
            category="static_analysis",
        )
        html_path = None

    summary = f"Static analysis report saved to {path}"
    if html_path:
        summary += f"; HTML {html_path}"
    summary += f" (sha256={sha256 or 'unknown'})"
    log.info(summary, category="static_analysis")
    return SavedReportPaths(json_path=path, html_path=html_path, view=view_payload)


def _read_report(path: Path) -> Optional[StaticAnalysisReport]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        log.warning(
            f"Failed to load static analysis report at {path}: {exc}",
            category="static_analysis",
        )
        return None

    try:
        return StaticAnalysisReport.from_dict(payload)
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(
            f"Invalid report payload at {path}: {exc}", category="static_analysis"
        )
        return None


def list_reports() -> List[StoredReport]:
    """Return all stored reports ordered by newest first."""

    if not REPORTS_DIR.exists():
        return []

    entries: List[StoredReport] = []
    for path in sorted(REPORTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        report = _read_report(path)
        if report:
            entries.append(StoredReport(path=path, report=report))
    return entries


def load_report(path: Path) -> StaticAnalysisReport:
    """Load a report from disk and return the parsed dataclass."""

    report = _read_report(path)
    if report is None:
        raise ReportStorageError(f"Report at {path} could not be loaded.")
    return report


__all__ = [
    "save_report",
    "list_reports",
    "load_report",
    "ReportStorageError",
    "StoredReport",
    "SavedReportPaths",
]
