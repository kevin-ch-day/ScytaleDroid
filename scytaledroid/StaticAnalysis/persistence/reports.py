"""Persistence helpers for static analysis reports."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from scytaledroid.Config import app_config
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ..core import StaticAnalysisReport


REPORTS_DIR = Path(app_config.DATA_DIR) / "static_analysis" / "reports"


class ReportStorageError(Exception):
    """Raised when reports cannot be persisted or loaded."""


@dataclass(frozen=True)
class StoredReport:
    """Represents a report stored on disk."""

    path: Path
    report: StaticAnalysisReport


def save_report(report: StaticAnalysisReport) -> Path:
    """Persist *report* to the reports directory and return the path."""

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    sha256 = report.hashes.get("sha256")
    filename = f"{sha256}.json" if sha256 else f"report_{report.generated_at}.json"
    path = REPORTS_DIR / filename

    payload = report.to_dict()
    try:
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
    except OSError as exc:  # pragma: no cover - filesystem errors
        raise ReportStorageError(f"Unable to write report to {path}: {exc}") from exc

    log.info(
        f"Static analysis report saved to {path} (sha256={sha256 or 'unknown'})",
        category="static_analysis",
    )
    return path


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


__all__ = ["save_report", "list_reports", "load_report", "ReportStorageError", "StoredReport"]
