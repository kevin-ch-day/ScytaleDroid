"""Persistence helpers for static analysis reports."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from scytaledroid.Config import app_config
from scytaledroid.Database.db_utils.package_utils import resolve_package_identity
from scytaledroid.Utils.LoggingUtils import logging_events
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ..core import StaticAnalysisReport

if TYPE_CHECKING:  # pragma: no cover - imported for type checking only
    # Import from package to align with runtime import and re-exports
    pass


_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


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
    html_path: Path | None
    view: dict[str, object]


def save_report(report: StaticAnalysisReport) -> SavedReportPaths:
    """Persist *report* to disk and return the generated artefact paths."""

    # Import via package; re-exports ensure stable import path
    from ..reporting import build_report_view, save_html_report

    sha256 = report.hashes.get("sha256")
    metadata = report.metadata if isinstance(report.metadata, dict) else {}
    session_stamp = metadata.get("session_stamp")
    mode = _normalize_report_mode(getattr(app_config, "STATIC_REPORT_JSON_MODE", "both"))
    latest_path, archive_path = _resolve_report_paths(report, sha256=sha256, session_stamp=session_stamp)

    view_payload = dict(build_report_view(report))
    payload = report.to_dict()
    payload["view"] = view_payload
    payload["metadata"] = _enrich_report_metadata(payload.get("metadata"), report)
    try:
        if mode in {"latest", "both"}:
            latest_path.parent.mkdir(parents=True, exist_ok=True)
            with latest_path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True, default=str)
        if mode in {"archive", "both"} and archive_path is not None:
            archive_path.parent.mkdir(parents=True, exist_ok=True)
            with archive_path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True, default=str)
    except OSError as exc:  # pragma: no cover - filesystem errors
        target = latest_path if mode in {"latest", "both"} else archive_path or latest_path
        raise ReportStorageError(f"Unable to write report to {target}: {exc}") from exc

    path = latest_path if mode in {"latest", "both"} else archive_path or latest_path

    html_path: Path | None
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
    identity = resolve_package_identity(str(report.manifest.package_name or ""), context="static_analysis")
    log.info(
        summary,
        category="static_analysis",
        extra={
            "event": logging_events.REPORT_SAVED,
            "session_stamp": session_stamp,
            **identity.as_metadata(),
            "version_name": report.manifest.version_name,
            "version_code": report.manifest.version_code,
            "report_sha256": sha256,
            "json_path": str(path),
            "archive_path": str(archive_path) if archive_path else None,
            "html_path": str(html_path) if html_path else None,
            "analysis_version": report.analysis_version,
            "generated_at": report.generated_at,
        },
    )
    return SavedReportPaths(json_path=path, html_path=html_path, view=view_payload)


def _enrich_report_metadata(
    metadata: object,
    report: StaticAnalysisReport,
) -> dict[str, object]:
    enriched = dict(metadata) if isinstance(metadata, dict) else {}
    identity = resolve_package_identity(str(report.manifest.package_name or ""), context="static_analysis")
    enriched.update(identity.as_metadata())
    return enriched


def _safe_filename(value: str) -> str:
    cleaned = _SAFE_FILENAME_RE.sub("-", value.strip())
    cleaned = cleaned.strip("-.")
    return cleaned or "report"


def _read_report(path: Path) -> StaticAnalysisReport | None:
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


def list_reports() -> list[StoredReport]:
    """Return all stored reports ordered by newest first."""

    roots = _report_search_roots()
    if not any(root.exists() for root in roots):
        return []

    def _sort_key(entry: StoredReport) -> tuple:
        report = entry.report
        # Deterministic ordering: avoid filesystem mtimes (easy to disturb via copy/unzip/rsync).
        generated_at = str(getattr(report, "generated_at", "") or "")
        meta = getattr(report, "metadata", None)
        session_stamp = ""
        if isinstance(meta, dict):
            session_stamp = str(meta.get("session_stamp") or "")
        version_code = getattr(getattr(report, "manifest", None), "version_code", None)
        try:
            version_code_i = int(version_code) if version_code is not None else -1
        except (TypeError, ValueError):
            version_code_i = -1
        return (
            1 if generated_at else 0,
            generated_at,
            1 if session_stamp else 0,
            session_stamp,
            version_code_i,
            entry.path.name,
        )

    entries: list[StoredReport] = []
    seen_identities: set[tuple[str, str, str, str, str]] = set()
    for path in _iter_report_paths():
        report = _read_report(path)
        if report:
            identity = _report_identity(report)
            if identity in seen_identities:
                continue
            seen_identities.add(identity)
            entries.append(StoredReport(path=path, report=report))
    entries.sort(key=_sort_key, reverse=True)
    return entries


def load_report(path: Path) -> StaticAnalysisReport:
    """Load a report from disk and return the parsed dataclass."""

    report = _read_report(path)
    if report is None:
        raise ReportStorageError(f"Report at {path} could not be loaded.")
    return report


def _reports_root() -> Path:
    return Path(app_config.DATA_DIR) / "static_analysis" / "reports"


def _normalize_report_mode(mode: str) -> str:
    normalized = str(mode or "latest").strip().lower()
    return normalized if normalized in {"latest", "archive", "both"} else "latest"


def _resolve_report_paths(
    report: StaticAnalysisReport,
    *,
    sha256: str | None,
    session_stamp: object | None,
) -> tuple[Path, Path]:
    reports_root = _reports_root()
    file_stem = _report_file_stem(report, sha256=sha256)
    latest_path = reports_root / "latest" / f"{file_stem}.json"
    archive_session = _report_archive_session(report, session_stamp=session_stamp)
    archive_path = reports_root / "archive" / archive_session / f"{file_stem}.json"
    return latest_path, archive_path


def _report_file_stem(report: StaticAnalysisReport, *, sha256: str | None) -> str:
    if sha256:
        return _safe_filename(sha256)
    generated_suffix = _safe_filename(report.generated_at)
    return f"report_{generated_suffix}"


def _report_archive_session(report: StaticAnalysisReport, *, session_stamp: object | None) -> str:
    if isinstance(session_stamp, str) and session_stamp.strip():
        return _safe_filename(session_stamp)
    generated_suffix = _safe_filename(report.generated_at)
    return generated_suffix or "session"


def _report_search_roots() -> tuple[Path, ...]:
    reports_root = _reports_root()
    return (
        reports_root / "latest",
        reports_root / "archive",
        reports_root,
    )


def _iter_report_paths() -> list[Path]:
    roots = _report_search_roots()
    seen_paths: set[Path] = set()
    ordered_paths: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.json")):
            if path in seen_paths:
                continue
            seen_paths.add(path)
            ordered_paths.append(path)
    return ordered_paths


def _report_identity(report: StaticAnalysisReport) -> tuple[str, str, str, str, str]:
    metadata = report.metadata if isinstance(report.metadata, dict) else {}
    return (
        str(report.hashes.get("sha256") or ""),
        str(metadata.get("session_stamp") or ""),
        str(report.manifest.package_name or ""),
        str(report.generated_at or ""),
        str(report.file_name or ""),
    )


__all__ = [
    "save_report",
    "list_reports",
    "load_report",
    "ReportStorageError",
    "StoredReport",
    "SavedReportPaths",
]
