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
_REPORT_CACHE_TOKEN: tuple[str, ...] | None = None
_REPORT_CACHE_ENTRIES: list[StoredReport] | None = None
_REPORT_CACHE_PACKAGE_INDEX: dict[str, list[StoredReport]] | None = None
_REPORT_PACKAGE_INDEX_VERSION = 1


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


def _report_cache_token() -> tuple[str, ...]:
    return tuple(str(root.resolve(strict=False)) for root in _report_search_roots())


def _clear_report_cache() -> None:
    global _REPORT_CACHE_TOKEN, _REPORT_CACHE_ENTRIES, _REPORT_CACHE_PACKAGE_INDEX
    _REPORT_CACHE_TOKEN = None
    _REPORT_CACHE_ENTRIES = None
    _REPORT_CACHE_PACKAGE_INDEX = None


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


def _set_report_cache(entries: list[StoredReport]) -> None:
    global _REPORT_CACHE_TOKEN, _REPORT_CACHE_ENTRIES, _REPORT_CACHE_PACKAGE_INDEX
    entries.sort(key=_sort_key, reverse=True)
    _REPORT_CACHE_TOKEN = _report_cache_token()
    _REPORT_CACHE_ENTRIES = list(entries)
    package_index: dict[str, list[StoredReport]] = {}
    for entry in entries:
        package_name = str(getattr(getattr(entry.report, "manifest", None), "package_name", "") or "").strip().lower()
        if not package_name:
            continue
        package_index.setdefault(package_name, []).append(entry)
    _REPORT_CACHE_PACKAGE_INDEX = package_index
    _write_report_package_index(entries)


def _cache_saved_report(path: Path, report: StaticAnalysisReport) -> None:
    global _REPORT_CACHE_TOKEN, _REPORT_CACHE_ENTRIES
    token = _report_cache_token()
    if _REPORT_CACHE_TOKEN != token or _REPORT_CACHE_ENTRIES is None:
        return
    identity = _report_identity(report)
    updated = [entry for entry in _REPORT_CACHE_ENTRIES if _report_identity(entry.report) != identity]
    updated.append(StoredReport(path=path, report=report))
    _set_report_cache(updated)


def _report_package_index_path() -> Path:
    return _reports_root() / "_cache" / f"package_index_v{_REPORT_PACKAGE_INDEX_VERSION}.json"


def _package_index_entry(entry: StoredReport) -> dict[str, object]:
    report = entry.report
    metadata = report.metadata if isinstance(report.metadata, dict) else {}
    return {
        "path": str(entry.path),
        "package_name": str(getattr(getattr(report, "manifest", None), "package_name", "") or "").strip().lower(),
        "sha256": str(report.hashes.get("sha256") or ""),
        "session_stamp": str(metadata.get("session_stamp") or ""),
        "generated_at": str(getattr(report, "generated_at", "") or ""),
        "version_code": str(getattr(getattr(report, "manifest", None), "version_code", "") or ""),
        "file_name": str(getattr(report, "file_name", "") or ""),
    }


def _write_report_package_index(entries: list[StoredReport]) -> None:
    index_path = _report_package_index_path()
    payload = {
        "schema_version": _REPORT_PACKAGE_INDEX_VERSION,
        "entries": [_package_index_entry(entry) for entry in entries],
    }
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_report_package_index() -> list[dict[str, object]] | None:
    index_path = _report_package_index_path()
    if not index_path.exists():
        return None
    try:
        payload = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if int(payload.get("schema_version") or 0) != _REPORT_PACKAGE_INDEX_VERSION:
        return None
    entries = payload.get("entries")
    if not isinstance(entries, list):
        return None
    normalized: list[dict[str, object]] = []
    for row in entries:
        if not isinstance(row, dict):
            continue
        package_name = str(row.get("package_name") or "").strip().lower()
        path = str(row.get("path") or "").strip()
        if not package_name or not path:
            continue
        normalized.append(row)
    return normalized


def _upsert_report_package_index_entry(path: Path, report: StaticAnalysisReport) -> None:
    package_name = str(getattr(getattr(report, "manifest", None), "package_name", "") or "").strip().lower()
    if not package_name:
        return
    existing = _read_report_package_index() or []
    entry = _package_index_entry(StoredReport(path=path, report=report))
    identity = (
        str(entry.get("sha256") or ""),
        str(entry.get("session_stamp") or ""),
        package_name,
        str(entry.get("generated_at") or ""),
        str(entry.get("file_name") or ""),
    )
    updated = [
        row
        for row in existing
        if (
            str(row.get("sha256") or ""),
            str(row.get("session_stamp") or ""),
            str(row.get("package_name") or "").strip().lower(),
            str(row.get("generated_at") or ""),
            str(row.get("file_name") or ""),
        )
        != identity
    ]
    updated.append(entry)
    updated.sort(
        key=lambda row: (
            1 if str(row.get("generated_at") or "") else 0,
            str(row.get("generated_at") or ""),
            1 if str(row.get("session_stamp") or "") else 0,
            str(row.get("session_stamp") or ""),
            int(str(row.get("version_code") or "-1")) if str(row.get("version_code") or "").isdigit() else -1,
            str(row.get("path") or ""),
        ),
        reverse=True,
    )
    index_path = _report_package_index_path()
    payload = {
        "schema_version": _REPORT_PACKAGE_INDEX_VERSION,
        "entries": updated,
    }
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _stored_reports_from_index(package_name: str) -> list[StoredReport] | None:
    indexed = _read_report_package_index()
    if indexed is None:
        return None
    rows = [row for row in indexed if str(row.get("package_name") or "").strip().lower() == package_name]
    if not rows:
        return []
    entries: list[StoredReport] = []
    for row in rows:
        path = Path(str(row.get("path") or ""))
        if not path.exists():
            return None
        report = _read_report(path)
        if report is None:
            return None
        entries.append(StoredReport(path=path, report=report))
    entries.sort(key=_sort_key, reverse=True)
    return entries


def save_report(
    report: StaticAnalysisReport,
    *,
    execution_id: str | None = None,
) -> SavedReportPaths:
    """Persist *report* to disk and return the generated artefact paths."""

    # Import via package; re-exports ensure stable import path
    from ..reporting import save_html_report

    sha256 = report.hashes.get("sha256")
    metadata = report.metadata if isinstance(report.metadata, dict) else {}
    session_stamp = metadata.get("session_stamp")
    mode = _normalize_report_mode(getattr(app_config, "STATIC_REPORT_JSON_MODE", "both"))
    latest_path, archive_path = _resolve_report_paths(report, sha256=sha256, session_stamp=session_stamp)

    view_payload, payload = _build_report_payload(report)
    try:
        _write_report_payload(
            payload=payload,
            latest_path=latest_path,
            archive_path=archive_path,
            mode=mode,
        )
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
            "execution_id": execution_id,
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
    try:
        cached_report = StaticAnalysisReport.from_dict(payload)
    except Exception:
        cached_report = report
    _cache_saved_report(path, cached_report)
    _upsert_report_package_index_entry(path, cached_report)
    return SavedReportPaths(json_path=path, html_path=html_path, view=view_payload)


def refresh_saved_report_json(report: StaticAnalysisReport) -> SavedReportPaths:
    """Rewrite persisted JSON payloads for *report* without regenerating HTML."""

    sha256 = report.hashes.get("sha256")
    metadata = report.metadata if isinstance(report.metadata, dict) else {}
    session_stamp = metadata.get("session_stamp")
    mode = _normalize_report_mode(getattr(app_config, "STATIC_REPORT_JSON_MODE", "both"))
    latest_path, archive_path = _resolve_report_paths(report, sha256=sha256, session_stamp=session_stamp)
    view_payload, payload = _build_report_payload(report)
    try:
        _write_report_payload(
            payload=payload,
            latest_path=latest_path,
            archive_path=archive_path,
            mode=mode,
        )
    except OSError as exc:  # pragma: no cover - filesystem errors
        target = latest_path if mode in {"latest", "both"} else archive_path or latest_path
        raise ReportStorageError(f"Unable to refresh report JSON at {target}: {exc}") from exc

    path = latest_path if mode in {"latest", "both"} else archive_path or latest_path
    try:
        cached_report = StaticAnalysisReport.from_dict(payload)
    except Exception:
        cached_report = report
    _cache_saved_report(path, cached_report)
    _upsert_report_package_index_entry(path, cached_report)
    return SavedReportPaths(json_path=path, html_path=None, view=view_payload)


def _build_report_payload(report: StaticAnalysisReport) -> tuple[dict[str, object], dict[str, object]]:
    from ..reporting import build_report_view

    view_payload = dict(build_report_view(report))
    payload = report.to_dict()
    payload["view"] = view_payload
    payload["metadata"] = _enrich_report_metadata(payload.get("metadata"), report)
    return view_payload, payload


def _write_report_payload(
    *,
    payload: dict[str, object],
    latest_path: Path,
    archive_path: Path | None,
    mode: str,
) -> None:
    if mode in {"latest", "both"}:
        latest_path.parent.mkdir(parents=True, exist_ok=True)
        with latest_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, default=str)
    if mode in {"archive", "both"} and archive_path is not None:
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        with archive_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, default=str)


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
        _clear_report_cache()
        return []

    token = _report_cache_token()
    if _REPORT_CACHE_TOKEN == token and _REPORT_CACHE_ENTRIES is not None:
        if all(entry.path.exists() for entry in _REPORT_CACHE_ENTRIES):
            return list(_REPORT_CACHE_ENTRIES)
        _clear_report_cache()

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
    _set_report_cache(entries)
    return list(entries)


def reports_for_package(package_name: str | None) -> list[StoredReport]:
    """Return cached stored reports for one package, newest first."""

    package_norm = str(package_name or "").strip().lower()
    if not package_norm:
        return []
    token = _report_cache_token()
    if (
        _REPORT_CACHE_TOKEN == token
        and _REPORT_CACHE_PACKAGE_INDEX is not None
        and _REPORT_CACHE_ENTRIES is not None
        and all(entry.path.exists() for entry in _REPORT_CACHE_ENTRIES)
    ):
        return list(_REPORT_CACHE_PACKAGE_INDEX.get(package_norm, ()))
    indexed_entries = _stored_reports_from_index(package_norm)
    if indexed_entries is not None:
        return indexed_entries
    entries = list_reports()
    return [
        entry
        for entry in entries
        if str(getattr(getattr(entry.report, "manifest", None), "package_name", "") or "").strip().lower()
        == package_norm
    ]


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
    cache_root = (_reports_root() / "_cache").resolve(strict=False)
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.json")):
            try:
                if path.resolve(strict=False).is_relative_to(cache_root):
                    continue
            except AttributeError:
                resolved = path.resolve(strict=False)
                if str(resolved).startswith(str(cache_root)):
                    continue
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
    "refresh_saved_report_json",
    "list_reports",
    "reports_for_package",
    "load_report",
    "ReportStorageError",
    "StoredReport",
    "SavedReportPaths",
]
