"""util_actions.py - Standalone utility actions for the system menu."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils.logging_engine import LOG_FILES

_RETENTION_ENV_VAR = "SCYTALEDROID_STATIC_RETENTION_DAYS"


@dataclass
class _RemovalStats:
    count: int = 0
    bytes_freed: int = 0


def clear_screen() -> None:
    """Clear the terminal window without extra noise."""

    os.system("cls" if os.name == "nt" else "clear")


def show_log_locations() -> None:
    """Display key log locations for quick reference."""

    logs_root = Path(app_config.LOGS_DIR).expanduser()
    data_root = Path(app_config.DATA_DIR).expanduser()

    if not logs_root.exists():
        logs_root.mkdir(parents=True, exist_ok=True)

    print(
        status_messages.status(
            f"Logs directory: {logs_root.resolve()}", level="info"
        )
    )

    for category, filename in sorted(LOG_FILES.items()):
        friendly = category.replace("_", " ").title()
        log_path = logs_root / filename
        print(
            status_messages.status(
                f"  {friendly}: {log_path}", level="info"
            )
        )

    state_dir = data_root / app_config.DEVICE_STATE_DIR
    print(
        status_messages.status(
            f"Device state cache: {state_dir}", level="info"
        )
    )

    static_reports = data_root / "static_analysis" / "reports"
    print(
        status_messages.status(
            f"Static-analysis reports: {static_reports}", level="info"
        )
    )


def clean_static_analysis_artifacts(*, retention_days: Optional[int] = None) -> None:
    """Remove stale static-analysis artefacts to keep local storage tidy."""

    resolved_retention = _resolve_retention_days(retention_days)

    static_root = Path(app_config.DATA_DIR) / "static_analysis"
    reports_dir = static_root / "reports"
    tmp_dir = static_root / "tmp"
    cache_dir = static_root / "cache"
    html_root = Path(app_config.OUTPUT_DIR) / "reports" / "static_analysis"

    cutoff = datetime.now(timezone.utc) - timedelta(days=resolved_retention)

    report_patterns = ("*.json", "*.ndjson", "*.ndjson.gz", "*.json.gz", "*.zip", "*.tar.gz")
    removed_reports = _prune_files(reports_dir, report_patterns, cutoff)
    removed_html = _prune_files(html_root, ("*.html", "*.htm"), cutoff)
    removed_tmp = _clear_directory(tmp_dir)
    removed_cache = _clear_directory(cache_dir)

    print(
        status_messages.status(
            "Static-analysis housekeeping completed.", level="info"
        )
    )

    _render_cleanup_summary(
        label="Reports",
        stats=removed_reports,
        missing="  Reports directory not found; nothing to prune.",
        retention_days=resolved_retention,
    )
    _render_cleanup_summary(
        label="HTML exports",
        stats=removed_html,
        missing="  HTML exports directory not found; nothing to prune.",
        retention_days=resolved_retention,
    )
    _render_cleanup_summary(
        label="Temp directory",
        stats=removed_tmp,
        missing="  Temp directory not found; skipping.",
    )
    _render_cleanup_summary(
        label="Cache directory",
        stats=removed_cache,
        missing="  Cache directory not found; skipping.",
    )


def _resolve_retention_days(retention_days: Optional[int]) -> int:
    if retention_days is not None and retention_days > 0:
        return retention_days

    env_value = os.environ.get(_RETENTION_ENV_VAR)
    if env_value:
        try:
            parsed = int(env_value)
            if parsed > 0:
                return parsed
        except ValueError:
            print(
                status_messages.status(
                    f"Ignoring invalid {_RETENTION_ENV_VAR} value '{env_value}'.",
                    level="warn",
                )
            )

    return getattr(app_config, "STATIC_ANALYSIS_RETENTION_DAYS", 30)


def _prune_files(
    directory: Path, patterns: Iterable[str], cutoff: datetime
) -> _RemovalStats | None:
    if not directory.exists():
        return None

    removed = _RemovalStats()
    for pattern in patterns:
        for path in directory.glob(pattern):
            try:
                modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
                if modified < cutoff:
                    removed.bytes_freed += path.stat().st_size
                    path.unlink()
                    removed.count += 1
            except OSError as exc:
                print(
                    status_messages.status(
                        f"Failed to remove {path}: {exc}", level="warn"
                    )
                )
    return removed


def _clear_directory(directory: Path) -> _RemovalStats | None:
    if not directory.exists():
        directory.mkdir(parents=True, exist_ok=True)
        return None

    removed = _RemovalStats()
    for child in directory.iterdir():
        try:
            if child.is_dir() and not child.is_symlink():
                removed.bytes_freed += _dir_size(child)
                shutil.rmtree(child)
            else:
                size = child.stat().st_size if child.exists() else 0
                child.unlink()
                removed.bytes_freed += size
            removed.count += 1
        except OSError as exc:
            print(
                status_messages.status(
                    f"Failed to remove {child}: {exc}", level="warn"
                )
            )
    directory.mkdir(parents=True, exist_ok=True)
    return removed


def _dir_size(path: Path) -> int:
    total = 0
    for child in path.rglob("*"):
        try:
            if child.is_file() and not child.is_symlink():
                total += child.stat().st_size
        except OSError:
            continue
    return total


def _render_cleanup_summary(
    *,
    label: str,
    stats: _RemovalStats | None,
    missing: str,
    retention_days: Optional[int] = None,
) -> None:
    if stats is None:
        print(status_messages.status(missing, level="info"))
        return

    if stats.count == 0:
        window_text = (
            f" older than {retention_days} days" if retention_days is not None else ""
        )
        message = f"  {label}: nothing to remove{window_text}."
    else:
        window_text = (
            f" older than {retention_days} days" if retention_days is not None else ""
        )
        size_text = _format_bytes(stats.bytes_freed)
        message = (
            f"  {label}: deleted {stats.count} item(s){window_text}, freeing {size_text}."
        )

    print(status_messages.status(message, level="info"))


def _format_bytes(byte_count: int) -> str:
    if byte_count <= 0:
        return "0 B"

    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(byte_count)
    unit_index = 0
    while value >= 1024 and unit_index < len(units) - 1:
        value /= 1024
        unit_index += 1
    if unit_index == 0:
        return f"{int(value)} {units[unit_index]}"
    return f"{value:.1f} {units[unit_index]}"


__all__ = [
    "clean_static_analysis_artifacts",
    "clear_screen",
    "show_log_locations",
]
