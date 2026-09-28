"""Read-only log-directory health inventory.

The report describes storage and retention signals only.  It never creates,
rotates, truncates, compresses, or deletes log files.
"""

from __future__ import annotations

import os
from collections import defaultdict
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.Utils.LoggingUtils.logging_engine import LOG_CONFIGS

DEFAULT_STALE_DAYS = 30
DEFAULT_LARGEST_LIMIT = 10


def configured_stale_days(environ: Mapping[str, str] | None = None) -> int:
    """Return the configured age threshold, falling back to a safe default."""

    source = os.environ if environ is None else environ
    value = str(source.get("SCYTALEDROID_LOGS_STALE_DAYS", DEFAULT_STALE_DAYS)).strip()
    try:
        days = int(value)
    except (TypeError, ValueError):
        return DEFAULT_STALE_DAYS
    return days if days >= 0 else DEFAULT_STALE_DAYS


def _category_for(path: Path, log_root: Path) -> str:
    relative = path.relative_to(log_root)
    if len(relative.parts) > 1:
        return relative.parts[0]

    name = relative.name
    for category, config in LOG_CONFIGS.items():
        for basename in (config.text_file, config.json_file):
            if basename and (name == basename or name.startswith(f"{basename}.")):
                return category
    return "unclassified_root"


def _iso_utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat().replace("+00:00", "Z")


def collect_log_health(
    log_root: Path | None = None,
    *,
    older_than_days: int | None = None,
    largest_limit: int = DEFAULT_LARGEST_LIMIT,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Collect a deterministic, read-only inventory beneath ``log_root``."""

    root = Path(app_config.LOGS_DIR if log_root is None else log_root).expanduser()
    stale_days = configured_stale_days() if older_than_days is None else int(older_than_days)
    if stale_days < 0:
        raise ValueError("older_than_days must be zero or greater")
    if largest_limit < 1:
        raise ValueError("largest_limit must be at least one")

    observed_now = now or datetime.now(UTC)
    if observed_now.tzinfo is None:
        observed_now = observed_now.replace(tzinfo=UTC)
    else:
        observed_now = observed_now.astimezone(UTC)
    cutoff = observed_now - timedelta(days=stale_days)

    rows: list[dict[str, Any]] = []
    unreadable: list[str] = []
    skipped_symlinks: list[str] = []
    if root.exists():
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                skipped_symlinks.append(relative)
                continue
            if not path.is_file():
                continue
            try:
                stat = path.stat()
            except OSError:
                unreadable.append(relative)
                continue
            rotated = path.name.endswith(".gz")
            modified = datetime.fromtimestamp(stat.st_mtime, tz=UTC)
            rows.append(
                {
                    "path": relative,
                    "category": _category_for(path, root),
                    "size_bytes": stat.st_size,
                    "modified_at_utc": _iso_utc(stat.st_mtime),
                    "rotated": rotated,
                    "stale": modified < cutoff,
                }
            )

    by_category: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "file_count": 0,
            "size_bytes": 0,
            "active_file_count": 0,
            "rotated_file_count": 0,
            "stale_file_count": 0,
        }
    )
    for row in rows:
        bucket = by_category[str(row["category"])]
        bucket["file_count"] += 1
        bucket["size_bytes"] += int(row["size_bytes"])
        bucket["rotated_file_count" if row["rotated"] else "active_file_count"] += 1
        if row["stale"]:
            bucket["stale_file_count"] += 1

    rotated_rows = [row for row in rows if row["rotated"]]
    stale_rows = [row for row in rows if row["stale"]]
    oldest_rotated = min(rotated_rows, key=lambda row: str(row["modified_at_utc"]), default=None)
    largest = sorted(rows, key=lambda row: (-int(row["size_bytes"]), str(row["path"])))[
        :largest_limit
    ]

    return {
        "report_schema_version": "scytaledroid_logs_health_v1",
        "captured_at_utc": observed_now.isoformat().replace("+00:00", "Z"),
        "log_root": str(root.resolve(strict=False)),
        "log_root_exists": root.is_dir(),
        "read_only": True,
        "stale_threshold_days": stale_days,
        "stale_cutoff_utc": cutoff.isoformat().replace("+00:00", "Z"),
        "summary": {
            "file_count": len(rows),
            "total_size_bytes": sum(int(row["size_bytes"]) for row in rows),
            "active_file_count": sum(1 for row in rows if not row["rotated"]),
            "rotated_file_count": len(rotated_rows),
            "stale_file_count": len(stale_rows),
            "stale_active_file_count": sum(1 for row in stale_rows if not row["rotated"]),
            "stale_rotated_file_count": sum(1 for row in stale_rows if row["rotated"]),
            "unreadable_file_count": len(unreadable),
            "skipped_symlink_count": len(skipped_symlinks),
        },
        "categories": {key: by_category[key] for key in sorted(by_category)},
        "oldest_rotated": oldest_rotated,
        "largest_files": largest,
        "stale_files": sorted(
            stale_rows, key=lambda row: (str(row["modified_at_utc"]), str(row["path"]))
        ),
        "unreadable_files": unreadable,
        "skipped_symlinks": skipped_symlinks,
    }


def humanize_bytes(value: int) -> str:
    """Render a compact binary-unit size."""

    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024.0 or unit == "TiB":
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TiB"


def render_log_health(report: Mapping[str, Any]) -> str:
    """Render a concise operator view from ``collect_log_health`` output."""

    summary = report.get("summary") if isinstance(report.get("summary"), Mapping) else {}
    lines = [
        "LOG HEALTH — READ ONLY",
        f"Root                    :: {report.get('log_root')}",
        f"Files                   :: {summary.get('file_count', 0)}",
        f"Total size              :: {humanize_bytes(int(summary.get('total_size_bytes', 0) or 0))}",
        (
            "Active / rotated        :: "
            f"{summary.get('active_file_count', 0)} / {summary.get('rotated_file_count', 0)}"
        ),
        (
            f"Stale over {report.get('stale_threshold_days', 0)} days      :: "
            f"{summary.get('stale_file_count', 0)} "
            f"(active {summary.get('stale_active_file_count', 0)}, "
            f"rotated {summary.get('stale_rotated_file_count', 0)})"
        ),
    ]
    oldest = report.get("oldest_rotated")
    if isinstance(oldest, Mapping):
        lines.append(
            f"Oldest rotated          :: {oldest.get('modified_at_utc')} · {oldest.get('path')}"
        )
    if summary.get("unreadable_file_count") or summary.get("skipped_symlink_count"):
        lines.append(
            "Review                  :: "
            f"unreadable {summary.get('unreadable_file_count', 0)} · "
            f"symlinks skipped {summary.get('skipped_symlink_count', 0)}"
        )

    categories = report.get("categories")
    if isinstance(categories, Mapping) and categories:
        lines.extend(("", "Categories:"))
        for name, value in categories.items():
            if not isinstance(value, Mapping):
                continue
            lines.append(
                f"  {name:<20} {humanize_bytes(int(value.get('size_bytes', 0) or 0)):>10} · "
                f"{value.get('file_count', 0)} files · {value.get('stale_file_count', 0)} stale"
            )

    largest = report.get("largest_files")
    if isinstance(largest, list) and largest:
        lines.extend(("", "Largest files:"))
        for row in largest:
            if isinstance(row, Mapping):
                lines.append(
                    f"  {humanize_bytes(int(row.get('size_bytes', 0) or 0)):>10}  {row.get('path')}"
                )
    lines.extend(("", "No files were modified or deleted."))
    return "\n".join(lines)


__all__ = [
    "DEFAULT_LARGEST_LIMIT",
    "DEFAULT_STALE_DAYS",
    "collect_log_health",
    "configured_stale_days",
    "humanize_bytes",
    "render_log_health",
]
