"""Per-package DB severity table rendering for static analysis runs."""

from __future__ import annotations

import csv
from collections import defaultdict
from collections.abc import Mapping, MutableMapping, Sequence
from pathlib import Path

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Utils.DisplayUtils import status_messages, table_utils

from .db_verification_common import placeholders_for, resolve_static_run_ids
from .results_formatters import _normalize_target_sdk

DEFAULT_PACKAGE_TABLE_LIMIT = 20
_SEVERITY_COLUMNS: tuple[str, ...] = ("High", "Medium", "Low", "Info")


def _safe_int(value: object, default: int = 0) -> int:
    """Safely coerce DB values into integers."""
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def _row_value(row: object, index: int, key: str) -> object | None:
    """Return a value from a DB row that may be a dict or tuple/list."""
    if isinstance(row, Mapping):
        return row.get(key)

    if isinstance(row, Sequence) and not isinstance(row, (str, bytes)):
        try:
            return row[index]
        except IndexError:
            return None

    return None


def _normalize_severity_label(value: object) -> str | None:
    """Normalize persisted severity labels into the report table buckets."""
    token = str(value or "").strip()

    if not token:
        return None

    token_upper = token.upper()

    aliases = {
        "P0": "High",
        "P1": "High",
        "P2": "Medium",
        "P3": "Low",
        "NOTE": "Info",
        "INFO": "Info",
        "INFORMATIONAL": "Info",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "MED": "Medium",
        "LOW": "Low",
    }

    return aliases.get(token_upper, token)


def _per_app_severity_from_findings(
    static_run_ids: Sequence[int],
) -> list[tuple[str, str, int]]:
    """Fetch normalized finding counts grouped by package and severity."""
    if not static_run_ids:
        return []

    placeholders = placeholders_for(static_run_ids)

    try:
        rows = core_q.run_sql(
            f"""
            SELECT a.package_name, f.severity, COUNT(*) as cnt
            FROM static_analysis_findings f
            JOIN static_analysis_runs r ON r.id = f.run_id
            JOIN app_versions av ON av.id = r.app_version_id
            JOIN apps a ON a.id = av.app_id
            WHERE f.run_id IN ({placeholders})
            GROUP BY a.package_name, f.severity
            ORDER BY a.package_name, f.severity
            """,
            tuple(static_run_ids),
            fetch="all",
        )
    except Exception:
        return []

    results: list[tuple[str, str, int]] = []

    for row in rows or []:
        pkg = _row_value(row, 0, "package_name")
        sev = _row_value(row, 1, "severity")
        cnt = _row_value(row, 2, "cnt")

        if pkg is None or sev is None:
            continue

        label = _normalize_severity_label(sev)
        if not label:
            continue

        results.append((str(pkg), label, _safe_int(cnt)))

    return results


def _target_sdk_by_package(static_run_ids: Sequence[int]) -> Mapping[str, object]:
    """Return package_name -> target_sdk for the provided static run ids."""
    if not static_run_ids:
        return {}

    placeholders = placeholders_for(static_run_ids)

    try:
        target_rows = core_q.run_sql(
            f"""
            SELECT a.package_name, av.target_sdk
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            WHERE sar.id IN ({placeholders})
            ORDER BY sar.id DESC
            """,
            tuple(static_run_ids),
            fetch="all",
            dictionary=True,
        )
    except Exception:
        return {}

    target_map: dict[str, object] = {}

    for row in target_rows or []:
        if not isinstance(row, Mapping):
            continue

        package_name = row.get("package_name")
        if package_name is None:
            continue

        target_map[str(package_name)] = row.get("target_sdk")

    return target_map


def _build_table_rows(
    *,
    counts: Mapping[str, Mapping[str, int]],
    target_map: Mapping[str, object],
) -> list[list[str]]:
    """Build display/export table rows."""
    table_rows: list[list[str]] = []

    for idx, package_name in enumerate(sorted(counts.keys()), start=1):
        package_counts = counts[package_name]
        target_sdk = _normalize_target_sdk(target_map.get(package_name))

        table_rows.append(
            [
                str(idx),
                package_name,
                target_sdk,
                *[
                    str(_safe_int(package_counts.get(column)))
                    for column in _SEVERITY_COLUMNS
                ],
            ]
        )

    return table_rows


def _write_normalized_findings_csv(
    *,
    session_stamp: str,
    table_rows: Sequence[Sequence[str]],
) -> Path | None:
    """Write the full normalized findings table to CSV."""
    try:
        export_dir = Path("output") / "tables"
        export_dir.mkdir(parents=True, exist_ok=True)

        export_path = export_dir / f"{session_stamp}_normalized_findings.csv"
        with export_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["#", "Package", "targetSdk", *_SEVERITY_COLUMNS])
            writer.writerows(table_rows)

        return export_path
    except Exception:
        return None


def _render_table(
    *,
    session_stamp: str,
    table_rows: list[list[str]],
) -> None:
    """Render the terminal table and save full CSV output."""
    full_count = len(table_rows)
    table_rows_display = table_rows[:DEFAULT_PACKAGE_TABLE_LIMIT]
    export_path = _write_normalized_findings_csv(
        session_stamp=session_stamp,
        table_rows=table_rows,
    )

    print()

    if full_count > DEFAULT_PACKAGE_TABLE_LIMIT:
        print(
            f"Normalized findings (deduped) — top {DEFAULT_PACKAGE_TABLE_LIMIT} of {full_count} packages"
        )
    else:
        print("Normalized findings (deduped) — per package")

    table_utils.render_table(
        ["#", "Package", "targetSdk", *_SEVERITY_COLUMNS],
        table_rows_display,
    )

    if export_path is not None and full_count > DEFAULT_PACKAGE_TABLE_LIMIT:
        print(
            status_messages.status(
                f"Full normalized findings table saved: {export_path}",
                level="info",
            )
        )


def render_db_severity_table(session_stamp: str) -> bool:
    """Render normalized per-package finding counts from persisted DB rows."""
    static_run_ids = resolve_static_run_ids(session_stamp)
    severity_rows = _per_app_severity_from_findings(static_run_ids)

    if not severity_rows:
        return False

    counts: MutableMapping[str, MutableMapping[str, int]] = defaultdict(
        lambda: {column: 0 for column in _SEVERITY_COLUMNS}
    )

    for package_name, severity_label, count in severity_rows:
        if severity_label not in _SEVERITY_COLUMNS:
            continue

        counts[package_name][severity_label] += count

    target_map = _target_sdk_by_package(static_run_ids)
    table_rows = _build_table_rows(
        counts=counts,
        target_map=target_map,
    )

    if not table_rows:
        return False

    _render_table(
        session_stamp=session_stamp,
        table_rows=table_rows,
    )

    return True