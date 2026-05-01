"""DB MASVS summary rendering for static analysis runs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from scytaledroid.Utils.DisplayUtils import status_messages

from ..persistence.reports.masvs_summary_report import (
    fetch_db_masvs_summary,
    fetch_db_masvs_summary_static_many,
)
from .db_verification_common import resolve_static_run_ids
from .output_mode import compact_success_output_enabled

_MASVS_AREAS: tuple[str, ...] = ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE")


def _safe_int(value: object, default: int = 0) -> int:
    """Safely coerce a DB value into an integer."""
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def _safe_float(value: object) -> float | None:
    """Safely coerce a DB value into a float."""
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_mapping(value: object) -> Mapping[str, object]:
    """Return a mapping when possible, otherwise an empty mapping."""
    return value if isinstance(value, Mapping) else {}


def _normalize_rows(rows: object) -> list[Mapping[str, object]]:
    """Normalize MASVS summary rows into mapping objects."""
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        return []

    normalized: list[Mapping[str, object]] = []
    for row in rows:
        if isinstance(row, Mapping):
            normalized.append(row)

    return normalized


def _find_area_entry(
    rows: Sequence[Mapping[str, object]],
    area: str,
) -> Mapping[str, object] | None:
    """Find the MASVS row for one area."""
    for row in rows:
        if str(row.get("area") or "").upper() == area:
            return row
    return None


def _masvs_status(entry: Mapping[str, object] | None) -> str:
    """Return PASS/WARN/FAIL/NO DATA for one MASVS area row."""
    if entry is None:
        return "NO DATA"

    high = _safe_int(entry.get("high"))
    medium = _safe_int(entry.get("medium"))
    quality = _as_mapping(entry.get("quality"))
    coverage_status = str(quality.get("coverage_status") or "").strip().lower()

    if coverage_status == "no_data":
        return "NO DATA"
    if high:
        return "FAIL"
    if medium:
        return "WARN"
    return "PASS"


def _render_compact_masvs(rows: Sequence[Mapping[str, object]]) -> None:
    """Render one-line MASVS status output for normal successful runs."""
    statuses: list[str] = []

    for area in _MASVS_AREAS:
        entry = _find_area_entry(rows, area)
        statuses.append(f"{area.title()}={_masvs_status(entry)}")

    print()
    print("MASVS: " + ", ".join(statuses))


def _format_cvss_fields(entry: Mapping[str, object]) -> tuple[str, str, str]:
    """Return formatted worst score, average score, and band count fields."""
    cvss = _as_mapping(entry.get("cvss"))

    worst_score = _safe_float(cvss.get("worst_score"))
    worst_band = str(cvss.get("worst_severity") or "")
    worst_identifier = str(cvss.get("worst_identifier") or "")

    if worst_score is None:
        worst_display = "—"
    else:
        worst_display = f"{worst_score:.1f} {worst_band} ({worst_identifier})"

    avg_score = _safe_float(cvss.get("average_score"))
    avg_display = f"{avg_score:.1f}" if avg_score is not None else "—"

    band_counts = _as_mapping(cvss.get("band_counts"))
    order = ("Critical", "High", "Medium", "Low", "None")
    band_display_parts = [
        f"{label[0]}:{_safe_int(band_counts.get(label))}"
        for label in order
        if _safe_int(band_counts.get(label)) > 0
    ]
    band_display = ", ".join(band_display_parts) if band_display_parts else "—"

    return worst_display, avg_display, band_display


def _render_verbose_masvs(
    *,
    summary_label: str,
    run_id: object,
    summary_hint: str | None,
    rows: Sequence[Mapping[str, object]],
) -> None:
    """Render the full MASVS table for verbose/debug output."""
    print()

    header = f"DB MASVS Summary ({summary_label}={run_id}"
    if summary_hint:
        header += f"; {summary_hint}"
    header += ")"

    print(header)
    print("MASVS matrix totals (area rollup)")
    print("Area       High  Med   Low   Info  Status  Worst CVSS                Avg  Bands")

    no_data = True

    for area in _MASVS_AREAS:
        entry = _find_area_entry(rows, area)

        if entry is None:
            print(f"{area.title():<9}  0     0     0     0     NO DATA —                        —    —")
            continue

        high = _safe_int(entry.get("high"))
        medium = _safe_int(entry.get("medium"))
        low = _safe_int(entry.get("low"))
        info = _safe_int(entry.get("info"))
        status = _masvs_status(entry)

        if status != "NO DATA":
            no_data = False

        worst_display, avg_display, band_display = _format_cvss_fields(entry)

        print(
            f"{area.title():<9}  {high:<5} {medium:<5} {low:<5} {info:<6}"
            f"{status:<6} {worst_display:<24} {avg_display:<4} {band_display}"
        )

    if no_data:
        print(status_messages.status("DB MASVS Summary has no data for this run.", level="warn"))


def _load_masvs_summary() -> tuple[str, object, str | None, list[Mapping[str, object]]] | None:
    """Load the latest MASVS summary from persisted DB rows."""
    from scytaledroid.Utils.System import output_prefs

    ctx = output_prefs.get_run_context()

    if ctx and not ctx.persistence_ready:
        print()
        print(
            status_messages.status(
                "DB MASVS Summary unavailable (persistence gate failed).",
                level="warn",
            )
        )
        return None

    summary: tuple[object, object] | None = None
    summary_label = "run_id"
    summary_hint: str | None = None
    session_stamp = ctx.session_stamp if ctx and ctx.session_stamp else None

    if session_stamp:
        static_ids = resolve_static_run_ids(session_stamp)
        if static_ids:
            summary = fetch_db_masvs_summary_static_many(static_ids)
            summary_label = "latest_static_run_id"
            summary_hint = f"aggregated_runs={len(static_ids)}"

    if summary is None:
        summary = fetch_db_masvs_summary()

    if not summary:
        return None

    run_id, raw_rows = summary
    rows = _normalize_rows(raw_rows)

    return summary_label, run_id, summary_hint, rows


def render_db_masvs_summary() -> None:
    """Render compact or verbose MASVS summary from persisted DB rows."""
    try:
        summary = _load_masvs_summary()
        if summary is None:
            return

        summary_label, run_id, summary_hint, rows = summary

        if compact_success_output_enabled():
            _render_compact_masvs(rows)
            return

        _render_verbose_masvs(
            summary_label=summary_label,
            run_id=run_id,
            summary_hint=summary_hint,
            rows=rows,
        )

    except Exception:
        pass