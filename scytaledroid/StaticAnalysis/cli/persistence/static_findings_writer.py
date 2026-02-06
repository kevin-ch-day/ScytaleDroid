"""Helpers for persisting baseline static findings details."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence

from scytaledroid.Database.db_func.static_analysis import static_findings as _sf
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .utils import require_canonical_schema


def coerce_severity_counts(totals: Mapping[str, int]) -> MutableMapping[str, int]:
    """Normalise severity counters coming from CLI payloads."""

    def _value(*keys: str) -> int:
        for key in keys:
            value = totals.get(key)
            if value is None:
                continue
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
        return 0

    return {
        "High": _value("High", "H"),
        "Medium": _value("Medium", "Med", "M"),
        "Low": _value("Low", "L"),
        "Info": _value("Info", "Information", "I"),
    }


def persist_static_findings(
    *,
    package_name: str,
    session_stamp: str,
    scope_label: str,
    severity_counts: Mapping[str, int],
    details: Mapping[str, object],
    findings: Sequence[object] | None,
    static_run_id: int | None = None,
) -> list[str]:
    errors: list[str] = []
    try:
        require_canonical_schema()
        if not _sf.ensure_tables():
            raise RuntimeError("static_findings tables unavailable (schema outdated; run migrations)")
        if static_run_id is None:
            raise RuntimeError("static_run_id missing; run migrations")
        summary_id = _sf.upsert_summary(
            package_name=package_name,
            session_stamp=session_stamp,
            scope_label=scope_label,
            severity_counts=severity_counts,
            details=details,
            run_id=None,
            static_run_id=static_run_id,
        )
        if summary_id is None:
            raise RuntimeError("static findings summary write failed (schema mismatch; run migrations)")
        if findings:
            _sf.replace_findings(
                summary_id, tuple(findings), run_id=None, static_run_id=static_run_id
            )
    except Exception as exc:  # pragma: no cover - defensive
        message = f"Failed to persist static findings summary for {package_name}: {exc}"
        log.warning(message, category="static_analysis")
        errors.append(message)
    return errors


__all__ = ["coerce_severity_counts", "persist_static_findings"]
