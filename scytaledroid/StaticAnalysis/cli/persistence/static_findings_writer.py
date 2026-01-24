"""Helpers for persisting baseline static findings details."""

from __future__ import annotations

from typing import Mapping, MutableMapping, Sequence

from scytaledroid.Database.db_func.static_analysis import static_findings as _sf
from scytaledroid.Utils.LoggingUtils import logging_utils as log


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
    run_id: int | None,
    static_run_id: int | None = None,
) -> list[str]:
    errors: list[str] = []
    try:
        if not _sf.ensure_tables():
            raise RuntimeError("static_findings tables unavailable")
        # static_findings_summary.run_id points to static_analysis_runs.id,
        # so only use legacy runs.run_id when no static_run_id is available.
        effective_run_id = None if static_run_id is not None else run_id
        summary_id = _sf.upsert_summary(
            package_name=package_name,
            session_stamp=session_stamp,
            scope_label=scope_label,
            severity_counts=severity_counts,
            details=details,
            run_id=effective_run_id,
            static_run_id=static_run_id,
        )
        if summary_id is None:
            # Fallback for legacy schemas without run_id linkage.
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
            # Last-chance lookup in case the row was inserted but not returned due to schema quirks.
            summary_id = _sf.lookup_summary_id(
                package_name=package_name,
                session_stamp=session_stamp,
                scope_label=scope_label,
                run_id=effective_run_id,
                static_run_id=static_run_id,
            )
        if summary_id is None:
            message = (
                "upsert_summary returned None (static findings summary may already exist under legacy schema)"
            )
            log.warning(message, category="static_analysis")
            log.warning(
                (
                    f"static findings summary unresolved "
                    f"(package={package_name} session={session_stamp} scope={scope_label} "
                    f"run_id={effective_run_id} static_run_id={static_run_id})"
                ),
                category="db",
            )
        else:
            if findings:
                _sf.replace_findings(
                    summary_id, tuple(findings), run_id=effective_run_id, static_run_id=static_run_id
                )
    except Exception as exc:  # pragma: no cover - defensive
        message = f"Failed to persist static findings summary for {package_name}: {exc}"
        log.warning(message, category="static_analysis")
        errors.append(message)
    return errors


__all__ = ["coerce_severity_counts", "persist_static_findings"]
