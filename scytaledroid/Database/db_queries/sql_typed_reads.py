"""Shared SQL expressions for typed-read cutovers with legacy fallback."""

from __future__ import annotations


def resolved_dynamic_session_static_run_id(alias: str = "ds") -> str:
    """Return a typed-preferred static run id expression for ``dynamic_sessions``."""

    return (
        f"COALESCE("
        f"{alias}.static_run_id_u, "
        f"CASE "
        f"WHEN {alias}.static_run_id IS NOT NULL AND {alias}.static_run_id >= 0 "
        f"THEN CAST({alias}.static_run_id AS UNSIGNED) "
        f"ELSE NULL "
        f"END"
        f")"
    )


def resolved_static_run_started_at_utc(alias: str = "sar") -> str:
    """Return a typed-preferred DATETIME expression for ``static_analysis_runs``."""

    legacy_parse = (
        f"COALESCE("
        f"STR_TO_DATE(REPLACE(REPLACE({alias}.run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s.%f'), "
        f"STR_TO_DATE(REPLACE(REPLACE({alias}.run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s')"
        f")"
    )
    return f"COALESCE({alias}.run_started_at_utc, {legacy_parse})"


def resolved_static_run_started_utc_text(alias: str = "sar") -> str:
    """Return a text/legacy-compatible UTC timestamp projection for views."""

    normalized = resolved_static_run_started_at_utc(alias)
    return f"COALESCE(DATE_FORMAT({normalized}, '%Y-%m-%d %H:%i:%s'), {alias}.run_started_utc)"


__all__ = [
    "resolved_dynamic_session_static_run_id",
    "resolved_static_run_started_at_utc",
    "resolved_static_run_started_utc_text",
]
