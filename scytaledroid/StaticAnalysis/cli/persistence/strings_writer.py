"""Helpers for persisting static string analysis artifacts."""

from __future__ import annotations

from typing import Mapping, MutableMapping

from scytaledroid.Database.db_func.static_analysis import string_analysis as _sa
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .utils import require_canonical_schema
_STRING_COUNT_KEYS: tuple[str, ...] = (
    "endpoints",
    "http_cleartext",
    "api_keys",
    "analytics_ids",
    "cloud_refs",
    "ipc",
    "uris",
    "flags",
    "certs",
    "high_entropy",
    "placeholders_downgraded",
    "placeholders_suppressed",
    "doc_hosts_suppressed",
    "doc_cdns_suppressed",
    "trailing_punct_trimmed",
    "ws_wss_seen",
    "ipv6_seen",
)


def normalise_string_counts(raw: object) -> MutableMapping[str, int]:
    """Coerce incoming payload counts into an int mapping."""

    source = raw if isinstance(raw, Mapping) else {}
    return {
        key: int(source.get(key, 0) or 0)
        for key in _STRING_COUNT_KEYS
    }


def persist_string_summary(
    *,
    package_name: str,
    session_stamp: str,
    scope_label: str,
    counts: Mapping[str, int],
    samples: Mapping[str, object],
    run_id: int | None,
    static_run_id: int | None = None,
) -> list[str]:
    errors: list[str] = []
    try:
        require_canonical_schema()
        if not _sa.ensure_tables():
            raise RuntimeError("static_string tables unavailable")
        if static_run_id is None:
            raise RuntimeError(
                "static_run_id missing for string persistence; "
                "run migrations or regenerate static outputs."
            )
        summary_record = _sa.StringSummaryRecord(
            package_name=package_name,
            session_stamp=session_stamp,
            scope_label=scope_label,
            run_id=run_id,
            static_run_id=static_run_id,
            counts=counts,
        )
        summary_id = _sa.upsert_summary(summary_record)
        if summary_id is None:
            raise RuntimeError(
                f"upsert_summary returned None "
                f"(package={package_name}, session={session_stamp}, scope={scope_label}, "
                f"run_id={run_id}, static_run_id={static_run_id})"
            )
        _sa.replace_top_samples(
            summary_id,
            samples,
            top_n=3,
            static_run_id=static_run_id,
        )
    except Exception as exc:  # pragma: no cover - defensive
        message = (
            f"Failed to persist string analysis summary for {package_name}: {exc}"
        )
        log.warning(message, category="static_analysis")
        log.error(
            "String persistence failure",
            category="db",
            extra={
                "package": package_name,
                "run_id": run_id,
                "static_run_id": static_run_id,
                "counts_keys": list(counts.keys()),
                "exception": str(exc),
            },
        )
        errors.append(message)
    return errors


__all__ = ["normalise_string_counts", "persist_string_summary"]
