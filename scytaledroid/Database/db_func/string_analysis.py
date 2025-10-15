"""DB helpers for static string analysis persistence."""

from __future__ import annotations

from typing import Mapping, Sequence

from ..db_core import run_sql
from ..db_queries import string_analysis as queries


def ensure_tables() -> bool:
    try:
        run_sql(queries.CREATE_STRING_SUMMARY)
        run_sql(queries.CREATE_STRING_SAMPLES)
        return True
    except Exception:
        return False


def tables_exist() -> bool:
    try:
        row1 = run_sql(queries.TABLE_EXISTS_SUMMARY, fetch="one")
        row2 = run_sql(queries.TABLE_EXISTS_SAMPLES, fetch="one")
        return bool(row1 and int(row1[0]) > 0 and row2 and int(row2[0]) > 0)
    except Exception:
        return False


def upsert_summary(
    *,
    package_name: str,
    session_stamp: str,
    scope_label: str,
    counts: Mapping[str, int],
) -> int | None:
    payload = {
        "package_name": package_name,
        "session_stamp": session_stamp,
        "scope_label": scope_label,
        "endpoints": int(counts.get("endpoints", 0)),
        "http_cleartext": int(counts.get("http_cleartext", 0)),
        "api_keys": int(counts.get("api_keys", 0)),
        "analytics_ids": int(counts.get("analytics_ids", 0)),
        "cloud_refs": int(counts.get("cloud_refs", 0)),
        "ipc": int(counts.get("ipc", 0)),
        "uris": int(counts.get("uris", 0)),
        "flags": int(counts.get("flags", 0)),
        "certs": int(counts.get("certs", 0)),
        "high_entropy": int(counts.get("high_entropy", 0)),
    }
    try:
        run_sql(queries.INSERT_STRING_SUMMARY, payload)
        row = run_sql(
            queries.SELECT_SUMMARY_ID,
            (package_name, session_stamp, scope_label),
            fetch="one",
        )
        return int(row[0]) if row else None
    except Exception:
        return None


def replace_top_samples(
    summary_id: int,
    samples: Mapping[str, Sequence[Mapping[str, object]]],
    *,
    top_n: int = 3,
) -> tuple[int, int]:
    """Replace samples for summary_id with top N per bucket.

    Returns (deleted, inserted).
    """
    deleted = 0
    inserted = 0
    try:
        # Clear previous
        run_sql(queries.DELETE_SAMPLES_FOR_SUMMARY, (summary_id,))
        deleted = 1  # semantic marker (not actual count)
    except Exception:
        pass
    try:
        rank = 1
        for bucket, entries in samples.items():
            if not entries:
                continue
            for sample in list(entries)[: int(top_n)]:
                value_masked = sample.get("value_masked") or sample.get("value")
                src = sample.get("src")
                tag = sample.get("tag")
                run_sql(
                    queries.INSERT_SAMPLE,
                    (summary_id, bucket, str(value_masked)[:512], str(src)[:512], (str(tag) if tag is not None else None)[:64] if tag else None, rank),
                )
                inserted += 1
                rank += 1
    except Exception:
        pass
    return deleted, inserted


__all__ = [
    "ensure_tables",
    "tables_exist",
    "upsert_summary",
    "replace_top_samples",
]

