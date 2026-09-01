"""Helpers for repo-owned external SDK / tracker reference intel."""

from __future__ import annotations

import csv
import hashlib
import json
from collections.abc import Callable, Mapping
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from scytaledroid.Database.db_queries.canonical.schema import CREATE_EXTERNAL_SDK_TRACKER_INTEL

RunSql = Callable[..., Any]

EXODUS_TRACKERS_URL = "https://reports.exodus-privacy.eu.org/api/trackers"
EXODUS_SOURCE_KEY = "exodus_privacy"
EXODUS_SOURCE_TERMS_NOTE = (
    "Exodus Privacy API database results: ODbL 1.0; individual contents: "
    "DbCL 1.0. Retain attribution and refresh conservatively."
)
EXODUS_DATABASE_LICENSE_URL = "https://opendatacommons.org/licenses/odbl/1-0/"
EXODUS_CONTENTS_LICENSE_URL = "https://opendatacommons.org/licenses/dbcl/1-0/"


def _canonical_json_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def tracker_rows_content_sha256(rows: list[Mapping[str, Any]]) -> str:
    """Hash normalized tracker content independent of retrieval timestamp/date."""

    volatile = {"fetched_at_utc", "snapshot_date"}
    stable_rows = [
        {key: value for key, value in sorted(row.items()) if key not in volatile}
        for row in rows
    ]
    return _canonical_json_sha256(stable_rows)


def load_verified_refresh_receipt(
    path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load a frozen receipt and verify its declared normalized hashes."""

    raw = path.read_bytes()
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("tracker receipt must be a JSON object")
    rows_raw = payload.get("rows")
    summary_raw = payload.get("summary")
    if not isinstance(rows_raw, list) or not rows_raw:
        raise ValueError("tracker receipt contains no rows")
    if not isinstance(summary_raw, Mapping):
        raise ValueError("tracker receipt summary is missing")
    rows = [dict(row) for row in rows_raw if isinstance(row, Mapping)]
    if len(rows) != len(rows_raw):
        raise ValueError("tracker receipt contains non-object rows")

    calculated_content = tracker_rows_content_sha256(rows)
    calculated_snapshot = _canonical_json_sha256(rows)
    declared_content = str(summary_raw.get("normalized_content_sha256") or "")
    declared_snapshot = str(summary_raw.get("normalized_snapshot_sha256") or "")
    if declared_content and declared_content != calculated_content:
        raise ValueError("tracker receipt normalized-content hash mismatch")
    if declared_snapshot and declared_snapshot != calculated_snapshot:
        raise ValueError("tracker receipt normalized-snapshot hash mismatch")

    provenance = {
        "source_receipt_path": str(path.resolve()),
        "source_receipt_file_sha256": hashlib.sha256(raw).hexdigest(),
        "source_payload_canonical_sha256": summary_raw.get(
            "source_payload_canonical_sha256"
        ),
        "normalized_content_sha256": calculated_content,
        "normalized_snapshot_sha256": calculated_snapshot,
        "source_snapshot_date": summary_raw.get("snapshot_date"),
        "source_url": summary_raw.get("source_url"),
    }
    return rows, provenance


def fetch_exodus_trackers(url: str = EXODUS_TRACKERS_URL, *, timeout: int = 30) -> dict[str, Any]:
    """Fetch the current Exodus tracker dictionary."""

    request = Request(
        url,
        headers={
            "User-Agent": "ScytaleDroid external-sdk-tracker-intel/1.0",
            "Accept": "application/json",
        },
    )
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed HTTPS source
        return json.load(response)


def _clean_text(value: object, *, max_len: int | None = None) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    if max_len is not None:
        return text[:max_len]
    return text


def _clean_json_array(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = _clean_text(item)
        if not text:
            continue
        key = text.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(text)
    return out


def _parse_iso_date(value: object) -> str | None:
    text = _clean_text(value, max_len=32)
    if not text:
        return None
    try:
        return date.fromisoformat(text).isoformat()
    except ValueError:
        return None


def normalize_exodus_trackers(
    payload: Mapping[str, object],
    *,
    fetched_at_utc: datetime | None = None,
    snapshot_date: date | None = None,
    source_url: str = EXODUS_TRACKERS_URL,
) -> list[dict[str, Any]]:
    """Normalize the Exodus `/api/trackers` payload into DB-ready rows."""

    fetched_at = fetched_at_utc or datetime.now(UTC)
    snap = snapshot_date or fetched_at.date()
    tracker_map = payload.get("trackers")
    if not isinstance(tracker_map, Mapping):
        return []

    rows: list[dict[str, Any]] = []
    for tracker_id_raw, tracker_payload in sorted(tracker_map.items(), key=lambda item: str(item[0])):
        if not isinstance(tracker_payload, Mapping):
            continue
        tracker_id = _clean_text(tracker_payload.get("id") or tracker_id_raw, max_len=64)
        tracker_name = _clean_text(tracker_payload.get("name"), max_len=191)
        if not tracker_id or not tracker_name:
            continue
        categories = _clean_json_array(tracker_payload.get("categories"))
        documentation = _clean_json_array(tracker_payload.get("documentation"))
        rows.append(
            {
                "intel_source": EXODUS_SOURCE_KEY,
                "tracker_id_external": tracker_id,
                "tracker_name": tracker_name,
                "code_signature": _clean_text(tracker_payload.get("code_signature"), max_len=255),
                "network_signature": _clean_text(tracker_payload.get("network_signature")),
                "website": _clean_text(tracker_payload.get("website")),
                "description": _clean_text(tracker_payload.get("description")),
                "categories_json": json.dumps(categories, ensure_ascii=True, sort_keys=False),
                "documentation_json": json.dumps(documentation, ensure_ascii=True, sort_keys=False),
                "creation_date": _parse_iso_date(tracker_payload.get("creation_date")),
                "snapshot_date": snap.isoformat(),
                "source_url": source_url,
                "source_terms_note": EXODUS_SOURCE_TERMS_NOTE,
                "fetched_at_utc": fetched_at.replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S"),
                "is_active": 1,
            }
        )
    return rows


def ensure_external_tracker_intel_schema(run_sql: RunSql) -> None:
    """Create the repo-owned external tracker intel table if needed."""

    run_sql(
        CREATE_EXTERNAL_SDK_TRACKER_INTEL,
        (),
        query_name="external_sdk_tracker_intel.ensure_schema",
    )


def load_external_tracker_snapshot_counts(run_sql: RunSql, *, snapshot_date: str) -> dict[str, int]:
    row = run_sql(
        """
        SELECT
          COUNT(*) AS total_rows,
          COUNT(DISTINCT tracker_id_external) AS distinct_trackers
        FROM external_sdk_tracker_intel
        WHERE snapshot_date = %s
          AND intel_source = %s
        """,
        (snapshot_date, EXODUS_SOURCE_KEY),
        fetch="one",
        dictionary=True,
        query_name="external_sdk_tracker_intel.snapshot_counts",
    ) or {}
    if not isinstance(row, Mapping):
        return {"total_rows": 0, "distinct_trackers": 0}
    return {
        "total_rows": int(row.get("total_rows") or 0),
        "distinct_trackers": int(row.get("distinct_trackers") or 0),
    }


def upsert_external_tracker_rows(run_sql: RunSql, rows: list[Mapping[str, Any]]) -> int:
    """Upsert normalized rows into the external tracker intel table."""

    sql = """
        INSERT INTO external_sdk_tracker_intel (
          intel_source,
          tracker_id_external,
          tracker_name,
          code_signature,
          network_signature,
          website,
          description,
          categories_json,
          documentation_json,
          creation_date,
          snapshot_date,
          source_url,
          source_terms_note,
          fetched_at_utc,
          is_active
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
          tracker_name = VALUES(tracker_name),
          code_signature = VALUES(code_signature),
          network_signature = VALUES(network_signature),
          website = VALUES(website),
          description = VALUES(description),
          categories_json = VALUES(categories_json),
          documentation_json = VALUES(documentation_json),
          creation_date = VALUES(creation_date),
          source_url = VALUES(source_url),
          source_terms_note = VALUES(source_terms_note),
          fetched_at_utc = VALUES(fetched_at_utc),
          is_active = VALUES(is_active)
    """
    writes = 0
    for row in rows:
        run_sql(
            sql,
            (
                row.get("intel_source"),
                row.get("tracker_id_external"),
                row.get("tracker_name"),
                row.get("code_signature"),
                row.get("network_signature"),
                row.get("website"),
                row.get("description"),
                row.get("categories_json"),
                row.get("documentation_json"),
                row.get("creation_date"),
                row.get("snapshot_date"),
                row.get("source_url"),
                row.get("source_terms_note"),
                row.get("fetched_at_utc"),
                int(row.get("is_active") or 0),
            ),
            query_name="external_sdk_tracker_intel.upsert",
        )
        writes += 1
    return writes


def build_refresh_summary(
    *,
    rows: list[Mapping[str, Any]],
    snapshot_before: Mapping[str, int] | None,
    snapshot_after: Mapping[str, int] | None,
    applied: bool,
    source_url: str = EXODUS_TRACKERS_URL,
    source_payload: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    categories: dict[str, int] = {}
    website_populated = 0
    code_signature_populated = 0
    network_signature_populated = 0
    for row in rows:
        try:
            cats = json.loads(str(row.get("categories_json") or "[]"))
        except json.JSONDecodeError:
            cats = []
        if isinstance(cats, list):
            for cat in cats:
                text = _clean_text(cat)
                if text:
                    categories[text] = categories.get(text, 0) + 1
        if row.get("website"):
            website_populated += 1
        if row.get("code_signature"):
            code_signature_populated += 1
        if row.get("network_signature"):
            network_signature_populated += 1
    top_categories = [
        {"category": key, "row_count": value}
        for key, value in sorted(categories.items(), key=lambda item: (-item[1], item[0]))[:15]
    ]
    snapshot_date = str(rows[0].get("snapshot_date")) if rows else None
    before_total = int((snapshot_before or {}).get("total_rows") or 0)
    after_total = int((snapshot_after or {}).get("total_rows") or 0)
    return {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "intel_source": EXODUS_SOURCE_KEY,
        "source_url": source_url,
        "snapshot_date": snapshot_date,
        "applied": bool(applied),
        "row_count": len(rows),
        "snapshot_rows_before": before_total,
        "snapshot_rows_after": after_total,
        "snapshot_new_rows_estimate": max(after_total - before_total, 0),
        "distinct_tracker_ids": len({str(row.get("tracker_id_external") or "") for row in rows if row.get("tracker_id_external")}),
        "rows_with_code_signature": code_signature_populated,
        "rows_with_network_signature": network_signature_populated,
        "rows_with_website": website_populated,
        "top_categories": top_categories,
        "source_terms_note": EXODUS_SOURCE_TERMS_NOTE,
        "source_database_license": EXODUS_DATABASE_LICENSE_URL,
        "source_contents_license": EXODUS_CONTENTS_LICENSE_URL,
        "snapshot_date_semantics": "UTC retrieval date, not an upstream release/version date",
        "source_payload_canonical_sha256": (
            _canonical_json_sha256(source_payload)
            if source_payload is not None
            else None
        ),
        "normalized_content_sha256": tracker_rows_content_sha256(rows),
        "normalized_snapshot_sha256": _canonical_json_sha256(rows),
        "fetched_at_utc": rows[0].get("fetched_at_utc") if rows else None,
        "no_db_writes": not applied,
    }


def write_refresh_receipt_bundle(
    *,
    summary: Mapping[str, Any],
    rows: list[Mapping[str, Any]],
    output_dir: Path,
    stem: str,
) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / f"{stem}.json"
    csv_path = output_dir / f"{stem}.csv"
    txt_path = output_dir / f"{stem}.txt"

    json_payload = {"summary": dict(summary), "rows": [dict(row) for row in rows]}
    json_path.write_text(json.dumps(json_payload, indent=2, sort_keys=True), encoding="utf-8")

    fieldnames = [
        "intel_source",
        "tracker_id_external",
        "tracker_name",
        "code_signature",
        "network_signature",
        "website",
        "creation_date",
        "snapshot_date",
        "source_url",
        "is_active",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fieldnames})

    lines = [
        "# external sdk tracker intel refresh",
        f"generated_at: {summary.get('generated_at')}",
        f"source: {summary.get('intel_source')}",
        f"snapshot_date: {summary.get('snapshot_date')}",
        f"applied: {summary.get('applied')}",
        f"row_count: {summary.get('row_count')}",
        f"rows_with_code_signature: {summary.get('rows_with_code_signature')}",
        f"rows_with_network_signature: {summary.get('rows_with_network_signature')}",
        f"rows_with_website: {summary.get('rows_with_website')}",
        f"source_url: {summary.get('source_url')}",
    ]
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return {
        "json": str(json_path),
        "csv": str(csv_path),
        "txt": str(txt_path),
    }


__all__ = [
    "EXODUS_SOURCE_KEY",
    "EXODUS_SOURCE_TERMS_NOTE",
    "EXODUS_TRACKERS_URL",
    "EXODUS_DATABASE_LICENSE_URL",
    "EXODUS_CONTENTS_LICENSE_URL",
    "build_refresh_summary",
    "ensure_external_tracker_intel_schema",
    "fetch_exodus_trackers",
    "load_external_tracker_snapshot_counts",
    "load_verified_refresh_receipt",
    "normalize_exodus_trackers",
    "tracker_rows_content_sha256",
    "upsert_external_tracker_rows",
    "write_refresh_receipt_bundle",
]
