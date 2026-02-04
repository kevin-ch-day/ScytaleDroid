"""Import Erebus-style permission governance snapshots from CSV."""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path

from scytaledroid.Database.db_core import run_sql
from scytaledroid.Utils.LoggingUtils import logging_utils as log

REQUIRED_COLUMNS = {
    "permission_string",
    "namespace_type",
    "theme_primary",
    "risk_class",
    "triage_status",
}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_datetime(value: str | None) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return text


def _load_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("CSV has no header row.")
        columns = {name.strip() for name in reader.fieldnames if name}
        missing = REQUIRED_COLUMNS - columns
        if missing:
            raise ValueError(f"CSV missing required columns: {', '.join(sorted(missing))}")
        return [dict(row) for row in reader]


def _upsert_snapshot(version: str, snapshot_hash: str, source: str | None) -> str:
    run_sql(
        """
        INSERT INTO permission_governance_snapshots (governance_version, snapshot_sha256, source_system)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE snapshot_sha256 = VALUES(snapshot_sha256), source_system = VALUES(source_system)
        """,
        (version, snapshot_hash, source or "EREBUS"),
    )
    return version


def _insert_entries(snapshot_id: str, rows: Iterable[Mapping[str, object]]) -> int:
    count = 0
    for row in rows:
        payload = {
            "governance_version": snapshot_id,
            "permission_string": (row.get("permission_string") or "").strip(),
            "namespace_type": (row.get("namespace_type") or "").strip(),
            "theme_primary": (row.get("theme_primary") or "").strip(),
            "theme_tags_json": row.get("theme_tags_json"),
            "risk_class": (row.get("risk_class") or "").strip(),
            "triage_status": (row.get("triage_status") or "UNREVIEWED").strip(),
            "last_reviewed_at_utc": _parse_datetime(row.get("last_reviewed_at_utc") or row.get("last_reviewed_at")),
            "reviewer_id": (row.get("reviewer_id") or "").strip() or None,
            "notes": row.get("notes"),
        }
        if not payload["permission_string"]:
            continue
        run_sql(
            """
            INSERT INTO permission_governance_snapshot_rows (
              governance_version,
              permission_string,
              namespace_type,
              theme_primary,
              theme_tags_json,
              risk_class,
              triage_status,
              last_reviewed_at_utc,
              reviewer_id,
              notes
            )
            VALUES (
              %(governance_version)s,
              %(permission_string)s,
              %(namespace_type)s,
              %(theme_primary)s,
              %(theme_tags_json)s,
              %(risk_class)s,
              %(triage_status)s,
              %(last_reviewed_at_utc)s,
              %(reviewer_id)s,
              %(notes)s
            )
            ON DUPLICATE KEY UPDATE
              namespace_type = VALUES(namespace_type),
              theme_primary = VALUES(theme_primary),
              theme_tags_json = VALUES(theme_tags_json),
              risk_class = VALUES(risk_class),
              triage_status = VALUES(triage_status),
              last_reviewed_at_utc = VALUES(last_reviewed_at_utc),
              reviewer_id = VALUES(reviewer_id),
              notes = VALUES(notes)
            """,
            payload,
        )
        count += 1
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import permission governance snapshot CSV.")
    parser.add_argument("csv_path", help="Path to permission_governance_snapshot.csv")
    parser.add_argument("--version", required=True, help="Governance version (e.g., gov_v20260123.1)")
    parser.add_argument("--source", default="EREBUS", help="Optional snapshot source label")
    args = parser.parse_args(argv)

    path = Path(args.csv_path)
    if not path.exists():
        print(f"CSV not found: {path}")
        return 2

    try:
        rows = _load_rows(path)
    except Exception as exc:
        print(f"Failed to read CSV: {exc}")
        return 2

    snapshot_hash = _sha256(path)
    try:
        run_sql("START TRANSACTION")
        snapshot_id = _upsert_snapshot(args.version, snapshot_hash, args.source)
        inserted = _insert_entries(snapshot_id, rows)
        run_sql("COMMIT")
    except Exception as exc:
        try:
            run_sql("ROLLBACK")
        except Exception:
            pass
        log.warning(f"Governance import failed: {exc}", category="database")
        print(f"Import failed: {exc}")
        return 1

    print(f"Imported governance snapshot {args.version}")
    print(f"Snapshot hash: {snapshot_hash}")
    print(f"Rows applied : {inserted}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
