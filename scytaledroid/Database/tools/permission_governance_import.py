"""Import Erebus-style permission governance snapshots from CSV."""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
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

_NAMESPACE_TYPE_MAP = {
    "framework": "AOSP",
    "aosp": "AOSP",
    "google": "GMS",
    "gms": "GMS",
    "oem": "OEM",
    "app": "APP_DEFINED",
    "app_defined": "APP_DEFINED",
    "custom": "APP_DEFINED",
    "third_party_sdk": "THIRD_PARTY_SDK",
    "sdk": "THIRD_PARTY_SDK",
}

_RISK_CLASS_MAP = {
    "high": "A",
    "medium": "B",
    "low": "C",
    "unknown": "U",
    "unreviewed": "U",
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


def _fallback_version() -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    return f"erebus_gov_v0_{stamp}_01"


def _summarize_rows(rows: Iterable[Mapping[str, object]]) -> dict[str, object]:
    total = 0
    unique_permissions: set[str] = set()
    duplicates = 0
    missing_required = {key: 0 for key in REQUIRED_COLUMNS}
    namespace_counts: dict[str, int] = {}
    triage_counts: dict[str, int] = {}
    for row in rows:
        total += 1
        perm = str(row.get("permission_string") or "").strip()
        if perm:
            if perm in unique_permissions:
                duplicates += 1
            unique_permissions.add(perm)
        for key in REQUIRED_COLUMNS:
            if not str(row.get(key) or "").strip():
                missing_required[key] += 1
        namespace = _normalize_namespace_type(row.get("namespace_type")) or "<missing>"
        triage = str(row.get("triage_status") or "").strip().lower() or "<missing>"
        namespace_counts[namespace] = namespace_counts.get(namespace, 0) + 1
        triage_counts[triage] = triage_counts.get(triage, 0) + 1
    return {
        "total": total,
        "unique_permissions": len(unique_permissions),
        "duplicates": duplicates,
        "missing_required": missing_required,
        "namespace_counts": dict(sorted(namespace_counts.items())),
        "triage_counts": dict(sorted(triage_counts.items())),
    }


def _normalize_namespace_type(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    key = text.lower()
    if key in _NAMESPACE_TYPE_MAP:
        return _NAMESPACE_TYPE_MAP[key]
    upper = text.upper()
    if upper in {"AOSP", "GMS", "OEM", "APP_DEFINED", "THIRD_PARTY_SDK", "UNKNOWN"}:
        return upper
    return "UNKNOWN"


def _normalize_risk_class(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return "U"
    key = text.lower()
    if key in _RISK_CLASS_MAP:
        return _RISK_CLASS_MAP[key]
    upper = text.upper()
    if upper in {"A", "B", "C", "U"}:
        return upper
    return "U"


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
            "namespace_type": _normalize_namespace_type(row.get("namespace_type")) or "UNKNOWN",
            "theme_primary": (row.get("theme_primary") or "").strip(),
            "theme_tags_json": row.get("theme_tags_json"),
            "risk_class": _normalize_risk_class(row.get("risk_class")),
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
    parser.add_argument("--version", required=False, help="Governance version (e.g., gov_v20260123.1)")
    parser.add_argument("--source", default="EREBUS", help="Optional snapshot source label")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate and summarize the CSV without writing to the database.",
    )
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

    summary = _summarize_rows(rows)
    if args.validate_only:
        print("Validation summary")
        print("------------------")
        print(f"Rows total        : {summary['total']}")
        print(f"Unique permissions: {summary['unique_permissions']}")
        print(f"Duplicates        : {summary['duplicates']}")
        print("Missing required fields (empty values)")
        for key, count in summary["missing_required"].items():
            print(f"  {key}: {count}")
        print("By namespace_type")
        for key, count in summary["namespace_counts"].items():
            print(f"  {key}: {count}")
        print("By triage_status")
        for key, count in summary["triage_counts"].items():
            print(f"  {key}: {count}")
        return 0

    version = args.version or _fallback_version()
    if not args.version:
        print(f"No --version provided. Using auto-generated version: {version}")

    snapshot_hash = _sha256(path)
    try:
        run_sql("START TRANSACTION")
        snapshot_id = _upsert_snapshot(version, snapshot_hash, args.source)
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

    print(f"Imported governance snapshot {snapshot_id}")
    print(f"Snapshot hash: {snapshot_hash}")
    print(f"Rows applied : {inserted}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
