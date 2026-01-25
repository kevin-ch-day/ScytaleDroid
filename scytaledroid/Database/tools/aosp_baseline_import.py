"""Import AOSP permission baseline entries from CSV."""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from datetime import datetime
from pathlib import Path

from scytaledroid.Database.db_core import run_sql
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_permissions(path: Path) -> list[str]:
    with path.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "permission_string" not in reader.fieldnames:
            raise ValueError("CSV must include permission_string column.")
        perms = []
        for row in reader:
            value = (row.get("permission_string") or "").strip()
            if value:
                perms.append(value)
        return perms


def _insert_entries(
    android_release: str,
    source_type: str,
    baseline_hash: str,
    generated_at: str,
    permissions: list[str],
) -> int:
    raise RuntimeError(
        "AOSP baseline import is deprecated. "
        "Use android_permission_dict_aosp as the sole AOSP source of truth."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import AOSP permission baseline CSV.")
    parser.add_argument("csv_path", help="CSV containing permission_string column")
    parser.add_argument("--android-release", required=True, help="Android release (e.g., 15)")
    parser.add_argument("--source-type", default="aosp_manifest", help="Baseline source type")
    parser.add_argument("--generated-at", default=None, help="Generation timestamp (ISO8601)")
    args = parser.parse_args(argv)

    path = Path(args.csv_path)
    if not path.exists():
        print(f"CSV not found: {path}")
        return 2

    try:
        permissions = _load_permissions(path)
    except Exception as exc:
        print(f"Failed to read CSV: {exc}")
        return 2

    baseline_hash = _sha256(path)
    generated_at = args.generated_at or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    try:
        _insert_entries(args.android_release, args.source_type, baseline_hash, generated_at, permissions)
    except Exception as exc:
        log.warning(f"AOSP baseline import blocked: {exc}", category="database")
        print(f"Import blocked: {exc}")
        return 2

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
