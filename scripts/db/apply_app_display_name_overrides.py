#!/usr/bin/env python3
"""Apply curated apps.display_name values from a CSV (catalog hygiene).

Dry-run by default; pass --apply to commit. Never fills from device_inventory.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_CSV = _REPO_ROOT / "data" / "reference" / "app_display_name_overrides.csv"


_APPS_DISPLAY_NAME_MAX_LEN = 255


def _load_rows(path: Path) -> list[tuple[str, str, str, str]]:
    """Load CSV rows; duplicate package_name (case-insensitive) uses last row in file."""
    by_lower: dict[str, tuple[str, str, str, str]] = {}
    if not path.is_file():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "package_name" not in reader.fieldnames:
            return []
        for row in reader:
            pkg = str(row.get("package_name") or "").strip()
            if not pkg:
                continue
            key = pkg.lower()
            disp = str(row.get("display_name") or "").strip()
            src = str(row.get("source") or "").strip()
            notes = str(row.get("notes") or "").strip()
            by_lower[key] = (pkg, disp, src, notes)
    return sorted(by_lower.values(), key=lambda t: t[0].lower())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Apply package_name -> display_name overrides into apps (dry-run unless --apply).",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=_DEFAULT_CSV,
        metavar="PATH",
        dest="csv_path",
        help=f"CSV with columns package_name,display_name,source,notes (default: {_DEFAULT_CSV}).",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Perform writes (default is dry-run only).",
    )
    args = parser.parse_args()

    try:
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_core.db_engine import DatabaseError
        from scytaledroid.Database.db_core.session import database_session
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    run_sql = core_q.run_sql
    run_sql_rowcount = core_q.run_sql_rowcount
    path = Path(args.csv_path)
    if not path.is_file():
        sys.stderr.write(f"CSV not found (not a file): {path}\n")
        return 1
    loaded = _load_rows(path)
    if not loaded:
        sys.stderr.write(
            f"No data rows in CSV (need header package_name,display_name,...): {path}\n"
        )
        return 1

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"Mode: {mode}")
    print(f"CSV : {path}")
    print()

    def process(with_writes: bool) -> tuple[int, int, int, Counter[str]]:
        """Returns (rows_updated_or_zero, skipped, would_change, skip_reason_counts)."""

        updated = 0
        skipped = 0
        would_change = 0
        skip_reasons: Counter[str] = Counter()
        for package_name, display_name, source, notes in loaded:
            if not display_name:
                print(
                    f"SKIP {package_name!r} (empty_display_name_in_csv) "
                    f"source={source!r} notes={notes!r}"
                )
                skipped += 1
                skip_reasons["empty_display_name_in_csv"] += 1
                continue
            if display_name.lower() == package_name.lower():
                print(
                    f"SKIP {package_name!r} (display_name_equals_package_name) "
                    f"source={source!r} notes={notes!r}"
                )
                skipped += 1
                skip_reasons["display_name_equals_package_name"] += 1
                continue
            if len(display_name) > _APPS_DISPLAY_NAME_MAX_LEN:
                print(
                    f"SKIP {package_name!r} (display_name_too_long len={len(display_name)} "
                    f"max={_APPS_DISPLAY_NAME_MAX_LEN}) source={source!r}"
                )
                skipped += 1
                skip_reasons["display_name_too_long"] += 1
                continue

            before = run_sql(
                "SELECT id, package_name, display_name FROM apps WHERE LOWER(package_name) = LOWER(%s)",
                (package_name,),
                fetch="one_dict",
            )
            if before is None:
                print(
                    f"SKIP {package_name!r} (no_apps_row) wanted={display_name!r} "
                    f"source={source!r} notes={notes!r}"
                )
                skipped += 1
                skip_reasons["no_apps_row"] += 1
                continue

            cur = before.get("display_name")
            if cur is not None and str(cur).strip() != "":
                print(
                    f"SKIP {package_name!r} (display_name_already_set) "
                    f"current={cur!r} wanted={display_name!r}"
                )
                skipped += 1
                skip_reasons["display_name_already_set"] += 1
                continue

            b_disp = before.get("display_name")
            print(
                f"ROW  {package_name!r}\n"
                f"     before display_name={b_disp!r}\n"
                f"     after  display_name={display_name!r} (source={source!r} notes={notes!r})"
            )
            would_change += 1

            if with_writes:
                n = run_sql_rowcount(
                    """
                    UPDATE apps
                    SET display_name = %s, updated_at = CURRENT_TIMESTAMP
                    WHERE LOWER(package_name) = LOWER(%s)
                      AND (display_name IS NULL OR TRIM(display_name) = '')
                    """,
                    (display_name, package_name),
                    query_name="apply_app_display_name_overrides.update",
                )
                if n != 1:
                    print(f"     WARN: expected 1 row updated, got {n}")
                updated += int(n)
        return updated, skipped, would_change, skip_reasons

    def _format_skip_reasons(reasons: Counter[str]) -> str:
        if not reasons:
            return "(none)"
        parts = [f"{k}={reasons[k]}" for k in sorted(reasons)]
        return ", ".join(parts)

    try:
        if not args.apply:
            with database_session():
                _u, skipped, would_change, skip_reasons = process(False)
            print()
            print(
                "Summary: "
                f"csv_packages={len(loaded)} "
                f"would_change_apps.display_name={would_change} "
                f"skipped={skipped} "
                f"by_reason {{{_format_skip_reasons(skip_reasons)}}}"
            )
            print("Dry-run complete. Re-run with --apply to write changes inside a transaction.")
            return 0

        with database_session() as db:
            with db.transaction():
                updated, skipped, would_change, skip_reasons = process(True)
    except DatabaseError as exc:
        sys.stderr.write(f"Database error: {exc}\n")
        return 2
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:  # noqa: BLE001 — operator-facing boundary
        sys.stderr.write(f"Apply failed: {exc}\n")
        return 2

    print()
    print(
        f"Done. rows_updated={updated} rows_skipped={skipped} "
        f"candidates={would_change} by_reason {{{_format_skip_reasons(skip_reasons)}}}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
