#!/usr/bin/env python3
"""Read-only report: apps.display_name gaps vs latest (or chosen) device inventory.

Catalog hygiene only — does not write the database or touch static analysis.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_OVERRIDES = _REPO_ROOT / "data" / "reference" / "app_display_name_overrides.csv"
_DEFAULT_LABEL_HINT_PACKAGES = ("com.block.juggle", "com.mobileapp.android.relia")


def _load_override_csv(path: Path) -> dict[str, tuple[str, str, str, str]]:
    """Map lower(package_name) -> (package_name, display_name, source, notes)."""

    by_lower: dict[str, tuple[str, str, str, str]] = {}
    if not path.is_file():
        return by_lower
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "package_name" not in reader.fieldnames:
            return by_lower
        for row in reader:
            pkg = str(row.get("package_name") or "").strip()
            if not pkg:
                continue
            disp = str(row.get("display_name") or "").strip()
            src = str(row.get("source") or "").strip()
            notes = str(row.get("notes") or "").strip()
            key = pkg.lower()
            # Last row wins so operators can append corrections without silent drops.
            by_lower[key] = (pkg, disp, src, notes)
    return by_lower


def _resolve_snapshot_id(run_sql, explicit: int | None) -> tuple[int | None, str]:
    if explicit is not None:
        row = run_sql(
            "SELECT snapshot_id FROM device_inventory_snapshots WHERE snapshot_id = %s",
            (explicit,),
            fetch="one",
        )
        if row is None:
            return None, f"snapshot_id {explicit} not found in device_inventory_snapshots"
        return int(row[0]), "OK"
    row = run_sql(
        "SELECT MAX(snapshot_id) FROM device_inventory_snapshots",
        fetch="one",
    )
    if row is None or row[0] is None:
        return None, "no rows in device_inventory_snapshots"
    return int(row[0]), "OK"


def _parse_label_hint_packages(raw: str | None) -> tuple[str, ...]:
    if raw is None or not str(raw).strip():
        return _DEFAULT_LABEL_HINT_PACKAGES
    seen: dict[str, None] = {}
    for part in str(raw).split(","):
        p = part.strip().lower()
        if p and p not in seen:
            seen[p] = None
    out = tuple(seen.keys())[:24]
    return out if out else _DEFAULT_LABEL_HINT_PACKAGES


def _format_fixed_table(
    title: str,
    underline: str,
    headers: tuple[str, ...],
    widths: tuple[int, ...],
    rows: list[tuple[str, ...]],
) -> None:
    print(title)
    print(underline)
    head = "  " + "  ".join(h[: w].ljust(w) for h, w in zip(headers, widths))
    print(head)
    print("  " + "  ".join("-" * w for w in widths))
    for row in rows:
        cells = []
        for value, w in zip(row, widths):
            cells.append(str(value)[:w].ljust(w))
        print("  " + "  ".join(cells))
    print()


def _emit_focus_detail_tables(
    focus_list: list[dict[str, object]],
    overrides: dict[str, tuple[str, str, str, str]],
) -> None:
    pending: list[dict[str, object]] = []
    queued: list[dict[str, object]] = []
    for r in focus_list:
        pkg = str(r.get("package_name") or "").strip()
        entry = overrides.get(pkg.lower())
        has_csv = bool(entry and entry[1].strip())
        if has_csv:
            queued.append(r)
        else:
            pending.append(r)

    if pending:
        rows_pt: list[tuple[str, ...]] = []
        for r in pending:
            pkg = str(r.get("package_name") or "").strip()
            ver = str(r.get("version_name") or "").strip() or "—"
            splits = str(int(r.get("split_count") or 0))
            repo = str(int(r.get("repo_row_count") or 0))
            rows_pt.append((pkg, ver, splits, repo))
        _format_fixed_table(
            "Pending review",
            "--------------",
            ("Package", "Version", "Splits", "Repo rows"),
            (36, 14, 8, 10),
            rows_pt,
        )
    else:
        print("Pending review")
        print("--------------")
        print("  (none)")
        print()

    if queued:
        rows_q: list[tuple[str, ...]] = []
        for r in queued:
            pkg = str(r.get("package_name") or "").strip()
            entry = overrides.get(pkg.lower())
            csv_disp = (entry[1] if entry else "")[:40]
            ver = str(r.get("version_name") or "").strip() or "—"
            splits = str(int(r.get("split_count") or 0))
            repo = str(int(r.get("repo_row_count") or 0))
            rows_q.append((pkg, csv_disp, ver, splits, repo))
        _format_fixed_table(
            "Curated CSV override (still in NULL-only bucket)",
            "-------------------------------------------------",
            ("Package", "CSV display_name", "Version", "Splits", "Repo rows"),
            (32, 22, 12, 8, 10),
            rows_q,
        )


def _confidence_for_hint(
    *,
    package_lower: str,
    inv_label: str | None,
    repo_versions: list[str],
) -> tuple[str | None, str]:
    """Return (optional_candidate_label, confidence_line)."""

    inv_l = (inv_label or "").strip()
    if inv_l and inv_l.lower() != package_lower:
        return inv_l, "medium (device_inventory.app_label differs from package_name)"

    best: str | None = None
    for vn in repo_versions:
        t = str(vn or "").strip()
        if not t or t.lower() == package_lower:
            continue
        if len(t) > 64:
            continue
        if t.replace(".", "").replace(" ", "").isdigit():
            continue
        if "(" in t and ")" in t:
            best = t
            break
        if best is None:
            best = t

    if best:
        return (
            best,
            "low (android_apk_repository.version_name is usually a version string, not a marketing title; verify on APK)",
        )

    return None, "low (no alternate label in inventory/repo fields queried; manifest label would need APK tooling)"


def _emit_harvest_label_hints(
    run_sql,
    *,
    snapshot_id: int,
    packages: tuple[str, ...],
) -> None:
    print("Harvest label hints (read-only, not applied)")
    print("---------------------------------------------")
    print(
        "  Sources: device_inventory for this snapshot, android_apk_repository aggregates. "
        "Manifest application-label is not stored in these tables; use static/APK tooling to confirm."
    )
    print()

    if not packages:
        print("  (no packages requested)")
        print()
        return

    placeholders = ",".join(["%s"] * len(packages))
    inv_rows = run_sql(
        f"""
        SELECT package_name, app_label, version_name, version_code, split_count, is_split,
               SUBSTRING(IFNULL(CAST(extras AS CHAR), ''), 1, 160) AS extras_preview
        FROM device_inventory
        WHERE snapshot_id = %s
          AND LOWER(package_name) IN ({placeholders})
        """,
        (snapshot_id, *packages),
        fetch="all_dict",
    )
    inv_by_lower = {
        str(r.get("package_name") or "").strip().lower(): r for r in (inv_rows or []) if r.get("package_name")
    }

    repo_rows = run_sql(
        f"""
        SELECT LOWER(package_name) AS lp, version_name, version_code,
               MAX(is_split_member) AS any_split, COUNT(*) AS row_n
        FROM android_apk_repository
        WHERE LOWER(package_name) IN ({placeholders})
        GROUP BY lp, version_name, version_code
        ORDER BY lp, row_n DESC
        """,
        tuple(packages),
        fetch="all_dict",
    )
    repo_by_pkg: dict[str, list[dict[str, object]]] = {}
    for row in repo_rows or []:
        lp = str(row.get("lp") or "").strip().lower()
        repo_by_pkg.setdefault(lp, []).append(row)

    for pkg in packages:
        print(f"  Package: {pkg}")
        inv = inv_by_lower.get(pkg.lower())
        if not inv:
            print("    device_inventory: (no row for this snapshot)")
            inv_ver = None
            inv_label = None
        else:
            inv_label = str(inv.get("app_label") or "").strip() or None
            inv_ver = str(inv.get("version_name") or "").strip() or None
            vc = inv.get("version_code")
            splits = int(inv.get("split_count") or 0)
            is_split = int(inv.get("is_split") or 0)
            extras = str(inv.get("extras_preview") or "").strip()
            print(
                f"    device_inventory: version_name={inv_ver!r} version_code={vc!r} "
                f"split_count={splits} is_split={is_split} app_label={inv_label!r}"
            )
            if extras:
                print(f"    extras preview   : {extras!r}")

        rlist = repo_by_pkg.get(pkg.lower(), [])
        repo_versions = sorted(
            {str(x.get("version_name") or "").strip() for x in rlist if str(x.get("version_name") or "").strip()}
        )
        if rlist:
            top = rlist[:6]
            bits = [
                f"v={str(x.get('version_name') or '')!r} code={x.get('version_code')!r} "
                f"split={x.get('any_split')!r} n={x.get('row_n')!r}"
                for x in top
            ]
            print(f"    android_apk_repository (top rows): {' | '.join(bits)}")
        else:
            print("    android_apk_repository: (no rows)")

        candidate, conf = _confidence_for_hint(
            package_lower=pkg.lower(),
            inv_label=inv_label,
            repo_versions=repo_versions,
        )
        if candidate:
            print(f"    candidate label  : {candidate!r}")
        else:
            print("    candidate label  : (none from DB-only heuristics)")
        print(f"    confidence       : {conf}")
        print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Report apps.display_name hygiene against device_inventory (read-only).",
    )
    parser.add_argument(
        "--snapshot-id",
        type=int,
        default=None,
        help="Inventory snapshot to analyze (default: latest MAX(snapshot_id)).",
    )
    parser.add_argument(
        "--overrides-csv",
        type=Path,
        default=_DEFAULT_OVERRIDES,
        help=f"Override candidate CSV (default: {_DEFAULT_OVERRIDES}).",
    )
    parser.add_argument(
        "--focus-play-store-unclassified",
        action="store_true",
        help="Print focus bucket tables and optional harvest label hints.",
    )
    parser.add_argument(
        "--label-hint-packages",
        default=None,
        metavar="PKGS",
        help=(
            "Comma-separated packages for harvest hint section when using "
            f"--focus-play-store-unclassified (default: {','.join(_DEFAULT_LABEL_HINT_PACKAGES)})."
        ),
    )
    parser.add_argument(
        "--no-harvest-label-hints",
        action="store_true",
        help="With --focus-play-store-unclassified, skip harvest/repo label hint block.",
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
    overrides_path = Path(args.overrides_csv)
    if not overrides_path.is_file():
        sys.stderr.write(f"Warning: overrides CSV not found, metrics use empty map: {overrides_path}\n")
    overrides = _load_override_csv(overrides_path)

    snap_id: int | None = None
    total_inventory_rows = 0
    missing_display_name = 0
    inventory_label_equals_package = 0
    focus_list: list[dict[str, object]] = []
    apps_labeled_lower: set[str] = set()

    try:
        with database_session():
            resolved_id, snap_err = _resolve_snapshot_id(run_sql, args.snapshot_id)
            if resolved_id is None:
                sys.stderr.write(f"Snapshot resolution failed: {snap_err}\n")
                return 1
            snap_id = resolved_id

            total_inv = run_sql(
                "SELECT COUNT(*) FROM device_inventory WHERE snapshot_id = %s",
                (snap_id,),
                fetch="one",
            )
            total_inventory_rows = int(total_inv[0]) if total_inv else 0

            missing_dn = run_sql(
                """
                SELECT COUNT(*)
                FROM device_inventory di
                LEFT JOIN apps a ON LOWER(di.package_name) = LOWER(a.package_name)
                WHERE di.snapshot_id = %s
                  AND (a.id IS NULL OR a.display_name IS NULL OR TRIM(a.display_name) = '')
                """,
                (snap_id,),
                fetch="one",
            )
            missing_display_name = int(missing_dn[0]) if missing_dn else 0

            label_eq_pkg = run_sql(
                """
                SELECT COUNT(*)
                FROM device_inventory di
                WHERE di.snapshot_id = %s
                  AND LOWER(TRIM(IFNULL(di.app_label, ''))) = LOWER(TRIM(di.package_name))
                """,
                (snap_id,),
                fetch="one",
            )
            inventory_label_equals_package = int(label_eq_pkg[0]) if label_eq_pkg else 0

            focus_rows = run_sql(
                """
                SELECT
                  di.package_name,
                  di.app_label,
                  di.version_name,
                  di.version_code,
                  di.split_count,
                  a.display_name AS apps_display_name,
                  (
                    SELECT COUNT(*)
                    FROM android_apk_repository r
                    WHERE LOWER(r.package_name) = LOWER(di.package_name)
                  ) AS repo_row_count
                FROM device_inventory di
                LEFT JOIN apps a ON LOWER(di.package_name) = LOWER(a.package_name)
                WHERE di.snapshot_id = %s
                  AND di.source_label = 'Play Store'
                  AND di.profile_name = 'Unclassified'
                  AND di.partition_label = 'Data (/data)'
                  AND di.installer = 'com.android.vending'
                  AND di.review_needed = 1
                  AND (a.display_name IS NULL OR TRIM(IFNULL(a.display_name, '')) = '')
                  AND LOWER(TRIM(IFNULL(di.app_label, ''))) = LOWER(TRIM(di.package_name))
                ORDER BY di.package_name
                """,
                (snap_id,),
                fetch="all_dict",
            )
            focus_list = list(focus_rows or [])

            curated_lower = sorted({k for k, t in overrides.items() if t[1].strip()})
            if curated_lower:
                placeholders = ",".join(["%s"] * len(curated_lower))
                app_rows = run_sql(
                    f"""
                    SELECT LOWER(package_name) AS lp, display_name
                    FROM apps
                    WHERE LOWER(package_name) IN ({placeholders})
                    """,
                    tuple(curated_lower),
                    fetch="all_dict",
                )
                for row in app_rows or []:
                    lp = str(row.get("lp") or "").strip().lower()
                    dn = row.get("display_name")
                    if lp and dn is not None and str(dn).strip() != "":
                        apps_labeled_lower.add(lp)
    except DatabaseError as exc:
        sys.stderr.write(f"Database error: {exc}\n")
        return 2
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:  # noqa: BLE001 — operator-facing boundary
        sys.stderr.write(f"Report failed: {exc}\n")
        return 2

    focus_bucket_row_count = len(focus_list)
    focus_with_repo = sum(1 for r in focus_list if int(r.get("repo_row_count") or 0) > 0)
    focus_repo_rows_total = sum(int(r.get("repo_row_count") or 0) for r in focus_list)

    focus_lower = {str(r.get("package_name") or "").strip().lower() for r in focus_list}
    override_lower_keys = set(overrides.keys())

    focus_with_csv_name = 0
    focus_still_need_review = 0
    focus_missing_from_csv = 0
    for r in focus_list:
        pkg = str(r.get("package_name") or "").strip()
        okey = pkg.lower()
        if okey not in override_lower_keys:
            focus_missing_from_csv += 1
        entry = overrides.get(okey)
        has_csv_name = bool(entry and entry[1].strip())
        if has_csv_name:
            focus_with_csv_name += 1
        apps_dn = r.get("apps_display_name")
        if apps_dn is None or str(apps_dn).strip() == "":
            if not has_csv_name:
                focus_still_need_review += 1

    csv_curated_already_labeled = 0
    csv_curated_outside_focus_bucket = 0
    for key, (_pkg, disp, _src, _notes) in overrides.items():
        if not disp.strip():
            continue
        if key in focus_lower:
            continue
        if key in apps_labeled_lower:
            csv_curated_already_labeled += 1
        else:
            csv_curated_outside_focus_bucket += 1

    print("App label hygiene (read-only)")
    print(f"  snapshot_id                     : {snap_id}")
    print(f"  total inventory rows            : {total_inventory_rows}")
    print(f"  missing apps.display_name       : {missing_display_name}")
    print(f"  inventory app_label = package   : {inventory_label_equals_package}")
    print()
    print("Focused bucket (Play Store / Unclassified / Data (/data) / review_needed=1 /")
    print("  installer=com.android.vending / apps.display_name empty / app_label=package)")
    print(
        "  Note: this bucket only counts rows where apps.display_name is still empty, "
        "so row count drops after successful override apply."
    )
    print(
        "  Note: static scan preflight counts every in-scope package with empty "
        "apps.display_name (no inventory filters). That total can exceed "
        "'still needing review' here when packages fall outside this bucket."
    )
    print(f"  bucket row count                : {focus_bucket_row_count}")
    print(f"  bucket packages with repo rows  : {focus_with_repo}")
    print(f"  bucket android_apk_repository rows (sum per package): {focus_repo_rows_total}")
    print(f"  bucket rows with possible manual override (CSV name): {focus_with_csv_name}")
    print(f"  bucket rows still needing review (no CSV name yet): {focus_still_need_review}")
    print(f"  focus bucket packages missing from CSV entirely: {focus_missing_from_csv}")
    print(f"  CSV curated rows already labeled in apps: {csv_curated_already_labeled}")
    print(
        f"  CSV curated rows outside latest inventory focus bucket: "
        f"{csv_curated_outside_focus_bucket}"
    )
    if csv_curated_outside_focus_bucket:
        print(
            "    Non-zero means: CSV has a suggested display_name, the package is not in "
            "the NULL-only focus bucket above, and apps.display_name is still empty "
            "(filters/snapshot drift, missing apps row, or typo in package_name)."
        )

    if args.focus_play_store_unclassified:
        _emit_focus_detail_tables(focus_list, overrides)
        if not args.no_harvest_label_hints:
            hint_pkgs = _parse_label_hint_packages(args.label_hint_packages)
            with database_session():
                _emit_harvest_label_hints(run_sql, snapshot_id=int(snap_id or 0), packages=hint_pkgs)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
