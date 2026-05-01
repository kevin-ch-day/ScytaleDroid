#!/usr/bin/env python3
"""Profile v3 static readiness check.

Paper #3 dynamic capture requires a `static_run_id` (static_analysis_runs.id) per app.
This gate verifies that each catalog package has at least one COMPLETED static run
in the canonical DB schema.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _load_catalog(catalog_path: Path) -> dict[str, object]:
    try:
        payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    except Exception:
        payload = {}
    return payload if isinstance(payload, dict) else {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Profile v3 static readiness in the canonical DB.")
    parser.add_argument(
        "--catalog",
        default=str(Path("profiles") / "profile_v3_app_catalog.json"),
        help="Profile v3 app catalog path.",
    )
    args = parser.parse_args(argv)

    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except Exception:
        pass

    catalog_path = Path(args.catalog)
    catalog = _load_catalog(catalog_path)
    pkgs = [str(k).strip().lower() for k in catalog.keys() if str(k).strip()]
    if not pkgs:
        print("PROFILE_V3_STATIC_READY_FAIL: catalog is empty")
        return 2

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception as exc:
        print(f"PROFILE_V3_STATIC_READY_FAIL: DB imports unavailable: {exc}")
        return 2

    if str(getattr(db_config, "DB_CONFIG", {}).get("engine", "")).lower() not in {"mysql", "mariadb"}:
        print("PROFILE_V3_STATIC_READY_FAIL: DB is not enabled (dynamic requires static_run_id)")
        return 2

    placeholders = ", ".join(["%s"] * len(pkgs))
    # Paper readiness should be based on "has at least one COMPLETED static run".
    # A later failed re-run should not regress readiness if a completed run exists.
    rows = core_q.run_sql(
        f"""
        SELECT
          LOWER(a.package_name) AS package_name,
          MAX(CASE WHEN UPPER(sar.status) = 'COMPLETED' THEN sar.id ELSE NULL END) AS completed_static_run_id,
          MAX(sar.id) AS latest_static_run_id
        FROM static_analysis_runs sar
        JOIN app_versions av ON av.id = sar.app_version_id
        JOIN apps a ON a.id = av.app_id
        WHERE LOWER(a.package_name) IN ({placeholders})
        GROUP BY LOWER(a.package_name)
        """,
        tuple(pkgs),
        fetch="all",
        dictionary=True,
    ) or []

    completed_by_pkg: dict[str, int] = {}
    latest_by_pkg: dict[str, int] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        pkg = str(r.get("package_name") or "").strip().lower()
        if not pkg:
            continue
        comp = r.get("completed_static_run_id")
        lat = r.get("latest_static_run_id")
        if comp is not None:
            try:
                completed_by_pkg[pkg] = int(comp)
            except Exception:
                pass
        if lat is not None:
            try:
                latest_by_pkg[pkg] = int(lat)
            except Exception:
                pass

    missing = sorted(set(pkgs) - set(completed_by_pkg.keys()))
    warnings: list[tuple[str, str, str]] = []
    if latest_by_pkg:
        run_ids = sorted(set(latest_by_pkg.values()))
        ph = ", ".join(["%s"] * len(run_ids))
        status_rows = core_q.run_sql(
            f"""
            SELECT id, status, session_stamp
            FROM static_analysis_runs
            WHERE id IN ({ph})
            """,
            tuple(run_ids),
            fetch="all",
            dictionary=True,
        ) or []
        status_by_id: dict[int, tuple[str, str]] = {}
        for r in status_rows:
            if not isinstance(r, dict):
                continue
            try:
                rid = int(r.get("id"))
            except Exception:
                continue
            status = str(r.get("status") or "").strip().upper()
            stamp = str(r.get("session_stamp") or "").strip()
            status_by_id[rid] = (status, stamp)
        for pkg, rid in sorted(latest_by_pkg.items()):
            status, stamp = status_by_id.get(rid, ("", ""))
            if status and status != "COMPLETED" and pkg in completed_by_pkg:
                warnings.append((pkg, status, stamp))

    ok = (not missing)
    if ok:
        print(f"[OK] Profile v3 static readiness: PASS (apps={len(pkgs)})")
        print(f"[COPY] v3_static_ready=PASS apps={len(pkgs)}")
        if warnings:
            print("[WARN] Latest static run is not COMPLETED for some packages, but a COMPLETED run exists:")
            for pkg, status, stamp in warnings[:8]:
                suffix = f" session={stamp}" if stamp else ""
                print(f"- {pkg} latest_status={status}{suffix}")
        return 0

    print("[FAIL] Profile v3 static readiness: FAIL")
    print(f"[COPY] v3_static_ready=FAIL apps={len(pkgs)} missing={len(missing)} bad=0")
    if missing:
        print("Missing static run:")
        for pkg in missing:
            print(f"- {pkg}")
    print("Next steps:")
    print("- Static APK analysis -> Run Profile v3 Structural Cohort (batch)")
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        raise SystemExit(0)
