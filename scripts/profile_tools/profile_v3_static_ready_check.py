#!/usr/bin/env python3
"""Profile v3 static readiness check.

Paper #3 dynamic capture requires a `static_run_id` (static_analysis_runs.id) per app.
This gate verifies that each catalog package has at least one COMPLETED static run
in the canonical DB schema.
"""

from __future__ import annotations

import json
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


def main() -> int:
    catalog_path = Path("profiles") / "profile_v3_app_catalog.json"
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
    # Latest run per package (by static_analysis_runs.id).
    rows = core_q.run_sql(
        f"""
        SELECT
          a.package_name,
          MAX(sar.id) AS static_run_id
        FROM static_analysis_runs sar
        JOIN app_versions av ON av.id = sar.app_version_id
        JOIN apps a ON a.id = av.app_id
        WHERE LOWER(a.package_name) IN ({placeholders})
        GROUP BY a.package_name
        """,
        tuple(pkgs),
        fetch="all",
        dictionary=True,
    ) or []

    latest: dict[str, int] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        pkg = str(r.get("package_name") or "").strip().lower()
        rid = r.get("static_run_id")
        if pkg and rid is not None:
            try:
                latest[pkg] = int(rid)
            except Exception:
                continue

    missing = sorted(set(pkgs) - set(latest.keys()))
    bad: list[tuple[str, str, str]] = []
    if latest:
        run_ids = sorted(set(latest.values()))
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

        for pkg, rid in sorted(latest.items()):
            status, stamp = status_by_id.get(rid, ("", ""))
            if status != "COMPLETED":
                bad.append((pkg, status or "UNKNOWN", stamp or ""))

    ok = (not missing) and (not bad)
    if ok:
        print(f"[OK] Profile v3 static readiness: PASS (apps={len(pkgs)})")
        print(f"[COPY] v3_static_ready=PASS apps={len(pkgs)}")
        return 0

    print("[FAIL] Profile v3 static readiness: FAIL")
    print(f"[COPY] v3_static_ready=FAIL apps={len(pkgs)} missing={len(missing)} bad={len(bad)}")
    if missing:
        print("Missing static run:")
        for pkg in missing:
            print(f"- {pkg}")
    if bad:
        print("Latest static run not COMPLETED:")
        for pkg, status, stamp in bad:
            suffix = f" session={stamp}" if stamp else ""
            print(f"- {pkg} status={status}{suffix}")
    print("Next steps:")
    print("- Static APK analysis -> Run Profile v3 Structural Cohort (batch)")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
