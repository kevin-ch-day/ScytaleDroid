#!/usr/bin/env python3
"""Quick health checks for static analysis linkage and run_map integrity."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

import mysql.connector

ROOT_DIR = Path(__file__).resolve().parents[2]
ENV_FILE = Path(os.environ.get("SCYTALEDROID_ENV_FILE", ROOT_DIR / ".env"))
SESSIONS_DIR: Path | None = None

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


def _load_env() -> None:
    if not ENV_FILE.exists():
        return
    for raw in ENV_FILE.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def _db_connect():
    url = _resolve_db_url()
    if not url:
        raise SystemExit(
            "Database configuration not set "
            "(SCYTALEDROID_DB_URL or SCYTALEDROID_DB_NAME/USER/PASSWD/HOST/PORT)."
        )
    parsed = urlparse(url)
    scheme = _normalize_db_scheme(parsed.scheme)
    if scheme not in {"mysql", "mariadb"}:
        raise SystemExit(f"Unsupported DB scheme: {parsed.scheme}")
    return mysql.connector.connect(
        user=parsed.username,
        password=parsed.password,
        host=parsed.hostname or "localhost",
        port=parsed.port or 3306,
        database=(parsed.path or "").lstrip("/"),
    )


def _normalize_db_scheme(scheme: str) -> str:
    token = (scheme or "").strip().lower()
    if "+" in token:
        token = token.split("+", 1)[0]
    return token


def _compose_db_url_from_parts() -> str | None:
    name = (os.environ.get("SCYTALEDROID_DB_NAME") or "").strip()
    if not name:
        return None
    user = (os.environ.get("SCYTALEDROID_DB_USER") or "").strip()
    passwd = (os.environ.get("SCYTALEDROID_DB_PASSWD") or "").strip()
    host = (os.environ.get("SCYTALEDROID_DB_HOST") or "").strip() or "localhost"
    port = (os.environ.get("SCYTALEDROID_DB_PORT") or "").strip() or "3306"
    scheme = _normalize_db_scheme(os.environ.get("SCYTALEDROID_DB_SCHEME") or "mysql")
    auth = user
    if passwd:
        auth = f"{user}:{passwd}" if user else f":{passwd}"
    if auth:
        return f"{scheme}://{auth}@{host}:{port}/{name}"
    return f"{scheme}://{host}:{port}/{name}"


def _resolve_db_url() -> str | None:
    raw = (os.environ.get("SCYTALEDROID_DB_URL") or "").strip()
    if raw:
        return raw
    return _compose_db_url_from_parts()


def _fetchall(cur, sql, params=()):
    cur.execute(sql, params)
    return cur.fetchall()


def _fetchone(cur, sql, params=()):
    cur.execute(sql, params)
    return cur.fetchone()


def _table_exists(cur, name: str) -> bool:
    row = _fetchone(
        cur,
        "SELECT COUNT(*) FROM information_schema.tables "
        "WHERE table_schema = DATABASE() AND table_name = %s",
        (name,),
    )
    return bool(row and int(row[0] or 0) > 0)


def _load_run_map(session_stamp: str) -> tuple[dict | None, str]:
    if SESSIONS_DIR is None:
        return None, "sessions directory not initialised"
    run_map_path = SESSIONS_DIR / session_stamp / "run_map.json"
    if not run_map_path.exists():
        return None, f"missing run_map.json at {run_map_path}"
    try:
        payload = json.loads(run_map_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, f"invalid run_map.json: {exc}"
    if not isinstance(payload, dict):
        return None, "run_map.json is not a JSON object"
    return payload, ""


def _session_summary(cur, session_stamp: str) -> dict[str, object]:
    summary: dict[str, object] = {"session": session_stamp}
    row = _fetchone(
        cur,
        """
        SELECT COUNT(*) AS runs,
               SUM(pipeline_version IS NULL OR pipeline_version = '') AS missing_pipeline
        FROM static_analysis_runs
        WHERE session_stamp = %s
        """,
        (session_stamp,),
    )
    if row:
        summary["runs"] = int(row[0] or 0)
        summary["missing_pipeline"] = int(row[1] or 0)

    snapshot_key = f"perm-audit:app:{session_stamp}"
    snapshot = _fetchone(
        cur,
        "SELECT snapshot_id, apps_total FROM permission_audit_snapshots WHERE snapshot_key = %s",
        (snapshot_key,),
    )
    summary["snapshot_id"] = snapshot[0] if snapshot else None
    summary["snapshot_apps_total"] = int(snapshot[1]) if snapshot else None
    if snapshot:
        apps_row = _fetchone(
            cur,
            "SELECT COUNT(*) FROM permission_audit_apps WHERE snapshot_id = %s",
            (snapshot[0],),
        )
        summary["snapshot_apps_rows"] = int(apps_row[0] or 0) if apps_row else 0

    if _table_exists(cur, "static_session_run_links"):
        links_row = _fetchone(
            cur,
            "SELECT COUNT(*) FROM static_session_run_links WHERE session_stamp = %s",
            (session_stamp,),
        )
        summary["session_links"] = int(links_row[0] or 0) if links_row else 0
    else:
        summary["session_links"] = None

    return summary


def _compare_packages(cur, session_stamp: str, run_map: dict | None) -> list[str]:
    warnings: list[str] = []
    run_map_pkgs: set[str] = set()
    if run_map:
        apps = run_map.get("apps")
        if isinstance(apps, list):
            for entry in apps:
                if isinstance(entry, dict):
                    pkg = entry.get("package")
                    if pkg:
                        run_map_pkgs.add(str(pkg))
    snapshot_key = f"perm-audit:app:{session_stamp}"
    snapshot = _fetchone(
        cur,
        "SELECT snapshot_id FROM permission_audit_snapshots WHERE snapshot_key = %s",
        (snapshot_key,),
    )
    audit_pkgs: set[str] = set()
    if snapshot:
        rows = _fetchall(
            cur,
            "SELECT package_name FROM permission_audit_apps WHERE snapshot_id = %s",
            (snapshot[0],),
        )
        for row in rows:
            if row and row[0]:
                audit_pkgs.add(str(row[0]))
    link_pkgs: set[str] = set()
    if _table_exists(cur, "static_session_run_links"):
        rows = _fetchall(
            cur,
            "SELECT package_name FROM static_session_run_links WHERE session_stamp = %s",
            (session_stamp,),
        )
        for row in rows:
            if row and row[0]:
                link_pkgs.add(str(row[0]))

    if run_map_pkgs and audit_pkgs and run_map_pkgs != audit_pkgs:
        missing = sorted(run_map_pkgs - audit_pkgs)
        extra = sorted(audit_pkgs - run_map_pkgs)
        if missing:
            warnings.append(f"permission_audit_apps missing packages: {', '.join(missing)}")
        if extra:
            warnings.append(f"permission_audit_apps has extra packages: {', '.join(extra)}")
    if run_map_pkgs and link_pkgs and run_map_pkgs != link_pkgs:
        missing = sorted(run_map_pkgs - link_pkgs)
        extra = sorted(link_pkgs - run_map_pkgs)
        if missing:
            warnings.append(f"static_session_run_links missing packages: {', '.join(missing)}")
        if extra:
            warnings.append(f"static_session_run_links has extra packages: {', '.join(extra)}")
    return warnings


def main() -> int:
    _load_env()
    from scytaledroid.Config import app_config

    global SESSIONS_DIR
    SESSIONS_DIR = Path(app_config.DATA_DIR) / "sessions"
    conn = _db_connect()
    cur = conn.cursor()
    rows = _fetchall(
        cur,
        """
        SELECT session_stamp
        FROM static_analysis_runs
        WHERE session_stamp IS NOT NULL AND session_stamp <> ''
        GROUP BY session_stamp
        ORDER BY MAX(id) DESC
        LIMIT 5
        """,
    )
    sessions = [row[0] for row in rows if row and row[0]]
    if not sessions:
        print("No sessions found in static_analysis_runs.")
        return 0

    print("Static pipeline health (latest sessions):")
    for session in sessions:
        summary = _session_summary(cur, session)
        run_map, run_map_err = _load_run_map(session)
        run_map_count = 0
        if run_map and isinstance(run_map.get("apps"), list):
            run_map_count = len(run_map["apps"])
        print(f"- {session}: runs={summary.get('runs')} missing_pipeline={summary.get('missing_pipeline')}")
        if run_map_err:
            print(f"  run_map: {run_map_err}")
        else:
            print(f"  run_map: ok (apps={run_map_count})")
        print(f"  snapshot_id={summary.get('snapshot_id')} apps_total={summary.get('snapshot_apps_total')} apps_rows={summary.get('snapshot_apps_rows')}")
        links = summary.get("session_links")
        links_text = "n/a" if links is None else str(links)
        print(f"  session_links={links_text}")
        for warning in _compare_packages(cur, session, run_map):
            print(f"  WARN: {warning}")
    cur.close()
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
