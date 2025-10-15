#!/usr/bin/env python3
"""
Normalize android_detected_permissions:
  1) Expand relative perm names (".FOO" -> "<package_name>.FOO")
  2) Uppercase perm_name
  3) Recompute namespace = lower(first two labels) or NULL
  4) (optional) Dedupe identical (apk_id, artifact_label, perm_name)
  5) (optional) Create helpful indexes

Uses scytaledroid.Database.db_core.db_config.DB_CONFIG
"""

import argparse
from typing import Any, Dict, List, Optional, Tuple

# --- DB config from your project ---
from scytaledroid.Database.db_core.db_config import DB_CONFIG  # hardcoded dev config

# --- DB driver (pure Python) ---
import pymysql
DriverError = pymysql.MySQLError


def get_conn() -> pymysql.connections.Connection:
    cfg = DB_CONFIG
    return pymysql.connect(
        host=cfg["host"],
        port=int(cfg["port"]),
        user=cfg["user"],
        password=cfg["password"],
        database=cfg["database"],
        charset=cfg.get("charset", "utf8mb4"),
        autocommit=False,
        cursorclass=pymysql.cursors.DictCursor,
    )


def compute_namespace(perm_name: Optional[str]) -> Optional[str]:
    if not perm_name or "." not in perm_name:
        return None
    parts = perm_name.split(".")
    if len(parts) >= 2:
        return ".".join(parts[:2]).lower()
    return parts[0].lower()


def expand_and_normalize(package_name: Optional[str], perm_name: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not perm_name:
        return None, None
    name = perm_name.strip()
    if name.startswith(".") and package_name:
        name = f"{package_name}{name}"
    name = name.upper()
    ns = compute_namespace(name)
    return name, ns


def fetch_problem_rows(cur, limit: Optional[int]) -> List[Dict[str, Any]]:
    sql = """
    SELECT detected_id, apk_id, package_name, artifact_label, perm_name, namespace
    FROM android_detected_permissions
    WHERE
      perm_name LIKE '.%%'
      OR perm_name <> UPPER(perm_name)
      OR namespace = '.permission'
      OR (namespace IS NULL AND perm_name LIKE '%%.%%')
    ORDER BY detected_id ASC
    """
    if limit:
        sql += " LIMIT %s"
        cur.execute(sql, (limit,))
    else:
        cur.execute(sql)
    return list(cur.fetchall())


def apply_updates(cur, updates: List[Dict[str, Any]]) -> int:
    if not updates:
        return 0
    sql = """
    UPDATE android_detected_permissions
    SET perm_name=%(perm_name)s,
        namespace=%(namespace)s
    WHERE detected_id=%(detected_id)s
    """
    cur.executemany(sql, updates)
    return cur.rowcount


def dedupe(cur) -> int:
    cur.execute("""
        SELECT apk_id, artifact_label, perm_name, MIN(detected_id) AS keep_id, COUNT(*) AS cnt
        FROM android_detected_permissions
        GROUP BY apk_id, artifact_label, perm_name
        HAVING cnt > 1
    """)
    dup_groups = list(cur.fetchall())
    if not dup_groups:
        return 0

    to_delete: List[int] = []
    for g in dup_groups:
        cur.execute("""
           SELECT detected_id FROM android_detected_permissions
           WHERE apk_id=%s AND artifact_label=%s AND perm_name=%s
             AND detected_id <> %s
        """, (g["apk_id"], g["artifact_label"], g["perm_name"], g["keep_id"]))
        to_delete += [row["detected_id"] for row in cur.fetchall()]

    deleted = 0
    if to_delete:
        CHUNK = 1000
        for i in range(0, len(to_delete), CHUNK):
            chunk = to_delete[i:i+CHUNK]
            fmt = ",".join(["%s"] * len(chunk))
            cur.execute(f"DELETE FROM android_detected_permissions WHERE detected_id IN ({fmt})", chunk)
            deleted += cur.rowcount
    return deleted


def ensure_indexes(cur, create_unique: bool, create_ns_index: bool):
    if create_unique:
        # MariaDB supports IF NOT EXISTS for indexes in recent versions; if not, this will error—run once.
        cur.execute("""
        ALTER TABLE android_detected_permissions
        ADD UNIQUE KEY IF NOT EXISTS ux_detected_apk_artifact_perm (apk_id, artifact_label, perm_name)
        """)
    if create_ns_index:
        cur.execute("""
        ALTER TABLE android_detected_permissions
        ADD INDEX IF NOT EXISTS ix_detected_namespace (namespace)
        """)


def main():
    ap = argparse.ArgumentParser(description="Normalize and dedupe android_detected_permissions")
    ap.add_argument("--limit", type=int, default=None, help="Limit rows processed (test safely)")
    ap.add_argument("--batch-size", type=int, default=1000, help="Update batch size")
    ap.add_argument("--dedupe", action="store_true", help="Delete duplicate rows (keep smallest detected_id)")
    ap.add_argument("--create-indexes", action="store_true", help="Create helpful indexes (unique & namespace)")
    ap.add_argument("--dry-run", action="store_true", help="Show what would change but do not commit")
    args = ap.parse_args()

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            if args.create_indexes:
                ensure_indexes(cur, create_unique=True, create_ns_index=True)

            rows = fetch_problem_rows(cur, args.limit)
            print(f"Found {len(rows)} rows needing normalization.")
            updates: List[Dict[str, Any]] = []

            for r in rows:
                new_perm, new_ns = expand_and_normalize(r["package_name"], r["perm_name"])
                if new_perm != r["perm_name"] or new_ns != r["namespace"]:
                    updates.append({
                        "detected_id": r["detected_id"],
                        "perm_name": new_perm,
                        "namespace": new_ns,
                    })

            changed = 0
            if updates:
                for i in range(0, len(updates), args.batch_size):
                    batch = updates[i:i+args.batch_size]
                    if args.dry_run:
                        for u in batch[:10]:
                            print(f"UPDATE detected_id={u['detected_id']}: perm_name -> {u['perm_name']} | namespace -> {u['namespace']}")
                    else:
                        changed += apply_updates(cur, batch)

            deduped = 0
            if args.dedupe and not args.dry_run:
                deduped = dedupe(cur)

            if args.dry_run:
                conn.rollback()
                print(f"[DRY-RUN] Would update {len(updates)} rows; would delete {deduped} duplicates.")
            else:
                conn.commit()
                print(f"Updated {changed} rows.")
                if args.dedupe:
                    print(f"Deleted {deduped} duplicate rows.")

    except DriverError as e:
        conn.rollback()
        print(f"Database error: {e}")
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()

