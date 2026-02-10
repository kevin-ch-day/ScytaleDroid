"""DB-backed app labels/profiles.

This is intentionally small and best-effort:
- Many CLI flows should still work without a DB connection.
- When DB is available, it becomes the canonical source for display_name and profile_key,
  reducing scattered JSON/constant maps.
"""

from __future__ import annotations

from collections.abc import Iterable


def fetch_display_name_map(packages: Iterable[str]) -> dict[str, str]:
    """Best-effort map of package_name -> apps.display_name from DB.

    Returns {} on any failure.
    """
    pkgs = sorted({str(p).strip() for p in packages if str(p).strip()})
    if not pkgs:
        return {}
    try:
        from scytaledroid.Database.db_core import run_sql
    except Exception:
        return {}
    try:
        placeholders = ",".join(["%s"] * len(pkgs))
        sql = f"SELECT package_name, display_name FROM apps WHERE package_name IN ({placeholders})"
        rows = run_sql(sql, tuple(pkgs), fetch="all", dictionary=True)
    except Exception:
        return {}
    mapping: dict[str, str] = {}
    for row in rows or []:
        pkg = str(row.get("package_name") or "").strip()
        name = str(row.get("display_name") or "").strip()
        if pkg and name:
            mapping[pkg] = name
    return mapping


def fetch_display_name(package_name: str) -> str | None:
    """Best-effort lookup of a single display name."""
    pkg = str(package_name or "").strip()
    if not pkg:
        return None
    m = fetch_display_name_map([pkg])
    return m.get(pkg)


def upsert_display_names(display_name_by_package: dict[str, str], *, overwrite: bool) -> int:
    """Upsert apps.display_name for the provided mapping.

    Returns number of payload rows attempted.
    """
    items = []
    for k, v in (display_name_by_package or {}).items():
        pkg = str(k).strip()
        name = str(v).strip()
        if pkg and name:
            items.append((pkg, name))
    if not items:
        return 0

    try:
        from scytaledroid.Database.db_core import run_sql_many
    except Exception:
        return 0

    if overwrite:
        sql = """
        INSERT INTO apps (package_name, display_name)
        VALUES (%s, %s)
        ON DUPLICATE KEY UPDATE
          display_name = VALUES(display_name),
          updated_at = CURRENT_TIMESTAMP
        """
    else:
        sql = """
        INSERT INTO apps (package_name, display_name)
        VALUES (%s, %s)
        ON DUPLICATE KEY UPDATE
          display_name = COALESCE(display_name, VALUES(display_name)),
          updated_at = CURRENT_TIMESTAMP
        """

    run_sql_many(sql, items)
    return len(items)


def upsert_display_aliases(
    alias_key: str,
    display_name_by_package: dict[str, str],
    *,
    overwrite: bool,
) -> int:
    """Upsert context-specific display aliases (does not touch apps.display_name).

    This is for cases like publication/paper rendering where shorter labels may be
    desirable, but the DB canonical display_name should remain the full product name.
    """
    key = str(alias_key or "").strip()
    if not key:
        return 0
    items: list[tuple[str, str, str]] = []
    for k, v in (display_name_by_package or {}).items():
        pkg = str(k).strip()
        name = str(v).strip()
        if pkg and name:
            items.append((key, pkg, name))
    if not items:
        return 0

    try:
        from scytaledroid.Database.db_core import run_sql_many
    except Exception:
        return 0

    if overwrite:
        sql = """
        INSERT INTO app_display_aliases (alias_key, package_name, display_name)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE
          display_name = VALUES(display_name),
          updated_at = CURRENT_TIMESTAMP
        """
    else:
        sql = """
        INSERT INTO app_display_aliases (alias_key, package_name, display_name)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE
          display_name = COALESCE(display_name, VALUES(display_name)),
          updated_at = CURRENT_TIMESTAMP
        """

    run_sql_many(sql, items)
    return len(items)
