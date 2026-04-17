"""DB-backed app ordering helpers.

This module centralizes "display ordering" so we don't rely on scattered JSON
lists or implicit sorts when DB is available.

Ordering is keyed (e.g., 'publication', 'operational_default') and maps:
  (ordering_key, package_name) -> sort_order
"""

from __future__ import annotations

from collections.abc import Iterable


def upsert_ordering(ordering_key: str, package_names: Iterable[str]) -> int:
    """Upsert an exact ordering for the given key.

    Returns number of package rows written (best-effort; 0 on failure).
    """
    key = str(ordering_key or "").strip()
    pkgs = [str(p).strip() for p in (package_names or []) if str(p).strip()]
    if not key or not pkgs:
        return 0
    try:
        from scytaledroid.Database.db_core import run_sql_many
    except Exception:
        return 0

    payload = [(key, pkg, idx) for idx, pkg in enumerate(pkgs, start=1)]
    sql = """
    INSERT INTO app_display_orderings (ordering_key, package_name, sort_order)
    VALUES (%s, %s, %s)
    ON DUPLICATE KEY UPDATE
      sort_order = VALUES(sort_order),
      updated_at = CURRENT_TIMESTAMP
    """
    try:
        run_sql_many(sql, payload, query_name="apps.ordering.upsert")
    except Exception:
        return 0
    return len(payload)


def fetch_ordering(ordering_key: str) -> list[str]:
    """Return packages in display order for the given key (or [] on failure)."""
    key = str(ordering_key or "").strip()
    if not key:
        return []
    try:
        from scytaledroid.Database.db_core import run_sql
    except Exception:
        return []
    try:
        rows = run_sql(
            """
            SELECT package_name
            FROM app_display_orderings
            WHERE ordering_key=%s
            ORDER BY sort_order ASC, package_name ASC
            """,
            (key,),
            fetch="all",
            dictionary=False,
            query_name="apps.ordering.fetch",
        ) or []
    except Exception:
        return []
    out: list[str] = []
    for r in rows:
        # run_sql may return tuples; be defensive.
        pkg = None
        if isinstance(r, (list, tuple)) and r:
            pkg = r[0]
        elif isinstance(r, dict):
            pkg = r.get("package_name")
        pkg = str(pkg or "").strip()
        if pkg:
            out.append(pkg)
    return out


__all__ = ["upsert_ordering", "fetch_ordering"]
