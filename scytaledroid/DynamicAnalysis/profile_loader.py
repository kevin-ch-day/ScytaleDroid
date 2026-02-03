"""Dynamic profile helpers for the CLI."""

from __future__ import annotations

from scytaledroid.Database.db_core import run_sql


def load_db_profiles() -> list[dict[str, object]]:
    try:
        rows = run_sql(
            (
                "SELECT p.profile_key, p.display_name, COUNT(a.package_name) AS app_count "
                "FROM android_app_profiles p "
                "LEFT JOIN apps a ON a.profile_key = p.profile_key "
                "WHERE p.is_active = 1 "
                "GROUP BY p.profile_key, p.display_name "
                "ORDER BY p.display_name"
            ),
            fetch="all",
            dictionary=True,
        )
    except Exception:
        return []
    profiles = []
    for row in rows or []:
        profiles.append(
            {
                "profile_key": str(row.get("profile_key") or "").strip(),
                "display_name": str(row.get("display_name") or "").strip() or "Unnamed profile",
                "app_count": int(row.get("app_count") or 0),
            }
        )
    return [row for row in profiles if row["profile_key"]]


def load_profile_packages(profile_key: str) -> set[str]:
    try:
        rows = run_sql(
            "SELECT package_name FROM apps WHERE profile_key = %s",
            (profile_key,),
            fetch="all",
            dictionary=True,
        )
    except Exception:
        return set()
    return {str(row.get("package_name") or "").strip().lower() for row in rows or [] if row.get("package_name")}


__all__ = ["load_db_profiles", "load_profile_packages"]
