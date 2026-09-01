"""Dynamic profile helpers for the CLI."""

from __future__ import annotations

from collections.abc import Iterable

from scytaledroid.Database.db_core import run_sql


def _normalize_key(value: object) -> str:
    return str(value or "").strip().upper()


def _cohort_key_from_profile_key(profile_key: str) -> str | None:
    normalized = _normalize_key(profile_key)
    if not normalized:
        return None
    if normalized.startswith("RESEARCH_COHORT:"):
        suffix = normalized.split(":", 1)[1].strip()
        return suffix.lower() or None
    if normalized.startswith("RESEARCH_DATASET_"):
        return normalized.lower()
    return None


def _is_research_profile_key(profile_key: object) -> bool:
    return _cohort_key_from_profile_key(str(profile_key or "")) is not None


def _load_android_app_profiles() -> list[dict[str, object]]:
    profiles: list[dict[str, object]] = []
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
        rows = []
    for row in rows or []:
        profile_key = _normalize_key(row.get("profile_key"))
        if not profile_key:
            continue
        profiles.append(
            {
                "profile_key": profile_key,
                "display_name": str(row.get("display_name") or "").strip() or "Unnamed profile",
                "app_count": int(row.get("app_count") or 0),
                "source": "android_app_profiles",
            }
        )
    profiles.sort(key=lambda row: str(row.get("display_name") or row.get("profile_key") or "").casefold())
    return profiles


def load_operational_profiles() -> list[dict[str, object]]:
    """Return operator/category profiles from android_app_profiles only."""

    return [
        row
        for row in _load_android_app_profiles()
        if row.get("profile_key") and not _is_research_profile_key(row.get("profile_key"))
    ]


def load_research_cohort_profiles() -> list[dict[str, object]]:
    """Return DB-backed research cohorts formatted as profile-like rows."""

    try:
        from scytaledroid.Database.db_func.research_cohorts import list_active_research_cohorts

        cohort_rows = list_active_research_cohorts()
    except Exception:
        cohort_rows = []
    profiles: list[dict[str, object]] = []
    for row in cohort_rows or []:
        cohort_key = str(row.get("cohort_key") or "").strip().lower()
        alias_key = _normalize_key(cohort_key)
        if not alias_key:
            continue
        profiles.append(
            {
                "profile_key": alias_key,
                "display_name": str(row.get("display_name") or alias_key).strip() or alias_key,
                "app_count": int(row.get("active_member_count") or 0),
                "source": "research_cohorts",
                "cohort_key": cohort_key,
            }
        )
    profiles.sort(key=lambda row: str(row.get("display_name") or row.get("profile_key") or "").casefold())
    return [row for row in profiles if row.get("profile_key")]


def _merge_profiles(*profile_sets: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    profiles_by_key: dict[str, dict[str, object]] = {}
    for profile_rows in profile_sets:
        for row in profile_rows:
            profile_key = _normalize_key(row.get("profile_key"))
            if not profile_key:
                continue
            item = dict(row)
            item["profile_key"] = profile_key
            existing = profiles_by_key.get(profile_key)
            if existing is None:
                profiles_by_key[profile_key] = item
                continue
            existing["display_name"] = str(item.get("display_name") or existing.get("display_name") or "").strip() or str(
                existing.get("display_name") or item.get("display_name") or profile_key
            )
            existing["app_count"] = max(int(existing.get("app_count") or 0), int(item.get("app_count") or 0))
            sources = {
                str(existing.get("source") or "").strip(),
                str(item.get("source") or "").strip(),
            }
            sources.discard("")
            existing["source"] = "+".join(sorted(sources)) if len(sources) > 1 else next(iter(sources), "")
            if item.get("cohort_key"):
                existing["cohort_key"] = item["cohort_key"]
    profiles = list(profiles_by_key.values())
    profiles.sort(key=lambda row: str(row.get("display_name") or row.get("profile_key") or "").casefold())
    return [row for row in profiles if row.get("profile_key")]


def load_all_profiles() -> list[dict[str, object]]:
    """Return the legacy mixed view of operational profiles plus research cohorts."""

    return _merge_profiles(load_operational_profiles(), load_research_cohort_profiles())


def load_profile_packages(profile_key: str) -> set[str]:
    normalized = _normalize_key(profile_key)
    cohort_key = _cohort_key_from_profile_key(normalized)
    if cohort_key:
        try:
            from scytaledroid.Database.db_func.research_cohorts import (
                fetch_active_research_cohort_packages,
            )

            packages = {
                str(pkg).strip().lower()
                for pkg in fetch_active_research_cohort_packages(cohort_key)
                if str(pkg).strip()
            }
        except Exception:
            packages = set()
        if packages:
            return packages
    try:
        rows = run_sql(
            "SELECT package_name FROM apps WHERE profile_key = %s",
            (normalized,),
            fetch="all",
            dictionary=True,
        )
    except Exception:
        return set()
    return {str(row.get("package_name") or "").strip().lower() for row in rows or [] if row.get("package_name")}


__all__ = [
    "load_all_profiles",
    "load_operational_profiles",
    "load_profile_packages",
    "load_research_cohort_profiles",
]
