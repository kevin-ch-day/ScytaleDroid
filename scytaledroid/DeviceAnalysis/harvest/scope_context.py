"""Context builders and filtering helpers for harvest scope selection."""

from __future__ import annotations

import re
from collections import Counter
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from scytaledroid.Database.db_core import db_queries
from scytaledroid.Utils.DisplayUtils import status_messages

from .models import InventoryRow, ScopeSelection
from . import rules
from .watchlists import Watchlist, filter_rows_by_watchlist, load_watchlists

# Human-friendly labels for why packages are filtered out of scope.
EXCLUSION_LABELS = {
    "family_excluded": "Family excluded (com.android./com.motorola. not Play)",
    "google_core": "Google core modules (not Play/allow-list)",
    "not_in_scope": "Not in scope (no Play installer or /data path)",
    "non_root_paths": "Non-user partition path",
}

_APP_NAME_CACHE: Dict[str, str] = {}


def maybe_str(value: object) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def load_app_names(package_names: Sequence[str]) -> Dict[str, str]:
    missing = [name for name in package_names if name not in _APP_NAME_CACHE]
    if missing:
        placeholders = ", ".join(["%s"] * len(missing))
        query = (
            "SELECT package_name, display_name "
            "FROM apps "
            f"WHERE package_name IN ({placeholders})"
        )
        try:
            rows = db_queries.run_sql(query, tuple(missing), fetch="all", dictionary=True)
        except Exception:
            rows = []
        for row in rows or []:
            pkg = maybe_str(row.get("package_name"))
            label = maybe_str(row.get("display_name"))
            if pkg and label:
                _APP_NAME_CACHE[pkg] = label
    return {name: _APP_NAME_CACHE.get(name) for name in package_names if name in _APP_NAME_CACHE}


def build_inventory_rows(packages: Sequence[Dict[str, object]]) -> List[InventoryRow]:
    """Normalise raw inventory package dictionaries into ``InventoryRow`` entries."""

    rows: List[InventoryRow] = []
    package_names: List[str] = []
    for pkg in packages:
        package_name = str(pkg.get("package_name") or "").strip()
        if not package_name:
            continue
        package_names.append(package_name)
    app_names = load_app_names(package_names)

    for pkg in packages:
        package_name = str(pkg.get("package_name") or "").strip()
        if not package_name:
            continue
        apk_paths = [
            str(path).strip()
            for path in pkg.get("apk_paths", [])  # type: ignore[arg-type]
            if str(path).strip()
        ]
        split_count = int(pkg.get("split_count") or len(apk_paths) or 0)
        app_label = maybe_str(pkg.get("app_label")) or app_names.get(package_name)
        profile_key = _normalize_profile_key(
            maybe_str(pkg.get("profile_key") or pkg.get("profile_id")),
            maybe_str(pkg.get("profile_name")),
        )
        profile_name = maybe_str(pkg.get("profile_name")) or profile_key
        rows.append(
            InventoryRow(
                raw=dict(pkg),
                package_name=package_name,
                app_label=app_label,
                installer=maybe_str(pkg.get("installer")),
                category=maybe_str(pkg.get("category")),
                primary_path=maybe_str(pkg.get("primary_path")),
                profile_key=profile_key,
                profile=profile_name,
                version_name=maybe_str(pkg.get("version_name")),
                version_code=maybe_str(pkg.get("version_code")),
                apk_paths=apk_paths,
                split_count=split_count,
            )
        )
    return rows


def _normalize_profile_key(profile_key: Optional[str], profile_name: Optional[str]) -> Optional[str]:
    if profile_key and profile_key.strip():
        return profile_key.strip().upper()
    name = (profile_name or "").strip().lower()
    if not name:
        return None
    if "social" in name:
        return "SOCIAL"
    if "messaging" in name or "comms" in name or "communication" in name:
        return "MESSAGING"
    if "shopping" in name:
        return "SHOPPING"
    if "amazon" in name:
        return "AMAZON_USER"
    if "google" in name:
        return "GOOGLE_USER"
    if "browser" in name:
        return "BROWSER"
    if "media" in name or "stream" in name:
        return "MEDIA"
    if "productivity" in name or "office" in name:
        return "PRODUCTIVITY"
    if "news" in name or "reading" in name:
        return "NEWS"
    if "system" in name or "core" in name:
        return "SYSTEM_CORE"
    if "unclassified" in name:
        return "UNCLASSIFIED"
    return None


def in_default_scope(row: InventoryRow, allow: Set[str]) -> bool:
    include, _ = _default_scope_decision(row, allow)
    return include


def apply_default_scope(
    rows: Sequence[InventoryRow], allow: Set[str]
) -> Tuple[List[InventoryRow], Dict[str, int]]:
    selected: List[InventoryRow] = []
    excluded: Dict[str, int] = {}
    for row in rows:
        include, reason = _default_scope_decision(row, allow)
        if include:
            selected.append(row)
        elif reason:
            excluded[reason] = excluded.get(reason, 0) + 1
    return selected, dict(sorted(excluded.items()))


def build_scope_context(rows: Sequence[InventoryRow], allow: Set[str]) -> Dict[str, object]:
    def estimate(selection: Sequence[InventoryRow]) -> Dict[str, int]:
        return {"packages": len(selection), "files": estimated_files(selection)}

    target_profiles = {"SOCIAL", "MESSAGING", "MEDIA", "BROWSER", "PRODUCTIVITY", "SHOPPING", "NEWS"}
    profile_counts: Counter[str] = Counter(
        (row.profile_key or "").upper()
        for row in rows
        if (row.profile_key or "").upper() in target_profiles
    )
    profile_total_rows = [
        row for row in rows if (row.profile_key or "").upper() in target_profiles
    ]

    default_rows, default_excluded = apply_default_scope(rows, allow)
    google_rows = [row for row in rows if row.package_name in allow]
    google_filtered, _ = apply_default_scope(google_rows, allow)
    google_user_rows = [row for row in rows if rules.is_google_user_app(row.package_name)]
    google_user_filtered, _ = apply_default_scope(google_user_rows, allow)

    watchlist_entries: List[_WatchlistEntry] = []
    watchlist_totals = {"packages": 0, "files": 0}
    for watchlist in load_watchlists():
        watch_rows = filter_rows_by_watchlist(rows, watchlist.packages)
        if not watch_rows:
            continue
        filtered, excluded = apply_default_scope(watch_rows, allow)
        if not filtered:
            continue
        counts = {"packages": len(filtered), "files": estimated_files(filtered)}
        preview = ", ".join(row.display_name() for row in filtered[:3])
        watchlist_entries.append(
            _WatchlistEntry(
                watchlist=watchlist,
                filtered=filtered,
                excluded=excluded,
                counts=counts,
                preview=preview,
            )
        )
        watchlist_totals["packages"] += counts["packages"]
        watchlist_totals["files"] += counts["files"]

    category_map = _fetch_category_map([row.package_name for row in rows])
    def _normalize_category(name: str | None) -> str | None:
        if not name:
            return None
        cleaned = name.strip()
        if not cleaned:
            return None
        lowered = cleaned.lower()
        if lowered in {"social", "social media", "social-media"}:
            return "Social media"
        if lowered in {"messaging", "communication", "comm"} or (
            "messaging" in lowered and "comm" in lowered
        ):
            return "Communication"
        return cleaned
    category_groups: Dict[str, List[InventoryRow]] = {}
    for row in rows:
        category_name = category_map.get(row.package_name) or row.profile
        if not category_name:
            try:
                from scytaledroid.StaticAnalysis.modules.categories import resolve_category

                category_name = resolve_category(row.package_name, {})
            except Exception:
                category_name = None
        normalized = _normalize_category(category_name)
        if normalized:
            category_groups.setdefault(normalized, []).append(row)

    return {
        "default_counts": estimate(default_rows),
        "default_excluded": default_excluded,
        "profile_counts": profile_counts,
        "profile_summary": estimate(profile_total_rows),
        "google_user": estimate(google_user_filtered),
        "google_exceptions": estimate(google_filtered),
        "families": estimate([row for row in rows if rules.family(row.package_name) in {"android", "google", "motorola"}]),
        "everything": estimate(rows),
        "watchlists": watchlist_entries,
        "watchlist_totals": watchlist_totals,
        "category_groups": category_groups,
    }


def _default_scope_decision(row: InventoryRow, allow: Set[str]) -> Tuple[bool, Optional[str]]:
    is_play = row.installer == rules.PLAY_STORE_INSTALLER
    is_user = rules.is_user_path(row.primary_path)

    if not is_user:
        return False, "non_root_paths"

    if not (is_play or is_user):
        return False, "not_in_scope"

    fam = rules.family(row.package_name)
    if fam in {"android", "motorola"}:
        if is_play:
            return True, None
        return False, "family_excluded"
    if fam == "google":
        if is_play or row.package_name in allow:
            return True, None
        return False, "google_core"
    return True, None


def _fetch_category_map(package_names: Sequence[str]) -> Dict[str, str]:
    if not package_names:
        return {}
    placeholders = ", ".join(["%s"] * len(package_names))
    query = (
        "SELECT d.package_name, c.category_name "
        "FROM apps d "
        "JOIN android_app_categories c ON c.category_id = d.category_id "
        f"WHERE d.package_name IN ({placeholders})"
    )

    rows = db_queries.run_sql(query, tuple(package_names), fetch="all", dictionary=True)
    mapping: Dict[str, str] = {}
    if rows:
        for row in rows:
            pkg = str(row.get("package_name") or "").strip()
            category = str(row.get("category_name") or "").strip()
            if pkg and category:
                mapping[pkg] = category
    return mapping


def estimated_files(rows: Sequence[InventoryRow]) -> int:
    total = 0
    for row in rows:
        if row.split_count:
            total += row.split_count
        else:
            total += 1
    return total


def sample_names(rows: Sequence[InventoryRow], limit: int = 3) -> List[str]:
    names: List[str] = []
    for row in rows:
        if len(names) >= limit:
            break
        names.append(row.display_name())
    return names


def collect_exclusion_samples(
    rows: Sequence[InventoryRow], filtered: Sequence[InventoryRow], allow: Set[str]
) -> Dict[str, List[str]]:
    samples: Dict[str, List[str]] = {}
    filtered_set = {row.package_name for row in filtered}
    for row in rows:
        if row.package_name in filtered_set:
            continue
        _, reason = _default_scope_decision(row, allow)
        if not reason:
            continue
        samples.setdefault(reason, []).append(row.display_name())
    for key in list(samples):
        samples[key] = sorted(set(samples[key]))[:5]
    return samples


class _WatchlistEntry:
    def __init__(
        self,
        watchlist: Watchlist,
        filtered: List[InventoryRow],
        excluded: Dict[str, int],
        counts: Dict[str, int],
        preview: str,
    ) -> None:
        self.watchlist = watchlist
        self.filtered = filtered
        self.excluded = excluded
        self.counts = counts
        self.preview = preview

    def summary_row(self) -> Tuple[str, str, str, str]:
        return (
            self.watchlist.name,
            str(self.counts.get("packages", 0)),
            str(self.counts.get("files", 0)),
            self.preview,
        )
