"""Delta helpers for inventory metadata."""

from __future__ import annotations

from collections.abc import Sequence

from scytaledroid.Database.db_utils.package_utils import normalize_package_name

from .normalizers import display_version, normalise_version_code


def build_package_delta_summary(
    snapshot_packages: Sequence[dict[str, object]] | None,
    current_signatures: Sequence[tuple[str, str | None, str | None]],
    *,
    limit: int | None = 5,
) -> dict[str, object | None]:
    if not snapshot_packages:
        return None

    previous_map: dict[str, dict[str, str | None]] = {}
    for entry in snapshot_packages:
        if not isinstance(entry, dict):
            continue
        name = entry.get("package_name")
        if not isinstance(name, str) or not name:
            continue
        canonical_name = normalize_package_name(name, context="inventory")
        if not canonical_name:
            continue
        previous_map[canonical_name] = {
            "version_code": normalise_version_code(entry.get("version_code")),
            "version_name": entry.get("version_name") if isinstance(entry.get("version_name"), str) else None,
        }

    current_map: dict[str, dict[str, str | None]] = {}
    for name, version_code, version_name in current_signatures:
        if not isinstance(name, str) or not name:
            continue
        canonical_name = normalize_package_name(name, context="inventory")
        if not canonical_name:
            continue
        current_map[canonical_name] = {
            "version_code": normalise_version_code(version_code),
            "version_name": version_name if isinstance(version_name, str) else None,
        }

    if not previous_map and not current_map:
        return None

    previous_names = set(previous_map)
    current_names = set(current_map)

    added = sorted(current_names - previous_names)
    removed = sorted(previous_names - current_names)
    updated: list[dict[str, str | None]] = []
    for name in sorted(previous_names & current_names):
        previous_entry = previous_map.get(name) or {}
        current_entry = current_map.get(name) or {}
        previous_token = display_version(
            previous_entry.get("version_code"), previous_entry.get("version_name")
        )
        current_token = display_version(
            current_entry.get("version_code"), current_entry.get("version_name")
        )
        if previous_token == current_token:
            continue
        updated.append(
            {
                "package": name,
                "before": previous_token,
                "after": current_token,
            }
        )

    total_added = len(added)
    total_removed = len(removed)
    total_updated = len(updated)
    total_changed = total_added + total_removed + total_updated
    if total_changed == 0:
        return None

    summary: dict[str, object] = {
        "total_added": total_added,
        "total_removed": total_removed,
        "total_updated": total_updated,
        "total_changed": total_changed,
    }

    summary["added_full"] = added
    summary["removed_full"] = removed
    summary["updated_full"] = updated

    if limit is not None:
        if added:
            summary["added"] = added[:limit]
        if removed:
            summary["removed"] = removed[:limit]
        if updated:
            summary["updated"] = updated[:limit]

    return summary
