"""Delta helpers for filtering APK pull scopes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

try:
    # Prefer the shared normalizer when DB utilities are available.
    from scytaledroid.Database.db_utils.package_utils import normalize_package_name  # type: ignore
except Exception:  # pragma: no cover - clean machines may not have DB deps installed
    from scytaledroid.Utils.LoggingUtils import logging_utils as log

    _SUSPICIOUS_TOKENS = ("/", "\\", "=", "base.apk")

    def normalize_package_name(value: str, *, context: str = "inventory") -> str:
        cleaned = (value or "").strip().lower()
        if not cleaned:
            return ""
        suspicious = (" " in cleaned) or any(token in cleaned for token in _SUSPICIOUS_TOKENS)
        if suspicious:
            log.warning(
                f"Suspicious package_name '{value}' encountered; normalizing to '{cleaned}'.",
                category=context,
            )
        elif cleaned.endswith(".apk"):
            log.warning(
                f"package_name '{value}' ends with .apk; allowing but flagging for review.",
                category=context,
            )
        return cleaned


def extract_delta_summary(snapshot_rows: Mapping[str, object]) -> Mapping[str, object] | None:
    """Return the most relevant delta summary available for the current scope."""

    summary = snapshot_rows.get("package_delta_summary") if isinstance(snapshot_rows, Mapping) else None
    if isinstance(summary, Mapping) and summary.get("total_changed"):
        return summary
    alternate = snapshot_rows.get("package_delta") if isinstance(snapshot_rows, Mapping) else None
    if isinstance(alternate, Mapping) and alternate.get("total_changed"):
        return alternate
    return None


def collect_delta_package_names(summary: Mapping[str, object]) -> set[str]:
    """Extract the set of package names that should be harvested based on a delta summary."""

    names: set[str] = set()
    added = summary.get("added_full") or summary.get("added")
    if isinstance(added, Sequence):
        for entry in added:
            if isinstance(entry, str) and entry:
                canonical = normalize_package_name(entry, context="inventory")
                if canonical:
                    names.add(canonical)

    updated = summary.get("updated_full") or summary.get("updated")
    if isinstance(updated, Sequence):
        for entry in updated:
            if isinstance(entry, Mapping):
                candidate = entry.get("package")
                if isinstance(candidate, str) and candidate:
                    canonical = normalize_package_name(candidate, context="inventory")
                    if canonical:
                        names.add(canonical)

    # Explicitly ignore removed packages (nothing to harvest)
    return names


def apply_delta_filter(package_rows: Sequence[Any], *, include: set[str]) -> list[Any]:
    """Return a filtered list of rows based on a delta package set."""

    if not include:
        return list(package_rows)
    filtered: list[Any] = []
    for row in package_rows:
        name = getattr(row, "package_name", None)
        if not isinstance(name, str):
            continue
        canonical = normalize_package_name(name, context="inventory")
        if canonical in include:
            filtered.append(row)
    return filtered
