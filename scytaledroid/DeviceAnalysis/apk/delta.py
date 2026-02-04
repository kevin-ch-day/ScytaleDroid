"""Delta helpers for filtering APK pull scopes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


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
                names.add(entry)

    updated = summary.get("updated_full") or summary.get("updated")
    if isinstance(updated, Sequence):
        for entry in updated:
            if isinstance(entry, Mapping):
                candidate = entry.get("package")
                if isinstance(candidate, str) and candidate:
                    names.add(candidate)

    # Explicitly ignore removed packages (nothing to harvest)
    return names


def apply_delta_filter(package_rows: Sequence[Any], *, include: set[str]) -> list[Any]:
    """Return a filtered list of rows based on a delta package set."""

    if not include:
        return list(package_rows)
    return [row for row in package_rows if getattr(row, "package_name", None) in include]
