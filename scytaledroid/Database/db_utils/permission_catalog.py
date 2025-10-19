"""Utilities to refresh the Android framework permission catalog."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Mapping

import yaml

from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Database.db_func.permissions import framework_permissions


DEFAULT_CATALOG_PATHS = (
    Path("config/framework_permissions.yaml"),
    Path("data/config/framework_permissions.yaml"),
)


def _load_catalog(path: Path) -> Iterable[Mapping[str, object]]:
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, list):
        raise ValueError("framework permissions YAML must contain a list")
    return [entry for entry in data if isinstance(entry, dict)]


def refresh_framework_catalog(catalog_path: Path | None = None) -> None:
    """Populate ``android_framework_permissions`` from a YAML catalog."""

    path = catalog_path
    if path is None:
        for candidate in DEFAULT_CATALOG_PATHS:
            if candidate.exists():
                path = candidate
                break
    if path is None:
        print(status_messages.status("No framework_permissions.yaml found. Nothing to refresh.", level="warn"))
        return

    try:
        records = list(_load_catalog(path))
    except Exception as exc:  # pragma: no cover - defensive
        print(status_messages.status(f"Unable to load catalog: {exc}", level="error"))
        return

    if not records:
        print(status_messages.status("Framework permission catalog is empty; aborting.", level="warn"))
        return

    framework_permissions.ensure_table()
    upserted = framework_permissions.upsert_permissions(records, source="yaml", limit=None)
    total = framework_permissions.count_rows() or 0
    print(status_messages.status(
        f"Upserted {upserted} framework permissions (catalog now {total} rows).",
        level="info",
    ))


__all__ = ["refresh_framework_catalog"]
