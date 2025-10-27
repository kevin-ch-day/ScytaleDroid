"""Utilities to refresh the Android framework permission catalog."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Mapping

import yaml

from scytaledroid.StaticAnalysis.modules.permissions.catalog import discover_catalog_paths
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Database.db_func.permissions import framework_permissions


def _load_catalog(path: Path) -> Iterable[Mapping[str, object]]:
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, list):
        raise ValueError("framework permissions YAML must contain a list")
    return [entry for entry in data if isinstance(entry, dict)]


def _expand_catalog_path(path: Path) -> list[Path]:
    if path.is_dir():
        files: list[Path] = []
        for pattern in ("*.yaml", "*.yml"):
            files.extend(sorted(path.glob(pattern)))
        return files
    return [path]


def refresh_framework_catalog(catalog_path: Path | None = None) -> None:
    """Populate ``android_framework_permissions`` from a YAML catalog."""

    candidate_paths: list[Path] = []
    if catalog_path is not None:
        candidate_paths.extend(_expand_catalog_path(catalog_path))
    else:
        candidate_paths.extend(discover_catalog_paths())

    candidate_paths = [path for path in candidate_paths if path.exists()]

    if not candidate_paths:
        print(status_messages.status("No permission catalog files found. Nothing to refresh.", level="warn"))
        return

    records: list[Mapping[str, object]] = []
    for path in candidate_paths:
        try:
            for entry in _load_catalog(path):
                payload = dict(entry)
                payload.setdefault("source", path.stem)
                records.append(payload)
        except Exception as exc:  # pragma: no cover - defensive
            print(status_messages.status(f"Unable to load catalog {path}: {exc}", level="error"))

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
