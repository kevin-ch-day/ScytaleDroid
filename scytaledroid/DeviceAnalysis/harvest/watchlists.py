"""Watchlist helpers for curated APK harvest selections."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence, TYPE_CHECKING

from scytaledroid.Utils.LoggingUtils import logging_utils as log


if TYPE_CHECKING:  # pragma: no cover - import for type checkers only
    from .models import InventoryRow


WATCHLIST_DIR = Path("data/watchlists")


@dataclass(frozen=True)
class Watchlist:
    """Curated list of packages used to seed harvest scopes."""

    name: str
    packages: List[str]
    path: Path

    @property
    def slug(self) -> str:
        return re.sub(r"[^a-zA-Z0-9_-]+", "_", self.name.lower()).strip("_") or "watchlist"


_CACHE: List[Watchlist] | None = None


def reset_watchlist_cache() -> None:
    """Invalidate cached watchlist data (used after saving)."""

    global _CACHE
    _CACHE = None


def load_watchlists() -> List[Watchlist]:
    """Return all watchlists discovered under ``data/watchlists``."""

    global _CACHE
    if _CACHE is not None:
        return list(_CACHE)

    watchlists: List[Watchlist] = []
    for path in WATCHLIST_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning(f"Failed to parse watchlist {path}: {exc}", category="device")
            continue

        name = str(data.get("name") or path.stem).strip()
        raw_packages = data.get("packages")
        if not isinstance(raw_packages, Iterable):
            log.warning(
                f"Watchlist {path} is missing a valid 'packages' array.", category="device"
            )
            continue

        packages = [str(pkg).strip() for pkg in raw_packages if str(pkg).strip()]
        if not packages:
            continue

        watchlists.append(Watchlist(name=name, packages=packages, path=path))

    _CACHE = sorted(watchlists, key=lambda w: w.name.lower())
    return list(_CACHE)


def save_watchlist(name: str, packages: Sequence[str], *, overwrite: bool = False) -> Path:
    """Persist a watchlist definition to disk and return the file path."""

    WATCHLIST_DIR.mkdir(parents=True, exist_ok=True)
    watchlist_name = name.strip() or "Watchlist"
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", watchlist_name.lower()).strip("_") or "watchlist"
    path = WATCHLIST_DIR / f"{slug}.json"

    unique_packages = sorted({pkg.strip() for pkg in packages if str(pkg).strip()})
    data = {"name": watchlist_name, "packages": unique_packages}

    if path.exists() and not overwrite:
        raise FileExistsError(path)

    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    reset_watchlist_cache()
    return path


def filter_rows_by_watchlist(
    rows: Sequence["InventoryRow"], packages: Iterable[str]
) -> List["InventoryRow"]:
    package_set = {pkg.lower() for pkg in packages}
    return [row for row in rows if row.package_name.lower() in package_set]


__all__ = [
    "Watchlist",
    "filter_rows_by_watchlist",
    "load_watchlists",
    "reset_watchlist_cache",
    "save_watchlist",
]
