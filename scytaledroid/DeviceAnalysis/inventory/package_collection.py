"""ADB package collection and enrichment (UI-free)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Protocol, Tuple, List


class ProgressCallback(Protocol):
    def __call__(
        self,
        processed: int,
        total: int,
        elapsed_seconds: float,
        eta_seconds: Optional[float],
        split_apks: int,
    ) -> None:
        ...


@dataclass
class PackageRow:
    """Normalized representation of an installed package."""

    package_name: str
    version_name: str | None
    version_code: int | None
    installer: str | None
    partition: str | None
    category_name: str | None = None
    profile_name: str | None = None
    app_label: str | None = None
    split_count: int = 1
    paths: List[str] | None = None
    extras: dict | None = None


@dataclass
class CollectionStats:
    total_packages: int
    split_packages: int
    new_packages: int
    removed_packages: int
    elapsed_seconds: float


def collect_inventory(
    serial: str,
    *,
    filter_fn: Optional[Callable[[PackageRow], bool]] = None,
    progress_cb: Optional[ProgressCallback] = None,
) -> Tuple[List[PackageRow], CollectionStats]:
    """
    Collect inventory rows from ADB and enrich them with canonical metadata.

    NOTE: This is a placeholder; the existing logic from inventory.py should be
    migrated here. This function must not print UI.
    """
    raise NotImplementedError("collect_inventory must be implemented from existing logic.")

