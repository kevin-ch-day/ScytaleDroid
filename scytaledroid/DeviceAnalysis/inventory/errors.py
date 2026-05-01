from __future__ import annotations

from dataclasses import dataclass


@dataclass
class InventoryCollectionError(RuntimeError):
    """Raised when a package fails during inventory collection."""

    package: str
    index: int
    total: int
    stage: str
    original: Exception

    def __str__(self) -> str:  # pragma: no cover - stringification
        prefix = (
            f"Inventory collection failed at package={self.package} "
            f"idx={self.index}/{self.total} stage={self.stage}"
        )
        return f"{prefix}: {self.original}"