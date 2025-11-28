from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class InventoryMode(str, Enum):
    BASELINE = "baseline"
    USER_ONLY = "user_only"
    BULK = "bulk"
    INCREMENTAL = "incremental"

    @property
    def label(self) -> str:
        return {
            InventoryMode.BASELINE: "Baseline (all packages)",
            InventoryMode.USER_ONLY: "User apps only",
            InventoryMode.BULK: "Bulk (faster, lower fidelity)",
            InventoryMode.INCREMENTAL: "Incremental (changed packages only)",
        }[self]

    @property
    def description(self) -> str:
        return {
            InventoryMode.BASELINE: "Scan full inventory with standard precision.",
            InventoryMode.USER_ONLY: "Focus on user-installed / Play / sideload apps.",
            InventoryMode.BULK: "Faster scan with reduced metadata; for large fleets.",
            InventoryMode.INCREMENTAL: "Scan only packages that changed since last snapshot.",
        }[self]

    @classmethod
    def from_str(cls, raw: str) -> "InventoryMode":
        raw_norm = (raw or "").strip().lower()
        try:
            return cls(raw_norm)
        except ValueError:
            return cls.BASELINE


@dataclass
class InventoryConfig:
    mode: InventoryMode = InventoryMode.BASELINE
    user_handle: Optional[int] = None

    @classmethod
    def from_env(cls) -> "InventoryConfig":
        raw_mode = os.getenv("SCYTALEDROID_INVENTORY_MODE", InventoryMode.BASELINE.value)
        return cls(mode=InventoryMode.from_str(raw_mode))

    def is_user_only(self) -> bool:
        return self.mode is InventoryMode.USER_ONLY

    def is_full_inventory(self) -> bool:
        return self.mode in (InventoryMode.BASELINE, InventoryMode.BULK)

    def staleness_threshold_hours(self) -> int:
        return 24

    def brief(self) -> str:
        return f"{self.mode.value} — {self.mode.label}"
