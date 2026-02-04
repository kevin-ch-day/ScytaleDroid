from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class HarvestPullMode(StrEnum):
    QUICK = "quick"
    FULL = "full"
    TEST = "test"

    @property
    def label(self) -> str:
        return {
            HarvestPullMode.QUICK: "Quick pull",
            HarvestPullMode.FULL: "Full pull",
            HarvestPullMode.TEST: "Test pull",
        }[self]

    @property
    def description(self) -> str:
        return {
            HarvestPullMode.QUICK: "Resolve paths via pm; fast, recommended.",
            HarvestPullMode.FULL: "Use inventory snapshot paths; slower but deterministic.",
            HarvestPullMode.TEST: "Dry run: list planned artifacts only, no downloads.",
        }[self]

    @property
    def hint(self) -> str:
        return {
            HarvestPullMode.QUICK: "Uses live pm path; ignores stale apk_paths.",
            HarvestPullMode.FULL: "Useful when validating inventory snapshots.",
            HarvestPullMode.TEST: "Safe preview for large scopes.",
        }[self]


@dataclass
class HarvestModeConfig:
    mode: HarvestPullMode

    @classmethod
    def from_menu_choice(cls, choice: str) -> HarvestModeConfig:
        return {
            "1": cls(HarvestPullMode.QUICK),
            "2": cls(HarvestPullMode.FULL),
            "3": cls(HarvestPullMode.TEST),
        }.get(choice, cls(HarvestPullMode.QUICK))

    def use_inventory_paths(self) -> bool:
        return self.mode is HarvestPullMode.FULL

    def is_dry_run(self) -> bool:
        return self.mode is HarvestPullMode.TEST
