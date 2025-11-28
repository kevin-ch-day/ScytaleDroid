from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List


class StaticProfile(str, Enum):
    FULL = "full"
    LIGHTWEIGHT = "lightweight"

    @property
    def label(self) -> str:
        return {
            StaticProfile.FULL: "Full analysis",
            StaticProfile.LIGHTWEIGHT: "Accelerated analysis",
        }[self]

    @property
    def description(self) -> str:
        return {
            StaticProfile.FULL: "Run all detectors, reset caches, emit verification digest.",
            StaticProfile.LIGHTWEIGHT: "Run core detectors for MASVS/risk tracking and persist results.",
        }[self]


@dataclass
class StaticRunConfig:
    profile: StaticProfile
    reset_schema: bool = False

    @classmethod
    def from_menu_choice(cls, choice: str) -> "StaticRunConfig":
        if choice == "2":
            return cls(profile=StaticProfile.LIGHTWEIGHT)
        return cls(profile=StaticProfile.FULL)

    def detectors(self) -> List[str]:
        if self.profile is StaticProfile.FULL:
            return [
                "permissions",
                "strings",
                "webview",
                "nsc",
                "ipc",
                "crypto",
                "sdk",
                "dynload",
                "storage_surface",
            ]
        return ["permissions", "strings", "webview", "ipc", "storage_surface"]
