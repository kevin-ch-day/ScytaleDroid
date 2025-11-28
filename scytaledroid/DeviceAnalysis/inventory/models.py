"""Domain models for inventory snapshots and deltas (forensic-friendly)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Mapping, Optional, Sequence


@dataclass
class PackageRecord:
    """Normalized view of a package discovered during inventory."""

    package_name: str
    label: str
    install_source: str
    role: str  # User / OEM / System / Mainline / Vendor / Unknown
    partition: str  # /data, /product, /system, /apex, /vendor, Other/Unknown
    is_split: bool = False
    is_user_scope_candidate: bool = False
    metadata: Mapping[str, object] = field(default_factory=dict)


@dataclass
class InventorySnapshot:
    """In-memory representation of an inventory snapshot."""

    device_serial: str
    created_at: datetime
    mode_key: str
    packages: List[PackageRecord]

    def total_packages(self) -> int:
        return len(self.packages)

    def split_apk_packages(self) -> int:
        return sum(1 for p in self.packages if p.is_split)

    def user_scope_candidates(self) -> List[PackageRecord]:
        return [p for p in self.packages if p.is_user_scope_candidate]

    def by_field_counts(self, attr: str) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for pkg in self.packages:
            key = getattr(pkg, attr, None) or "Unknown"
            counts[str(key)] = counts.get(str(key), 0) + 1
        return counts


@dataclass
class InventoryDelta:
    """Delta between two snapshots."""

    current: InventorySnapshot
    previous: Optional[InventorySnapshot]
    new_packages: Sequence[PackageRecord]
    removed_packages: Sequence[PackageRecord]
    updated_packages: Sequence[PackageRecord]

    @classmethod
    def from_snapshots(
        cls,
        current: InventorySnapshot,
        previous: Optional[InventorySnapshot],
    ) -> InventoryDelta:
        prev_map = {p.package_name: p for p in (previous.packages if previous else [])}
        curr_map = {p.package_name: p for p in current.packages}

        new: List[PackageRecord] = []
        removed: List[PackageRecord] = []
        updated: List[PackageRecord] = []

        for name, pkg in curr_map.items():
            prev = prev_map.get(name)
            if prev is None:
                new.append(pkg)
            elif pkg.metadata != prev.metadata:
                updated.append(pkg)

        for name, pkg in prev_map.items():
            if name not in curr_map:
                removed.append(pkg)

        return cls(
            current=current,
            previous=previous,
            new_packages=new,
            removed_packages=removed,
            updated_packages=updated,
        )

    def summary_counts(self) -> Dict[str, int]:
        return {
            "new": len(self.new_packages),
            "removed": len(self.removed_packages),
            "updated": len(self.updated_packages),
        }
