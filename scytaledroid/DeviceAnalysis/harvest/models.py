"""Data models used during APK harvest planning and execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass(frozen=True)
class InventoryRow:
    """Lightweight representation of an inventory entry used for planning."""

    raw: Dict[str, object]
    package_name: str
    app_label: Optional[str]
    installer: Optional[str]
    category: Optional[str]
    primary_path: Optional[str]
    profile: Optional[str]
    version_name: Optional[str]
    version_code: Optional[str]
    apk_paths: List[str] = field(default_factory=list)
    split_count: int = 0


@dataclass(frozen=True)
class ArtifactPlan:
    """Planned artifact pull action for a specific package path."""

    source_path: str
    artifact: str
    file_name: str
    is_split_member: bool


@dataclass
class PackagePlan:
    """Harvest operations planned for a single package."""

    inventory: InventoryRow
    artifacts: List[ArtifactPlan]
    total_paths: int
    policy_filtered_count: int = 0
    policy_filtered_reason: Optional[str] = None
    skip_reason: Optional[str] = None


@dataclass
class HarvestPlan:
    """Complete plan ready for execution."""

    packages: List[PackagePlan]
    policy_filtered: Dict[str, int]
    failures: List[str]


@dataclass
class ArtifactResult:
    """Successful artifact harvest result."""

    file_name: str
    apk_id: int
    dest_path: Path
    source_path: str


@dataclass
class ArtifactError:
    """Details for an artifact that failed to pull."""

    source_path: str
    reason: str


@dataclass
class PullResult:
    """Execution result for a package plan."""

    plan: PackagePlan
    ok: List[ArtifactResult] = field(default_factory=list)
    errors: List[ArtifactError] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)


@dataclass
class ScopeSelection:
    """Scope selection metadata preserved for reruns and summaries."""

    label: str
    packages: List[InventoryRow]
    kind: str
    metadata: Dict[str, object] = field(default_factory=dict)

