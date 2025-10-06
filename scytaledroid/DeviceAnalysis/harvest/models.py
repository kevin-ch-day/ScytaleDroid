"""Data models used during APK harvest planning and execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


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

    def display_name(self) -> str:
        return (self.app_label or self.package_name).strip()


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
    apk_id: Optional[int]
    dest_path: Path
    source_path: str
    sha256: Optional[str] = None
    status: str = "written"
    skip_reason: Optional[str] = None


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
class ArtifactSummary:
    """Lightweight artifact descriptor for summary/logging."""

    file_name: str
    status: str
    dest_path: Optional[str] = None
    sha256: Optional[str] = None
    skip_reason: Optional[str] = None


@dataclass
class PackageHarvestResult:
    """Aggregated harvest outcome for a single package."""

    package_name: str
    app_label: str
    artifacts: List[ArtifactSummary] = field(default_factory=list)
    errors: List[ArtifactError] = field(default_factory=list)
    skipped_reasons: List[str] = field(default_factory=list)


@dataclass
class HarvestResult:
    """Aggregated harvest run context for summaries/logging."""

    serial: Optional[str] = None
    run_timestamp: Optional[str] = None
    scope_name: Optional[str] = None
    guard_brief: Optional[str] = None
    packages: List[PackageHarvestResult] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScopeSelection:
    """Scope selection metadata preserved for reruns and summaries."""

    label: str
    packages: List[InventoryRow]
    kind: str
    metadata: Dict[str, object] = field(default_factory=dict)
