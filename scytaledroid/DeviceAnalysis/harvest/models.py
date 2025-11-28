"""Data models used during APK harvest planning and execution."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
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

    def is_play_store_install(self) -> bool:
        """Heuristic: package came from Play Store."""
        return (self.installer or "").strip() == "com.android.vending"

    def is_user_scope_candidate(self) -> bool:
        """Heuristic: /data path indicates user-app scope."""
        return bool(self.primary_path and str(self.primary_path).startswith("/data/"))

    def to_dict(self) -> Dict[str, object]:
        """Shallow dict for logging/serialization."""
        return asdict(self)


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

    def is_policy_blocked(self) -> bool:
        """True when all paths are filtered by policy."""
        return bool(self.skip_reason) or (self.policy_filtered_count and not self.artifacts)

    def to_dict(self) -> Dict[str, object]:
        return {
            "inventory": self.inventory.to_dict(),
            "artifacts": [asdict(a) for a in self.artifacts],
            "total_paths": self.total_paths,
            "policy_filtered_count": self.policy_filtered_count,
            "policy_filtered_reason": self.policy_filtered_reason,
            "skip_reason": self.skip_reason,
        }


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

    def display_name(self) -> str:
        return (self.app_label or self.package_name).strip()

    def has_writes(self) -> bool:
        return any(artifact.status == "written" for artifact in self.artifacts)

    def has_errors(self) -> bool:
        return bool(self.errors)

    def to_dict(self) -> Dict[str, object]:
        return {
            "package_name": self.package_name,
            "app_label": self.app_label,
            "artifacts": [asdict(a) for a in self.artifacts],
            "errors": [asdict(err) for err in self.errors],
            "skipped_reasons": list(self.skipped_reasons),
        }


@dataclass
class HarvestResult:
    """Aggregated harvest run context for summaries/logging."""

    serial: Optional[str] = None
    run_timestamp: Optional[str] = None
    scope_name: Optional[str] = None
    guard_brief: Optional[str] = None
    packages: List[PackageHarvestResult] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "serial": self.serial,
            "run_timestamp": self.run_timestamp,
            "scope_name": self.scope_name,
            "guard_brief": self.guard_brief,
            "packages": [pkg.to_dict() for pkg in self.packages],
            "meta": dict(self.meta),
        }


@dataclass
class ScopeSelection:
    """Scope selection metadata preserved for reruns and summaries."""

    label: str
    packages: List[InventoryRow]
    kind: str
    metadata: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "label": self.label,
            "kind": self.kind,
            "packages": [pkg.to_dict() for pkg in self.packages],
            "metadata": dict(self.metadata),
        }
