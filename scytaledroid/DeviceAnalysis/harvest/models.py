"""Data models used during APK harvest planning and execution."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class InventoryRow:
    """Lightweight representation of an inventory entry used for planning."""

    raw: dict[str, object]
    package_name: str
    app_label: str | None
    installer: str | None
    category: str | None
    primary_path: str | None
    profile_key: str | None
    profile: str | None
    version_name: str | None
    version_code: str | None
    apk_paths: list[str] = field(default_factory=list)
    split_count: int = 0

    def display_name(self) -> str:
        return (self.app_label or self.package_name).strip()

    def is_play_store_install(self) -> bool:
        """Heuristic: package came from Play Store."""
        return (self.installer or "").strip() == "com.android.vending"

    def is_user_scope_candidate(self) -> bool:
        """Heuristic: /data path indicates user-app scope."""
        return bool(self.primary_path and str(self.primary_path).startswith("/data/"))

    def to_dict(self) -> dict[str, object]:
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
    artifacts: list[ArtifactPlan]
    total_paths: int
    policy_filtered_count: int = 0
    policy_filtered_reason: str | None = None
    skip_reason: str | None = None

    def is_policy_blocked(self) -> bool:
        """True when all paths are filtered by policy."""
        return bool(self.skip_reason) or (self.policy_filtered_count and not self.artifacts)

    def to_dict(self) -> dict[str, object]:
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

    packages: list[PackagePlan]
    policy_filtered: dict[str, int]
    failures: list[str]


@dataclass
class ArtifactResult:
    """Successful artifact harvest result."""

    file_name: str
    apk_id: int | None
    dest_path: Path
    source_path: str
    sha256: str | None = None
    status: str = "written"
    skip_reason: str | None = None
    file_size: int | None = None
    pulled_at: str | None = None
    artifact_label: str | None = None
    is_base: bool | None = None
    observed_source_path: str | None = None
    mirror_failure_reasons: list[str] = field(default_factory=list)


@dataclass
class ArtifactError:
    """Details for an artifact that failed to pull."""

    source_path: str
    reason: str


@dataclass
class PullResult:
    """Execution result for a package plan."""

    plan: PackagePlan
    ok: list[ArtifactResult] = field(default_factory=list)
    errors: list[ArtifactError] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    preflight_reason: str | None = None
    mirror_failure_reasons: list[str] = field(default_factory=list)
    drift_reasons: list[str] = field(default_factory=list)
    capture_status: str | None = None
    persistence_status: str = "not_requested"
    research_status: str = "pending_audit"
    comparison: dict[str, object] = field(default_factory=dict)
    package_manifest_path: Path | None = None


@dataclass
class ArtifactSummary:
    """Lightweight artifact descriptor for summary/logging."""

    file_name: str
    status: str
    dest_path: str | None = None
    sha256: str | None = None
    skip_reason: str | None = None


@dataclass
class PackageHarvestResult:
    """Aggregated harvest outcome for a single package."""

    package_name: str
    app_label: str
    artifacts: list[ArtifactSummary] = field(default_factory=list)
    errors: list[ArtifactError] = field(default_factory=list)
    skipped_reasons: list[str] = field(default_factory=list)
    preflight_reason: str | None = None
    mirror_failure_reasons: list[str] = field(default_factory=list)
    drift_reasons: list[str] = field(default_factory=list)
    capture_status: str | None = None
    persistence_status: str = "not_requested"
    research_status: str = "pending_audit"
    manifest_path: str | None = None

    def display_name(self) -> str:
        return (self.app_label or self.package_name).strip()

    def has_writes(self) -> bool:
        return any(artifact.status == "written" for artifact in self.artifacts)

    def has_errors(self) -> bool:
        return bool(self.errors)

    def to_dict(self) -> dict[str, object]:
        return {
            "package_name": self.package_name,
            "app_label": self.app_label,
            "artifacts": [asdict(a) for a in self.artifacts],
            "errors": [asdict(err) for err in self.errors],
            "skipped_reasons": list(self.skipped_reasons),
            "preflight_reason": self.preflight_reason,
            "mirror_failure_reasons": list(self.mirror_failure_reasons),
            "drift_reasons": list(self.drift_reasons),
            "capture_status": self.capture_status,
            "persistence_status": self.persistence_status,
            "research_status": self.research_status,
            "manifest_path": self.manifest_path,
        }


@dataclass
class HarvestResult:
    """Aggregated harvest run context for summaries/logging."""

    serial: str | None = None
    run_timestamp: str | None = None
    scope_name: str | None = None
    guard_brief: str | None = None
    packages: list[PackageHarvestResult] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
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
    packages: list[InventoryRow]
    kind: str
    metadata: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "kind": self.kind,
            "packages": [pkg.to_dict() for pkg in self.packages],
            "metadata": dict(self.metadata),
        }
