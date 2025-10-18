"""Shared data models for static analysis CLI modules."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Mapping, Optional, Tuple

from ..core import StaticAnalysisReport
from ..core.repository import ArtifactGroup


@dataclass(frozen=True)
class ScopeSelection:
    """Represents the scope of a static-analysis run."""

    scope: str
    label: str
    groups: Tuple[ArtifactGroup, ...]


@dataclass(frozen=True)
class RunParameters:
    """User-facing configuration for an analysis run."""

    profile: str
    scope: str
    scope_label: str
    selected_tests: Tuple[str, ...] = tuple()
    evidence_lines: int = 2
    finding_limit: int = 25
    secrets_entropy: float = 4.5
    secrets_hits_per_bucket: int = 40
    secrets_scope: str = "resources"
    strings_mode: str = "both"
    string_max_samples: int = 2
    string_min_entropy: float = 4.8
    string_cleartext_only: bool = False
    workers: str = "auto"
    reuse_cache: bool = True
    log_level: str = "info"
    trace_detectors: Tuple[str, ...] = tuple()
    dry_run: bool = False

    @property
    def profile_label(self) -> str:
        return {
            "metadata": "Metadata",
            "permissions": "Permission analysis",
            "lightweight": "Lightweight",
            "full": "Full",
            "split": "Split-APK composition",
            "custom": "Custom",
        }.get(self.profile, self.profile.title())


@dataclass
class ArtifactOutcome:
    label: str
    report: StaticAnalysisReport
    severity: Counter[str]
    duration_seconds: float
    saved_path: Optional[str]
    started_at: datetime
    finished_at: datetime
    metadata: Mapping[str, object] | None = None


@dataclass
class AppRunResult:
    package_name: str
    category: str
    artifacts: list[ArtifactOutcome] = field(default_factory=list)
    signer: Optional[str] = None

    def severity_totals(self) -> Counter[str]:
        totals: Counter[str] = Counter()
        for artifact in self.artifacts:
            totals.update(artifact.severity)
        return totals

    def base_artifact_outcome(self) -> Optional[ArtifactOutcome]:
        from .sections import extract_integrity_profiles  # localized import

        for artifact in self.artifacts:
            _, _, artifact_profile, _ = extract_integrity_profiles(artifact.report)
            role = str((artifact_profile or {}).get("role") or "").lower()
            if role == "base":
                return artifact
        return self.artifacts[0] if self.artifacts else None

    def base_report(self) -> Optional[StaticAnalysisReport]:
        base_artifact = self.base_artifact_outcome()
        return base_artifact.report if base_artifact else None


@dataclass
class RunOutcome:
    results: list[AppRunResult]
    started_at: datetime
    finished_at: datetime
    scope: ScopeSelection
    base_dir: Path
    warnings: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()


__all__ = ["ScopeSelection", "RunParameters", "ArtifactOutcome", "AppRunResult", "RunOutcome"]
