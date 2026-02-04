"""Shared context and configuration models for static-analysis detectors."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING
from xml.etree.ElementTree import Element

if TYPE_CHECKING:  # pragma: no cover - type checking imports only
    from scytaledroid.StaticAnalysis._androguard import APK

    from ..modules.network_security.models import NetworkSecurityPolicy
    from ..modules.permissions import PermissionCatalog
    from ..modules.string_analysis.extractor import StringIndex
    from .findings import DetectorResult
    from .models import (
        ComponentSummary,
        ManifestFlags,
        ManifestSummary,
        PermissionSummary,
    )


@dataclass(frozen=True)
class SecretsSamplerConfig:
    """Tuning knobs for the secrets detector sampler."""

    entropy_threshold: float = 4.8
    hits_per_bucket: int = 40
    scope: str = "both"


@dataclass(frozen=True)
class AnalysisConfig:
    """Configuration flags controlling a static-analysis run."""

    profile: str = "quick"
    verbosity: str = "summary"
    persistence_mode: str = "json_only"
    analysis_version: str = "2.0.0-alpha"
    enabled_detectors: Sequence[str | None] = None
    enable_string_index: bool = True
    secrets_sampler: SecretsSamplerConfig | None = None


@dataclass
class DetectorContext:
    """Aggregated context passed to detectors during analysis."""

    apk_path: Path
    apk: APK
    manifest_root: Element
    manifest_summary: ManifestSummary
    manifest_flags: ManifestFlags
    permissions: PermissionSummary
    components: ComponentSummary
    exported_components: ComponentSummary
    features: Sequence[str]
    libraries: Sequence[str]
    signatures: Sequence[str]
    metadata: Mapping[str, object]
    hashes: Mapping[str, str]
    string_index: StringIndex | None = None
    network_security_policy: NetworkSecurityPolicy | None = None
    permission_catalog: PermissionCatalog | None = None
    intermediate_results: Sequence[DetectorResult] = field(default_factory=tuple)
    config: AnalysisConfig = field(default_factory=AnalysisConfig)


__all__ = ["AnalysisConfig", "DetectorContext", "SecretsSamplerConfig"]