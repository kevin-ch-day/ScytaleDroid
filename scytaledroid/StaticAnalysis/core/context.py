"""Shared context and configuration models for static-analysis detectors."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional, Sequence, TYPE_CHECKING
from xml.etree.ElementTree import Element

if TYPE_CHECKING:  # pragma: no cover - type checking imports only
    from scytaledroid.StaticAnalysis._androguard import APK
    from .findings import DetectorResult
    from .models import (
        ComponentSummary,
        ManifestFlags,
        ManifestSummary,
        PermissionSummary,
    )
    from ..modules.network_security.models import NetworkSecurityPolicy
    from ..modules.string_analysis.extractor import StringIndex


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
    enabled_detectors: Optional[Sequence[str]] = None
    enable_string_index: bool = True
    secrets_sampler: Optional[SecretsSamplerConfig] = None


@dataclass
class DetectorContext:
    """Aggregated context passed to detectors during analysis."""

    apk_path: Path
    apk: "APK"
    manifest_root: Element
    manifest_summary: "ManifestSummary"
    manifest_flags: "ManifestFlags"
    permissions: "PermissionSummary"
    components: "ComponentSummary"
    exported_components: "ComponentSummary"
    features: Sequence[str]
    libraries: Sequence[str]
    signatures: Sequence[str]
    metadata: Mapping[str, object]
    hashes: Mapping[str, str]
    string_index: Optional["StringIndex"] = None
    network_security_policy: Optional["NetworkSecurityPolicy"] = None
    intermediate_results: Sequence["DetectorResult"] = field(default_factory=tuple)
    config: AnalysisConfig = field(default_factory=AnalysisConfig)


__all__ = ["AnalysisConfig", "DetectorContext", "SecretsSamplerConfig"]
