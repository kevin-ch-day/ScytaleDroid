"""Core pipeline components for static analysis."""

from .apk_snapshot import ApkSnapshot, build_apk_snapshot
from .context import AnalysisConfig, DetectorContext
from .errors import StaticAnalysisError
from .models import (
    ComponentSummary,
    ManifestFlags,
    ManifestSummary,
    PermissionSummary,
    StaticAnalysisReport,
)
from .pipeline import (
    PIPELINE_STAGES,
    PipelineStage,
    analyze_apk,
)
from .pipeline_artifacts import PipelineArtifacts
from .findings import (
    SeverityLevel,
    MasvsCategory,
    EvidencePointer,
    Finding,
    DetectorResult,
)

__all__ = [
    "ApkSnapshot",
    "AnalysisConfig",
    "DetectorContext",
    "build_apk_snapshot",
    "analyze_apk",
    "ComponentSummary",
    "ManifestFlags",
    "ManifestSummary",
    "PermissionSummary",
    "StaticAnalysisReport",
    "StaticAnalysisError",
    "PipelineStage",
    "PIPELINE_STAGES",
    "PipelineArtifacts",
    "SeverityLevel",
    "MasvsCategory",
    "EvidencePointer",
    "Finding",
    "DetectorResult",
]
