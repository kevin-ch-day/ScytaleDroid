"""Core pipeline components for static analysis."""

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
from .findings import (
    SeverityLevel,
    MasvsCategory,
    EvidencePointer,
    Finding,
    DetectorResult,
)

__all__ = [
    "AnalysisConfig",
    "DetectorContext",
    "analyze_apk",
    "ComponentSummary",
    "ManifestFlags",
    "ManifestSummary",
    "PermissionSummary",
    "StaticAnalysisReport",
    "StaticAnalysisError",
    "PipelineStage",
    "PIPELINE_STAGES",
    "SeverityLevel",
    "MasvsCategory",
    "EvidencePointer",
    "Finding",
    "DetectorResult",
]
