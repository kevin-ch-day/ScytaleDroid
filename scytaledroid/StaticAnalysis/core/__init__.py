"""Core pipeline components for static analysis."""

from .context import AnalysisConfig, DetectorContext
from .pipeline import analyze_apk, StaticAnalysisReport, StaticAnalysisError
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
    "StaticAnalysisReport",
    "StaticAnalysisError",
    "SeverityLevel",
    "MasvsCategory",
    "EvidencePointer",
    "Finding",
    "DetectorResult",
]
