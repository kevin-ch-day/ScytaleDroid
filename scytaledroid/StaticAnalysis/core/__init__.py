"""Core pipeline components for static analysis."""

from __future__ import annotations

from importlib import import_module

_LAZY_EXPORTS = {
    "AnalysisConfig": (".context", "AnalysisConfig"),
    "DetectorContext": (".context", "DetectorContext"),
    "SecretsSamplerConfig": (".context", "SecretsSamplerConfig"),
    "StaticAnalysisError": (".errors", "StaticAnalysisError"),
    "DetectorResult": (".findings", "DetectorResult"),
    "EvidencePointer": (".findings", "EvidencePointer"),
    "Finding": (".findings", "Finding"),
    "MasvsCategory": (".findings", "MasvsCategory"),
    "SeverityLevel": (".findings", "SeverityLevel"),
    "ComponentSummary": (".models", "ComponentSummary"),
    "ManifestFlags": (".models", "ManifestFlags"),
    "ManifestSummary": (".models", "ManifestSummary"),
    "PermissionSummary": (".models", "PermissionSummary"),
    "StaticAnalysisReport": (".models", "StaticAnalysisReport"),
    "PIPELINE_STAGES": (".pipeline", "PIPELINE_STAGES"),
    "PipelineStage": (".pipeline", "PipelineStage"),
    "analyze_apk": (".pipeline", "analyze_apk"),
    "PipelineArtifacts": (".pipeline_artifacts", "PipelineArtifacts"),
}


def __getattr__(name: str) -> object:
    if name not in _LAZY_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr_name = _LAZY_EXPORTS[name]
    module = import_module(module_name, __name__)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


__all__ = [
    "AnalysisConfig",
    "DetectorContext",
    "SecretsSamplerConfig",
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
