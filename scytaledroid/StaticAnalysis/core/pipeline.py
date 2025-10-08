"""Core helpers for running static analysis on APK artifacts."""

from __future__ import annotations

from time import perf_counter
from pathlib import Path
from typing import Mapping, Optional, Sequence

from .apk_snapshot import build_apk_snapshot
from .context import AnalysisConfig
from .findings import Badge, DetectorResult, EvidencePointer, Finding
from .models import (
    ComponentSummary,
    ManifestFlags,
    ManifestSummary,
    PermissionSummary,
    StaticAnalysisReport,
)
from .pipeline_artifacts import assemble_pipeline_artifacts


def make_detector_result(
    *,
    detector_id: str,
    section_key: str,
    status: Badge,
    started_at: float,
    findings: Sequence[Finding] | None = None,
    metrics: Mapping[str, object] | None = None,
    evidence: Sequence[EvidencePointer] | None = None,
    notes: Sequence[str] | None = None,
    subitems: Sequence[Mapping[str, object]] | None = None,
    raw_debug: Optional[str] = None,
) -> DetectorResult:
    """Build a deterministic :class:`DetectorResult` instance."""

    duration = max(0.0, round(perf_counter() - started_at, 1))
    metrics_payload = dict(metrics or {})
    evidence_payload = tuple(evidence or ())
    notes_payload = tuple(note for note in notes or () if note)
    findings_payload = tuple(findings or ())
    if subitems:
        subitems_payload = tuple(dict(item) for item in subitems)
    else:
        subitems_payload = None

    return DetectorResult(
        detector_id=detector_id,
        section_key=section_key,
        status=status,
        duration_sec=duration,
        metrics=metrics_payload,
        evidence=evidence_payload,
        notes=notes_payload,
        findings=findings_payload,
        subitems=subitems_payload,
        raw_debug=raw_debug,
    )


from .detector_runner import PIPELINE_STAGES, PipelineStage, run_detector_pipeline


def analyze_apk(
    apk_path: Path,
    *,
    metadata: Optional[Mapping[str, object]] = None,
    storage_root: Optional[Path] = None,
    config: Optional[AnalysisConfig] = None,
) -> StaticAnalysisReport:
    """Run lightweight static analysis on *apk_path* and return a report."""

    snapshot = build_apk_snapshot(
        apk_path,
        metadata=metadata,
        storage_root=storage_root,
        config=config,
    )

    context = snapshot.build_context()
    pipeline_results = run_detector_pipeline(context)
    context.intermediate_results = tuple(pipeline_results)
    artifacts = assemble_pipeline_artifacts(context)

    detector_results = artifacts.results
    report_metadata = dict(snapshot.metadata)

    if artifacts.trace:
        report_metadata["pipeline_trace"] = artifacts.trace
    if artifacts.summary:
        report_metadata["pipeline_summary"] = artifacts.summary
        compliance_payload = artifacts.summary.get("masvs_compliance")
        if compliance_payload:
            report_metadata["masvs_compliance"] = compliance_payload
    if artifacts.reproducibility_bundle:
        report_metadata["repro_bundle"] = artifacts.reproducibility_bundle

    findings = tuple(
        finding for result in detector_results for finding in result.findings
    )
    detector_metrics = dict(artifacts.metrics)

    return StaticAnalysisReport(
        file_path=str(snapshot.apk_path.resolve()),
        relative_path=snapshot.relative_path,
        file_name=snapshot.apk_path.name,
        file_size=snapshot.file_size,
        hashes=snapshot.hashes,
        manifest=snapshot.manifest,
        manifest_flags=snapshot.manifest_flags,
        permissions=snapshot.permissions,
        components=snapshot.components,
        exported_components=snapshot.exported_components,
        features=snapshot.features,
        libraries=snapshot.libraries,
        signatures=snapshot.signatures,
        metadata=report_metadata,
        scan_profile=snapshot.config.profile,
        analysis_version=snapshot.config.analysis_version,
        findings=findings,
        detector_metrics=detector_metrics,
        detector_results=detector_results,
    )


__all__ = [
    "PipelineStage",
    "PIPELINE_STAGES",
    "StaticAnalysisReport",
    "ManifestSummary",
    "ManifestFlags",
    "PermissionSummary",
    "ComponentSummary",
    "analyze_apk",
    "make_detector_result",
]
