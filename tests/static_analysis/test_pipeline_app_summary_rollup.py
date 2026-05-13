"""Tests for per-app pipeline summary roll-up (split artifacts)."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult, ArtifactOutcome
from scytaledroid.StaticAnalysis.cli.execution.scan_report import _summarize_app_pipeline
from scytaledroid.StaticAnalysis.core.findings import Badge, DetectorResult
from scytaledroid.StaticAnalysis.core.models import StaticAnalysisReport


def _minimal_report(
    *,
    detector_results: tuple[DetectorResult, ...],
    pipeline_summary: dict[str, object] | None = None,
) -> StaticAnalysisReport:
    meta: dict[str, object] = {}
    if pipeline_summary is not None:
        meta["pipeline_summary"] = pipeline_summary
    return StaticAnalysisReport(
        file_path="/tmp/x.apk",
        relative_path=None,
        file_name="x.apk",
        file_size=1,
        hashes={"sha256": "0" * 64},
        metadata=meta,
        detector_results=detector_results,
    )


def _dr(det: str, status: Badge) -> DetectorResult:
    return DetectorResult(
        detector_id=det,
        section_key=det,
        status=status,
        duration_sec=0.0,
        metrics={},
        findings=(),
    )


def test_summarize_merges_warn_across_splits_per_detector() -> None:
    """Two artifacts with the same detector WARN should count as one WARN for the package."""
    summary = {
        "detector_total": 3,
        "detector_executed": 3,
        "detector_skipped": 0,
        "total_duration_sec": 1.0,
        "status_counts": {"WARN": 1, "OK": 2},
        "severity_counts": {},
        "policy_fail_detectors": [],
        "finding_fail_detectors": [],
        "error_detectors": [],
    }
    r1 = _minimal_report(
        detector_results=(_dr("manifest", Badge.WARN), _dr("secrets", Badge.OK)),
        pipeline_summary=dict(summary),
    )
    r2 = _minimal_report(
        detector_results=(_dr("manifest", Badge.WARN), _dr("secrets", Badge.OK)),
        pipeline_summary=dict(summary),
    )
    now = datetime.now(UTC)
    app = AppRunResult("com.example.app", "Cat")
    app.artifacts = [
        ArtifactOutcome("base", r1, Counter(), 0.0, None, now, now),
        ArtifactOutcome("split", r2, Counter(), 0.0, None, now, now),
    ]

    out = _summarize_app_pipeline(app)
    assert out["warn_count"] == 1
    assert out["ok_count"] == 1
    assert out["status_counts"]["WARN"] == 1
    assert out["status_counts"]["OK"] == 1


def test_summarize_worst_status_wins_across_splits() -> None:
    summary = {
        "detector_total": 2,
        "detector_executed": 2,
        "detector_skipped": 0,
        "total_duration_sec": 1.0,
        "status_counts": {"OK": 1, "WARN": 1},
        "severity_counts": {},
    }
    r1 = _minimal_report(
        detector_results=(_dr("network_surface", Badge.OK),),
        pipeline_summary=dict(summary),
    )
    r2 = _minimal_report(
        detector_results=(_dr("network_surface", Badge.WARN),),
        pipeline_summary=dict(summary),
    )
    now = datetime.now(UTC)
    app = AppRunResult("com.example.app", "Cat")
    app.artifacts = [
        ArtifactOutcome("a", r1, Counter(), 0.0, None, now, now),
        ArtifactOutcome("b", r2, Counter(), 0.0, None, now, now),
    ]
    out = _summarize_app_pipeline(app)
    assert out["warn_count"] == 1
    assert out["ok_count"] == 0


def test_policy_fail_deduped_across_artifact_summaries() -> None:
    row = {"detector": "integrity_identity", "section": "integrity_identity"}
    summary = {
        "detector_total": 1,
        "detector_executed": 1,
        "detector_skipped": 0,
        "total_duration_sec": 1.0,
        "status_counts": {"OK": 1},
        "severity_counts": {},
        "policy_fail_detectors": [row],
        "finding_fail_detectors": [],
        "error_detectors": [],
    }
    r1 = _minimal_report(
        detector_results=(_dr("integrity_identity", Badge.FAIL),),
        pipeline_summary=dict(summary),
    )
    r2 = _minimal_report(
        detector_results=(_dr("integrity_identity", Badge.FAIL),),
        pipeline_summary=dict(summary),
    )
    now = datetime.now(UTC)
    app = AppRunResult("com.example.app", "Cat")
    app.artifacts = [
        ArtifactOutcome("a", r1, Counter(), 0.0, None, now, now),
        ArtifactOutcome("b", r2, Counter(), 0.0, None, now, now),
    ]
    out = _summarize_app_pipeline(app)
    assert out["policy_fail_count"] == 1
    assert len(out["policy_fail_detectors"]) == 1


def test_fallback_sums_metadata_when_no_detector_results() -> None:
    """Legacy / partial payloads: keep summing ``pipeline_summary.status_counts``."""
    summary = {
        "detector_total": 2,
        "detector_executed": 2,
        "detector_skipped": 0,
        "total_duration_sec": 1.0,
        "status_counts": {"WARN": 1, "OK": 1},
        "severity_counts": {},
    }
    r = _minimal_report(detector_results=(), pipeline_summary=dict(summary))
    now = datetime.now(UTC)
    app = AppRunResult("com.example.app", "Cat")
    app.artifacts = [ArtifactOutcome("only", r, Counter(), 0.0, None, now, now)]
    out = _summarize_app_pipeline(app)
    assert out["warn_count"] == 1
    assert out["ok_count"] == 1
