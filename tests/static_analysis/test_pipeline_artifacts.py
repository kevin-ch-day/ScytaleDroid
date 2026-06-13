from __future__ import annotations

from scytaledroid.StaticAnalysis.core.findings import Badge, DetectorResult
from scytaledroid.StaticAnalysis.core.pipeline_artifacts import (
    build_pipeline_summary,
    build_pipeline_trace,
)


def test_build_pipeline_summary_skipped_uses_metrics_summary_when_no_skip_reason() -> None:
    results = (
        DetectorResult(
            detector_id="domain_verification",
            section_key="domain",
            status=Badge.SKIPPED,
            duration_sec=0.0,
            metrics={
                "summary": "Domain verification analysis placeholder",
                "status": "skipped",
                "placeholder_detector": True,
            },
        ),
    )
    summary = build_pipeline_summary(results)
    skipped = summary.get("skipped_detectors")
    placeholders = summary.get("placeholder_detectors")
    assert skipped is None
    assert isinstance(placeholders, list) and len(placeholders) == 1
    assert placeholders[0]["reason"] == "Domain verification analysis placeholder"
    assert summary.get("placeholder_detector_count") == 1


def test_build_pipeline_summary_skipped_prefers_skip_reason_over_summary() -> None:
    results = (
        DetectorResult(
            detector_id="x",
            section_key="s",
            status=Badge.SKIPPED,
            duration_sec=0.0,
            metrics={
                "skip_reason": "profile gate",
                "summary": "placeholder text",
            },
        ),
    )
    summary = build_pipeline_summary(results)
    skipped = summary.get("skipped_detectors")
    assert isinstance(skipped, list) and skipped[0]["reason"] == "profile gate"


def test_build_pipeline_trace_skipped_adds_summary_to_notes() -> None:
    results = (
        DetectorResult(
            detector_id="domain_verification",
            section_key="domain",
            status=Badge.SKIPPED,
            duration_sec=0.0,
            metrics={"summary": "Domain verification analysis placeholder"},
        ),
    )
    trace = build_pipeline_trace(results)
    assert len(trace) == 1
    notes = trace[0].get("notes")
    assert isinstance(notes, tuple)
    assert "Domain verification analysis placeholder" in notes
