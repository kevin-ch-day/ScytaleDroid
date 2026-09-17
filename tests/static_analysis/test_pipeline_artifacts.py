from __future__ import annotations

from types import SimpleNamespace
from xml.etree import ElementTree

from scytaledroid.StaticAnalysis.core.findings import Badge, DetectorResult
from scytaledroid.StaticAnalysis.core.pipeline_artifacts import (
    build_pipeline_summary,
    build_pipeline_trace,
    build_reproducibility_bundle,
)


def test_reproducibility_bundle_binds_string_payload_without_duplicate_embedding() -> None:
    payload = {"samples": {"urls": ["https://example.test/a"] * 100}}
    context = SimpleNamespace(
        metadata={"post_run_string_payload": payload, "session_stamp": "session-1"},
        manifest_summary=SimpleNamespace(
            to_dict=lambda: {},
            version_name=None,
            version_code=None,
            min_sdk=None,
            target_sdk=None,
            compile_sdk=None,
        ),
        manifest_flags=SimpleNamespace(to_dict=lambda: {}),
        permissions=SimpleNamespace(
            to_dict=lambda: {}, declared=(), dangerous=(), custom=(), custom_definitions={}
        ),
        components=SimpleNamespace(to_dict=lambda: {}),
        exported_components=SimpleNamespace(to_dict=lambda: {}),
        manifest_root=ElementTree.Element("manifest"),
        hashes={},
        features=(),
        libraries=(),
        signatures=(),
        network_security_policy=None,
        string_index=None,
        intermediate_results=(),
    )

    bundle = build_reproducibility_bundle(context)
    metadata = bundle["metadata"]

    assert metadata["session_stamp"] == "session-1"
    assert metadata["post_run_string_payload_embedded"] is False
    assert len(metadata["post_run_string_payload_sha256"]) == 64
    assert "post_run_string_payload" not in metadata


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
    coverage = summary.get("measurement_coverage")
    assert isinstance(coverage, dict)
    assert coverage["planned_stage_count"] == 1
    assert coverage["implemented_stage_count"] == 0
    assert coverage["placeholder_stage_count"] == 1
    assert coverage["implemented_stage_execution_rate"] is None


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
    assert summary["non_placeholder_skip_class_counts"] == {"other": 1}


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
