"""Guardrails: stage progress observers must not abort the detector pipeline."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from scytaledroid.StaticAnalysis.core import detector_runner
from scytaledroid.StaticAnalysis.core.context import AnalysisConfig
from scytaledroid.StaticAnalysis.core.detector_runner import PipelineStage, run_detector_pipeline
from scytaledroid.StaticAnalysis.core.findings import Badge, DetectorResult
from scytaledroid.StaticAnalysis.detectors.base import BaseDetector


class _FakeQuickOkDetector(BaseDetector):
    detector_id = "fake_quick_ok"
    default_profiles = ("quick", "full")

    def run(self, context):  # noqa: ANN001 - matches BaseDetector
        return DetectorResult(
            detector_id=self.detector_id,
            section_key="fake_sec",
            status=Badge.OK,
            duration_sec=0.0,
        )


class _FakeHeavyDetector(BaseDetector):
    """Used only on the quick-profile skip path (run must not be called)."""

    detector_id = "fake_heavy"
    default_profiles = ("quick", "full")

    def run(self, context):  # noqa: ANN001
        raise AssertionError("detector.run must not be invoked when skipped by quick profile")


class _FakeStringIndexDetector(BaseDetector):
    detector_id = "fake_string_idx"
    default_profiles = ("quick", "full")
    requires_string_index = True

    def run(self, context):  # noqa: ANN001
        raise AssertionError("detector.run must not be invoked when string index is unavailable")


def test_stage_observer_raises_pipeline_still_returns_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        detector_runner,
        "PIPELINE_STAGES",
        (PipelineStage(_FakeQuickOkDetector, "fake_sec", include_in_quick=True),),
    )

    def _boom(_payload: object) -> None:
        raise RuntimeError("observer failed")

    ctx = SimpleNamespace(
        config=AnalysisConfig(profile="full", enabled_detectors=None),
        stage_observer=_boom,
        intermediate_results=(),
    )
    results = run_detector_pipeline(ctx)
    assert len(results) == 1
    assert results[0].detector_id == "fake_quick_ok"
    assert results[0].status == Badge.OK


def test_quick_profile_skip_uses_safe_emit_observer_failure_still_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        detector_runner,
        "PIPELINE_STAGES",
        (PipelineStage(_FakeHeavyDetector, "heavy_sec", include_in_quick=False),),
    )

    def _boom(_payload: object) -> None:
        raise RuntimeError("observer failed on quick skip")

    ctx = SimpleNamespace(
        config=AnalysisConfig(profile="quick", enabled_detectors=None),
        stage_observer=_boom,
        intermediate_results=(),
    )
    results = run_detector_pipeline(ctx)
    assert len(results) == 1
    assert results[0].status == Badge.SKIPPED
    assert results[0].notes == ("skipped by quick profile",)


def test_safe_emit_failure_debug_includes_payload_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str, str, object | None]] = []

    def _fake_debug(
        message: str,
        category: str = "application",
        *,
        extra: object | None = None,
    ) -> None:
        captured.append((message, category, extra))

    monkeypatch.setattr(detector_runner.log, "debug", _fake_debug)

    def _boom(_payload: object) -> None:
        raise ValueError("emit broke")

    detector_runner._safe_emit_progress(
        _boom,
        {
            "event": "stage_end",
            "detector_id": "d1",
            "section_key": "sx",
            "stage_index": 2,
            "status": "skipped",
        },
    )
    assert len(captured) == 1
    msg, category, extra = captured[0]
    assert category == "static_analysis"
    assert "event='stage_end'" in msg
    assert "detector_id='d1'" in msg
    assert "section_key='sx'" in msg
    assert "stage_index=2" in msg
    assert "status='skipped'" in msg
    assert isinstance(extra, dict)
    assert extra == {
        "event": "stage_end",
        "detector_id": "d1",
        "section_key": "sx",
        "stage_index": 2,
        "status": "skipped",
    }


def test_safe_emit_failure_debug_omits_absent_status(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str, str, object | None]] = []

    def _fake_debug(
        message: str,
        category: str = "application",
        *,
        extra: object | None = None,
    ) -> None:
        captured.append((message, category, extra))

    monkeypatch.setattr(detector_runner.log, "debug", _fake_debug)

    def _boom(_payload: object) -> None:
        raise RuntimeError("x")

    detector_runner._safe_emit_progress(
        _boom,
        {
            "event": "stage_start",
            "detector_id": "d0",
            "section_key": "s0",
            "stage_index": 1,
        },
    )
    msg, _, extra = captured[0]
    assert "status" not in msg
    assert isinstance(extra, dict)
    assert "status" not in extra


def test_string_index_required_detector_skips_before_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        detector_runner,
        "PIPELINE_STAGES",
        (PipelineStage(_FakeStringIndexDetector, "string_sec", include_in_quick=True),),
    )

    ctx = SimpleNamespace(
        config=AnalysisConfig(profile="full", enabled_detectors=None),
        stage_observer=None,
        intermediate_results=(),
        string_index=None,
    )

    results = run_detector_pipeline(ctx)
    assert len(results) == 1
    assert results[0].status == Badge.SKIPPED
    assert results[0].notes == ("string index unavailable",)
