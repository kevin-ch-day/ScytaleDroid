from __future__ import annotations

from dataclasses import dataclass

from scytaledroid.StaticAnalysis.cli.batch.log_semantics import (
    BatchStageLevel,
    BatchWarnKind,
    summarize_stage_levels,
)


@dataclass
class FakeMetrics:
    policy_gate: bool = False


@dataclass
class FakeDetectorResult:
    status: str
    section_key: str
    metrics: object | None = None


@dataclass
class FakeReport:
    detector_results: list[FakeDetectorResult]


@dataclass
class FakeArtifact:
    report: FakeReport


@dataclass
class FakeAppResult:
    artifacts: list[FakeArtifact]


def test_batch_stage_level_mapping() -> None:
    res_warn = FakeDetectorResult(status="WARN", section_key="manifest_hygiene")
    res_fail_finding = FakeDetectorResult(
        status="FAIL", section_key="ipc_components", metrics=FakeMetrics(policy_gate=False)
    )
    res_fail_policy = FakeDetectorResult(
        status="FAIL", section_key="correlation_findings", metrics=FakeMetrics(policy_gate=True)
    )
    res_err = FakeDetectorResult(status="ERROR", section_key="native_jni")
    assert BatchStageLevel.from_detector_result(res_warn) == BatchStageLevel.WARN
    assert BatchStageLevel.from_detector_result(res_fail_finding) == BatchStageLevel.FINDING
    assert BatchStageLevel.from_detector_result(res_fail_policy) == BatchStageLevel.POLICY_FAIL
    assert BatchStageLevel.from_detector_result(res_err) == BatchStageLevel.ERROR


def test_warn_collapse_prefers_base_only() -> None:
    base = FakeArtifact(report=FakeReport(detector_results=[FakeDetectorResult(status="WARN", section_key="webview")]))
    split = FakeArtifact(report=FakeReport(detector_results=[FakeDetectorResult(status="WARN", section_key="webview")]))
    app = FakeAppResult(artifacts=[base, split])

    def _resolver(artifact: FakeArtifact) -> str:
        return "base" if artifact is base else "split_x"

    lines = summarize_stage_levels(app, artifact_set_resolver=_resolver)
    webview = next(item for item in lines if item.section == "webview")
    assert webview.level == BatchStageLevel.WARN
    assert webview.warn_kind == BatchWarnKind.RISK
    assert set(webview.artifact_sets) == {"base"}
    assert webview.format().startswith("RISK")


def test_warn_kind_evidence_from_reason_codes() -> None:
    res = FakeDetectorResult(
        status="WARN",
        section_key="correlation_findings",
        metrics={"reason_codes": ["not_applicable:baseline_missing"]},
    )
    app = FakeAppResult(artifacts=[FakeArtifact(report=FakeReport(detector_results=[res]))])
    lines = summarize_stage_levels(app, artifact_set_resolver=lambda _a: "base")
    item = lines[0]
    assert item.level == BatchStageLevel.WARN
    assert item.warn_kind == BatchWarnKind.EVIDENCE
    assert item.format().startswith("EVIDENCE_WARN")
    assert "not_applicable:baseline_missing" in item.format()
