import math

from scytaledroid.StaticAnalysis.analytics import (
    build_finding_matrices,
    build_workload_profile,
)
from scytaledroid.StaticAnalysis.core.findings import (
    Badge,
    DetectorResult,
    Finding,
    MasvsCategory,
    SeverityLevel,
)


def make_finding(
    finding_id: str,
    *,
    severity: SeverityLevel,
    category: MasvsCategory,
    status: Badge,
    metrics: dict[str, object] | None = None,
    tags: tuple[str, ...] = (),
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title="example",
        severity_gate=severity,
        category_masvs=category,
        status=status,
        because="because",
        evidence=tuple(),
        metrics=metrics or {},
        tags=tags,
    )


def test_build_finding_matrices_tracks_matrices_and_indicators():
    finding = make_finding(
        "F-1",
        severity=SeverityLevel.P0,
        category=MasvsCategory.NETWORK,
        status=Badge.FAIL,
        metrics={"protection_level": "Dangerous"},
        tags=("ipc",),
    )
    result = DetectorResult(
        detector_id="ipc_components",
        section_key="ipc",
        status=Badge.FAIL,
        duration_sec=1.2,
        findings=(finding,),
    )

    matrices, indicators = build_finding_matrices((result,))

    assert matrices["severity_by_category"]["NETWORK"]["P0"] == 1
    assert matrices["guard_strength_by_severity"]["dangerous"]["P0"] == 1
    assert matrices["tags_by_severity"]["ipc"]["P0"] == 1
    assert "novelty_index" in indicators
    assert indicators["novelty_index"] >= 0.0


def test_build_workload_profile_classifies_runtimes():
    finding = make_finding(
        "F-2",
        severity=SeverityLevel.P1,
        category=MasvsCategory.PRIVACY,
        status=Badge.WARN,
    )
    fast_result = DetectorResult(
        detector_id="fast",
        section_key="privacy",
        status=Badge.OK,
        duration_sec=0.2,
        findings=tuple(),
    )
    slow_result = DetectorResult(
        detector_id="slow",
        section_key="privacy",
        status=Badge.WARN,
        duration_sec=2.5,
        findings=(finding,),
    )

    profile = build_workload_profile((fast_result, slow_result))

    assert profile["summary"]["total_findings"] == 1
    assert math.isclose(profile["summary"]["total_duration_sec"], 2.7)
    assert profile["detector_load"]["slow"]["status"] in {"elevated", "critical"}
    assert profile["detector_load"]["fast"]["status"] in {"idle", "baseline"}
