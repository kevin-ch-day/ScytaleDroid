from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.detail import collect_findings
from scytaledroid.StaticAnalysis.cli.models import AppRunResult, ArtifactOutcome
from scytaledroid.StaticAnalysis.core.findings import SeverityLevel


def _make_artifact_with_finding(section: str, location: str) -> ArtifactOutcome:
    severity_gate = SeverityLevel.P1
    evidence_pointer = SimpleNamespace(location=location, description=None)
    finding = SimpleNamespace(
        severity_gate=severity_gate,
        finding_id="TEST-002",
        title="Duplicate diff",
        because="Reason",
        evidence=[evidence_pointer],
        remediate="Fix",
    )
    detector = SimpleNamespace(
        section_key=section,
        detector_id="diff_exported",
        findings=[finding],
    )
    report = SimpleNamespace(detector_results=[detector])
    return ArtifactOutcome(
        label="base",
        report=report,
        severity=Counter({"M": 1}),
        duration_seconds=0.1,
        saved_path=None,
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        metadata={},
    )


def test_collect_findings_deduplicates_duplicates():
    artifact_a = _make_artifact_with_finding("diff", "AndroidManifest.xml")
    artifact_b = _make_artifact_with_finding("diff", "AndroidManifest.xml")
    app_result = AppRunResult("com.example", "Test", artifacts=[artifact_a, artifact_b])

    grouped = collect_findings(app_result, evidence_lines=1)
    entries = grouped.get("diff", [])
    assert len(entries) == 1
    assert entries[0]["id"] == "TEST-002"
