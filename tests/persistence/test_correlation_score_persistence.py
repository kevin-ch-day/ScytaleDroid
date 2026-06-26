from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.persistence import assembly
from scytaledroid.StaticAnalysis.core.findings import Badge, Finding, MasvsCategory, SeverityLevel


def _finding(*, metrics: dict[str, object] | None = None) -> Finding:
    return Finding(
        finding_id="corr-test",
        title="Correlation test finding",
        severity_gate=SeverityLevel.P1,
        category_masvs=MasvsCategory.OTHER,
        status=Badge.WARN,
        because="test",
        metrics=metrics or {},
    )


def test_score_from_finding_uses_integer_metrics_score(monkeypatch) -> None:
    monkeypatch.setattr(assembly, "_finding_weight_score", lambda finding: 999)
    assert assembly.score_from_finding(_finding(metrics={"score": 37})) == 37


def test_score_from_finding_uses_numeric_string_metrics_score(monkeypatch) -> None:
    monkeypatch.setattr(assembly, "_finding_weight_score", lambda finding: 999)
    assert assembly.score_from_finding(_finding(metrics={"score": "41"})) == 41


def test_score_from_finding_preserves_explicit_zero(monkeypatch) -> None:
    monkeypatch.setattr(assembly, "_finding_weight_score", lambda finding: 999)
    assert assembly.score_from_finding(_finding(metrics={"score": 0})) == 0


def test_score_from_finding_falls_back_when_metrics_score_missing(monkeypatch) -> None:
    monkeypatch.setattr(assembly, "_finding_weight_score", lambda finding: 17)
    assert assembly.score_from_finding(_finding(metrics={})) == 17


def test_score_from_finding_falls_back_when_metrics_score_invalid(monkeypatch) -> None:
    monkeypatch.setattr(assembly, "_finding_weight_score", lambda finding: 19)
    assert assembly.score_from_finding(_finding(metrics={"score": "not-a-number"})) == 19


def test_score_from_finding_returns_finding_weight_when_metrics_score_unusable(monkeypatch) -> None:
    monkeypatch.setattr(assembly, "_finding_weight_score", lambda finding: 82)
    assert assembly.score_from_finding(_finding(metrics={"score": None})) == 82
