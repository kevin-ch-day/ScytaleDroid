from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult, ArtifactOutcome


def _outcome(*, report: object, saved_path: str | None, is_base: bool = True) -> ArtifactOutcome:
    now = datetime.now(UTC)
    return ArtifactOutcome(
        label="base",
        report=report,  # type: ignore[arg-type]
        severity=Counter(),
        duration_seconds=0.1,
        saved_path=saved_path,
        started_at=now,
        finished_at=now,
        is_base=is_base,
    )


def test_persisted_report_is_released_and_reloaded_transiently(tmp_path, monkeypatch) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text("{}", encoding="utf-8")
    live_report = object()
    reloaded_report = object()
    artifact = _outcome(report=live_report, saved_path=str(report_path))
    app = AppRunResult("com.example", "test", artifacts=[artifact])

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.persistence.reports.load_report",
        lambda path: reloaded_report,
    )

    assert app.release_persisted_reports() == 1
    assert artifact.report is None
    assert app.base_report() is reloaded_report
    assert artifact.report is None


def test_report_is_not_released_without_durable_json(tmp_path) -> None:
    live_report = object()
    artifact = _outcome(report=live_report, saved_path=str(tmp_path / "missing.json"))
    app = AppRunResult("com.example", "test", artifacts=[artifact])

    assert app.release_persisted_reports() == 0
    assert artifact.report is live_report
