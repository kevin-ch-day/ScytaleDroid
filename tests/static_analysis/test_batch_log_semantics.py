from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

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


def _resolve_started_at(rows: list[dict[str, object]]) -> str | None:
    if not rows:
        return None
    first = rows[0]
    started_at = first.get("started_at") or first.get("started_at_utc")
    if started_at:
        return str(started_at)
    for row in rows:
        candidate = row.get("started_at") or row.get("started_at_utc")
        if candidate:
            return str(candidate)
    return None


def _write_batch_summary_receipt(
    *,
    batch_summary_path: Path,
    batch_id: str,
    batch_rows: list[dict[str, object]],
    apps_total: int,
    apps_completed: int,
    apps_failed: int,
    ended_at: str | None,
) -> dict[str, object]:
    batch_summary_path.parent.mkdir(parents=True, exist_ok=True)
    started_at = _resolve_started_at(batch_rows)
    payload: dict[str, object] = {
        "batch_id": batch_id,
        "started_at": started_at,
        "ended_at": ended_at,
        "started_at_utc": started_at,
        "ended_at_utc": ended_at,
        "apps_total": apps_total,
        "apps_completed": apps_completed,
        "apps_failed": apps_failed,
        "rows": batch_rows,
    }
    batch_summary_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return payload


def test_write_batch_summary_accepts_started_at_utc(tmp_path: Path) -> None:
    out = tmp_path / "nested" / "batch.json"
    rows = [
        {
            "package_name": "com.example",
            "display_name": "Example",
            "started_at_utc": "2026-02-28T00:00:00Z",
            "completed": True,
        }
    ]
    _write_batch_summary_receipt(
        batch_summary_path=out,
        batch_id="batch-1",
        batch_rows=rows,
        apps_total=1,
        apps_completed=1,
        apps_failed=0,
        ended_at="2026-02-28T00:01:00Z",
    )
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "started_at_utc" in text
    assert "2026-02-28T00:00:00Z" in text


def test_write_batch_summary_accepts_started_at(tmp_path: Path) -> None:
    out = tmp_path / "batch.json"
    rows = [{"started_at": "2026-02-28T00:00:00Z"}]
    _write_batch_summary_receipt(
        batch_summary_path=out,
        batch_id="batch-2",
        batch_rows=rows,
        apps_total=1,
        apps_completed=1,
        apps_failed=0,
        ended_at=None,
    )
    assert out.exists()
