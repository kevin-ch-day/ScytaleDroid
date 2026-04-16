from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.execution.artifact_publication import (
    publish_persisted_artifacts,
)


def test_publish_persisted_artifacts_fails_closed_when_required_artifact_missing(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text("{}", encoding="utf-8")
    calls: list[tuple[str, object]] = []

    result = publish_persisted_artifacts(
        base_report=SimpleNamespace(metadata={}),
        payload={},
        package_name="com.example.app",
        static_run_id=321,
        profile="full",
        scope="app",
        report_path=report_path,
        paper_grade_requested=True,
        required_paper_artifacts=(
            "static_baseline_json",
            "static_dynamic_plan_json",
            "static_report",
            "manifest_evidence",
        ),
        ended_at_utc="2026-04-15T00:00:00Z",
        abort_signal=None,
        write_baseline_json_fn=lambda *_a, **_k: None,
        write_dynamic_plan_json_fn=lambda *_a, **_k: None,
        governance_ready_fn=lambda: (True, "ok"),
        write_manifest_evidence_fn=lambda *_a, **_k: None,
        build_artifact_registry_entries_fn=lambda **_k: [],
        record_artifacts_fn=lambda **_k: calls.append(("record", None)),
        run_sql_fn=lambda *_a, **_k: [("static_report",)],
        refresh_static_run_manifest_fn=lambda *_a, **_k: calls.append(("refresh", None)),
        finalize_static_run_fn=lambda **kwargs: calls.append(("finalize", kwargs["abort_reason"])),
    )

    assert result.skip_remaining_processing is True
    assert any("static_baseline_json" in warning for warning in result.warnings)
    assert ("finalize", "missing_required_artifacts") in calls
    assert ("refresh", None) not in calls
