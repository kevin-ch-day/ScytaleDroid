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


def test_publish_persisted_artifacts_prepares_required_artifacts_before_validation(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text("{}", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text("{}", encoding="utf-8")
    plan_path = tmp_path / "plan.json"
    plan_path.write_text("{}", encoding="utf-8")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text("{}", encoding="utf-8")
    calls: list[tuple[str, object]] = []
    registry_types = {
        "static_baseline_json",
        "static_dynamic_plan_json",
        "static_report",
        "manifest_evidence",
    }

    def prepare_required_artifacts(static_run_id: int) -> None:
        calls.append(("prepare", static_run_id))
        registry_types.add("dep_snapshot")

    def run_sql(*_a, **_k):
        calls.append(("validate", None))
        return [(artifact_type,) for artifact_type in sorted(registry_types)]

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
            "dep_snapshot",
        ),
        ended_at_utc="2026-04-15T00:00:00Z",
        abort_signal=None,
        write_baseline_json_fn=lambda *_a, **_k: baseline_path,
        write_dynamic_plan_json_fn=lambda *_a, **_k: plan_path,
        governance_ready_fn=lambda: (True, "ok"),
        write_manifest_evidence_fn=lambda *_a, **_k: manifest_path,
        build_artifact_registry_entries_fn=lambda **_k: [],
        record_artifacts_fn=lambda **_k: calls.append(("record", None)),
        prepare_required_artifacts_fn=prepare_required_artifacts,
        run_sql_fn=run_sql,
        refresh_static_run_manifest_fn=lambda *_a, **_k: True,
        finalize_static_run_fn=lambda **kwargs: calls.append(("finalize", kwargs["abort_reason"])),
    )

    assert result.skip_remaining_processing is False
    assert ("prepare", 321) in calls
    assert calls.index(("prepare", 321)) < calls.index(("validate", None))
    assert not any(call[0] == "finalize" for call in calls)


def test_publish_persisted_artifacts_governance_downgrade_does_not_emit_persistence_warnings(
    tmp_path: Path, capsys,
) -> None:
    """MISSING_GOVERNANCE is printed but must not land in warnings (avoids false persistence_failed)."""
    import scytaledroid.StaticAnalysis.cli.execution.artifact_publication as ap

    ap._GOVERNANCE_DOWNGRADE_SHOWN.clear()
    report_path = tmp_path / "report.json"
    report_path.write_text("{}", encoding="utf-8")

    result = publish_persisted_artifacts(
        base_report=SimpleNamespace(metadata={}),
        payload={},
        package_name="com.example.app",
        static_run_id=999,
        profile="full",
        scope="app",
        report_path=report_path,
        paper_grade_requested=True,
        required_paper_artifacts=("static_baseline_json",),
        ended_at_utc="2026-05-01T00:00:00Z",
        abort_signal=None,
        write_baseline_json_fn=lambda *_a, **_k: tmp_path / "baseline.json",
        write_dynamic_plan_json_fn=lambda *_a, **_k: tmp_path / "plan.json",
        governance_ready_fn=lambda: (False, "governance_query_failed:no_db"),
        write_manifest_evidence_fn=lambda *_a, **_k: tmp_path / "manifest.json",
        build_artifact_registry_entries_fn=lambda **_k: [],
        record_artifacts_fn=lambda **_k: None,
        run_sql_fn=lambda *_a, **_k: [],
        refresh_static_run_manifest_fn=lambda *_a, **_k: True,
        finalize_static_run_fn=lambda **_k: None,
    )

    out = capsys.readouterr().out
    assert "Run grade: EXPERIMENTAL (MISSING_GOVERNANCE)" in out
    assert "Core persistence still applies" in out
    assert result.warnings == []


def test_publish_persisted_artifacts_governance_banner_deduped_per_failure_key(
    tmp_path: Path, capsys,
) -> None:
    import scytaledroid.StaticAnalysis.cli.execution.artifact_publication as ap

    ap._GOVERNANCE_DOWNGRADE_SHOWN.clear()
    report_path = tmp_path / "report.json"
    report_path.write_text("{}", encoding="utf-8")
    common = dict(
        base_report=SimpleNamespace(metadata={}),
        payload={},
        static_run_id=1,
        profile="full",
        scope="group",
        report_path=report_path,
        paper_grade_requested=True,
        required_paper_artifacts=("static_baseline_json",),
        ended_at_utc="2026-05-01T00:00:00Z",
        abort_signal=None,
        write_baseline_json_fn=lambda *_a, **_k: tmp_path / "b1.json",
        write_dynamic_plan_json_fn=lambda *_a, **_k: tmp_path / "p1.json",
        governance_ready_fn=lambda: (
            False,
            "governance_query_failed:Dedicated permission-intel DB is not configured.",
        ),
        write_manifest_evidence_fn=lambda *_a, **_k: tmp_path / "m1.json",
        build_artifact_registry_entries_fn=lambda **_k: [],
        record_artifacts_fn=lambda *_k: None,
        run_sql_fn=lambda *_a, **_k: [],
        refresh_static_run_manifest_fn=lambda *_a, **_k: True,
        finalize_static_run_fn=lambda **_k: None,
    )

    publish_persisted_artifacts(package_name="com.one.app", **common)
    publish_persisted_artifacts(package_name="com.two.app", **common)
    out = capsys.readouterr().out
    assert out.count("Run grade: EXPERIMENTAL (MISSING_GOVERNANCE)") == 1
    assert out.count("Dedicated permission-intel DB is not configured") == 1
