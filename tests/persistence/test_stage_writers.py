from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.persistence.stage_writers import (
    persist_metrics_and_sections_stage,
    persist_permission_and_storage_stage,
)


def test_persist_permission_and_storage_stage_handles_missing_metadata_map() -> None:
    calls: dict[str, object] = {}
    stage_context = SimpleNamespace(
        package_for_run="com.example.app",
        base_report=SimpleNamespace(detector_metrics={}),
        session_stamp="sess-1",
        scope_label="all",
        metadata_map=None,
        metrics_bundle=SimpleNamespace(contributors=[]),
        baseline_payload={},
    )
    findings_context = SimpleNamespace(control_summary=None, total_findings=0, control_entry_count=0)

    persist_permission_and_storage_stage(
        run_id=99,
        static_run_id=None,
        stage_context=stage_context,
        findings_context=findings_context,
        raise_db_error=lambda stage, message: (_ for _ in ()).throw(AssertionError(f"{stage}:{message}")),
        persist_masvs_controls=lambda *_a, **_k: None,
        persist_storage_surface_data=lambda *_a, **_k: None,
        persist_permission_matrix=lambda **kwargs: calls.setdefault("matrix", kwargs),
        persist_permission_risk=lambda **kwargs: calls.setdefault("risk", kwargs),
        safe_int=lambda value: int(value) if value is not None else None,
    )

    assert calls["matrix"]["apk_id"] == 99
    assert calls["risk"]["run_id"] == 99


def test_persist_metrics_and_sections_stage_writes_static_sections_only() -> None:
    noted: list[str] = []
    stage_context = SimpleNamespace(
        package_for_run="com.example.app",
        session_stamp="sess-1",
        scope_label="all",
        metrics_bundle=SimpleNamespace(contributors=[]),
        baseline_payload={"baseline": {"string_analysis": {"samples": []}}, "app": {}},
        manifest_obj=SimpleNamespace(package_name="com.example.app"),
    )
    metrics_context = SimpleNamespace(metrics_payload={"score": 1})
    findings_context = SimpleNamespace(persisted_totals={"total": 0})
    outcome = SimpleNamespace(baseline_written=False, string_samples_persisted=0)

    persist_metrics_and_sections_stage(
        run_id=None,
        static_run_id=22,
        stage_context=stage_context,
        metrics_context=metrics_context,
        findings_context=findings_context,
        outcome=outcome,
        note_db_error=noted.append,
        raise_db_error=lambda stage, message: (_ for _ in ()).throw(RuntimeError(f"{stage}:{message}")),
        persist_static_sections_wrapper=lambda **_kwargs: ([], True, 3),
    )
    assert outcome.baseline_written is True
    assert outcome.string_samples_persisted == 3
    assert not noted


