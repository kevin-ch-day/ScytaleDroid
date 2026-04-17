from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from scytaledroid.DynamicAnalysis.ml.query_mode_phases import (
    prepare_group_training_inputs,
    prepare_query_selection_groups,
)
from scytaledroid.DynamicAnalysis.ml.selectors.models import SelectionResult, RunRef
from scytaledroid.DynamicAnalysis.ml.telemetry_windowing import WindowSpec


def _mk_ref(tmp_path: Path, run_id: str, *, base_sha: str | None = None) -> RunRef:
    evidence_dir = tmp_path / run_id
    evidence_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = evidence_dir / "run_manifest.json"
    manifest_path.write_text("{}", encoding="utf-8")
    return RunRef(
        run_id=run_id,
        evidence_dir=evidence_dir,
        manifest_path=manifest_path,
        manifest_sha256="a" * 64,
        package_name="com.example.app",
        base_apk_sha256=base_sha,
        mode="interactive",
        mode_source="test",
        run_profile="interactive_use",
        started_at_utc=None,
        ended_at_utc=None,
    )


def _mk_run(tmp_path: Path, run_id: str) -> SimpleNamespace:
    run_dir = tmp_path / run_id
    pcap_path = run_dir / "capture.pcap"
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    pcap_path.write_bytes(b"\x00\x01")
    return SimpleNamespace(
        run_id=run_id,
        package_name="com.example.app",
        run_dir=run_dir,
        pcap_path=pcap_path,
        pcap_report={"pcap_size_bytes": 2},
        pcap_features={},
        manifest={"dataset": {}, "target": {"package_name": "com.example.app", "version_code": "123"}},
        plan={"run_identity": {"static_handoff_hash": "x" * 64}},
    )


def test_prepare_query_selection_groups_excludes_missing_static_link(tmp_path, monkeypatch):
    import scytaledroid.DynamicAnalysis.ml.query_mode_phases as phase_module

    selection = SelectionResult(
        selector_type="freeze",
        query_params={},
        grouping_key="base_apk_sha256",
        pool_versions=False,
        included=[_mk_ref(tmp_path, "r1", base_sha="b" * 64)],
        excluded={},
    )
    monkeypatch.setattr(
        phase_module,
        "load_run_inputs",
        lambda _path: SimpleNamespace(
            plan={"run_identity": {}},
            package_name="com.example.app",
        ),
    )
    excluded: list[tuple[str, str]] = []

    prepared = prepare_query_selection_groups(
        selection=selection,
        paper_mode=True,
        exclude_run=lambda run_id, _pkg, reason, _details, _minw, _minb: excluded.append((run_id, reason)),
        min_windows_baseline_req=5,
        min_pcap_bytes_req_default=100,
    )

    assert prepared.groups == {}
    assert prepared.skipped_runs == 1
    assert excluded == [("r1", "ML_SKIPPED_MISSING_STATIC_LINK")]


def test_prepare_group_training_inputs_uses_union_fallback_in_query_mode(tmp_path, monkeypatch):
    import scytaledroid.DynamicAnalysis.ml.query_mode_phases as phase_module

    baseline = _mk_run(tmp_path, "b1")
    interactive = _mk_run(tmp_path, "i1")
    monkeypatch.setattr(
        phase_module,
        "derive_run_mode",
        lambda run: ("baseline", "test") if run.run_id == "b1" else ("interactive", "test"),
    )
    monkeypatch.setattr(phase_module, "get_sampling_duration_seconds", lambda _run: 60.0)
    monkeypatch.setattr(phase_module, "compute_ml_preflight", lambda _run: {"ok": True})
    monkeypatch.setattr(phase_module, "write_ml_preflight", lambda _path, _payload: None)
    monkeypatch.setattr(phase_module, "extract_packet_timeline", lambda _path: [])
    monkeypatch.setattr(
        phase_module,
        "build_window_features",
        lambda _packets, *, duration_s, spec: ([{"window_start_s": 0.0, "window_end_s": 10.0, "byte_count": 1, "packet_count": 1, "avg_packet_size_bytes": 1}], 0),
    )

    prepared, stats = prepare_group_training_inputs(
        group_key="com.example.app",
        runs=[baseline, interactive],
        snapshot_dir=tmp_path / "snapshot",
        paper_mode=False,
        min_windows_baseline_req=10,
        min_pcap_bytes_req_default=1,
        window_spec=WindowSpec(window_size_s=10.0, stride_s=5.0),
        run_output_dir=lambda run_id: tmp_path / "snapshot" / run_id / "ml",
        exclude_run=lambda *_args, **_kwargs: None,
    )

    assert prepared is not None
    assert prepared.training_mode == "union_fallback"
    assert stats.groups_union_fallback == 1
    assert stats.groups_skipped_baseline_gate_fail == 0


def test_prepare_group_training_inputs_fail_closes_in_paper_mode(tmp_path, monkeypatch):
    import scytaledroid.DynamicAnalysis.ml.query_mode_phases as phase_module

    baseline = _mk_run(tmp_path, "b1")
    interactive = _mk_run(tmp_path, "i1")
    monkeypatch.setattr(
        phase_module,
        "derive_run_mode",
        lambda run: ("baseline", "test") if run.run_id == "b1" else ("interactive", "test"),
    )
    monkeypatch.setattr(phase_module, "get_sampling_duration_seconds", lambda _run: 60.0)
    monkeypatch.setattr(phase_module, "compute_ml_preflight", lambda _run: {"ok": True})
    monkeypatch.setattr(phase_module, "write_ml_preflight", lambda _path, _payload: None)
    monkeypatch.setattr(phase_module, "extract_packet_timeline", lambda _path: [])
    monkeypatch.setattr(
        phase_module,
        "build_window_features",
        lambda _packets, *, duration_s, spec: ([{"window_start_s": 0.0, "window_end_s": 10.0, "byte_count": 1, "packet_count": 1, "avg_packet_size_bytes": 1}], 0),
    )
    excluded: list[tuple[str, str]] = []

    prepared, stats = prepare_group_training_inputs(
        group_key="com.example.app",
        runs=[baseline, interactive],
        snapshot_dir=tmp_path / "snapshot",
        paper_mode=True,
        min_windows_baseline_req=10,
        min_pcap_bytes_req_default=1,
        window_spec=WindowSpec(window_size_s=10.0, stride_s=5.0),
        run_output_dir=lambda run_id: tmp_path / "snapshot" / run_id / "ml",
        exclude_run=lambda run_id, _pkg, reason, _details, _minw, _minb: excluded.append((run_id, reason)),
    )

    assert prepared is None
    assert stats.groups_skipped_baseline_gate_fail == 1
    assert stats.runs_skipped == 2
    assert excluded == [
        ("b1", "ML_SKIPPED_BASELINE_GATE_FAIL"),
        ("i1", "ML_SKIPPED_BASELINE_GATE_FAIL"),
    ]
