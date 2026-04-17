import csv
import json
from pathlib import Path


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        return list(r)


def test_write_prevalence_csvs_aggregates_idle_vs_interactive(tmp_path, monkeypatch):
    from scytaledroid.Config import app_config
    from scytaledroid.DynamicAnalysis.ml import evidence_pack_ml_orchestrator as orchestrator

    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path))

    rows = [
        {
            "identity_key": "appA",
            "package_name": "com.example.a",
            "run_id": "rid_idle",
            "phase": "idle",
            "interaction_tag": "",
            "model": "iforest",
            "training_mode": "baseline_only",
            "low_signal": None,
            "windows_total": 10,
            "median": 0.0,
            "p95": 0.0,
            "max": 0.0,
            "anomalous_windows": 2,
            "anomalous_pct": 0.2,
            "threshold_value": 0.0,
            "threshold_percentile": 95,
            "ml_schema_version": 1,
        },
        {
            "identity_key": "appA",
            "package_name": "com.example.a",
            "run_id": "rid_i1",
            "phase": "interactive_a",
            "interaction_tag": "video_call",
            "model": "iforest",
            "training_mode": "baseline_only",
            "low_signal": None,
            "windows_total": 5,
            "median": 0.0,
            "p95": 0.0,
            "max": 0.0,
            "anomalous_windows": 1,
            "anomalous_pct": 0.2,
            "threshold_value": 0.0,
            "threshold_percentile": 95,
            "ml_schema_version": 1,
        },
        {
            "identity_key": "appA",
            "package_name": "com.example.a",
            "run_id": "rid_i2",
            "phase": "interactive_b",
            "interaction_tag": "video_call",
            "model": "iforest",
            "training_mode": "baseline_only",
            "low_signal": None,
            "windows_total": 5,
            "median": 0.0,
            "p95": 0.0,
            "max": 0.0,
            "anomalous_windows": 2,
            "anomalous_pct": 0.4,
            "threshold_value": 0.0,
            "threshold_percentile": 95,
            "ml_schema_version": 1,
        },
    ]

    orchestrator._write_prevalence_csvs(rows)

    main_path = tmp_path / "anomaly_prevalence_per_app_phase.csv"
    appendix_path = tmp_path / "anomaly_prevalence_per_run.csv"

    assert main_path.exists()
    assert appendix_path.exists()

    main = _read_csv(main_path)
    assert len(main) == 2

    idle = next(r for r in main if r["phase"] == "idle")
    inter = next(r for r in main if r["phase"] == "interactive")

    assert int(idle["windows_total"]) == 10
    assert int(idle["windows_flagged"]) == 2
    assert abs(float(idle["flagged_pct"]) - 0.2) < 1e-9

    assert int(inter["windows_total"]) == 10
    assert int(inter["windows_flagged"]) == 3
    assert abs(float(inter["flagged_pct"]) - 0.3) < 1e-9

    appendix = _read_csv(appendix_path)
    assert len(appendix) == len(rows)


def test_write_transport_mix_csvs_weighted_average(tmp_path, monkeypatch):
    from scytaledroid.Config import app_config
    from scytaledroid.DynamicAnalysis.ml import evidence_pack_ml_orchestrator as orchestrator

    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path))

    rows = [
        {
            "package_name": "com.example.a",
            "run_id": "idle1",
            "phase": "idle",
            "interaction_tag": "",
            "tls_ratio": 0.5,
            "quic_ratio": 0.1,
            "tcp_ratio": 0.9,
            "udp_ratio": 0.1,
            "pcap_bytes": 100,
        },
        {
            "package_name": "com.example.a",
            "run_id": "idle2",
            "phase": "idle",
            "interaction_tag": "",
            "tls_ratio": 1.0,
            "quic_ratio": 0.2,
            "tcp_ratio": 0.8,
            "udp_ratio": 0.2,
            "pcap_bytes": 300,
        },
        {
            "package_name": "com.example.a",
            "run_id": "i1",
            "phase": "interactive_a",
            "interaction_tag": "video",
            "tls_ratio": 1.0,
            "quic_ratio": 0.5,
            "tcp_ratio": 0.5,
            "udp_ratio": 0.5,
            "pcap_bytes": 100,
        },
        {
            "package_name": "com.example.a",
            "run_id": "i2",
            "phase": "interactive_b",
            "interaction_tag": "video",
            "tls_ratio": 0.0,
            "quic_ratio": 0.0,
            "tcp_ratio": 1.0,
            "udp_ratio": 0.0,
            "pcap_bytes": 100,
        },
    ]

    orchestrator._write_transport_mix_csvs(rows)

    main_path = tmp_path / "transport_mix_by_phase.csv"
    appendix_path = tmp_path / "transport_mix_per_run.csv"
    assert main_path.exists()
    assert appendix_path.exists()

    main = _read_csv(main_path)
    assert len(main) == 2
    idle = next(r for r in main if r["phase"] == "idle")
    inter = next(r for r in main if r["phase"] == "interactive")

    # Weighted avg: (0.5*100 + 1.0*300) / 400 = 0.875
    assert abs(float(idle["tls_ratio"]) - 0.875) < 1e-9
    assert int(idle["runs_in_phase"]) == 2
    assert int(idle["weight_bytes_total"]) == 400

    # Interactive: weights equal => simple mean == 0.5
    assert abs(float(inter["tls_ratio"]) - 0.5) < 1e-9
    assert int(inter["runs_in_phase"]) == 2
    assert int(inter["weight_bytes_total"]) == 200


def test_paper_artifacts_json_written_once(tmp_path, monkeypatch):
    from scytaledroid.DynamicAnalysis.ml import evidence_pack_ml_orchestrator as orchestrator

    # FREEZE_DIR is a module-level constant; patch it directly for the test.
    freeze_dir = tmp_path / "archive"
    freeze_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(orchestrator, "FREEZE_DIR", freeze_dir)
    # paper_artifacts path is derived at import time; patch it too.
    monkeypatch.setattr(orchestrator, "PAPER_ARTIFACTS_PATH", freeze_dir / "paper_artifacts.json")

    cand1 = orchestrator._ExemplarCandidate(
        run_id="rid1",
        package_name="com.example.a",
        interaction_tag="video",
        ended_at="2026-02-08T00:00:00Z",
        sustained_bytes_per_sec_k6=123.0,
        iforest_flagged_pct=0.5,
        ocsvm_flagged_pct=0.1,
    )
    orchestrator._maybe_write_paper_artifacts_json(candidate=cand1, freeze_manifest_path=Path("data/archive/dataset_freeze.json"))

    path = freeze_dir / "paper_artifacts.json"
    assert path.exists()
    first = json.loads(path.read_text(encoding="utf-8"))
    assert first["fig_B1_run_id"] == "rid1"

    cand2 = orchestrator._ExemplarCandidate(
        run_id="rid2",
        package_name="com.example.b",
        interaction_tag="video",
        ended_at="2026-02-09T00:00:00Z",
        sustained_bytes_per_sec_k6=999.0,
        iforest_flagged_pct=1.0,
        ocsvm_flagged_pct=1.0,
    )
    orchestrator._maybe_write_paper_artifacts_json(candidate=cand2, freeze_manifest_path=Path("data/archive/dataset_freeze.json"))
    second = json.loads(path.read_text(encoding="utf-8"))
    # Must be immutable once written.
    assert second["fig_B1_run_id"] == "rid1"


def test_select_fig_b1_exemplar_skips_bad_pcap_windowing(tmp_path, monkeypatch):
    from scytaledroid.DynamicAnalysis.ml import evidence_pack_ml_orchestrator as orchestrator

    evidence_root = tmp_path / "evidence"
    (evidence_root / "rid1").mkdir(parents=True, exist_ok=True)
    (evidence_root / "rid2").mkdir(parents=True, exist_ok=True)

    def _inputs_for(run_id: str):
        run_dir = evidence_root / run_id
        pcap_path = run_dir / "capture.pcap"
        pcap_path.write_bytes(b"pcap")
        return type(
            "RI",
            (),
            {
                "run_id": run_id,
                "run_dir": run_dir,
                "pcap_path": pcap_path,
                "manifest": {
                    "operator": {"messaging_activity": "video"},
                    "dataset": {"low_signal": False},
                },
                "pcap_report": {},
                "pcap_features": {},
            },
        )()

    inputs_by_rid = {"rid1": _inputs_for("rid1"), "rid2": _inputs_for("rid2")}
    monkeypatch.setattr(orchestrator, "load_run_inputs", lambda path: inputs_by_rid[path.name])
    monkeypatch.setattr(orchestrator, "get_sampling_duration_seconds", lambda _inputs: 60.0)

    def _extract_packet_timeline(path):
        if path.parent.name == "rid1":
            raise RuntimeError("tshark failed")
        return []

    monkeypatch.setattr(orchestrator, "extract_packet_timeline", _extract_packet_timeline)
    monkeypatch.setattr(
        orchestrator,
        "build_window_features",
        lambda _packets, *, duration_s, spec: (
            [{"byte_count": 1200, "window_start_s": 0.0, "window_end_s": 10.0}] * 6,
            0,
        ),
    )
    monkeypatch.setattr(
        orchestrator,
        "_read_scores_and_threshold",
        lambda _path: ([0.9] * 6, 0.5),
    )

    candidate = orchestrator._select_fig_b1_exemplar_from_existing_or_inputs(
        evidence_root=evidence_root,
        freeze_apps={
            "org.telegram.messenger": {
                "baseline_run_ids": ["base"],
                "interactive_run_ids": ["rid1", "rid2"],
            }
        },
        checksums={"rid1": {"ended_at": "2026-01-01T00:00:00Z"}, "rid2": {"ended_at": "2026-01-02T00:00:00Z"}},
    )

    assert candidate is not None
    assert candidate.run_id == "rid2"


def test_new_paper_tables_written(tmp_path, monkeypatch):
    from scytaledroid.Config import app_config
    from scytaledroid.DynamicAnalysis.ml import evidence_pack_ml_orchestrator as orchestrator

    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path))

    dars_rows = [
        {
            "package_name": "com.example.a",
            "run_id": "rid_i1",
            "phase": "interactive_a",
            "interaction_tag": "video",
            "model": "isolation_forest",
            "training_mode": "baseline_only",
            "windows_total_n": 10,
            "threshold_tau": 1.0,
            "operator": ">=",
            "exceedance_n": 2,
            "exceedance_ratio": 0.2,
            "top_k_policy": "ceil_10pct_n",
            "top_k_value": 1,
            "top_k_mean_score": 1.5,
            "severity_ratio": 1.5,
            "dars_v1": 47.5,
            "ml_schema_version": 1,
        }
    ]
    orchestrator._write_dars_components_csv(dars_rows)
    assert (tmp_path / "dars_components_per_run.csv").exists()

    baseline_rows = [
        {
            "package_name": "com.example.a",
            "model": "isolation_forest",
            "training_mode": "baseline_only",
            "baseline_run_id": "rid_b",
            "baseline_windows_n": 30,
            "baseline_score_mean": 0.8,
            "baseline_score_std": 0.2,
            "baseline_score_cv": 0.25,
            "baseline_score_p95": 1.2,
            "baseline_score_min": 0.1,
            "baseline_score_max": 1.5,
            "threshold_tau": 1.0,
            "tau_minus_mean": 0.2,
            "tau_over_mean_abs": 1.25,
            "ml_schema_version": 1,
        }
    ]
    orchestrator._write_baseline_stability_csv(baseline_rows)
    assert (tmp_path / "baseline_score_stability_per_app_model.csv").exists()

    strat_rows = [
        {
            "package_name": "com.example.a",
            "masvs_total_score": 0.72,
            "static_risk_score": 44.0,
            "static_risk_band": "MEDIUM",
            "exported_components_total": 10,
            "dangerous_permission_count": 5,
            "uses_cleartext_traffic": 0,
            "sdk_indicator_score": 0.3,
            "interactive_iforest_runs": 2,
            "interactive_iforest_exceedance_mean": 0.2,
            "interactive_iforest_dars_mean": 41.0,
            "interactive_iforest_dars_max": 47.5,
            "ml_schema_version": 1,
        }
    ]
    orchestrator._write_static_dynamic_stratification_csv(strat_rows)
    assert (tmp_path / "static_dynamic_stratification_per_app.csv").exists()
