import json
import csv
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
