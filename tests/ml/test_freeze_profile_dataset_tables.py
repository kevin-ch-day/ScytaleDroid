from __future__ import annotations

from pathlib import Path

import pytest
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as config
from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_preflight import RunInputs
from scytaledroid.DynamicAnalysis.ml.freeze_profile import dataset_tables as dt


def _run_inputs(
    *,
    run_id: str = "run-1",
    run_profile: str = "baseline_idle",
    manifest: dict | None = None,
    pcap_report: dict | None = None,
    pcap_features: dict | None = None,
    pcap_path: Path | None = None,
    plan: dict | None = None,
) -> RunInputs:
    return RunInputs(
        run_id=run_id,
        run_dir=Path("/tmp") / run_id,
        manifest=manifest or {},
        plan=plan,
        summary={"telemetry": {"stats": {"sampling_duration_seconds": 500}}},
        pcap_report=pcap_report,
        pcap_features=pcap_features,
        pcap_path=pcap_path,
        identity_key="pkg|1|sha",
        package_name="com.example.app",
        run_profile=run_profile,
    )


def test_phase_rows_include_empty_window_metrics() -> None:
    run = _run_inputs(manifest={"dataset": {"low_signal": True}})

    rows = dt.compute_phase_rows(
        identity_key="pkg|1|sha",
        package_name="com.example.app",
        app_runs=[run],
        per_model_scores_by_run={config.MODEL_IFOREST: {"run-1": [0.1, 0.5, 0.9]}},
        per_model_thresholds={config.MODEL_IFOREST: 0.5},
        per_run_phase={},
        per_run_tag={"run-1": "voice"},
        training_mode="baseline_only",
        per_run_empty_windows={"run-1": 1},
    )

    assert len(rows) == 1
    row = rows[0]
    assert row["phase"] == "idle"
    assert row["interaction_tag"] == "voice"
    assert row["duration_s"] == 500.0
    assert row["duration_tier"] == "extended"
    assert row["duration_tier_label"] == "Extended"
    assert row["anomalous_windows"] == 2
    assert row["empty_windows"] == 1
    assert row["empty_windows_pct"] == pytest.approx(1 / 3)
    assert row["low_signal"] is True


def test_transport_ratios_clamp_overlapping_protocol_hierarchy() -> None:
    run = _run_inputs(
        pcap_report={
            "protocol_hierarchy": [
                {"protocol": "tcp", "bytes": 100},
                {"protocol": "tls", "bytes": 500},
                {"protocol": "udp", "bytes": 50},
                {"protocol": "quic", "bytes": 120},
            ]
        }
    )

    tls, quic, tcp, udp = dt.transport_ratios_from_inputs(run)

    assert tls == 1.0
    assert quic == 1.0
    assert tcp == pytest.approx(100 / 150)
    assert udp == pytest.approx(50 / 150)


def test_pcap_size_prefers_report_then_file(tmp_path: Path) -> None:
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"12345")

    assert dt.pcap_size_bytes_from_inputs(_run_inputs(pcap_report={"pcap_size_bytes": "99"}, pcap_path=pcap)) == 99
    assert dt.pcap_size_bytes_from_inputs(_run_inputs(pcap_report={}, pcap_path=pcap)) == 5


def test_write_prevalence_csvs_aggregates_idle_and_interactive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dt.app_config, "DATA_DIR", str(tmp_path))

    dt.write_prevalence_csvs(
        [
            {
                "identity_key": "pkg|1|sha",
                "package_name": "com.example.app",
                "run_id": "idle-1",
                "phase": "idle",
                "interaction_tag": "",
                "duration_s": 240.0,
                "duration_tier": "standard",
                "duration_tier_label": "Standard",
                "model": config.MODEL_IFOREST,
                "training_mode": "baseline_only",
                "is_fallback_mode": False,
                "low_signal": False,
                "windows_total": 2,
                "empty_windows": 1,
                "empty_windows_pct": 0.5,
                "median": 0.1,
                "p95": 0.2,
                "max": 0.2,
                "anomalous_windows": 1,
                "anomalous_pct": 0.5,
                "threshold_value": 0.2,
                "threshold_percentile": 95.0,
                "ml_schema_version": 2,
            },
            {
                "identity_key": "pkg|1|sha",
                "package_name": "com.example.app",
                "run_id": "interactive-1",
                "phase": "interactive_a",
                "interaction_tag": "video",
                "duration_s": 901.0,
                "duration_tier": "long_observation",
                "duration_tier_label": "Long observation",
                "model": config.MODEL_IFOREST,
                "training_mode": "baseline_only",
                "is_fallback_mode": False,
                "low_signal": False,
                "windows_total": 3,
                "empty_windows": 0,
                "empty_windows_pct": 0.0,
                "median": 0.3,
                "p95": 0.8,
                "max": 0.9,
                "anomalous_windows": 2,
                "anomalous_pct": 2 / 3,
                "threshold_value": 0.2,
                "threshold_percentile": 95.0,
                "ml_schema_version": 2,
            },
        ]
    )

    main = (tmp_path / "anomaly_prevalence_per_app_phase.csv").read_text(encoding="utf-8")
    assert "com.example.app,idle" in main
    assert "com.example.app,interactive" in main
    assert ",0.5,baseline_only," in main
    assert ",0.6666666666666666,baseline_only," in main
    appendix = (tmp_path / "anomaly_prevalence_per_run.csv").read_text(encoding="utf-8")
    assert "duration_tier" in appendix
    assert "interactive-1,interactive_a,video,901.0,long_observation,Long observation" in appendix
