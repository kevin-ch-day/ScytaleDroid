"""DynamicAnalysis analysis-layer contracts (merged from former micro-modules).

Former files: ``test_netstats_calibration``, ``test_privacy_manifest``,
``test_feature_health_gate``, ``test_drift_detector``, ``test_probe_policy``,
``test_rbm_generator``, ``test_agreement``, ``test_contrastive``, ``test_state_evaluator``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from scytaledroid.DynamicAnalysis.analysis.agreement import AgreementInputs, arbitrate
from scytaledroid.DynamicAnalysis.analysis.contrastive_testing import (
    evaluate_contrastive,
    js_divergence,
    wasserstein_distance,
)
from scytaledroid.DynamicAnalysis.analysis.drift_detector import detect_drift
from scytaledroid.DynamicAnalysis.analysis.netstats_calibration import calibrate_netstats
from scytaledroid.DynamicAnalysis.analysis.probe_policy import select_adaptive_probes
from scytaledroid.DynamicAnalysis.analysis.privacy_manifest import (
    validate_privacy_manifest,
    write_privacy_manifest,
)
from scytaledroid.DynamicAnalysis.analysis.rbm_generator import RBMPoint, generate_rbm
from scytaledroid.DynamicAnalysis.analysis.state_evaluator import WindowFeatures, evaluate_state
from scytaledroid.DynamicAnalysis.exports.feature_health import build_feature_health_report


# --- netstats_calibration ---


def test_netstats_calibration_invalid():
    result = calibrate_netstats(pcap_bins=[100, 100], netstats_bins=[0, 0])
    assert result.status == "invalid"


# --- privacy_manifest ---


def test_privacy_manifest_roundtrip(tmp_path: Path):
    path = write_privacy_manifest(tmp_path)
    assert validate_privacy_manifest(path) is True


# --- feature_health ---


def test_feature_health_gate_fail(tmp_path: Path):
    telemetry_dir = tmp_path / "telemetry"
    telemetry_dir.mkdir()
    sample = telemetry_dir / "run-network.csv"
    sample.write_text("bytes_in,bytes_out\n0,0\n0,0\n", encoding="utf-8")
    report = build_feature_health_report(telemetry_dir, tmp_path)
    assert report["gating"]["status"] == "FAIL"


# --- drift_detector ---


def test_drift_detector_sustained():
    decision = detect_drift(
        baseline_dist=[0.9, 0.1],
        current_dist=[0.2, 0.8],
        state_proportions_js=0.2,
        js_threshold=0.1,
        wasserstein_threshold=0.05,
    )
    assert decision.decision in {"sustained", "rebaseline_candidate"}


# --- probe_policy ---


def test_probe_policy_uncertainty():
    probes = select_adaptive_probes(
        uncertainty_score=0.5,
        heartbeat_vs_sync_threshold=0.2,
        novel_mode_detected=False,
        now=datetime.now(UTC),
    )
    assert probes


# --- rbm_generator ---


def test_rbm_generator(tmp_path: Path):
    points = [
        RBMPoint(ts=0.0, state="idle", confidence=0.9, bytes_in=0.0, bytes_out=0.0, cpu_pct=1.0),
        RBMPoint(ts=1.0, state="heartbeat", confidence=0.7, bytes_in=100.0, bytes_out=50.0, cpu_pct=2.0),
    ]
    outputs = generate_rbm("run123", points, tmp_path)
    assert outputs["json"].exists()
    assert outputs["png"].exists()
    assert outputs["html"].exists()


# --- agreement ---


def test_arbitration_pcap_only():
    decision = arbitrate(
        AgreementInputs(
            lag_seconds=0.5,
            magnitude_ratio=0.9,
            pcap_present=True,
            netstats_present=False,
            cpu_pct=5.0,
        )
    )
    assert decision.decision == "pcap_only"
    assert "netstats_missing_use_pcap" in decision.reasons


# --- contrastive_testing ---


def test_contrastive_evaluation():
    js = js_divergence([0.1, 0.9], [0.8, 0.2])
    w = wasserstein_distance([1, 2, 3], [10, 11, 12])
    result = evaluate_contrastive(
        js_value=js,
        wasserstein_value=w,
        effect_threshold=0.1,
        replication_ok=True,
        label="A vs B",
    )
    assert result.effect_size_pass
    assert "meaningful" in result.conclusion


# --- state_evaluator ---


def test_state_evaluator_idle():
    now = datetime.now(UTC)
    features = WindowFeatures(
        window_start=now,
        window_end=now + timedelta(seconds=10),
        bytes_in=100,
        bytes_out=50,
        cpu_pct=1.0,
        mem_kb=100_000,
        burstiness=0.1,
        duty_cycle=0.1,
        periodicity=0.1,
        uplink_ratio=0.2,
    )
    decision = evaluate_state(features, cross_source_score=0.8, reproducible=True)
    assert decision.state in {"idle", "uncertain"}
    assert decision.evidence.rules_fired
