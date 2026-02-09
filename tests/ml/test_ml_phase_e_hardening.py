import io
import json
from pathlib import Path


def test_extract_packet_timeline_fails_closed_on_tshark_error(monkeypatch, tmp_path):
    from scytaledroid.DynamicAnalysis.ml import pcap_window_features as pwf

    class _FakeProc:
        def __init__(self):
            self.stdout = io.StringIO("")  # no output
            self.returncode = 1

        def wait(self, timeout=None):
            return self.returncode

        def terminate(self):
            return None

        def kill(self):
            return None

    def _fake_popen(cmd, stdout, stderr, text):  # noqa: ARG001
        return _FakeProc()

    monkeypatch.setattr(pwf.subprocess, "Popen", _fake_popen)

    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"not a real pcap")
    try:
        list(pwf.extract_packet_timeline(pcap))
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "tshark failed" in str(exc)


def test_transport_mix_fallback_clamps_quic_ratio(monkeypatch):
    from scytaledroid.DynamicAnalysis.ml import evidence_pack_ml_orchestrator as orchestrator

    # Minimal RunInputs-like object.
    class _RI:
        pcap_features = None
        pcap_report = {
            "protocol_hierarchy": [
                {"protocol": "udp", "bytes": 100},
                {"protocol": "quic", "bytes": 200},
                {"protocol": "tcp", "bytes": 50},
                {"protocol": "tls", "bytes": 50},
            ]
        }
        pcap_path = None

    tls, quic, tcp, udp = orchestrator._transport_ratios_from_inputs(_RI())  # type: ignore[arg-type]
    assert tls is not None and 0.0 <= tls <= 1.0
    assert quic is not None and 0.0 <= quic <= 1.0
    assert tcp is not None and 0.0 <= tcp <= 1.0
    assert udp is not None and 0.0 <= udp <= 1.0


def test_phase_e_preflight_stage_does_not_overwrite_v1_preflight(tmp_path):
    from scytaledroid.DynamicAnalysis.ml.experimental.pipelines.phase_e_v1 import PhaseEPreflightStage
    from scytaledroid.DynamicAnalysis.ml.experimental.core.pipeline import PipelineContext

    run_dir = tmp_path / "run"
    (run_dir / "inputs").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "artifacts" / "pcapdroid_capture").mkdir(parents=True, exist_ok=True)

    pcap_rel = "artifacts/pcapdroid_capture/app.pcap"
    (run_dir / pcap_rel).write_bytes(b"pcap")

    manifest = {
        "dynamic_run_id": "rid",
        "target": {"package_name": "com.example.app"},
        "operator": {"run_profile": "baseline_idle"},
        "artifacts": [{"type": "pcapdroid_capture", "relative_path": pcap_rel}],
    }
    (run_dir / "run_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (run_dir / "inputs/static_dynamic_plan.json").write_text("{}", encoding="utf-8")
    summary = {"telemetry": {"stats": {"sampling_duration_seconds": 180}}}
    (run_dir / "analysis/summary.json").write_text(json.dumps(summary), encoding="utf-8")
    (run_dir / "analysis/pcap_report.json").write_text("{}", encoding="utf-8")
    (run_dir / "analysis/pcap_features.json").write_text("{}", encoding="utf-8")

    out_dir = run_dir / "analysis/ml/v1"
    out_dir.mkdir(parents=True, exist_ok=True)
    pf_path = out_dir / "ml_preflight.json"
    pf_path.write_text("SENTINEL", encoding="utf-8")

    stage = PhaseEPreflightStage()
    ctx = PipelineContext(run_id="rid", run_dir=str(run_dir), output_dir=str(out_dir))
    stage.run(ctx)

    assert pf_path.read_text(encoding="utf-8") == "SENTINEL"
