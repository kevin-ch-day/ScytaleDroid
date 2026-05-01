from pathlib import Path

from scytaledroid.DynamicAnalysis.exports.feature_health import build_feature_health_report


def test_feature_health_gate_fail(tmp_path: Path):
    telemetry_dir = tmp_path / "telemetry"
    telemetry_dir.mkdir()
    sample = telemetry_dir / "run-network.csv"
    sample.write_text("bytes_in,bytes_out\n0,0\n0,0\n", encoding="utf-8")
    report = build_feature_health_report(telemetry_dir, tmp_path)
    assert report["gating"]["status"] == "FAIL"
