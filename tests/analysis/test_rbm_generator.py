from pathlib import Path

from scytaledroid.DynamicAnalysis.analysis.rbm_generator import RBMPoint, generate_rbm


def test_rbm_generator(tmp_path: Path):
    points = [
        RBMPoint(ts=0.0, state="idle", confidence=0.9, bytes_in=0.0, bytes_out=0.0, cpu_pct=1.0),
        RBMPoint(ts=1.0, state="heartbeat", confidence=0.7, bytes_in=100.0, bytes_out=50.0, cpu_pct=2.0),
    ]
    outputs = generate_rbm("run123", points, tmp_path)
    assert outputs["json"].exists()
    assert outputs["png"].exists()
    assert outputs["html"].exists()
