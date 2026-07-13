from __future__ import annotations

from pathlib import Path

from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_orchestrator import _baseline_bytes_gate_ok
from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_preflight import RunInputs


def _inputs(
    tmp_path: Path,
    run_id: str,
    *,
    size_bytes: int,
    min_pcap_bytes: int | None = None,
) -> RunInputs:
    dataset: dict[str, object] = {}
    if min_pcap_bytes is not None:
        dataset["min_pcap_bytes"] = min_pcap_bytes
    return RunInputs(
        run_id=run_id,
        run_dir=tmp_path / run_id,
        manifest={"dataset": dataset},
        plan={},
        summary={},
        pcap_report={"pcap_size_bytes": size_bytes},
        pcap_features={},
        pcap_path=None,
        identity_key="identity",
        package_name="com.example",
        run_profile="baseline_idle",
    )


def test_baseline_bytes_gate_respects_per_run_dataset_threshold(tmp_path: Path) -> None:
    runs = [
        _inputs(tmp_path, "baseline-a", size_bytes=12_000, min_pcap_bytes=10_000),
        _inputs(tmp_path, "baseline-b", size_bytes=18_000, min_pcap_bytes=10_000),
    ]

    ok, threshold = _baseline_bytes_gate_ok(runs, baseline_rids=["baseline-a", "baseline-b"])

    assert ok is True
    assert threshold == 10_000


def test_baseline_bytes_gate_uses_fallback_when_dataset_threshold_missing(tmp_path: Path) -> None:
    runs = [_inputs(tmp_path, "baseline-a", size_bytes=12_000)]

    ok, threshold = _baseline_bytes_gate_ok(runs, baseline_rids=["baseline-a"])

    assert ok is False
    assert threshold == 50_000
