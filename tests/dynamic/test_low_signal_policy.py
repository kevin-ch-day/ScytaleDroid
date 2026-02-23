from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap.low_signal import compute_low_signal_for_run


def _write_features(run_dir: Path, *, duration_s: float, data_bytes: int, packets: int, domains_topn: int) -> None:
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    payload = {
        "metrics": {
            "capture_duration_s": duration_s,
            "data_size_bytes": data_bytes,
            "packet_count": packets,
        },
        "proxies": {
            "unique_domains_topn": domains_topn,
        },
    }
    (run_dir / "analysis" / "pcap_features.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def test_low_signal_relaxed_for_snapchat_baseline_idle(tmp_path: Path) -> None:
    run_dir = tmp_path / "snap-baseline"
    _write_features(
        run_dir,
        duration_s=254.0,
        data_bytes=623_268,
        packets=1_021,
        domains_topn=11,
    )
    result = compute_low_signal_for_run(
        run_dir,
        package_name="com.snapchat.android",
        run_profile="baseline_idle",
    )
    assert isinstance(result, dict)
    assert result["low_signal"] is False
    assert result["low_signal_reasons"] == []
    assert int(result["low_signal_thresholds"]["min_data_size_bytes"]) == 500_000


def test_low_signal_remains_strict_for_social_feed_baseline_idle(tmp_path: Path) -> None:
    run_dir = tmp_path / "social-baseline"
    _write_features(
        run_dir,
        duration_s=254.0,
        data_bytes=623_268,
        packets=1_021,
        domains_topn=11,
    )
    result = compute_low_signal_for_run(
        run_dir,
        package_name="com.twitter.android",
        run_profile="baseline_idle",
    )
    assert isinstance(result, dict)
    assert result["low_signal"] is True
    assert "PCAP_BYTES_LOW" in result["low_signal_reasons"]
    assert int(result["low_signal_thresholds"]["min_data_size_bytes"]) == 1_000_000


def test_low_signal_whatsapp_tiny_idle_still_flagged(tmp_path: Path) -> None:
    run_dir = tmp_path / "wa-baseline"
    _write_features(
        run_dir,
        duration_s=250.0,
        data_bytes=26_890,
        packets=120,
        domains_topn=0,
    )
    result = compute_low_signal_for_run(
        run_dir,
        package_name="com.whatsapp",
        run_profile="baseline_idle",
    )
    assert isinstance(result, dict)
    assert result["low_signal"] is True
    assert "PCAP_BYTES_LOW" in result["low_signal_reasons"]
    assert int(result["low_signal_thresholds"]["min_data_size_bytes"]) == 500_000
