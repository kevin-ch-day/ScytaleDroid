from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap.low_signal import compute_low_signal_for_run


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_messaging_voice_call_rich_udp_run_suppresses_domains_low(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "operator": {
                "run_profile": "interaction_manual",
                "messaging_activity": "voice_call",
            }
        },
    )
    _write_json(
        run_dir / "analysis" / "pcap_features.json",
        {
            "metrics": {
                "capture_duration_s": 480.5,
                "data_size_bytes": 1_832_028,
                "packet_count": 11_229,
            },
            "proxies": {
                "unique_domains_topn": 1,
                "udp_ratio": 0.967,
                "unique_dst_ip_count": 7,
            },
        },
    )

    decision = compute_low_signal_for_run(
        run_dir,
        package_name="com.whatsapp",
        run_profile="interaction_manual",
    )

    assert decision is not None
    assert decision["low_signal"] is False
    assert decision["low_signal_reasons"] == []


def test_non_messaging_interaction_keeps_domains_low(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "operator": {
                "run_profile": "interaction_manual",
                "messaging_activity": "voice_call",
            }
        },
    )
    _write_json(
        run_dir / "analysis" / "pcap_features.json",
        {
            "metrics": {
                "capture_duration_s": 480.5,
                "data_size_bytes": 1_832_028,
                "packet_count": 11_229,
            },
            "proxies": {
                "unique_domains_topn": 1,
                "udp_ratio": 0.967,
                "unique_dst_ip_count": 7,
            },
        },
    )

    decision = compute_low_signal_for_run(
        run_dir,
        package_name="bbc.mobile.news.ww",
        run_profile="interaction_manual",
    )

    assert decision is not None
    assert decision["low_signal"] is True
    assert decision["low_signal_reasons"] == ["DOMAINS_LOW"]
