from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap.low_signal import compute_low_signal_for_run


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_messaging_interaction_suppresses_quiet_low_signal_when_structurally_valid(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    _write_json(
        run_dir / "analysis" / "pcap_features.json",
        {
            "metrics": {
                "capture_duration_s": 420.0,
                "data_size_bytes": 120_000,
                "packet_count": 420,
            },
            "proxies": {
                "unique_domains_topn": 1,
                "unique_ja4_count": 1,
            },
            "quality": {
                "report_status": "ok",
                "pcap_valid": True,
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


def test_non_messaging_voice_call_rich_udp_run_suppresses_domains_low(tmp_path: Path) -> None:
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


def test_idle_baseline_suppresses_bytes_low_when_other_signal_is_present(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_json(
        run_dir / "analysis" / "pcap_features.json",
        {
            "metrics": {
                "capture_duration_s": 462.7,
                "data_size_bytes": 397_064,
                "packet_count": 1_122,
            },
            "proxies": {
                "unique_domains_topn": 9,
            },
        },
    )

    decision = compute_low_signal_for_run(
        run_dir,
        package_name="com.linkedin.android",
        run_profile="baseline_idle",
    )

    assert decision is not None
    assert decision["low_signal"] is False
    assert decision["low_signal_reasons"] == []


def test_cnn_like_idle_baseline_suppresses_bytes_low_with_rich_evidence(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_json(
        run_dir / "analysis" / "pcap_features.json",
        {
            "metrics": {
                "capture_duration_s": 252.6,
                "data_size_bytes": 819_488,
                "packet_count": 1_218,
            },
            "proxies": {
                "unique_domains_topn": 12,
                "unique_ja4_count": 9,
            },
            "quality": {
                "report_status": "ok",
                "pcap_valid": True,
            },
            "service_context": {
                "summary": {
                    "service_count": 5,
                }
            },
        },
    )

    decision = compute_low_signal_for_run(
        run_dir,
        package_name="com.cnn.mobile.android.phone",
        run_profile="baseline_idle",
    )

    assert decision is not None
    assert decision["low_signal"] is False
    assert decision["low_signal_reasons"] == []


def test_service_unresolved_idle_baseline_uses_domain_and_ja4_evidence(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_json(
        run_dir / "analysis" / "pcap_features.json",
        {
            "metrics": {
                "capture_duration_s": 462.7,
                "data_size_bytes": 397_064,
                "packet_count": 1_122,
            },
            "proxies": {
                "unique_domains_topn": 9,
                "unique_ja4_count": 4,
            },
            "quality": {
                "report_status": "ok",
                "pcap_valid": True,
            },
            "service_context": {
                "summary": {
                    "service_count": 0,
                    "unresolved_domain_count": 9,
                }
            },
        },
    )

    decision = compute_low_signal_for_run(
        run_dir,
        package_name="com.linkedin.android",
        run_profile="baseline_idle",
    )

    assert decision is not None
    assert decision["low_signal"] is False
    assert decision["low_signal_reasons"] == []


def test_connected_baseline_suppresses_quiet_low_signal_when_sufficient(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_json(
        run_dir / "analysis" / "pcap_features.json",
        {
            "metrics": {
                "capture_duration_s": 480.0,
                "data_size_bytes": 55_000,
                "packet_count": 199,
            },
            "proxies": {
                "unique_domains_topn": 2,
                "unique_ja4_count": 1,
            },
            "quality": {
                "report_status": "ok",
                "pcap_valid": True,
            },
        },
    )

    decision = compute_low_signal_for_run(
        run_dir,
        package_name="com.whatsapp",
        run_profile="baseline_connected",
    )

    assert decision is not None
    assert decision["low_signal"] is False
    assert decision["low_signal_reasons"] == []


def test_non_messaging_connected_baseline_keeps_quiet_low_signal(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_json(
        run_dir / "analysis" / "pcap_features.json",
        {
            "metrics": {
                "capture_duration_s": 480.0,
                "data_size_bytes": 55_000,
                "packet_count": 199,
            },
            "proxies": {
                "unique_domains_topn": 2,
                "unique_ja4_count": 1,
            },
            "quality": {
                "report_status": "ok",
                "pcap_valid": True,
            },
        },
    )

    decision = compute_low_signal_for_run(
        run_dir,
        package_name="bbc.mobile.news.ww",
        run_profile="baseline_connected",
    )

    assert decision is not None
    assert decision["low_signal"] is True
    assert decision["low_signal_reasons"] == ["PCAP_BYTES_LOW", "PCAP_PACKETS_LOW", "DOMAINS_LOW"]


def test_idle_baseline_keeps_bytes_low_when_packets_are_too_sparse(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_json(
        run_dir / "analysis" / "pcap_features.json",
        {
            "metrics": {
                "capture_duration_s": 462.7,
                "data_size_bytes": 397_064,
                "packet_count": 99,
            },
            "proxies": {
                "unique_domains_topn": 9,
            },
        },
    )

    decision = compute_low_signal_for_run(
        run_dir,
        package_name="com.linkedin.android",
        run_profile="baseline_idle",
    )

    assert decision is not None
    assert decision["low_signal"] is True
    assert decision["low_signal_reasons"] == ["PCAP_BYTES_LOW", "PCAP_PACKETS_LOW"]


def test_social_feed_idle_baseline_suppresses_quiet_low_signal_when_tls_and_service_evidence_is_rich(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    _write_json(
        run_dir / "analysis" / "pcap_features.json",
        {
            "metrics": {
                "capture_duration_s": 449.2,
                "data_size_bytes": 139_696,
                "packet_count": 729,
            },
            "proxies": {
                "unique_domains_topn": 7,
                "unique_ja4_count": 4,
                "tls_client_hello_count": 12,
            },
            "quality": {
                "report_status": "ok",
                "pcap_valid": True,
            },
            "service_context": {
                "summary": {
                    "service_count": 3,
                }
            },
        },
    )

    decision = compute_low_signal_for_run(
        run_dir,
        package_name="com.twitter.android",
        run_profile="baseline_idle",
    )

    assert decision is not None
    assert decision["low_signal"] is False
    assert decision["low_signal_reasons"] == []


def test_social_feed_idle_baseline_keeps_low_signal_when_richness_is_not_corroborated(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    _write_json(
        run_dir / "analysis" / "pcap_features.json",
        {
            "metrics": {
                "capture_duration_s": 449.2,
                "data_size_bytes": 139_696,
                "packet_count": 251,
            },
            "proxies": {
                "unique_domains_topn": 1,
                "unique_ja4_count": 0,
                "tls_client_hello_count": 1,
            },
            "quality": {
                "report_status": "ok",
                "pcap_valid": True,
            },
            "service_context": {
                "summary": {
                    "service_count": 0,
                }
            },
        },
    )

    decision = compute_low_signal_for_run(
        run_dir,
        package_name="com.twitter.android",
        run_profile="baseline_idle",
    )

    assert decision is not None
    assert decision["low_signal"] is True
    assert decision["low_signal_reasons"] == ["PCAP_BYTES_LOW", "PCAP_PACKETS_LOW", "DOMAINS_LOW"]


def test_connected_baseline_keeps_low_signal_when_evidence_dimensions_are_weak(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    _write_json(
        run_dir / "analysis" / "pcap_features.json",
        {
            "metrics": {
                "capture_duration_s": 480.0,
                "data_size_bytes": 10_000,
                "packet_count": 42,
            },
            "proxies": {
                "unique_domains_topn": 0,
                "unique_ja4_count": 0,
            },
            "quality": {
                "report_status": "ok",
                "pcap_valid": True,
            },
        },
    )

    decision = compute_low_signal_for_run(
        run_dir,
        package_name="com.whatsapp",
        run_profile="baseline_connected",
    )

    assert decision is not None
    assert decision["low_signal"] is True
    assert decision["low_signal_reasons"] == ["PCAP_BYTES_LOW", "PCAP_PACKETS_LOW", "DOMAINS_LOW"]


def test_idle_baseline_keeps_low_signal_when_pcap_quality_is_invalid(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_json(
        run_dir / "analysis" / "pcap_features.json",
        {
            "metrics": {
                "capture_duration_s": 252.6,
                "data_size_bytes": 819_488,
                "packet_count": 1_218,
            },
            "proxies": {
                "unique_domains_topn": 12,
                "unique_ja4_count": 9,
            },
            "quality": {
                "report_status": "failed",
                "pcap_valid": False,
            },
        },
    )

    decision = compute_low_signal_for_run(
        run_dir,
        package_name="com.cnn.mobile.android.phone",
        run_profile="baseline_idle",
    )

    assert decision is not None
    assert decision["low_signal"] is True
    assert decision["low_signal_reasons"] == ["PCAP_BYTES_LOW"]
