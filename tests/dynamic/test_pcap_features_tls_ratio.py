import json

from scytaledroid.DynamicAnalysis.pcap.features import _extract_features, PcapFeatureConfig


def test_tls_ratio_uses_tcp_denominator_and_is_bounded():
    report = {
        "capinfos": {"parsed": {"capture_duration_s": 10, "packet_count": 10, "data_size_bytes": 1000}},
        "protocol_hierarchy": [
            {"protocol": "ip", "bytes": 1000},
            {"protocol": "tcp", "bytes": 800},
            # tls bytes are sometimes larger than tcp in tshark hierarchy output.
            {"protocol": "tls", "bytes": 1200},
            {"protocol": "udp", "bytes": 200},
            {"protocol": "quic", "bytes": 100},
        ],
        "top_sni": [],
        "top_dns": [],
        "report_status": "ok",
        "missing_tools": [],
    }
    features = _extract_features(report, PcapFeatureConfig(), operator={}, target={})
    proxies = features["proxies"]

    assert 0.0 <= proxies["tls_ratio"] <= 1.0
    # With tls > tcp, ratio should cap at 1.0 (not >1.0 and not None).
    assert proxies["tls_ratio"] == 1.0


def test_tls_ratio_is_fraction_when_tls_below_tcp():
    report = {
        "capinfos": {"parsed": {"capture_duration_s": 10, "packet_count": 10, "data_size_bytes": 1000}},
        "protocol_hierarchy": [
            {"protocol": "ip", "bytes": 1000},
            {"protocol": "tcp", "bytes": 800},
            {"protocol": "tls", "bytes": 400},
        ],
        "top_sni": [],
        "top_dns": [],
        "report_status": "ok",
        "missing_tools": [],
    }
    features = _extract_features(report, PcapFeatureConfig(), operator={}, target={})
    proxies = features["proxies"]
    assert proxies["tls_ratio"] == 0.5

