from __future__ import annotations


def test_extract_network_indicators_from_pcap_report():
    from scytaledroid.DynamicAnalysis.storage.network_indicators import extract_network_indicators_from_pcap_report

    report = {
        "top_dns": [{"value": "example.com", "count": 3}, {"value": " ", "count": 1}],
        "top_sni": [{"value": "sni.example.com", "count": 2}],
    }
    rows = extract_network_indicators_from_pcap_report(report)
    assert {"indicator_type": "dns", "indicator_value": "example.com", "indicator_count": 3, "indicator_source": "top_dns", "meta_json": None} in rows
    assert {"indicator_type": "sni", "indicator_value": "sni.example.com", "indicator_count": 2, "indicator_source": "top_sni", "meta_json": None} in rows
    # blank value is ignored
    assert not any(r["indicator_value"] == "" for r in rows)

