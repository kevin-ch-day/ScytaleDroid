from __future__ import annotations

import json
from pathlib import Path


def test_extract_network_indicators_from_pcap_report() -> None:
    from scytaledroid.DynamicAnalysis.storage.network_indicators import (
        extract_network_indicators_from_pcap_report,
    )

    report = {
        "top_dns": [{"value": "example.com", "count": 3}, {"value": " ", "count": 1}],
        "top_sni": [{"value": "sni.example.com", "count": 2}],
    }
    rows = extract_network_indicators_from_pcap_report(report)
    assert {
        "indicator_type": "dns",
        "indicator_value": "example.com",
        "indicator_count": 3,
        "indicator_source": "top_dns",
        "meta_json": None,
    } in rows
    assert {
        "indicator_type": "sni",
        "indicator_value": "sni.example.com",
        "indicator_count": 2,
        "indicator_source": "top_sni",
        "meta_json": None,
    } in rows
    assert not any(r["indicator_value"] == "" for r in rows)


def test_extract_network_indicators_includes_security_surface_inventory() -> None:
    from scytaledroid.DynamicAnalysis.storage.network_indicators import (
        extract_network_indicators_from_pcap_report,
    )

    report = {
        "top_dns": [],
        "top_sni": [],
        "security_surface": {
            "status": "ok",
            "risk_flags": ["http_metadata_observed"],
            "domain_inventory": {
                "dns_names": ["tracker.example"],
                "sni_names": ["cdn.example"],
                "dns_only_samples": ["dns-only.example"],
                "sni_only_samples": ["sni-only.example"],
            },
            "cleartext": {
                "top_http_hosts": [{"value": "tracker.example", "count": 4}],
                "sanitized_http_samples": [
                    {
                        "host": "tracker.example",
                        "method": "GET",
                        "sanitized_path": "/api/{id}",
                        "path_class": "parameterized",
                        "rows": 2,
                    }
                ],
            },
        },
    }
    rows = extract_network_indicators_from_pcap_report(report)
    sources = {row["indicator_source"] for row in rows}
    assert "security_surface.dns_inventory" in sources
    assert "security_surface.http_host" in sources
    assert "security_surface.risk_flag" in sources
    http_rows = [row for row in rows if row["indicator_type"] == "http_host"]
    assert any(row["indicator_value"] == "tracker.example" for row in http_rows)
    assert any(isinstance(row.get("meta_json"), dict) for row in http_rows)


def test_extract_network_indicators_includes_telegram_direct_ip_flows() -> None:
    from scytaledroid.DynamicAnalysis.storage.network_indicators import (
        extract_network_indicators_from_pcap_report,
    )

    report = {
        "package_name": "org.telegram.messenger",
        "flow_summary": {
            "top_flows": [
                {
                    "endpoint_a": "10.215.173.1:41568",
                    "endpoint_b": "149.154.175.51:443",
                    "packets": 210,
                    "bytes": 41430,
                    "protocol": "tcp",
                },
                {
                    "endpoint_a": "10.215.173.1:49578",
                    "endpoint_b": "216.239.38.223:443",
                    "packets": 17,
                    "bytes": 7862,
                    "protocol": "tcp",
                },
            ]
        },
    }

    rows = extract_network_indicators_from_pcap_report(report)

    ip_rows = [row for row in rows if row["indicator_type"] == "ip_dst"]
    assert len(ip_rows) == 1
    assert ip_rows[0]["indicator_value"] == "149.154.175.51"
    assert ip_rows[0]["indicator_count"] == 210
    assert ip_rows[0]["indicator_source"] == "top_flow_ip"
    assert ip_rows[0]["meta_json"]["cidr"] == "149.154.160.0/20"
    assert ip_rows[0]["meta_json"]["role_class"] == "telegram_datacenter_transport"


def test_security_operator_labels_from_run_dir_prefers_sidecar(tmp_path: Path) -> None:
    from scytaledroid.DynamicAnalysis.pcap.security_surface import (
        security_operator_labels_from_run_dir,
    )

    run_dir = tmp_path / "run-1"
    analysis = run_dir / "analysis"
    analysis.mkdir(parents=True)
    (analysis / "security_surface.json").write_text(
        json.dumps(
            {
                "status": "ok",
                "finding_count": 2,
                "risk_flags": ["http_metadata_observed"],
                "findings": [{"title": "HTTP metadata observed", "severity": "high"}],
                "cleartext": {
                    "http_observed": True,
                    "visibility_class": "cleartext_surface_present",
                },
            }
        ),
        encoding="utf-8",
    )

    labels = security_operator_labels_from_run_dir(run_dir)

    assert labels["status"] == "ok"
    assert labels["cleartext_http_label"] == "Y"
    assert labels["finding_count"] == 2
    assert labels["visibility_class"] == "cleartext_surface_present"
