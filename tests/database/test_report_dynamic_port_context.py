from __future__ import annotations

import csv
import json
from pathlib import Path

from scripts.db import report_dynamic_port_context as report


def test_split_endpoint_and_remote_endpoint_prefers_non_private_peer() -> None:
    assert report._split_endpoint("10.0.0.2:45678") == ("10.0.0.2", 45678)
    assert report._split_endpoint("[2001:db8::1]:443") == ("2001:db8::1", 443)

    host, port = report._remote_endpoint(
        {
            "endpoint_a": "10.0.0.2:45678",
            "endpoint_b": "157.240.146.35:3478",
        }
    )
    assert host == "157.240.146.35"
    assert port == 3478


def test_classify_port_labels_research_relevant_transports() -> None:
    assert report._classify_port("tcp", 443) == ("https_tls", "encrypted_web_or_api", 0)
    assert report._classify_port("udp", 443) == ("quic_or_udp_443", "quic_https_or_udp_media", 1)
    assert report._classify_port("udp", 3478) == ("stun_turn_rtc", "nat_traversal_or_relay", 1)
    assert report._classify_port("tcp", 5222) == (
        "xmpp_or_messaging",
        "long_lived_messaging_transport",
        1,
    )


def test_standard_port_context_uses_ranges_and_common_names() -> None:
    assert report._iana_port_range(443) == "well_known"
    assert report._iana_port_range(1400) == "registered"
    assert report._iana_port_range(53382) == "dynamic_private"
    assert report._standard_service_for_port("tcp", 443) == (
        "https",
        "HTTP over TLS",
        "curated_common",
    )
    assert report._classify_port("udp", 596) == (
        "well_known_standard_other",
        "standard_well_known_service_review_if_repeated",
        1,
    )


def test_publication_transport_summary_keeps_safe_caveats() -> None:
    rows = report._publication_transport_summary_rows(
        [
            {
                "package": "com.example.chat",
                "app_label": "Example Chat",
                "run_count": 2,
                "protocol_ports": "tcp/443, udp/443, udp/3478, udp/53382",
                "standard_services": "tcp/443=https, udp/443=https, udp/3478=stun",
                "port_class_counts": json.dumps(
                    {
                        "https_tls": 1,
                        "quic_or_udp_443": 1,
                        "remote_ephemeral_or_peer_port": 1,
                        "stun_turn_rtc": 1,
                    }
                ),
                "bytes_by_port_class": json.dumps({"remote_ephemeral_or_peer_port": 700}),
                "notable_top_flow_rows": 3,
                "total_top_flow_bytes": 5800,
            }
        ]
    )

    assert rows[0]["has_tls_https"] == "yes"
    assert rows[0]["has_udp443_quic_candidate"] == "yes"
    assert rows[0]["has_stun_turn_candidate"] == "yes"
    assert rows[0]["has_private_peer_udp"] == "yes"
    assert "candidate signal" in rows[0]["required_caveat"]
    assert "private peer UDP accounted for 700" in rows[0]["required_caveat"]
    assert "top flows included" in rows[0]["transport_statement"]


def test_apply_label_overrides_updates_package_fallback_labels() -> None:
    rows = [
        {
            "package": "com.example.news",
            "app_label": "com.example.news",
        },
        {
            "package": "com.example.chat",
            "app_label": "Old Chat",
        },
    ]

    updated = report._apply_label_overrides(
        rows,
        {
            "com.example.news": "Example News",
            "com.example.chat": "Example Chat",
        },
    )

    assert updated == 2
    assert rows[0]["app_label"] == "Example News"
    assert rows[1]["app_label"] == "Example Chat"


def test_generate_report_writes_port_context_bundle(tmp_path: Path) -> None:
    dynamic_root = tmp_path / "dynamic"
    publication_manifest = tmp_path / "publication_manifest.csv"
    publication_manifest.write_text(
        "app,package_name\nExample Chat,com.example.chat\n",
        encoding="utf-8",
    )
    run_dir = dynamic_root / "run-1"
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-1",
                "target": {
                    "package_name": "com.example.chat",
                    "display_name": "Example Chat",
                },
                "operator": {"run_profile": "interaction_manual"},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "package_name": "com.example.chat",
                "app_label": "Example Chat",
                "flow_summary": {
                    "top_flows": [
                        {
                            "endpoint_a": "10.0.0.2:40123",
                            "endpoint_b": "157.240.146.35:3478",
                            "protocol": "udp",
                            "bytes": 1200,
                            "packets": 20,
                            "directionality": "mixed",
                        },
                        {
                            "endpoint_a": "10.0.0.2:40124",
                            "endpoint_b": "8.8.8.8:443",
                            "protocol": "tcp",
                            "bytes": 3000,
                            "packets": 12,
                            "directionality": "mixed",
                        },
                        {
                            "endpoint_a": "10.0.0.2:40125",
                            "endpoint_b": "1.1.1.1:596",
                            "protocol": "udp",
                            "bytes": 900,
                            "packets": 9,
                            "directionality": "mixed",
                        },
                        {
                            "endpoint_a": "10.0.0.2:40126",
                            "endpoint_b": "192.168.0.13:53382",
                            "protocol": "udp",
                            "bytes": 700,
                            "packets": 7,
                            "directionality": "mixed",
                        },
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    out_dir = tmp_path / "out"
    summary = report.generate_report(
        dynamic_root=dynamic_root,
        publication_manifest=publication_manifest,
        output_dir=out_dir,
    )

    assert summary["pcap_report_count"] == 1
    assert summary["top_flow_port_rows"] == 4
    assert summary["distinct_protocol_port_count"] == 4
    assert summary["publication_transport_summary_rows"] == 1
    assert summary["publication_manifest_package_count"] == 1
    assert summary["publication_transport_excluded_package_count"] == 0
    assert summary["label_override_rows"] == 0
    assert summary["port_class_counts"] == {
        "https_tls": 1,
        "remote_ephemeral_or_peer_port": 1,
        "stun_turn_rtc": 1,
        "well_known_standard_other": 1,
    }
    assert summary["iana_port_range_counts"] == {"dynamic_private": 1, "well_known": 2, "registered": 1}
    assert summary["remote_host_scope_counts"] == {"private": 1, "public": 3}
    assert summary["standard_service_mapped_rows"] == 3
    assert summary["standard_service_unmapped_rows"] == 1
    assert summary["no_db_writes"] is True

    with (out_dir / "notable_ports.csv").open(encoding="utf-8") as handle:
        notable_rows = list(csv.DictReader(handle))
    assert len(notable_rows) == 3
    assert notable_rows[0]["remote_port"] == "3478"
    assert notable_rows[0]["port_class"] == "stun_turn_rtc"

    with (out_dir / "run_ports.csv").open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    https_rows = [row for row in rows if row["protocol"] == "tcp" and row["remote_port"] == "443"]
    assert https_rows
    assert https_rows[0]["iana_port_range"] == "well_known"
    assert https_rows[0]["standard_service_name"] == "https"

    with (out_dir / "port_catalog.csv").open(encoding="utf-8") as handle:
        catalog_rows = list(csv.DictReader(handle))
    dynamic_rows = [row for row in catalog_rows if row["protocol"] == "udp" and row["remote_port"] == "53382"]
    assert dynamic_rows
    assert dynamic_rows[0]["iana_port_range"] == "dynamic_private"
    assert dynamic_rows[0]["standard_service_name"] == ""
    assert dynamic_rows[0]["remote_host_scope_counts"] == '{"private": 1}'

    with (out_dir / "unmapped_ports.csv").open(encoding="utf-8") as handle:
        unmapped_rows = list(csv.DictReader(handle))
    assert len(unmapped_rows) == 1
    assert unmapped_rows[0]["remote_port"] == "53382"
    assert unmapped_rows[0]["remote_host_scope"] == "private"

    with (out_dir / "publication_transport_summary.csv").open(encoding="utf-8") as handle:
        publication_rows = list(csv.DictReader(handle))
    assert len(publication_rows) == 1
    assert publication_rows[0]["has_tls_https"] == "yes"
    assert publication_rows[0]["has_stun_turn_candidate"] == "yes"
    assert publication_rows[0]["has_private_peer_udp"] == "yes"
    assert "STUN/TURN indicates" in publication_rows[0]["required_caveat"]

    publication_md = (out_dir / "publication_transport_summary.md").read_text(encoding="utf-8")
    assert "Example Chat top flows included" in publication_md
    assert "has_private_peer_udp" in publication_md

    package_summary = (out_dir / "package_port_summary.csv").read_text(encoding="utf-8")
    assert "udp/3478" in package_summary
    assert "tcp/443" in package_summary
    assert "udp/596" in package_summary
    assert "udp/596=" in package_summary
