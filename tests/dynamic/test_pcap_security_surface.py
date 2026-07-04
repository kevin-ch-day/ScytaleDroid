from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.core.manifest import RunManifest
from scytaledroid.DynamicAnalysis.pcap.features import PcapFeatureConfig, write_pcap_features
from scytaledroid.DynamicAnalysis.pcap.security_surface import (
    compute_static_dynamic_cleartext_posture,
    export_payload_audit_rows,
    http_observed_from_report,
    render_security_review_md,
    sanitize_http_path,
    summarize_security_surface,
)


def test_sanitize_http_path_tokenizes_long_segments() -> None:
    path, path_class = sanitize_http_path("/api/users/0123456789abcdef/session")
    assert path == "/api/users/{id}/session"
    assert path_class == "parameterized"


def test_sanitize_http_path_root() -> None:
    path, path_class = sanitize_http_path("/")
    assert path == "/"
    assert path_class == "root"


def test_sanitize_http_path_literal_short_segment() -> None:
    path, path_class = sanitize_http_path("/health")
    assert path == "/health"
    assert path_class == "literal_path"


def test_summarize_security_surface_skips_without_pcap(tmp_path: Path) -> None:
    missing = tmp_path / "missing.pcap"
    surface = summarize_security_surface(missing, tshark_path="tshark")
    assert surface["status"] == "skipped"
    assert surface["finding_count"] == 0


def test_summarize_security_surface_builds_ethical_hacking_bundle(
    monkeypatch, tmp_path: Path
) -> None:
    pcap_path = tmp_path / "sample.pcap"
    pcap_path.write_bytes(b"pcap")

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.security_surface._protocol_hierarchy",
        lambda *args, **kwargs: [{"protocol": "http", "frames": 4, "bytes": 900}],
    )

    def _fake_run_tshark(cmd, timeout):
        joined = " ".join(cmd)
        if "http.request || http.response" in joined:
            return (
                0,
                "tracker.example\tGET\t/user/0123456789abcdef\t\n"
                "cdn.example\tGET\t/static/logo.png\t200\n",
                "",
            )
        if "dns.qry.name" in joined and "dns.flags.response == 0" in joined:
            return 0, "tracker.example\ncdn.example\n", ""
        if "dns.qry.type" in joined:
            return 0, "1\n16\n", ""
        if "tls.handshake.extensions_server_name" in joined:
            return 0, "cdn.example\n", ""
        if "tls.handshake.type == 11" in joined:
            return 0, "cdn.example\tCN=cdn.example\tJan  1 2020\tJan  1 2030\t\n", ""
        if "tls.alert_message" in joined and "-T" in joined and "frame.number" not in joined:
            return 0, "unknown_ca\n", ""
        if "frame.number" in joined:
            return 0, "1\n2\n", ""
        return 0, "", ""

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.security_surface._run_tshark",
        _fake_run_tshark,
    )

    surface = summarize_security_surface(
        pcap_path,
        tshark_path="tshark",
        flow_summary={
            "top_flows": [{"directionality": "outbound_only", "packets": 4, "bytes": 512}]
        },
        burst_summary={"burst_count": 2},
    )

    assert surface["status"] == "ok"
    assert surface["cleartext"]["http_observed"] is True
    assert surface["cleartext"]["http_host_count"] == 2
    assert surface["cleartext"]["protocol_visibility"]
    assert surface["finding_count"] >= 2
    assert "http_metadata_observed" in surface["risk_flags"]
    assert any(item.get("category") == "cleartext" for item in surface["findings"])


def test_http_observed_from_report_prefers_security_surface() -> None:
    assert http_observed_from_report(
        {
            "protocol_hierarchy": [{"protocol": "tls", "frames": 10, "bytes": 1000}],
            "security_surface": {
                "status": "ok",
                "cleartext": {
                    "http_observed": True,
                    "plaintext_protocol_frames": 0,
                    "visibility_class": "cleartext_surface_present",
                },
            },
        }
    )
    assert (
        http_observed_from_report(
            {
                "protocol_hierarchy": [{"protocol": "http", "frames": 2, "bytes": 100}],
                "security_surface": {
                    "status": "ok",
                    "cleartext": {
                        "http_observed": False,
                        "plaintext_protocol_frames": 0,
                        "visibility_class": "encrypted_or_opaque_dominant",
                    },
                },
            }
        )
        is False
    )


def test_compute_static_dynamic_cleartext_posture_denied_but_observed() -> None:
    posture = compute_static_dynamic_cleartext_posture(
        {
            "static_features": {"uses_cleartext_traffic": False},
            "network_targets": {"cleartext_domains": []},
        },
        {
            "security_surface": {
                "status": "ok",
                "cleartext": {
                    "http_observed": True,
                    "visibility_class": "cleartext_surface_present",
                },
            },
        },
    )
    assert posture["mismatch_class"] == "denied_but_observed"
    assert posture["dynamic_http_observed"] is True


def test_compute_static_dynamic_cleartext_posture_allowed_not_observed_encrypted() -> None:
    posture = compute_static_dynamic_cleartext_posture(
        {
            "static_features": {"uses_cleartext_traffic": True},
            "network_targets": {"cleartext_domains": ["api.example.com"]},
        },
        {
            "security_surface": {
                "status": "ok",
                "cleartext": {
                    "http_observed": False,
                    "visibility_class": "encrypted_or_opaque_dominant",
                },
            },
        },
    )
    assert posture["mismatch_class"] == "allowed_not_observed_encrypted"
    assert posture["static_cleartext_allowed"] is True


def test_summarize_security_surface_extracts_decoded_streams(monkeypatch, tmp_path: Path) -> None:
    pcap_path = tmp_path / "sample.pcap"
    pcap_path.write_bytes(b"pcap")

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.security_surface._protocol_hierarchy",
        lambda *args, **kwargs: [{"protocol": "ftp", "frames": 3, "bytes": 500}],
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.security_surface._extract_http_metadata",
        lambda *args, **kwargs: ([], "ok"),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.security_surface._analyze_dns_anomalies",
        lambda *args, **kwargs: {"risk_flags": []},
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.security_surface._analyze_tls_surface",
        lambda *args, **kwargs: {"risk_flags": []},
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.security_surface._build_domain_inventory",
        lambda *args, **kwargs: {"dns_unique_count": 0, "sni_unique_count": 0},
    )

    def _fake_run_tshark(cmd, timeout):
        joined = " ".join(cmd)
        if "frame.protocols" in joined and "ftp" in joined:
            return 0, "raw:ip:tcp:ftp\t120\t50000\t21\t\t\t7\n", ""
        return 0, "", ""

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.security_surface._run_tshark", _fake_run_tshark
    )

    surface = summarize_security_surface(pcap_path, tshark_path="tshark")
    assert surface["cleartext"]["decoded_stream_count"] == 1
    assert surface["cleartext"]["decoded_streams"][0]["protocol"] == "ftp"
    assert "decoded_cleartext_streams_observed" in surface["risk_flags"]


def test_write_pcap_features_includes_security_surface_proxies(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    analysis_dir = run_dir / "analysis"
    analysis_dir.mkdir(parents=True)
    report_path = analysis_dir / "pcap_report.json"
    report_path.write_text(
        json.dumps(
            {
                "report_status": "ok",
                "capinfos": {
                    "parsed": {
                        "packet_count": 10,
                        "data_size_bytes": 1000,
                        "capture_duration_s": 5.0,
                    }
                },
                "protocol_hierarchy": [{"protocol": "http", "frames": 4, "bytes": 900}],
                "top_sni": [],
                "top_dns": [],
                "security_surface": {
                    "status": "ok",
                    "finding_count": 3,
                    "risk_flags": ["http_metadata_observed", "elevated_dns_txt_queries"],
                    "cleartext": {
                        "http_observed": True,
                        "plaintext_protocol_frames": 4,
                        "visibility_class": "cleartext_surface_present",
                    },
                    "dns_anomalies": {"nxdomain_responses": 12, "txt_queries": 6},
                    "tls_surface": {"tls_alert_count": 1, "self_signed_count": 0},
                    "threat_heuristics": {"heuristic_score": 4},
                },
            }
        ),
        encoding="utf-8",
    )
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-1",
        created_at="2026-06-15T00:00:00Z",
        target={"package_name": "com.example.app"},
        artifacts=[],
    )

    artifact = write_pcap_features(manifest, run_dir, config=PcapFeatureConfig())
    assert artifact is not None

    payload = json.loads((analysis_dir / "pcap_features.json").read_text(encoding="utf-8"))
    assert payload["feature_schema_version"] == "v1.3"
    assert payload["proxies"]["cleartext_http_observed"] == 1
    assert payload["proxies"]["security_finding_count"] == 3
    assert payload["proxies"]["dns_nxdomain_responses"] == 12
    assert payload["security_surface"]["status"] == "ok"
    assert payload["security_surface"]["summary"]["http_observed"] is True


def test_export_payload_audit_rows_maps_security_surface_bundle(tmp_path: Path) -> None:
    pcap_path = tmp_path / "sample.pcap"
    pcap_path.write_bytes(b"pcap")
    surface = {
        "status": "ok",
        "risk_flags": ["http_metadata_observed", "decoded_cleartext_streams_observed"],
        "cleartext": {
            "visibility_class": "cleartext_surface_present",
            "http_status": "ok",
            "plaintext_protocol_frames": 4,
            "http_request_rows": 2,
            "http_response_rows": 1,
            "http_host_count": 1,
            "protocol_visibility": [
                {
                    "protocol": "http",
                    "frames": 4,
                    "bytes": 900,
                    "visibility": "cleartext_protocol_decoded",
                },
                {
                    "protocol": "dns",
                    "frames": 2,
                    "bytes": 200,
                    "visibility": "cleartext_name_metadata",
                },
            ],
            "sanitized_http_samples": [
                {
                    "host": "tracker.example",
                    "method": "GET",
                    "response_code": "",
                    "sanitized_path": "/api/{id}",
                    "path_class": "parameterized",
                    "rows": 2,
                }
            ],
            "decoded_streams": [
                {
                    "protocol": "ftp",
                    "transport": "tcp",
                    "src_port": "50000",
                    "dst_port": "21",
                    "tcp_stream": "3",
                    "frames": 2,
                    "bytes_total": 240,
                    "bytes_min": 120,
                    "bytes_max": 120,
                }
            ],
        },
    }
    run_row, http_rows, protocol_rows, decoded_rows = export_payload_audit_rows(
        run_id="run-1",
        package="com.example.app",
        app_label="Example",
        run_profile="baseline_idle",
        valid_dataset_run=1,
        pcap_path=pcap_path,
        surface=surface,
        report={"capinfos": {"parsed": {"packet_count": 10, "capture_duration_s": 5.0}}},
    )
    assert run_row["payload_visibility_class"] == "cleartext_surface_present"
    assert run_row["http_host_count"] == 1
    assert http_rows[0]["sanitized_path"] == "/api/{id}"
    assert protocol_rows[0]["visibility"] == "cleartext_protocol_decoded"
    assert decoded_rows[0]["protocol"] == "ftp"


def test_render_security_review_md_includes_findings() -> None:
    md = render_security_review_md(
        {
            "status": "ok",
            "finding_count": 1,
            "risk_flags": ["http_metadata_observed"],
            "findings": [
                {
                    "severity": "high",
                    "title": "HTTP metadata observed",
                    "detail": "Sanitized HTTP host/method/path metadata was extracted.",
                }
            ],
            "cleartext": {"http_observed": True, "visibility_class": "cleartext_surface_present"},
            "dns_anomalies": {},
            "tls_surface": {},
            "domain_inventory": {},
        },
        package_name="com.example.app",
        dynamic_run_id="run-1",
    )
    assert "# PCAP Security Review (metadata)" in md
    assert "HTTP metadata observed" in md
    assert "Cleartext HTTP" not in md or "HTTP metadata observed: yes" in md
