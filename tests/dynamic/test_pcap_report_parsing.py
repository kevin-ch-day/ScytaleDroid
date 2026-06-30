import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest
from scytaledroid.DynamicAnalysis.pcap.report import _parse_protocol_hierarchy_output


def test_parse_protocol_hierarchy_output_extracts_rows() -> None:
    sample = """
===================================================================
Protocol Hierarchy Statistics
Filter:

frame                                    frames:21037 bytes:61280633
  raw                                    frames:21037 bytes:61280633
    ip                                   frames:21037 bytes:61280633
      udp                                frames:8091 bytes:8112162
        dns                              frames:240 bytes:39665
        quic                             frames:7808 bytes:8038976
      tcp                                frames:12946 bytes:53168471
        tls                              frames:5416 bytes:41447181
===================================================================
""".strip()
    rows = _parse_protocol_hierarchy_output(sample)
    assert rows
    assert any(r.get("protocol") == "udp" for r in rows)
    assert any(r.get("protocol") == "tcp" for r in rows)
    assert any(r.get("protocol") == "tls" for r in rows)


def test_write_pcap_report_appends_advanced_sections(monkeypatch, tmp_path: Path) -> None:
    from scytaledroid.DynamicAnalysis.pcap.report import write_pcap_report

    run_dir = tmp_path / "run-1"
    (run_dir / "artifacts" / "pcapdroid_capture").mkdir(parents=True)
    pcap_path = run_dir / "artifacts" / "pcapdroid_capture" / "sample.pcap"
    pcap_path.write_bytes(b"pcap")

    monkeypatch.setattr("shutil.which", lambda tool: tool)
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report._run_capinfos",
        lambda *args, **kwargs: {
            "raw": "",
            "parsed": {"packet_count": 10, "data_size_bytes": 1000, "capture_duration_s": 5.0},
            "error": None,
        },
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report._run_protocol_hierarchy",
        lambda *args, **kwargs: [{"protocol": "ip", "frames": 10, "bytes": 1000}],
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report._run_top_fields_with_stats",
        lambda *args, **kwargs: {"items": [], "total_count": 0, "unique_count": 0, "top1_share": None},
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report.scan_pcap_timeseries_and_destinations",
        lambda *args, **kwargs: {
            "direction_summary": {"outbound_packets": 6, "inbound_packets": 4, "unknown_packets": 0},
            "flow_summary": {"flow_count": 2, "top_flows": []},
            "burst_summary": {"burst_count": 1},
            "tls_quic_visibility": {"tls_handshake_packets": 2, "quic_candidate_packets": 0},
        },
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report.summarize_transport_health",
        lambda *args, **kwargs: {
            "tcp_packet_count": 10,
            "issue_packet_count": 2,
            "issue_packet_ratio": 0.2,
            "reset_packet_count": 1,
            "event_counts": {"retransmission": 1, "duplicate_ack": 1},
            "affected_stream_count": 1,
            "top_streams": [{"tcp_stream": "7", "issue_packets": 2}],
        },
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report.summarize_tls_fingerprints",
        lambda *args, **kwargs: {
            "client_hello_count": 3,
            "server_hello_count": 2,
            "unique_ja3_count": 2,
            "unique_ja4_count": 2,
            "unique_ja3s_count": 2,
            "top1_ja3_share": 2.0 / 3.0,
        },
    )

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-1",
        created_at="2026-06-15T00:00:00Z",
        target={"package_name": "bbc.mobile.news.ww"},
        artifacts=[
            ArtifactRecord(
                relative_path="artifacts/pcapdroid_capture/sample.pcap",
                type="pcapdroid_capture",
                produced_by="pcapdroid_capture",
            )
        ],
    )
    artifact = write_pcap_report(manifest, run_dir)
    assert artifact is not None

    payload = json.loads((run_dir / "analysis" / "pcap_report.json").read_text(encoding="utf-8"))
    assert payload["package_name"] == "bbc.mobile.news.ww"
    assert payload["app_label"] == "bbc.mobile.news.ww"
    assert payload["direction_summary"]["outbound_packets"] == 6
    assert payload["flow_summary"]["flow_count"] == 2
    assert payload["burst_summary"]["burst_count"] == 1
    assert payload["tls_quic_visibility"]["tls_handshake_packets"] == 2
    assert payload["tls_fingerprints"]["unique_ja3_count"] == 2
    assert payload["transport_health"]["issue_packet_count"] == 2
    assert payload["service_context"]["status"] == "no_observations"
    assert payload["service_signals"]["status"] == "no_observations"


def test_write_pcap_report_includes_target_metadata(monkeypatch, tmp_path: Path) -> None:
    from scytaledroid.DynamicAnalysis.pcap.report import write_pcap_report

    run_dir = tmp_path / "run-1"
    (run_dir / "artifacts" / "pcapdroid_capture").mkdir(parents=True)
    pcap_path = run_dir / "artifacts" / "pcapdroid_capture" / "sample.pcap"
    pcap_path.write_bytes(b"pcap")

    monkeypatch.setattr("shutil.which", lambda tool: tool)
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report._run_capinfos",
        lambda *args, **kwargs: {
            "raw": "",
            "parsed": {"packet_count": 1, "data_size_bytes": 10, "capture_duration_s": 1.0},
            "error": None,
        },
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report._run_protocol_hierarchy",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report._run_top_fields_with_stats",
        lambda *args, **kwargs: {"items": [], "total_count": 0, "unique_count": 0, "top1_share": None},
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report.scan_pcap_timeseries_and_destinations",
        lambda *args, **kwargs: {
            "direction_summary": {},
            "flow_summary": {},
            "burst_summary": {},
            "tls_quic_visibility": {},
        },
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report.summarize_transport_health",
        lambda *args, **kwargs: {},
    )

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-1",
        created_at="2026-06-15T00:00:00Z",
        target={"package_name": "com.cnn.mobile.android.phone", "display_name": "CNN"},
        artifacts=[
            ArtifactRecord(
                relative_path="artifacts/pcapdroid_capture/sample.pcap",
                type="pcapdroid_capture",
                produced_by="pcapdroid_capture",
            )
        ],
    )
    artifact = write_pcap_report(manifest, run_dir)
    assert artifact is not None

    payload = json.loads((run_dir / "analysis" / "pcap_report.json").read_text(encoding="utf-8"))
    assert payload["package_name"] == "com.cnn.mobile.android.phone"
    assert payload["app_label"] == "CNN"


def test_write_pcap_report_prefers_db_display_name_when_manifest_label_missing(monkeypatch, tmp_path: Path) -> None:
    from scytaledroid.DynamicAnalysis.pcap.report import write_pcap_report

    run_dir = tmp_path / "run-1"
    (run_dir / "artifacts" / "pcapdroid_capture").mkdir(parents=True)
    pcap_path = run_dir / "artifacts" / "pcapdroid_capture" / "sample.pcap"
    pcap_path.write_bytes(b"pcap")

    monkeypatch.setattr("shutil.which", lambda tool: tool)
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report.fetch_display_name",
        lambda package_name: "WhatsApp" if package_name == "com.whatsapp" else None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report._run_capinfos",
        lambda *args, **kwargs: {
            "raw": "",
            "parsed": {"packet_count": 1, "data_size_bytes": 10, "capture_duration_s": 1.0},
            "error": None,
        },
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report._run_protocol_hierarchy",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report._run_top_fields_with_stats",
        lambda *args, **kwargs: {"items": [], "total_count": 0, "unique_count": 0, "top1_share": None},
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report.scan_pcap_timeseries_and_destinations",
        lambda *args, **kwargs: {
            "direction_summary": {},
            "flow_summary": {},
            "burst_summary": {},
            "tls_quic_visibility": {},
        },
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report.summarize_transport_health",
        lambda *args, **kwargs: {},
    )

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-1",
        created_at="2026-06-15T00:00:00Z",
        target={"package_name": "com.whatsapp"},
        artifacts=[
            ArtifactRecord(
                relative_path="artifacts/pcapdroid_capture/sample.pcap",
                type="pcapdroid_capture",
                produced_by="pcapdroid_capture",
            )
        ],
    )
    artifact = write_pcap_report(manifest, run_dir)
    assert artifact is not None

    payload = json.loads((run_dir / "analysis" / "pcap_report.json").read_text(encoding="utf-8"))
    assert payload["package_name"] == "com.whatsapp"
    assert payload["app_label"] == "WhatsApp"


def test_write_pcap_report_recovers_small_pcap_from_meta_when_capture_artifact_missing(
    monkeypatch, tmp_path: Path
) -> None:
    from scytaledroid.DynamicAnalysis.pcap.report import write_pcap_report

    run_dir = tmp_path / "run-1"
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    capture_dir.mkdir(parents=True)
    pcap_path = capture_dir / "scytaledroid_run-1.pcap"
    pcap_path.write_bytes(b"pcap-too-small")
    (capture_dir / "pcapdroid_capture_meta.json").write_text(
        json.dumps(
            {
                "pcap_name": "scytaledroid_run-1.pcap",
                "resolved_pcap_name": "scytaledroid_run-1.pcap",
                "pcap_size_bytes": len(b"pcap-too-small"),
                "pcap_valid": False,
                "min_pcap_bytes": 50000,
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr("shutil.which", lambda tool: tool)
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report._run_capinfos",
        lambda *args, **kwargs: {"raw": "", "parsed": {"packet_count": 1, "data_size_bytes": 14, "capture_duration_s": 1.0}, "error": None},
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report._run_protocol_hierarchy",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report._run_top_fields_with_stats",
        lambda *args, **kwargs: {"items": [], "total_count": 0, "unique_count": 0, "top1_share": None},
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report.scan_pcap_timeseries_and_destinations",
        lambda *args, **kwargs: {
            "direction_summary": {},
            "flow_summary": {},
            "burst_summary": {},
            "tls_quic_visibility": {},
        },
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.report.summarize_transport_health",
        lambda *args, **kwargs: {},
    )

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-1",
        created_at="2026-06-15T00:00:00Z",
        target={"package_name": "com.whatsapp"},
        artifacts=[
            ArtifactRecord(
                relative_path="artifacts/pcapdroid_capture/pcapdroid_capture_meta.json",
                type="pcapdroid_capture_meta",
                produced_by="pcapdroid_capture",
            )
        ],
    )
    artifact = write_pcap_report(manifest, run_dir)
    assert artifact is not None

    payload = json.loads((run_dir / "analysis" / "pcap_report.json").read_text(encoding="utf-8"))
    assert payload["pcap_path"] == "artifacts/pcapdroid_capture/scytaledroid_run-1.pcap"
    assert payload["pcap_capture_name"] == "scytaledroid_run-1.pcap"
    assert payload["pcap_size_bytes"] == len(b"pcap-too-small")
    assert payload["capture_identity"]["dynamic_run_id"] == "run-1"
    assert payload["capture_identity"]["package_name"] == "com.whatsapp"
    assert payload["capture_identity"]["package_slug"] == "com_whatsapp"
    assert payload["report_status"] == "ok"
