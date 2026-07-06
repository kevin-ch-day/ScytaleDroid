from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, ObserverRecord, RunManifest
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
    DatasetTrackerConfig,
    evaluate_dataset_validity,
)


def test_evaluate_dataset_validity_uses_summary_netstats_when_entry_omits_total(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "dynamic" / "run-1"
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis" / "summary.json").write_text(
        json.dumps(
            {
                "telemetry": {
                    "stats": {
                        "netstats_bytes_in_total": 1_500_000,
                        "netstats_bytes_out_total": 250_000,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "report_status": "ok",
                "capinfos": {
                    "parsed": {
                        "capture_duration_s": 240.0,
                        "packet_count": 4096,
                        "data_size_bytes": 512_000,
                    }
                },
                "protocol_hierarchy": [{"protocol": "ip", "bytes": 4096, "frames": 16}],
                "no_traffic_observed": 0,
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_features.json").write_text(
        json.dumps({"metrics": {}, "proxies": {}}), encoding="utf-8"
    )

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-1",
        created_at="2026-06-28T00:00:00Z",
        operator={
            "run_profile": "baseline_idle",
            "run_sequence": 1,
            "interaction_level": "minimal",
        },
    )

    validity = evaluate_dataset_validity(
        run_dir,
        manifest,
        {"pcap_size_bytes": 512_000},
        DatasetTrackerConfig(),
    )

    assert validity["valid_dataset_run"] is True
    assert validity["netstats_observed_bytes"] == 1_750_000


def test_evaluate_dataset_validity_treats_small_existing_pcap_as_too_small_not_missing(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "dynamic" / "run-1"
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    analysis_dir = run_dir / "analysis"
    capture_dir.mkdir(parents=True, exist_ok=True)
    analysis_dir.mkdir(parents=True, exist_ok=True)

    pcap_bytes = 20712
    (capture_dir / "scytaledroid_run-1.pcap").write_bytes(b"x" * pcap_bytes)
    (capture_dir / "pcapdroid_capture_meta.json").write_text(
        json.dumps(
            {
                "pcap_name": "scytaledroid_run-1.pcap",
                "resolved_pcap_name": "scytaledroid_run-1.pcap",
                "pcap_size_bytes": pcap_bytes,
                "pcap_valid": False,
                "min_pcap_bytes": 50000,
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "summary.json").write_text(
        json.dumps(
            {
                "telemetry": {
                    "stats": {"netstats_bytes_in_total": 5340, "netstats_bytes_out_total": 7268}
                }
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "pcap_report.json").write_text(
        json.dumps(
            {
                "report_status": "ok",
                "capinfos": {
                    "parsed": {
                        "capture_duration_s": 480.0,
                        "packet_count": 199,
                        "data_size_bytes": pcap_bytes,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "pcap_features.json").write_text(
        json.dumps({"metrics": {}, "proxies": {}}), encoding="utf-8"
    )

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-1",
        created_at="2026-06-30T00:00:00Z",
        operator={
            "run_profile": "baseline_idle",
            "run_sequence": 3,
            "interaction_level": "minimal",
        },
        observers=[
            ObserverRecord(observer_id="pcapdroid_capture", status="failed", error="too small")
        ],
        artifacts=[
            ArtifactRecord(
                relative_path="artifacts/pcapdroid_capture/pcapdroid_capture_meta.json",
                type="pcapdroid_capture_meta",
                produced_by="pcapdroid_capture",
            )
        ],
    )

    validity = evaluate_dataset_validity(run_dir, manifest, {}, DatasetTrackerConfig())

    assert validity["valid_dataset_run"] is False
    assert validity["invalid_reason_code"] == "PCAP_TOO_SMALL"
    assert validity.get("pcap_size_bytes") is None or validity.get("pcap_size_bytes") == pcap_bytes


def test_evaluate_dataset_validity_accepts_small_connected_baseline_above_connected_floor(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "dynamic" / "run-2"
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    analysis_dir = run_dir / "analysis"
    capture_dir.mkdir(parents=True, exist_ok=True)
    analysis_dir.mkdir(parents=True, exist_ok=True)

    pcap_bytes = 20712
    (capture_dir / "scytaledroid_run-2.pcap").write_bytes(b"x" * pcap_bytes)
    (capture_dir / "pcapdroid_capture_meta.json").write_text(
        json.dumps(
            {
                "pcap_name": "scytaledroid_run-2.pcap",
                "resolved_pcap_name": "scytaledroid_run-2.pcap",
                "pcap_size_bytes": pcap_bytes,
                "pcap_valid": False,
                "min_pcap_bytes": 50000,
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "summary.json").write_text(
        json.dumps(
            {
                "telemetry": {
                    "stats": {"netstats_bytes_in_total": 5340, "netstats_bytes_out_total": 7268}
                }
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "pcap_report.json").write_text(
        json.dumps(
            {
                "report_status": "ok",
                "capinfos": {
                    "parsed": {
                        "capture_duration_s": 480.0,
                        "packet_count": 199,
                        "data_size_bytes": pcap_bytes,
                    }
                },
                "protocol_hierarchy": [{"protocol": "tls", "bytes": pcap_bytes}],
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "pcap_features.json").write_text(
        json.dumps(
            {
                "metrics": {},
                "proxies": {},
                "quality": {"report_status": "ok", "pcap_enrichment": {"status": "ok"}},
            }
        ),
        encoding="utf-8",
    )

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-2",
        created_at="2026-06-30T00:00:00Z",
        scenario={"id": "paper3_profile_v3"},
        operator={
            "run_profile": "baseline_connected",
            "run_sequence": 3,
            "interaction_level": "minimal",
        },
        observers=[
            ObserverRecord(observer_id="pcapdroid_capture", status="failed", error="too small")
        ],
        artifacts=[
            ArtifactRecord(
                relative_path="artifacts/pcapdroid_capture/pcapdroid_capture_meta.json",
                type="pcapdroid_capture_meta",
                produced_by="pcapdroid_capture",
            )
        ],
    )

    validity = evaluate_dataset_validity(run_dir, manifest, {}, DatasetTrackerConfig())

    assert validity["valid_dataset_run"] is True
    assert validity["invalid_reason_code"] is None
    assert validity["min_pcap_bytes"] == 10_000
    assert validity.get("pcap_size_bytes") == pcap_bytes


def test_evaluate_dataset_validity_accepts_small_manual_messaging_text_above_connected_floor(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "dynamic" / "run-3"
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    analysis_dir = run_dir / "analysis"
    capture_dir.mkdir(parents=True, exist_ok=True)
    analysis_dir.mkdir(parents=True, exist_ok=True)

    pcap_bytes = 37_590
    (capture_dir / "scytaledroid_run-3.pcap").write_bytes(b"x" * pcap_bytes)
    (capture_dir / "pcapdroid_capture_meta.json").write_text(
        json.dumps(
            {
                "pcap_name": "scytaledroid_run-3.pcap",
                "resolved_pcap_name": "scytaledroid_run-3.pcap",
                "pcap_size_bytes": pcap_bytes,
                "pcap_valid": False,
                "min_pcap_bytes": 50_000,
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "summary.json").write_text(
        json.dumps(
            {
                "telemetry": {
                    "stats": {"netstats_bytes_in_total": 12_477, "netstats_bytes_out_total": 13_531}
                }
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "pcap_report.json").write_text(
        json.dumps(
            {
                "report_status": "ok",
                "capinfos": {
                    "parsed": {
                        "capture_duration_s": 289.09,
                        "packet_count": 399,
                        "data_size_bytes": pcap_bytes,
                    }
                },
                "protocol_hierarchy": [{"protocol": "tcp", "bytes": pcap_bytes}],
                "top_dns": [{"value": "g.whatsapp.net", "count": 2}],
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "pcap_features.json").write_text(
        json.dumps(
            {
                "metrics": {},
                "proxies": {},
                "quality": {"report_status": "ok", "pcap_enrichment": {"status": "ok"}},
            }
        ),
        encoding="utf-8",
    )

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-3",
        created_at="2026-07-01T00:00:00Z",
        scenario={"id": "basic_usage"},
        target={"package_name": "com.whatsapp"},
        operator={
            "run_profile": "interaction_manual",
            "run_sequence": 6,
            "interaction_level": "manual",
            "messaging_activity": "text_only",
        },
        observers=[
            ObserverRecord(observer_id="pcapdroid_capture", status="failed", error="too small")
        ],
        artifacts=[
            ArtifactRecord(
                relative_path="artifacts/pcapdroid_capture/pcapdroid_capture_meta.json",
                type="pcapdroid_capture_meta",
                produced_by="pcapdroid_capture",
            )
        ],
    )

    validity = evaluate_dataset_validity(run_dir, manifest, {}, DatasetTrackerConfig())

    assert validity["valid_dataset_run"] is True
    assert validity["invalid_reason_code"] is None
    assert validity["min_pcap_bytes"] == 10_000


def test_evaluate_dataset_validity_accepts_signal_like_quiet_connected_baseline_above_new_floor(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "dynamic" / "run-signal"
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    analysis_dir = run_dir / "analysis"
    capture_dir.mkdir(parents=True, exist_ok=True)
    analysis_dir.mkdir(parents=True, exist_ok=True)

    pcap_bytes = 12_893
    (capture_dir / "scytaledroid_run-signal.pcap").write_bytes(b"x" * pcap_bytes)
    (capture_dir / "pcapdroid_capture_meta.json").write_text(
        json.dumps(
            {
                "pcap_name": "scytaledroid_run-signal.pcap",
                "resolved_pcap_name": "scytaledroid_run-signal.pcap",
                "pcap_size_bytes": pcap_bytes,
                "pcap_valid": False,
                "min_pcap_bytes": 20_000,
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "summary.json").write_text(
        json.dumps(
            {
                "telemetry": {
                    "stats": {"netstats_bytes_in_total": 2398, "netstats_bytes_out_total": 1959}
                }
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "pcap_report.json").write_text(
        json.dumps(
            {
                "report_status": "ok",
                "capinfos": {
                    "parsed": {
                        "capture_duration_s": 250.85,
                        "packet_count": 110,
                        "data_size_bytes": 11_109,
                    }
                },
                "protocol_hierarchy": [{"protocol": "tls", "bytes": pcap_bytes}],
                "top_dns": [{"value": "grpc.chat.signal.org", "count": 4}],
                "top_sni": [{"value": "grpc.chat.signal.org", "count": 2}],
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "pcap_features.json").write_text(
        json.dumps(
            {
                "metrics": {
                    "capture_duration_s": 250.85,
                    "data_size_bytes": 11_109,
                    "packet_count": 110,
                },
                "proxies": {
                    "unique_domains_topn": 1,
                    "unique_ja4_count": 1,
                    "tls_client_hello_count": 2,
                },
                "quality": {"report_status": "ok", "pcap_valid": True, "pcap_enrichment": {"status": "ok"}},
            }
        ),
        encoding="utf-8",
    )

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-signal",
        created_at="2026-07-06T00:00:00Z",
        scenario={"id": "basic_usage"},
        target={"package_name": "org.thoughtcrime.securesms"},
        operator={
            "run_profile": "baseline_connected",
            "run_sequence": 1,
            "interaction_level": "minimal",
            "messaging_activity": "connected_idle",
            "baseline_protocol_id": "baseline_connected_v2",
            "baseline_protocol_version": 2,
        },
        observers=[
            ObserverRecord(observer_id="pcapdroid_capture", status="failed", error="too small")
        ],
        artifacts=[
            ArtifactRecord(
                relative_path="artifacts/pcapdroid_capture/pcapdroid_capture_meta.json",
                type="pcapdroid_capture_meta",
                produced_by="pcapdroid_capture",
            )
        ],
    )

    validity = evaluate_dataset_validity(run_dir, manifest, {}, DatasetTrackerConfig())

    assert validity["valid_dataset_run"] is True
    assert validity["invalid_reason_code"] is None
    assert validity["min_pcap_bytes"] == 10_000
    assert validity.get("pcap_size_bytes") == pcap_bytes
    assert validity.get("pcap_size_bytes") == pcap_bytes
