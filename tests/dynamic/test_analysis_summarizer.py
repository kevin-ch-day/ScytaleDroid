from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.analysis.summarizer import DynamicRunSummarizer
from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest


def _manifest(*, artifacts: list[ArtifactRecord]) -> RunManifest:
    return RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-1",
        created_at="2026-06-15T00:00:00Z",
        status="degraded",
        artifacts=artifacts,
    )


def test_summarizer_marks_pcap_unavailable_when_only_meta_exists(tmp_path: Path) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    meta_path = tmp_path / "artifacts" / "pcapdroid_capture" / "pcapdroid_capture_meta.json"
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(
        json.dumps(
            {
                "pcap_name": "scytaledroid_run-1.pcap",
                "pcap_size_bytes": 0,
                "pcap_valid": False,
                "capture_mode": "app_only",
            }
        ),
        encoding="utf-8",
    )
    manifest = _manifest(
        artifacts=[
            ArtifactRecord(
                relative_path=str(meta_path.relative_to(tmp_path)),
                type="pcapdroid_capture_meta",
                produced_by="pcapdroid_capture",
            )
        ]
    )

    summary = DynamicRunSummarizer(writer)._build_summary(manifest)

    assert summary["capture"]["pcap_available"] is False
    assert summary["capture"]["pcap_valid"] is False


def test_summarizer_marks_pcap_available_when_capture_artifact_exists(tmp_path: Path) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    meta_path = tmp_path / "artifacts" / "pcapdroid_capture" / "pcapdroid_capture_meta.json"
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(
        json.dumps(
            {
                "pcap_name": "scytaledroid_run-1.pcap",
                "pcap_size_bytes": 250000,
                "pcap_valid": True,
                "capture_mode": "app_only",
            }
        ),
        encoding="utf-8",
    )
    pcap_path = tmp_path / "artifacts" / "pcapdroid_capture" / "scytaledroid_run-1.pcap"
    pcap_path.write_bytes(b"pcap")
    manifest = _manifest(
        artifacts=[
            ArtifactRecord(
                relative_path=str(meta_path.relative_to(tmp_path)),
                type="pcapdroid_capture_meta",
                produced_by="pcapdroid_capture",
            ),
            ArtifactRecord(
                relative_path=str(pcap_path.relative_to(tmp_path)),
                type="pcapdroid_capture",
                produced_by="pcapdroid_capture",
                size_bytes=pcap_path.stat().st_size,
            ),
        ]
    )

    summary = DynamicRunSummarizer(writer)._build_summary(manifest)

    assert summary["capture"]["pcap_available"] is True


def test_summarizer_recovers_present_too_small_pcap_from_meta_only(tmp_path: Path) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    meta_path = tmp_path / "artifacts" / "pcapdroid_capture" / "pcapdroid_capture_meta.json"
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(
        json.dumps(
            {
                "pcap_name": "scytaledroid_run-1.pcap",
                "pcap_size_bytes": 12893,
                "pcap_valid": False,
                "capture_mode": "app_only",
                "min_pcap_bytes": 20000,
            }
        ),
        encoding="utf-8",
    )
    pcap_path = tmp_path / "artifacts" / "pcapdroid_capture" / "scytaledroid_run-1.pcap"
    pcap_path.write_bytes(b"x" * 12893)
    manifest = _manifest(
        artifacts=[
            ArtifactRecord(
                relative_path=str(meta_path.relative_to(tmp_path)),
                type="pcapdroid_capture_meta",
                produced_by="pcapdroid_capture",
            )
        ]
    )

    summary = DynamicRunSummarizer(writer)._build_summary(manifest)
    rendered = DynamicRunSummarizer(writer)._render_summary_md(summary)

    assert summary["capture"]["pcap_available"] is True
    assert summary["capture"]["pcap_valid"] is False
    assert summary["capture"]["pcap_size_bytes"] == 12893
    assert summary["flags"]["network_capture_present"] == "true"
    assert "Network capture present: yes." in rendered
    assert "PCAP valid: no." in rendered


def test_summarizer_prefers_repaired_dataset_truth_over_stale_pcap_meta(tmp_path: Path) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    meta_path = tmp_path / "artifacts" / "pcapdroid_capture" / "pcapdroid_capture_meta.json"
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(
        json.dumps(
            {
                "pcap_name": "scytaledroid_run-1.pcap",
                "pcap_size_bytes": 12893,
                "pcap_valid": False,
                "capture_mode": "app_only",
                "min_pcap_bytes": 20000,
            }
        ),
        encoding="utf-8",
    )
    pcap_path = tmp_path / "artifacts" / "pcapdroid_capture" / "scytaledroid_run-1.pcap"
    pcap_path.write_bytes(b"x" * 12893)
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="signal-repaired",
        created_at="2026-07-06T00:00:00Z",
        status="success",
        dataset={
            "valid_dataset_run": True,
            "countable": True,
            "cohort_eligibility": "COUNTABLE",
            "invalid_reason_code": None,
            "pcap_failure_detail": None,
            "pcap_size_bytes": 12893,
        },
        operator={"run_profile": "baseline_connected", "messaging_activity": "connected_idle"},
        target={"package_name": "org.thoughtcrime.securesms", "version_code": 171302},
        artifacts=[
            ArtifactRecord(
                relative_path=str(meta_path.relative_to(tmp_path)),
                type="pcapdroid_capture_meta",
                produced_by="pcapdroid_capture",
            )
        ],
    )

    summary = DynamicRunSummarizer(writer)._build_summary(manifest)
    rendered = DynamicRunSummarizer(writer)._render_summary_md(summary)

    assert summary["capture"]["pcap_available"] is True
    assert summary["capture"]["pcap_valid"] is True
    assert summary["pcap_valid"] is True
    assert summary["pcap_failure_detail"] is None
    assert summary["quota_detail"]["pcap_failure_detail"] is None
    assert "PCAP valid: yes." in rendered
    assert "Counts toward quota: YES (baseline_connected)." in rendered


def test_summarizer_falls_back_to_pcap_report_destinations(tmp_path: Path) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    report_path = tmp_path / "analysis" / "pcap_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(
            {
                "top_dns": [
                    {"value": "graph.facebook.com", "count": 8},
                    {"value": "edge-mqtt.facebook.com", "count": 4},
                ],
                "top_sni": [
                    {"value": "graph.facebook.com", "count": 4},
                    {"value": "lookaside.facebook.com", "count": 2},
                ],
                "service_context": {
                    "services": [
                        {
                            "domains": [
                                {"domain": "static.xx.fbcdn.net"},
                            ]
                        }
                    ],
                    "unresolved_domains": [
                        {"domain": "example-unresolved.test"},
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    manifest = _manifest(artifacts=[])

    summary = DynamicRunSummarizer(writer)._build_summary(manifest)

    assert summary["destinations_observed"] == [
        "graph.facebook.com",
        "edge-mqtt.facebook.com",
        "lookaside.facebook.com",
        "static.xx.fbcdn.net",
        "example-unresolved.test",
    ]
    assert summary["flags"]["cleartext_http_detected"] == "unknown"


def test_summarizer_uses_security_surface_for_cleartext_detection(tmp_path: Path) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    report_path = tmp_path / "analysis" / "pcap_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(
            {
                "top_dns": [{"value": "api.example.com", "count": 3}],
                "top_sni": [{"value": "api.example.com", "count": 3}],
                "security_surface": {
                    "status": "ok",
                    "finding_count": 1,
                    "risk_flags": ["http_metadata_observed"],
                    "findings": [
                        {
                            "severity": "high",
                            "category": "cleartext",
                            "title": "HTTP metadata observed",
                            "detail": "Sanitized HTTP host/method/path metadata was extracted.",
                        }
                    ],
                    "cleartext": {
                        "http_observed": True,
                        "visibility_class": "cleartext_surface_present",
                        "plaintext_protocol_frames": 4,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    manifest = _manifest(artifacts=[])

    summary = DynamicRunSummarizer(writer)._build_summary(manifest)
    rendered = DynamicRunSummarizer(writer)._render_summary_md(summary)

    assert summary["flags"]["cleartext_http_detected"] == "true"
    assert summary["flags"]["security_finding_count"] == 1
    assert summary["indicators"]["security_surface"]["finding_count"] == 1
    assert "Cleartext HTTP detected: yes." in rendered
    assert "## Security (metadata)" in rendered
    assert "HTTP metadata observed [high]" in rendered


def test_summarizer_includes_media_plane_indicator(tmp_path: Path) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    report_path = tmp_path / "analysis" / "pcap_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(
            {
                "top_dns": [{"value": "api.whatsapp.net", "count": 3}],
                "top_sni": [{"value": "graph.whatsapp.com", "count": 2}],
                "media_plane": {
                    "status": "ok",
                    "summary": {
                        "classification": "relay_media_likely",
                        "relay_endpoint_count": 3,
                        "turn_allocate_success_count": 16,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    manifest = _manifest(artifacts=[])

    summary = DynamicRunSummarizer(writer)._build_summary(manifest)

    assert summary["indicators"]["media_plane"]["status"] == "ok"
    assert summary["indicators"]["media_plane"]["summary"]["classification"] == "relay_media_likely"


def test_summarizer_includes_manual_call_outcome_fields(tmp_path: Path) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    manifest = _manifest(artifacts=[])
    manifest.operator = {
        "run_profile": "interaction_manual",
        "messaging_activity": "video_call",
        "call_type": "video",
        "call_attempted": True,
        "call_connected": False,
        "call_outcome_reason": "CALL_NOT_CONNECTED",
    }
    manifest.target = {
        "package_name": "com.facebook.orca",
    }
    manifest.environment = {
        "device_model": "moto g 5G 2024",
        "android_version": "15",
        "security_patch_level": "2026-06-05",
        "play_services_version": "25.22.35",
    }
    manifest.scenario = {"id": "basic_usage"}
    manifest.dataset = {"valid_dataset_run": True, "countable": True}

    summary = DynamicRunSummarizer(writer)._build_summary(manifest)
    rendered = DynamicRunSummarizer(writer)._render_summary_md(summary)

    assert summary["messaging_activity"] == "video_call"
    assert summary["call_type"] == "video"
    assert summary["call_attempted"] is True
    assert summary["call_connected"] is False
    assert summary["call_outcome_reason"] == "CALL_NOT_CONNECTED"
    assert "- Call connected: no." in rendered
    assert "- Call outcome: CALL_NOT_CONNECTED." in rendered


def test_summarizer_includes_cleartext_posture_mismatch(tmp_path: Path) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    report_path = tmp_path / "analysis" / "pcap_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(
            {
                "top_dns": [],
                "top_sni": [],
                "security_surface": {
                    "status": "ok",
                    "finding_count": 1,
                    "risk_flags": ["http_metadata_observed"],
                    "findings": [],
                    "cleartext": {
                        "http_observed": True,
                        "visibility_class": "cleartext_surface_present",
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    plan_path = tmp_path / "inputs" / "static_dynamic_plan.json"
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    plan_path.write_text(
        json.dumps(
            {
                "static_features": {"uses_cleartext_traffic": False},
                "network_targets": {"cleartext_domains": []},
            }
        ),
        encoding="utf-8",
    )
    manifest = _manifest(artifacts=[])

    summary = DynamicRunSummarizer(writer)._build_summary(manifest)
    rendered = DynamicRunSummarizer(writer)._render_summary_md(summary)

    assert summary["indicators"]["cleartext_posture"]["mismatch_class"] == "denied_but_observed"
    assert summary["flags"]["cleartext_mismatch_class"] == "denied_but_observed"
    assert "Static↔dynamic cleartext:" in rendered
    assert "denies cleartext" in rendered


def test_summarizer_security_surface_marks_encrypted_dominant_as_no_cleartext(
    tmp_path: Path,
) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    report_path = tmp_path / "analysis" / "pcap_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(
            {
                "top_dns": [{"value": "secure.example.com", "count": 2}],
                "security_surface": {
                    "status": "ok",
                    "finding_count": 0,
                    "risk_flags": [],
                    "findings": [],
                    "cleartext": {
                        "http_observed": False,
                        "plaintext_protocol_frames": 0,
                        "visibility_class": "encrypted_or_opaque_dominant",
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    manifest = _manifest(artifacts=[])

    summary = DynamicRunSummarizer(writer)._build_summary(manifest)

    assert summary["flags"]["cleartext_http_detected"] == "false"


def test_summarizer_includes_dataset_quota_and_indicator_fields(tmp_path: Path) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    report_path = tmp_path / "analysis" / "pcap_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(
            {
                "top_dns": [
                    {"value": "graph.facebook.com", "count": 8},
                ],
                "top_sni": [
                    {"value": "lookaside.facebook.com", "count": 5},
                ],
                "service_context": {"status": "ok", "service_count": 2},
                "service_signals": {
                    "status": "ok",
                    "signal_count": 1,
                    "signals": [{"signal_key": "messaging", "score": 0.9}],
                },
            }
        ),
        encoding="utf-8",
    )
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-2",
        created_at="2026-06-15T00:00:00Z",
        status="success",
        dataset={
            "valid_dataset_run": True,
            "countable": True,
            "cohort_eligibility": "COUNTABLE",
            "invalid_reason_code": None,
        },
        operator={"run_profile": "interaction_manual"},
        target={"package_name": "com.facebook.katana"},
        artifacts=[],
    )

    summary = DynamicRunSummarizer(writer)._build_summary(manifest)
    rendered = DynamicRunSummarizer(writer)._render_summary_md(summary)

    assert summary["run_profile"] == "interaction_manual"
    assert summary["dataset_verdict"] == "VALID"
    assert summary["counts_toward_quota"] is True
    assert summary["quota_detail"]["countability_label"] == "YES (interaction_manual)"
    assert summary["quota_detail"]["cohort_eligibility"] == "COUNTABLE"
    assert summary["verdicts"]["technical"] == "VALID"
    assert summary["verdicts"]["cohort"] == "COUNTABLE"
    assert summary["indicators"]["top_dns"] == [{"value": "graph.facebook.com", "count": 8}]
    assert summary["indicators"]["top_sni"] == [{"value": "lookaside.facebook.com", "count": 5}]
    assert summary["indicators"]["service_context"]["service_count"] == 2
    assert summary["indicators"]["service_signals"]["signal_count"] == 1
    assert "Run profile: interaction_manual." in rendered
    assert "Dataset verdict: VALID." in rendered
    assert "Counts toward quota: YES (interaction_manual)." in rendered
    assert "Network capture present: no." in rendered
    assert "PCAP valid: unknown." in rendered
    assert "Top DNS: graph.facebook.com (8)." in rendered
    assert "Top SNI: lookaside.facebook.com (5)." in rendered


def test_summarizer_uses_paper_exclusion_reason_for_valid_supplemental_run(tmp_path: Path) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-3",
        created_at="2026-06-15T00:00:00Z",
        status="success",
        dataset={
            "valid_dataset_run": True,
            "countable": False,
            "cohort_eligibility": "EXCLUDED",
            "invalid_reason_code": None,
            "paper_exclusion_primary_reason_code": "EXCLUDED_SCRIPT_ABORT",
        },
        operator={"run_profile": "interaction_scripted"},
        target={"package_name": "com.whatsapp"},
        artifacts=[],
    )

    summary = DynamicRunSummarizer(writer)._build_summary(manifest)
    rendered = DynamicRunSummarizer(writer)._render_summary_md(summary)

    assert summary["dataset_verdict"] == "VALID"
    assert summary["counts_toward_quota"] is False
    assert summary["quota_detail"]["countability_label"] == "NO (extra run)"
    assert summary["quota_detail"]["invalid_reason_code"] == "EXCLUDED_SCRIPT_ABORT"
    assert "Counts toward quota: NO (extra run)." in rendered
    assert "Invalid reason: EXCLUDED_SCRIPT_ABORT." in rendered


def test_summarizer_renders_dash_for_missing_invalid_reason(tmp_path: Path) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-4",
        created_at="2026-06-15T00:00:00Z",
        status="success",
        dataset={
            "valid_dataset_run": True,
            "countable": False,
            "cohort_eligibility": "EXTRA",
            "invalid_reason_code": None,
        },
        operator={"run_profile": "interaction_manual"},
        target={"package_name": "com.example.app"},
        artifacts=[],
    )

    summary = DynamicRunSummarizer(writer)._build_summary(manifest)
    rendered = DynamicRunSummarizer(writer)._render_summary_md(summary)

    assert summary["quota_detail"]["invalid_reason_code"] is None
    assert "Invalid reason: —." in rendered


def test_summarizer_labels_baseline_not_idle_explicitly(tmp_path: Path) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-5",
        created_at="2026-07-05T00:00:00Z",
        status="success",
        dataset={
            "valid_dataset_run": True,
            "countable": False,
            "cohort_eligibility": "EXTRA",
            "invalid_reason_code": None,
            "exploratory_class": "BASELINE_NOT_IDLE",
            "baseline_not_idle": True,
            "baseline_not_idle_reasons": [
                "BASELINE_BYTES_HIGH",
                "BASELINE_QUIC_MEDIA_HEAVY",
            ],
            "actual_sampling_seconds": 301.2,
        },
        operator={"run_profile": "baseline_idle"},
        target={"package_name": "com.zhiliaoapp.musically", "version_code": 2024507030},
        artifacts=[],
    )

    summary = DynamicRunSummarizer(writer)._build_summary(manifest)
    rendered = DynamicRunSummarizer(writer)._render_summary_md(summary)

    assert summary["package_name"] == "com.zhiliaoapp.musically"
    assert summary["version_code"] == 2024507030
    assert summary["counts_toward_quota"] is False
    assert summary["countability_reason"] == "BASELINE_NOT_IDLE"
    assert summary["exploratory_class"] == "BASELINE_NOT_IDLE"
    assert summary["capture_duration_s"] == 301.2
    assert summary["quota_detail"]["countability_label"] == "NO (BASELINE_NOT_IDLE)"
    assert summary["quota_detail"]["exploratory_class"] == "BASELINE_NOT_IDLE"
    assert summary["quota_detail"]["baseline_not_idle"] is True
    assert summary["quota_detail"]["baseline_not_idle_reasons"] == [
        "BASELINE_BYTES_HIGH",
        "BASELINE_QUIC_MEDIA_HEAVY",
    ]
    assert "Counts toward quota: NO (BASELINE_NOT_IDLE)." in rendered


def test_summarizer_surfaces_quota_window_metrics_from_pcap_features(tmp_path: Path) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    (tmp_path / "analysis").mkdir(parents=True, exist_ok=True)
    (tmp_path / "analysis" / "pcap_features.json").write_text(
        json.dumps(
            {
                "startup_profile": {
                    "summary": {
                        "window_s": 60,
                        "startup_total_bytes": 8600000,
                        "startup_byte_share": 0.94,
                        "post_start_median_bytes_per_min": 18500.0,
                        "post_start_mean_bytes_per_min": 20500.0,
                        "startup_dominant": True,
                    }
                },
                "window_metrics": {
                    "180s": {
                        "window_s": 180,
                        "total_bytes": 8650000,
                        "total_packets": 3666,
                        "avg_bytes_per_sec": 48055.5,
                        "bytes_per_second_p95": 120000.0,
                        "active_second_count": 132,
                    },
                    "240s": {
                        "window_s": 240,
                        "total_bytes": 8652000,
                        "total_packets": 3671,
                        "avg_bytes_per_sec": 36050.0,
                        "bytes_per_second_p95": 91000.0,
                        "active_second_count": 154,
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="guardian-run",
        created_at="2026-07-05T00:00:00Z",
        status="success",
        dataset={
            "valid_dataset_run": True,
            "countable": False,
            "cohort_eligibility": "EXTRA",
            "baseline_not_idle": True,
            "actual_sampling_seconds": 301.2,
        },
        operator={"run_profile": "baseline_idle"},
        target={"package_name": "com.guardian", "version_code": 23011},
        artifacts=[],
    )

    summary = DynamicRunSummarizer(writer)._build_summary(manifest)
    rendered = DynamicRunSummarizer(writer)._render_summary_md(summary)

    assert summary["capture"]["quota_window_metrics"]["180s"]["total_bytes"] == 8650000
    assert summary["capture"]["quota_window_metrics"]["240s"]["avg_bytes_per_sec"] == 36050.0
    assert summary["capture"]["startup_profile"]["startup_byte_share"] == 0.94
    assert "## Quota windows" in rendered
    assert "## Startup profile" in rendered
    assert "- First 60s: 8600000 bytes (94.0% of observed bytes)." in rendered
    assert "- Post-start tail: median 18500.0 B/min, mean 20500.0 B/min." in rendered
    assert "- Startup dominant: yes." in rendered
    assert "- 180s: 8650000 bytes, avg 48055.5 B/s, p95 120000.0 B/s, 3666 packets, active 132s." in rendered
    assert "- 240s: 8652000 bytes, avg 36050.0 B/s, p95 91000.0 B/s, 3671 packets, active 154s." in rendered


def test_summarizer_promotes_runtime_network_fields_to_top_level(tmp_path: Path) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    (tmp_path / "analysis").mkdir(parents=True, exist_ok=True)
    (tmp_path / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "capture_duration_s": 301.8,
                "dns_unique_count": 4,
                "sni_unique_count": 3,
                "top_dns": [{"value": "i.instagram.com", "count": 4}],
                "top_sni": [{"value": "edge-mqtt.facebook.com", "count": 3}],
                "service_context": {
                    "status": "ok",
                    "observed_domain_count": 4,
                    "service_count": 2,
                    "services": [
                        {"service_category": "social_platform"},
                        {"service_category": "messaging"},
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "analysis" / "pcap_features.json").write_text(
        json.dumps(
            {
                "fingerprints": {
                    "summary": {
                        "client_hello_count": 11,
                        "server_hello_count": 9,
                        "unique_ja3_count": 5,
                        "unique_ja3s_count": 2,
                        "unique_ja4_count": 4,
                        "top_alpn": [{"value": "h2", "count": 3}],
                        "top_ja3": [{"value": "ja3-a", "count": 5}],
                        "top_ja3s": [{"value": "ja3s-a", "count": 4}],
                        "top_ja4": [{"value": "ja4-a", "count": 3}],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    meta_path = tmp_path / "artifacts" / "pcapdroid_capture" / "pcapdroid_capture_meta.json"
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(
        json.dumps(
            {
                "pcap_size_bytes": 2366648,
                "pcap_valid": True,
                "capture_mode": "app_only",
            }
        ),
        encoding="utf-8",
    )
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="instagram-run",
        created_at="2026-07-06T00:00:00Z",
        status="success",
        dataset={
            "valid_dataset_run": True,
            "countable": True,
            "cohort_eligibility": "COUNTABLE",
            "actual_sampling_seconds": 240,
        },
        operator={"run_profile": "baseline_idle"},
        target={
            "package_name": "com.instagram.android",
            "version_code": 384209456,
            "version_name": "436.0.0.41.73",
        },
        artifacts=[
            ArtifactRecord(
                relative_path=str(meta_path.relative_to(tmp_path)),
                type="pcapdroid_capture_meta",
                produced_by="pcapdroid_capture",
            )
        ],
    )

    summary = DynamicRunSummarizer(writer)._build_summary(manifest)

    assert summary["version_name"] == "436.0.0.41.73"
    assert summary["pcap_valid"] is True
    assert summary["capinfos_capture_duration_s"] == 301.8
    assert summary["domain_count"] == 2
    assert summary["dns_count"] == 4
    assert summary["sni_count"] == 3
    assert summary["service_families_observed"] == "messaging, social_platform"
    assert summary["unique_service_families"] == 2
    assert summary["tls_client_hello_count"] == 11
    assert summary["tls_server_hello_count"] == 9
    assert summary["unique_ja3_count"] == 5
    assert summary["unique_ja3s_count"] == 2
    assert summary["unique_ja4_count"] == 4
    assert summary["top_alpn"] == [{"value": "h2", "count": 3}]
    assert summary["top_ja3"] == [{"value": "ja3-a", "count": 5}]
    assert summary["top_ja3s"] == [{"value": "ja3s-a", "count": 4}]
    assert summary["top_ja4"] == [{"value": "ja4-a", "count": 3}]
    assert summary["indicators"]["tls_fingerprints"]["unique_ja4_count"] == 4
    assert summary["indicators"]["top_alpn"] == [{"value": "h2", "count": 3}]


def test_summarizer_marks_present_but_too_small_pcap_with_explicit_failure_detail(
    tmp_path: Path,
) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    meta_path = tmp_path / "artifacts" / "pcapdroid_capture" / "pcapdroid_capture_meta.json"
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(
        json.dumps(
            {
                "pcap_size_bytes": 12893,
                "pcap_valid": False,
                "pcap_available": True,
                "min_pcap_bytes": 20000,
            }
        ),
        encoding="utf-8",
    )
    (meta_path.parent / "tiny.pcap").write_bytes(b"x" * 12893)
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="signal-small",
        created_at="2026-07-06T00:00:00Z",
        status="failed",
        dataset={
            "valid_dataset_run": False,
            "countable": False,
            "invalid_reason_code": "PCAP_MISSING",
            "pcap_failure_detail": "PCAP_LOCAL_FILE_MISSING",
            "min_pcap_bytes": 20000,
        },
        operator={"run_profile": "baseline_connected"},
        target={"package_name": "org.thoughtcrime.securesms", "version_code": 500000},
        artifacts=[
            ArtifactRecord(
                relative_path=str(meta_path.relative_to(tmp_path)),
                type="pcapdroid_capture_meta",
                produced_by="pcapdroid_capture",
            )
        ],
    )

    summary = DynamicRunSummarizer(writer)._build_summary(manifest)

    assert summary["capture"]["pcap_available"] is True
    assert summary["pcap_bytes"] == 12893
    assert summary["pcap_valid"] is False
    assert summary["pcap_failure_detail"] == "PCAP_TOO_SMALL"
    assert summary["quota_detail"]["pcap_failure_detail"] == "PCAP_TOO_SMALL"
