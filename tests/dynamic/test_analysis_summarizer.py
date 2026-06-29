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
