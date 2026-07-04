from __future__ import annotations

import csv
import json
from pathlib import Path

from scripts.db import report_dynamic_legacy_corpus as report


def test_classify_record_boundaries() -> None:
    assert report.classify_record({"valid_dataset_run": True, "countable": True}) == (
        "CURRENT_COUNTABLE",
        "valid current-build evidence counts toward quota",
    )
    assert report.classify_record(
        {"valid_dataset_run": True, "countable": False, "low_signal": True}
    ) == (
        "CURRENT_SUPPLEMENTAL_LOW_SIGNAL",
        "valid supplemental evidence excluded by low-signal policy",
    )
    assert report.classify_record(
        {"valid_dataset_run": True, "countable": False, "low_signal": False}
    ) == ("CURRENT_SUPPLEMENTAL_EXTRA", "valid supplemental evidence retained outside quota")
    assert report.classify_record(
        {"valid_dataset_run": False, "countable": False, "invalid_reason_code": "PCAP_MISSING"}
    ) == ("INVALID_EXCLUDED", "invalid or PCAP-excluded evidence")
    assert report.classify_record({"local_pack_present": True, "finalized_local": False}) == (
        "INCOMPLETE_LOCAL_PACK",
        "local evidence pack exists but did not finalize cleanly",
    )
    assert report.classify_record(
        {"db_row_present": True, "valid_dataset_run": None, "local_pack_present": False}
    ) == ("LEGACY_DB_ONLY_UNKNOWN", "historical DB-only row lacks modern validity contract")
    assert report.classify_record(
        {
            "local_pack_present": True,
            "valid_dataset_run": None,
            "run_manifest_present": True,
            "finalized_local": True,
        }
    ) == (
        "LEGACY_LOCAL_RECONSTRUCTABLE",
        "historical/local evidence can be partially reconstructed from files",
    )
    assert report.classify_record(
        {
            "local_pack_present": True,
            "valid_dataset_run": None,
            "raw_pcap_present": True,
            "pcap_report_present": False,
            "pcap_features_present": False,
            "finalized_local": True,
        }
    ) == ("RAW_EVIDENCE_DERIVED_MISSING", "raw PCAP exists but derived report/features are missing")
    assert report.classify_record({"valid_dataset_run": 1, "countable": 0, "low_signal": 1}) == (
        "CURRENT_SUPPLEMENTAL_LOW_SIGNAL",
        "valid supplemental evidence excluded by low-signal policy",
    )
    assert report.classify_record({"valid_dataset_run": 0, "countable": 0, "pcap_valid": 0}) == (
        "INVALID_EXCLUDED",
        "invalid or PCAP-excluded evidence",
    )


def test_has_pcap_artifact_supports_pcapng(tmp_path: Path) -> None:
    artifacts_dir = tmp_path / "artifacts"
    capture_dir = artifacts_dir / "pcapdroid_capture"
    capture_dir.mkdir(parents=True)
    (capture_dir / "capture.pcapng").write_bytes(b"pcapng")
    (capture_dir / "capture.pcapng.json").write_text("{}", encoding="utf-8")

    assert report._has_pcap_artifact(artifacts_dir) is True


def test_generate_report_writes_expected_outputs_and_rollups(tmp_path: Path) -> None:
    db_rows = [
        {
            "dynamic_run_id": "run-countable",
            "package_name": "com.facebook.orca",
            "app_label": "Messenger",
            "version_code": "343413012",
            "version_name": "1.0",
            "profile": "baseline_connected",
            "interaction_mode": "minimal",
            "valid_dataset_run": True,
            "countable": True,
            "quota_state": "QUOTA_VALID",
            "technical_validity_state": "TECH_VALID",
            "low_signal": True,
            "low_signal_reasons_json": '["PCAP_BYTES_LOW"]',
            "invalid_reason_code": "",
            "pcap_valid": True,
            "pcap_bytes": 272510,
            "packet_count": 755,
            "domain_count": 4,
            "domain_observation_rows": 8,
            "network_indicator_rows": 8,
            "network_feature_present": True,
            "top_domains_sample": "graph.facebook.com | edge-mqtt.facebook.com",
            "service_context_service_count": 2,
            "signal_count": 2,
            "db_row_present": True,
        },
        {
            "dynamic_run_id": "run-low-signal",
            "package_name": "com.twitter.android",
            "app_label": "X",
            "version_code": "312031000",
            "version_name": "12.3.1",
            "profile": "baseline_idle",
            "interaction_mode": "minimal",
            "valid_dataset_run": True,
            "countable": False,
            "quota_state": "SUPPLEMENTAL_VALID",
            "technical_validity_state": "TECH_VALID",
            "low_signal": True,
            "low_signal_reasons_json": '["PCAP_BYTES_LOW"]',
            "invalid_reason_code": "",
            "pcap_valid": True,
            "pcap_bytes": 939765,
            "packet_count": 1168,
            "domain_count": 12,
            "domain_observation_rows": 19,
            "network_indicator_rows": 19,
            "network_feature_present": True,
            "top_domains_sample": "x.com",
            "service_context_service_count": 1,
            "signal_count": 1,
            "db_row_present": True,
        },
        {
            "dynamic_run_id": "run-extra",
            "package_name": "bbc.mobile.news.ww",
            "app_label": "BBC",
            "version_code": "10007090",
            "version_name": "2026.4.0",
            "profile": "baseline_idle",
            "interaction_mode": "minimal",
            "valid_dataset_run": True,
            "countable": False,
            "quota_state": "SUPPLEMENTAL_VALID",
            "technical_validity_state": "TECH_VALID",
            "low_signal": False,
            "low_signal_reasons_json": "[]",
            "invalid_reason_code": "",
            "pcap_valid": True,
            "pcap_bytes": 3673184,
            "packet_count": 3367,
            "domain_count": 16,
            "domain_observation_rows": 20,
            "network_indicator_rows": 20,
            "network_feature_present": True,
            "top_domains_sample": "bbc.com",
            "service_context_service_count": 1,
            "signal_count": 1,
            "db_row_present": True,
        },
        {
            "dynamic_run_id": "run-invalid",
            "package_name": "com.cnn.mobile.android.phone",
            "app_label": "CNN",
            "version_code": "19250507",
            "version_name": "26.13.0",
            "profile": "interaction_scripted",
            "interaction_mode": "scripted",
            "valid_dataset_run": False,
            "countable": False,
            "quota_state": "QUOTA_INELIGIBLE",
            "technical_validity_state": "TECH_INVALID",
            "low_signal": None,
            "low_signal_reasons_json": "",
            "invalid_reason_code": "PCAP_MISSING",
            "pcap_valid": False,
            "pcap_bytes": 0,
            "packet_count": None,
            "domain_count": 0,
            "domain_observation_rows": 0,
            "network_indicator_rows": 0,
            "network_feature_present": False,
            "top_domains_sample": "",
            "service_context_service_count": 0,
            "signal_count": 0,
            "db_row_present": True,
        },
        {
            "dynamic_run_id": "run-legacy-db",
            "package_name": "com.whatsapp",
            "app_label": "WhatsApp",
            "version_code": "260607200",
            "version_name": "2.0",
            "profile": "baseline_connected",
            "interaction_mode": "minimal",
            "valid_dataset_run": None,
            "countable": None,
            "quota_state": "QUOTA_LEGACY_UNKNOWN",
            "technical_validity_state": "",
            "low_signal": None,
            "low_signal_reasons_json": "",
            "invalid_reason_code": "",
            "pcap_valid": True,
            "pcap_bytes": 862729,
            "packet_count": None,
            "domain_count": 0,
            "domain_observation_rows": 0,
            "network_indicator_rows": 0,
            "network_feature_present": False,
            "top_domains_sample": "",
            "service_context_service_count": 0,
            "signal_count": 0,
            "db_row_present": True,
        },
    ]
    local_rows = [
        {
            "dynamic_run_id": "run-local-reconstruct",
            "package_name": "org.telegram.messenger",
            "app_label": "Telegram",
            "version_code": "65272",
            "version_name": "legacy",
            "profile": "baseline_connected",
            "interaction_mode": "minimal",
            "valid_dataset_run": None,
            "countable": None,
            "quota_state": "",
            "technical_validity_state": "",
            "low_signal": None,
            "low_signal_reasons_json": "",
            "invalid_reason_code": "",
            "pcap_valid": True,
            "pcap_bytes": 769367,
            "packet_count": 880,
            "domain_count": 4,
            "domain_observation_rows": None,
            "network_indicator_rows": None,
            "network_feature_present": True,
            "top_domains_sample": "telegram.org",
            "service_context_service_count": 1,
            "signal_count": 0,
            "db_row_present": False,
            "local_pack_present": True,
            "run_manifest_present": True,
            "summary_present": True,
            "pcap_report_present": True,
            "pcap_features_present": True,
            "run_events_present": True,
            "finalized_local": True,
            "raw_pcap_present": True,
        },
        {
            "dynamic_run_id": "run-incomplete",
            "package_name": "org.thoughtcrime.securesms",
            "app_label": "Signal",
            "version_code": "164701",
            "version_name": "legacy",
            "profile": "baseline_connected",
            "interaction_mode": "minimal",
            "valid_dataset_run": None,
            "countable": None,
            "quota_state": "",
            "technical_validity_state": "",
            "low_signal": None,
            "low_signal_reasons_json": "",
            "invalid_reason_code": "",
            "pcap_valid": True,
            "pcap_bytes": 700732,
            "packet_count": None,
            "domain_count": 0,
            "domain_observation_rows": None,
            "network_indicator_rows": None,
            "network_feature_present": False,
            "top_domains_sample": "",
            "service_context_service_count": 0,
            "signal_count": 0,
            "db_row_present": False,
            "local_pack_present": True,
            "run_manifest_present": False,
            "summary_present": False,
            "pcap_report_present": False,
            "pcap_features_present": False,
            "run_events_present": True,
            "finalized_local": False,
            "raw_pcap_present": True,
        },
    ]

    summary = report.generate_report(
        output_dir=tmp_path,
        db_rows=db_rows,
        local_rows=local_rows,
    )

    assert summary["total_runs"] == 7
    assert summary["classification_counts"]["CURRENT_COUNTABLE"] == 1
    assert summary["classification_counts"]["CURRENT_SUPPLEMENTAL_LOW_SIGNAL"] == 1
    assert summary["classification_counts"]["CURRENT_SUPPLEMENTAL_EXTRA"] == 1
    assert summary["classification_counts"]["INVALID_EXCLUDED"] == 1
    assert summary["classification_counts"]["LEGACY_DB_ONLY_UNKNOWN"] == 1
    assert summary["classification_counts"]["LEGACY_LOCAL_RECONSTRUCTABLE"] == 1
    assert summary["classification_counts"]["INCOMPLETE_LOCAL_PACK"] == 1

    per_run = list(
        csv.DictReader((tmp_path / "per_run_classification.csv").open(newline="", encoding="utf-8"))
    )
    assert {row["classification"] for row in per_run} >= {
        "CURRENT_COUNTABLE",
        "CURRENT_SUPPLEMENTAL_LOW_SIGNAL",
        "CURRENT_SUPPLEMENTAL_EXTRA",
        "INVALID_EXCLUDED",
        "LEGACY_DB_ONLY_UNKNOWN",
        "LEGACY_LOCAL_RECONSTRUCTABLE",
        "INCOMPLETE_LOCAL_PACK",
    }
    twitter = next(row for row in per_run if row["package_name"] == "com.twitter.android")
    assert twitter["classification"] == "CURRENT_SUPPLEMENTAL_LOW_SIGNAL"
    assert twitter["evidence_era"] == "MODERN_FINALIZED"

    focus = list(
        csv.DictReader(
            (tmp_path / "messaging_baseline_rollup.csv").open(newline="", encoding="utf-8")
        )
    )
    messenger = next(row for row in focus if row["package_name"] == "com.facebook.orca")
    assert messenger["countable_baseline_connected"] == "1"
    whatsapp = next(row for row in focus if row["package_name"] == "com.whatsapp")
    assert whatsapp["legacy_unknown"] == "1"

    per_app = list(
        csv.DictReader((tmp_path / "per_app_rollup.csv").open(newline="", encoding="utf-8"))
    )
    by_package = {row["package_name"]: row for row in per_app}
    assert by_package["com.facebook.orca"]["domain_indexed_runs"] == "1"
    assert by_package["com.facebook.orca"]["network_context_state"] == "domain_ready"
    assert "domain observations" in by_package["com.facebook.orca"]["ingest_guidance"]
    assert by_package["com.whatsapp"]["network_context_state"] == "db_only_legacy"
    assert by_package["org.telegram.messenger"]["feature_context_runs"] == "1"
    assert by_package["org.telegram.messenger"]["network_context_state"] == "feature_only"
    assert "do not infer domains" in by_package["org.telegram.messenger"]["ingest_guidance"]

    md = (tmp_path / "evidence_governance_summary.md").read_text(encoding="utf-8")
    assert "CURRENT_SUPPLEMENTAL_LOW_SIGNAL" in md
    assert "Messaging Baseline Focus" in md

    persisted_summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert persisted_summary["total_runs"] == 7


def test_per_app_rollup_skips_blank_package_name() -> None:
    rows = [
        report._finalize_record(
            {
                "dynamic_run_id": "unknown-local-run",
                "package_name": "",
                "local_pack_present": True,
                "finalized_local": False,
                "db_row_present": False,
            }
        ),
        report._finalize_record(
            {
                "dynamic_run_id": "known-run",
                "package_name": "com.example.app",
                "db_row_present": True,
                "valid_dataset_run": True,
                "countable": True,
                "pcap_bytes": 100,
            }
        ),
    ]

    per_app = report._build_per_app_rollup(rows)

    assert len(per_app) == 1
    assert per_app[0]["package_name"] == "com.example.app"
