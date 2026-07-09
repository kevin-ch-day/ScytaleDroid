from __future__ import annotations

import json
from pathlib import Path

from scripts.db import report_dynamic_domain_context as report


def test_context_for_domain_prefers_curated_suffix_and_package_hints() -> None:
    bbc_api = report._context_for_domain(
        "bbc-global-app.api.bbc.com", package_name="bbc.mobile.news.ww"
    )
    assert bbc_api["owner_class"] == "first_party"
    assert bbc_api["role_class"] == "publisher_api"
    assert bbc_api["basis"] == "curated_exact"

    bbc_live = report._context_for_domain(
        "api.live.bbcx-internal.com", package_name="bbc.mobile.news.ww"
    )
    assert bbc_live["owner_class"] == "first_party"
    assert bbc_live["role_class"] == "publisher_api"
    assert bbc_live["basis"] == "curated_suffix"

    airship = report._context_for_domain(
        "device-api.urbanairship.com", package_name="bbc.mobile.news.ww"
    )
    assert airship["owner_class"] == "third_party"
    assert airship["role_class"] == "engagement_push"
    assert airship["basis"] == "curated_suffix"

    cnn_hint = report._context_for_domain(
        "images.cnn.com", package_name="com.cnn.mobile.android.phone"
    )
    assert cnn_hint["owner_class"] == "first_party"
    assert cnn_hint["basis"] == "package_root_hint"

    unknown = report._context_for_domain("mystery.example.net", package_name="bbc.mobile.news.ww")
    assert unknown["owner_class"] == "unknown"
    assert unknown["role_class"] == "unknown"


def test_context_for_domain_resolves_new_curated_provider_suffixes_and_exact_hosts() -> None:
    permutive = report._context_for_domain("api.permutive.com", package_name="bbc.mobile.news.ww")
    assert permutive["owner_class"] == "third_party"
    assert permutive["role_class"] == "audience_personalization"
    assert permutive["basis"] == "curated_suffix"

    liveramp = report._context_for_domain(
        "idsync.rlcdn.com", package_name="com.cnn.mobile.android.phone"
    )
    assert liveramp["owner_class"] == "third_party"
    assert liveramp["role_class"] == "identity_sync"
    assert liveramp["basis"] == "curated_suffix"

    ima = report._context_for_domain("imasdk.googleapis.com", package_name="bbc.mobile.news.ww")
    assert ima["owner_class"] == "third_party"
    assert ima["role_class"] == "adtech_monetization"
    assert ima["basis"] == "curated_exact"

    adobe = report._context_for_domain(
        "sp.auth.adobe.com", package_name="com.cnn.mobile.android.phone"
    )
    assert adobe["owner_class"] == "third_party"
    assert adobe["role_class"] == "identity_api"
    assert adobe["basis"] == "curated_suffix"

    ad_quality = report._context_for_domain(
        "ep1.adtrafficquality.google", package_name="bbc.mobile.news.ww"
    )
    assert ad_quality["owner_class"] == "third_party"
    assert ad_quality["role_class"] == "ad_measurement"
    assert ad_quality["basis"] == "curated_suffix"

    oracle = report._context_for_domain(
        "config.mtp.sag.us-ashburn-1.oci.oraclecloud.com",
        package_name="com.zhiliaoapp.musically",
    )
    assert oracle["owner_class"] == "third_party"
    assert oracle["role_class"] == "hosted_backend_infrastructure"
    assert oracle["basis"] == "curated_exact"

    meta_third_party = report._context_for_domain(
        "graph.facebook.com",
        package_name="com.zhiliaoapp.musically",
    )
    assert meta_third_party["owner_class"] == "third_party"
    assert meta_third_party["role_class"] == "social_graph_api"
    assert meta_third_party["basis"] == "curated_exact"

    meta_first_party = report._context_for_domain(
        "graph.facebook.com",
        package_name="com.facebook.katana",
    )
    assert meta_first_party["owner_class"] == "first_party"
    assert meta_first_party["role_class"] == "social_graph_api"
    assert meta_first_party["basis"] == "curated_exact"

    espn_api = report._context_for_domain(
        "fan.api.espn.com",
        package_name="com.espn.score_center",
    )
    assert espn_api["owner_class"] == "first_party"
    assert espn_api["role_class"] == "publisher_api"

    new_relic = report._context_for_domain(
        "mobile-collector.newrelic.com",
        package_name="com.espn.score_center",
    )
    assert new_relic["owner_class"] == "third_party"
    assert new_relic["role_class"] == "analytics_measurement"

    nielsen = report._context_for_domain(
        "secure-dcr.vtwenty.com",
        package_name="com.espn.score_center",
    )
    assert nielsen["owner_class"] == "third_party"
    assert nielsen["role_class"] == "audience_measurement"


def test_top_ip_destinations_resolves_telegram_direct_ip_flows() -> None:
    top = report._top_ip_destinations(
        {
            "flow_summary": {
                "top_flows": [
                    {
                        "endpoint_a": "10.215.173.1:41568",
                        "endpoint_b": "149.154.175.51:443",
                        "packets": 210,
                    },
                    {
                        "endpoint_a": "10.215.173.1:42258",
                        "endpoint_b": "91.108.56.196:443",
                        "packets": 19,
                    },
                    {
                        "endpoint_a": "10.215.173.1:42242",
                        "endpoint_b": "91.108.56.196:443",
                        "packets": 24,
                    },
                    {
                        "endpoint_a": "10.215.173.1:49578",
                        "endpoint_b": "216.239.38.223:443",
                        "packets": 17,
                    },
                ]
            }
        },
        package_name="org.telegram.messenger",
    )

    assert top == (("149.154.175.51", 210), ("91.108.56.196", 43))


def test_generate_report_summarizes_runs_and_context(tmp_path: Path) -> None:
    dynamic_root = tmp_path / "output" / "evidence" / "dynamic"
    run_dir = dynamic_root / "run-1"
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-1",
                "ended_at": "2026-06-15T19:40:00+00:00",
                "target": {
                    "package_name": "bbc.mobile.news.ww",
                    "display_name": "BBC News",
                },
                "dataset": {
                    "run_profile": "interaction_manual",
                    "valid_dataset_run": True,
                    "paper_eligible": True,
                    "countable": True,
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "top_dns": [
                    {"value": "bbc-global-app.api.bbc.com", "count": 4},
                    {"value": "googleads.g.doubleclick.net", "count": 2},
                ],
                "top_sni": [
                    {"value": "device-api.urbanairship.com", "count": 3},
                ],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_features.json").write_text(
        json.dumps({"proxies": {"domains_per_min": 7.0}}),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "static_dynamic_overlap.json").write_text(
        json.dumps(
            {
                "static_domains_count": 0,
                "dynamic_domains_count": 3,
            }
        ),
        encoding="utf-8",
    )

    run_dir2 = dynamic_root / "run-2"
    (run_dir2 / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir2 / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-2",
                "ended_at": "2026-06-15T19:50:00+00:00",
                "target": {
                    "package_name": "bbc.mobile.news.ww",
                    "display_name": "BBC News",
                },
                "dataset": {
                    "run_profile": "baseline_idle",
                    "valid_dataset_run": True,
                    "paper_eligible": True,
                    "countable": True,
                    "actual_sampling_seconds": 240.0,
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir2 / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "top_dns": [
                    {"value": "bbc-global-app.api.bbc.com", "count": 2},
                ],
                "top_sni": [
                    {"value": "ichef.bbci.co.uk", "count": 1},
                ],
                "pcap_size_bytes": 4096,
                "packet_count": 256,
                "dns_unique_count": 2,
                "sni_unique_count": 1,
            }
        ),
        encoding="utf-8",
    )
    (run_dir2 / "analysis" / "pcap_features.json").write_text(
        json.dumps({"proxies": {"domains_per_min": 3.0}}),
        encoding="utf-8",
    )
    (run_dir2 / "analysis" / "static_dynamic_overlap.json").write_text(
        json.dumps(
            {
                "static_domains_count": 0,
                "dynamic_domains_count": 2,
            }
        ),
        encoding="utf-8",
    )

    original_repo = report._REPO_ROOT
    original_dynamic_root = report._dynamic_root
    original_state_rows = report._load_state_rows
    try:
        report._REPO_ROOT = tmp_path  # type: ignore[assignment]
        report._dynamic_root = lambda: dynamic_root  # type: ignore[assignment]
        report._load_state_rows = lambda packages: {  # type: ignore[assignment]
            "bbc.mobile.news.ww": {
                "quota_counted_local": 5,
                "paper_eligible_local": 6,
                "baseline_valid_runs": 3,
                "interactive_valid_runs": 2,
                "extra_valid_runs": 1,
                "quota_met": True,
                "suggested_profile": "interaction_manual",
                "suggested_slot": 5,
            }
        }
        out_dir = tmp_path / "audit"
        summary = report.generate_dynamic_domain_context_report(output_dir=out_dir)
    finally:
        report._REPO_ROOT = original_repo  # type: ignore[assignment]
        report._dynamic_root = original_dynamic_root  # type: ignore[assignment]
        report._load_state_rows = original_state_rows  # type: ignore[assignment]

    assert summary["dynamic_runs_scanned"] == 2
    assert summary["packages_scanned"] == 1
    assert summary["packages_with_manual_runs"] == 1
    assert summary["packages_with_quota_met"] == 1
    assert summary["packages_with_baseline_manual_contrast"] == 1
    assert (out_dir / "summary.json").exists()
    package_rows = (out_dir / "package_run_overview.csv").read_text(encoding="utf-8")
    domain_rows = (out_dir / "package_domain_context.csv").read_text(encoding="utf-8")
    gap_rows = (out_dir / "package_context_gaps.csv").read_text(encoding="utf-8")
    contrast_rows = (out_dir / "package_profile_contrast.csv").read_text(encoding="utf-8")
    assert "bbc.mobile.news.ww" in package_rows
    assert "publisher_api" in domain_rows
    assert "engagement_push" in domain_rows
    assert "adtech_monetization" in domain_rows
    assert "runtime_domains_exceed_static_domain_context" in gap_rows
    assert "manual_only_domain_count" in contrast_rows
    assert "device-api.urbanairship.com" in contrast_rows


def test_generate_report_includes_telegram_ip_context(tmp_path: Path) -> None:
    dynamic_root = tmp_path / "output" / "evidence" / "dynamic"
    run_dir = dynamic_root / "run-telegram"
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-telegram",
                "ended_at": "2026-07-09T03:36:04+00:00",
                "target": {
                    "package_name": "org.telegram.messenger",
                    "display_name": "Telegram",
                },
                "dataset": {
                    "run_profile": "baseline_connected",
                    "valid_dataset_run": True,
                    "paper_eligible": True,
                    "countable": True,
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "top_dns": [{"value": "firebaselogging.googleapis.com", "count": 2}],
                "top_sni": [{"value": "firebaselogging.googleapis.com", "count": 1}],
                "flow_summary": {
                    "top_flows": [
                        {
                            "endpoint_a": "10.215.173.1:41568",
                            "endpoint_b": "149.154.175.51:443",
                            "packets": 210,
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    original_repo = report._REPO_ROOT
    original_dynamic_root = report._dynamic_root
    original_state_rows = report._load_state_rows
    try:
        report._REPO_ROOT = tmp_path  # type: ignore[assignment]
        report._dynamic_root = lambda: dynamic_root  # type: ignore[assignment]
        report._load_state_rows = lambda packages: {}  # type: ignore[assignment]
        out_dir = tmp_path / "audit"
        summary = report.generate_dynamic_domain_context_report(output_dir=out_dir)
    finally:
        report._REPO_ROOT = original_repo  # type: ignore[assignment]
        report._dynamic_root = original_dynamic_root  # type: ignore[assignment]
        report._load_state_rows = original_state_rows  # type: ignore[assignment]

    assert summary["observed_domains_total"] == 2
    assert summary["owner_class_counts"]["first_party"] == 1
    domain_rows = (out_dir / "package_domain_context.csv").read_text(encoding="utf-8")
    assert "149.154.175.51" in domain_rows
    assert "149.154.160.0/20" in domain_rows
    assert "telegram_datacenter_transport" in domain_rows
    assert "curated_cidr" in domain_rows
    assert "firebaselogging.googleapis.com" in domain_rows
