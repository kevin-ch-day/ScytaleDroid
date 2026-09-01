from __future__ import annotations

from pathlib import Path

from scripts.db import report_dynamic_service_signals as report


def test_generate_report_summarizes_signal_context(tmp_path: Path, monkeypatch) -> None:
    observations = [
        {
            "package_name": "bbc.mobile.news.ww",
            "display_name": "BBC News",
            "domain": "googleads.g.doubleclick.net",
            "root_domain": "doubleclick.net",
            "observed_owner_class": "third_party",
            "observed_role_class": "adtech_monetization",
            "total_hits": 5,
            "observed_run_count": 2,
        },
        {
            "package_name": "bbc.mobile.news.ww",
            "display_name": "BBC News",
            "domain": "device-api.urbanairship.com",
            "root_domain": "urbanairship.com",
            "observed_owner_class": "third_party",
            "observed_role_class": "engagement_push",
            "total_hits": 3,
            "observed_run_count": 1,
        },
    ]
    services = [
        {
            "service_key": "google_ads",
            "display_name": "Google Ads / DoubleClick",
            "owner_name": "Google",
            "owner_class": "third_party",
            "service_category": "adtech",
            "primary_use_case": "advertising_and_monetization",
            "documentation_url": "https://support.google.com/admanager/",
            "source_url": None,
            "confidence": "high",
        },
        {
            "service_key": "urbanairship",
            "display_name": "Airship",
            "owner_name": "Airship",
            "owner_class": "third_party",
            "service_category": "engagement",
            "primary_use_case": "push_and_customer_engagement",
            "documentation_url": "https://www.airship.com/",
            "source_url": None,
            "confidence": "high",
        },
    ]
    service_maps = [
        {
            "service_key": "google_ads",
            "package_name_scope": "",
            "domain_pattern": "doubleclick.net",
            "match_type": "SUFFIX",
            "role_class": "adtech_monetization",
            "source_url": None,
            "confidence": "high",
        },
        {
            "service_key": "urbanairship",
            "package_name_scope": "",
            "domain_pattern": "urbanairship.com",
            "match_type": "SUFFIX",
            "role_class": "engagement_push",
            "source_url": None,
            "confidence": "high",
        },
    ]
    signals = [
        {
            "signal_key": "third_party_advertising",
            "display_name": "Third-Party Advertising",
            "signal_family": "advertising",
            "focus_area": "privacy",
            "severity_hint": "medium",
            "description": "ad tech",
            "analyst_guidance": "compare with static trackers",
            "source_url": None,
        },
        {
            "signal_key": "push_or_engagement_platform",
            "display_name": "Push / Engagement Platform",
            "signal_family": "engagement",
            "focus_area": "mixed",
            "severity_hint": "medium",
            "description": "push infra",
            "analyst_guidance": "correlate with push behavior",
            "source_url": None,
        },
    ]
    service_signal_maps = [
        {
            "service_key": "google_ads",
            "signal_key": "third_party_advertising",
            "signal_strength": "primary",
            "confidence": "high",
            "rationale": None,
        },
        {
            "service_key": "urbanairship",
            "signal_key": "push_or_engagement_platform",
            "signal_strength": "primary",
            "confidence": "high",
            "rationale": None,
        },
    ]

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        mapping = {
            "dynamic.service_signals.report.observations": observations,
            "dynamic.service_signals.report.services": services,
            "dynamic.service_signals.report.service_maps": service_maps,
            "dynamic.service_signals.report.signals": signals,
            "dynamic.service_signals.report.service_signal_maps": service_signal_maps,
        }
        if query_name in mapping:
            return mapping[query_name]
        raise AssertionError(f"unexpected query_name={query_name!r} sql={sql[:80]!r}")

    monkeypatch.setattr("scytaledroid.Database.db_core.db_queries.run_sql", fake_run_sql)

    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["packages_scanned"] == 1
    assert summary["observation_rows"] == 2
    assert summary["signal_observation_rows"] == 3
    assert summary["focus_area_hit_counts"]["privacy"] == 10
    assert summary["focus_area_hit_counts"]["mixed"] == 3
    signal_rows = (out_dir / "package_signal_rows.csv").read_text(encoding="utf-8")
    summary_rows = (out_dir / "package_signal_summary.csv").read_text(encoding="utf-8")
    assert "third_party_advertising" in signal_rows
    assert "push_or_engagement_platform" in signal_rows
    assert "bbc.mobile.news.ww" in summary_rows


def test_generate_report_resolves_meta_sdk_and_microsoft_ads_atlas_rows(
    tmp_path: Path, monkeypatch
) -> None:
    observations = [
        {
            "package_name": "com.facebook.katana",
            "display_name": "Facebook",
            "domain": "cx.atdmt.com",
            "root_domain": "atdmt.com",
            "observed_owner_class": "third_party",
            "observed_role_class": "adtech_monetization",
            "total_hits": 2,
            "observed_run_count": 1,
        },
        {
            "package_name": "com.zhiliaoapp.musically",
            "display_name": "TikTok",
            "domain": "graph.facebook.com",
            "root_domain": "facebook.com",
            "observed_owner_class": "third_party",
            "observed_role_class": "social_graph_api",
            "total_hits": 2,
            "observed_run_count": 1,
        },
    ]
    services = [
        {
            "service_key": "microsoft_ads_atlas",
            "display_name": "Microsoft Advertising / Atlas",
            "owner_name": "Microsoft",
            "owner_class": "third_party",
            "service_category": "adtech",
            "primary_use_case": "ad_serving_click_tracking_and_measurement",
            "documentation_url": None,
            "source_url": None,
            "confidence": "medium",
        },
        {
            "service_key": "meta_sdk",
            "display_name": "Meta Platform SDK / APIs",
            "owner_name": "Meta",
            "owner_class": "third_party",
            "service_category": "social_platform",
            "primary_use_case": "social_graph_sdk_and_identity",
            "documentation_url": None,
            "source_url": None,
            "confidence": "medium",
        },
    ]
    service_maps = [
        {
            "service_key": "microsoft_ads_atlas",
            "package_name_scope": "",
            "domain_pattern": "atdmt.com",
            "match_type": "SUFFIX",
            "role_class": "adtech_monetization",
            "source_url": None,
            "confidence": "medium",
        },
        {
            "service_key": "meta_sdk",
            "package_name_scope": "",
            "domain_pattern": "facebook.com",
            "match_type": "SUFFIX",
            "role_class": "social_graph_api",
            "source_url": None,
            "confidence": "medium",
        },
    ]
    signals = [
        {
            "signal_key": "third_party_advertising",
            "display_name": "Third-Party Advertising",
            "signal_family": "advertising",
            "focus_area": "privacy",
            "severity_hint": "medium",
            "description": "ad tech",
            "analyst_guidance": "compare with static trackers",
            "source_url": None,
        },
        {
            "signal_key": "ad_measurement_or_verification",
            "display_name": "Ad Measurement / Verification",
            "signal_family": "advertising_measurement",
            "focus_area": "privacy",
            "severity_hint": "medium",
            "description": "measurement",
            "analyst_guidance": "interpret ad quality/measurement context",
            "source_url": None,
        },
        {
            "signal_key": "identity_or_tag_management",
            "display_name": "Identity / Tag Management",
            "signal_family": "identity_management",
            "focus_area": "privacy",
            "severity_hint": "high",
            "description": "identity orchestration",
            "analyst_guidance": "review sdk identity role",
            "source_url": None,
        },
    ]
    service_signal_maps = [
        {
            "service_key": "microsoft_ads_atlas",
            "signal_key": "third_party_advertising",
            "signal_strength": "primary",
            "confidence": "medium",
            "rationale": None,
        },
        {
            "service_key": "microsoft_ads_atlas",
            "signal_key": "ad_measurement_or_verification",
            "signal_strength": "secondary",
            "confidence": "medium",
            "rationale": None,
        },
        {
            "service_key": "meta_sdk",
            "signal_key": "identity_or_tag_management",
            "signal_strength": "primary",
            "confidence": "medium",
            "rationale": None,
        },
    ]

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        mapping = {
            "dynamic.service_signals.report.observations": observations,
            "dynamic.service_signals.report.services": services,
            "dynamic.service_signals.report.service_maps": service_maps,
            "dynamic.service_signals.report.signals": signals,
            "dynamic.service_signals.report.service_signal_maps": service_signal_maps,
        }
        if query_name in mapping:
            return mapping[query_name]
        raise AssertionError(f"unexpected query_name={query_name!r} sql={sql[:80]!r}")

    monkeypatch.setattr("scytaledroid.Database.db_core.db_queries.run_sql", fake_run_sql)

    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["services_without_signal_mappings"] == 0
    signal_rows = (out_dir / "package_signal_rows.csv").read_text(encoding="utf-8")
    assert "microsoft_ads_atlas" in signal_rows
    assert "meta_sdk" in signal_rows
    assert "identity_or_tag_management" in signal_rows


def test_generate_report_overlays_missing_seed_signal_maps(tmp_path: Path, monkeypatch) -> None:
    observations = [
        {
            "package_name": "com.facebook.katana",
            "display_name": "Facebook",
            "domain": "cx.atdmt.com",
            "root_domain": "atdmt.com",
            "observed_owner_class": "third_party",
            "observed_role_class": "adtech_monetization",
            "total_hits": 2,
            "observed_run_count": 1,
        }
    ]
    services = [
        {
            "service_key": "microsoft_ads_atlas",
            "display_name": "Microsoft Advertising / Atlas",
            "owner_name": "Microsoft",
            "owner_class": "third_party",
            "service_category": "adtech",
            "primary_use_case": "ad_serving_click_tracking_and_measurement",
            "documentation_url": None,
            "source_url": None,
            "confidence": "medium",
        }
    ]
    service_maps = [
        {
            "service_key": "microsoft_ads_atlas",
            "package_name_scope": "",
            "domain_pattern": "atdmt.com",
            "match_type": "SUFFIX",
            "role_class": "adtech_monetization",
            "source_url": None,
            "confidence": "medium",
        }
    ]
    signals = []
    service_signal_maps: list[dict[str, object]] = []

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        mapping = {
            "dynamic.service_signals.report.observations": observations,
            "dynamic.service_signals.report.services": services,
            "dynamic.service_signals.report.service_maps": service_maps,
            "dynamic.service_signals.report.signals": signals,
            "dynamic.service_signals.report.service_signal_maps": service_signal_maps,
        }
        if query_name in mapping:
            return mapping[query_name]
        raise AssertionError(f"unexpected query_name={query_name!r} sql={sql[:80]!r}")

    monkeypatch.setattr("scytaledroid.Database.db_core.db_queries.run_sql", fake_run_sql)

    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["services_without_signal_mappings"] == 0
    signal_rows = (out_dir / "package_signal_rows.csv").read_text(encoding="utf-8")
    assert "third_party_advertising" in signal_rows


def test_generate_report_resolves_reddit_runtime_hosts_from_seed_overlay(
    tmp_path: Path, monkeypatch
) -> None:
    observations = [
        {
            "package_name": "com.reddit.frontpage",
            "display_name": "Reddit",
            "domain": "w3-reporting.reddit.com",
            "root_domain": "reddit.com",
            "observed_owner_class": "first_party",
            "observed_role_class": "first_party_telemetry_reporting",
            "total_hits": 12,
            "observed_run_count": 1,
        },
        {
            "package_name": "com.reddit.frontpage",
            "display_name": "Reddit",
            "domain": "alb.reddit.com",
            "root_domain": "reddit.com",
            "observed_owner_class": "first_party",
            "observed_role_class": "first_party_app_backend",
            "total_hits": 5,
            "observed_run_count": 1,
        },
    ]

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        mapping = {
            "dynamic.service_signals.report.observations": observations,
            "dynamic.service_signals.report.services": [],
            "dynamic.service_signals.report.service_maps": [],
            "dynamic.service_signals.report.signals": [],
            "dynamic.service_signals.report.service_signal_maps": [],
        }
        if query_name in mapping:
            return mapping[query_name]
        raise AssertionError(f"unexpected query_name={query_name!r} sql={sql[:80]!r}")

    monkeypatch.setattr("scytaledroid.Database.db_core.db_queries.run_sql", fake_run_sql)

    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["services_without_signal_mappings"] == 0
    signal_rows = (out_dir / "package_signal_rows.csv").read_text(encoding="utf-8")
    assert "w3-reporting.reddit.com" in signal_rows
    assert "alb.reddit.com" in signal_rows
    assert "reddit_platform" in signal_rows
    assert "first_party_social_platform" in signal_rows


def test_generate_report_uses_clear_metric_name_for_services_without_signal_mappings(
    tmp_path: Path, monkeypatch
) -> None:
    observations = [
        {
            "package_name": "com.example.app",
            "display_name": "Example",
            "domain": "unknown-service.example",
            "root_domain": "example",
            "observed_owner_class": "third_party",
            "observed_role_class": "unknown",
            "total_hits": 1,
            "observed_run_count": 1,
        }
    ]
    services = [
        {
            "service_key": "example_service",
            "display_name": "Example Service",
            "owner_name": "Example",
            "owner_class": "third_party",
            "service_category": "analytics",
            "primary_use_case": "example",
            "documentation_url": None,
            "source_url": None,
            "confidence": "medium",
        }
    ]
    service_maps = [
        {
            "service_key": "example_service",
            "package_name_scope": "",
            "domain_pattern": "unknown-service.example",
            "match_type": "EXACT",
            "role_class": "unknown",
            "source_url": None,
            "confidence": "medium",
        }
    ]
    signals: list[dict[str, object]] = []
    service_signal_maps: list[dict[str, object]] = []

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        mapping = {
            "dynamic.service_signals.report.observations": observations,
            "dynamic.service_signals.report.services": services,
            "dynamic.service_signals.report.service_maps": service_maps,
            "dynamic.service_signals.report.signals": signals,
            "dynamic.service_signals.report.service_signal_maps": service_signal_maps,
        }
        if query_name in mapping:
            return mapping[query_name]
        raise AssertionError(f"unexpected query_name={query_name!r} sql={sql[:80]!r}")

    monkeypatch.setattr("scytaledroid.Database.db_core.db_queries.run_sql", fake_run_sql)

    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["services_without_signal_mappings"] == 1
    assert "services_without_signal_mappings_csv" in summary["output_files"]
    assert summary["output_files"]["services_without_signal_mappings_csv"].endswith(
        "services_without_signal_mappings.csv"
    )
