from __future__ import annotations

from pathlib import Path

from scripts.db import report_dynamic_service_context as report


def test_generate_report_summarizes_service_resolution(tmp_path: Path, monkeypatch) -> None:
    service_rows = [
        {
            "service_key": "bbc_first_party",
            "display_name": "BBC First-Party Services",
            "owner_name": "BBC",
            "owner_class": "first_party",
            "service_category": "publisher",
            "primary_use_case": "news_content_and_api",
            "source_url": "https://www.bbc.com",
            "confidence": "high",
        },
        {
            "service_key": "google_ads",
            "display_name": "Google Ads / DoubleClick",
            "owner_name": "Google",
            "owner_class": "third_party",
            "service_category": "adtech",
            "primary_use_case": "advertising_and_monetization",
            "source_url": "https://support.google.com/admanager/",
            "confidence": "high",
        },
    ]
    map_rows = [
        {
            "service_key": "bbc_first_party",
            "package_name_scope": "bbc.mobile.news.ww",
            "domain_pattern": "bbc.com",
            "match_type": "SUFFIX",
            "role_class": "publisher_api",
            "source_url": None,
            "confidence": "high",
        },
        {
            "service_key": "google_ads",
            "package_name_scope": "",
            "domain_pattern": "doubleclick.net",
            "match_type": "SUFFIX",
            "role_class": "adtech_monetization",
            "source_url": None,
            "confidence": "high",
        },
    ]
    observation_rows = [
        {
            "package_name": "bbc.mobile.news.ww",
            "display_name": "BBC News",
            "domain": "bbc-global-app.api.bbc.com",
            "root_domain": "bbc.com",
            "owner_class": "first_party",
            "role_class": "publisher_api",
            "total_hits": 6,
            "observed_run_count": 2,
        },
        {
            "package_name": "bbc.mobile.news.ww",
            "display_name": "BBC News",
            "domain": "googleads.g.doubleclick.net",
            "root_domain": "doubleclick.net",
            "owner_class": "third_party",
            "role_class": "adtech_monetization",
            "total_hits": 4,
            "observed_run_count": 2,
        },
        {
            "package_name": "bbc.mobile.news.ww",
            "display_name": "BBC News",
            "domain": "mystery.example.org",
            "root_domain": "example.org",
            "owner_class": "unknown",
            "role_class": "unknown",
            "total_hits": 1,
            "observed_run_count": 1,
        },
    ]
    coverage_rows = [
        {
            "package_name": "bbc.mobile.news.ww",
            "network_context_state": "domain_ready",
            "ingest_guidance": "use DB domain observations for historical network context",
            "domain_indexed_runs": 7,
            "feature_context_runs": 7,
            "indicator_context_runs": 7,
            "raw_pcap_runs": 7,
        },
        {
            "package_name": "org.telegram.messenger",
            "network_context_state": "feature_only",
            "ingest_guidance": "use feature/indicator context only; do not infer domains",
            "domain_indexed_runs": 0,
            "feature_context_runs": 3,
            "indicator_context_runs": 3,
            "raw_pcap_runs": 0,
        },
    ]

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        if query_name == "dynamic.service_context.report.services":
            return service_rows
        if query_name == "dynamic.service_context.report.maps":
            return map_rows
        if query_name == "dynamic.service_context.report.observations":
            return observation_rows
        raise AssertionError(f"unexpected query_name={query_name!r} sql={sql[:80]!r}")

    monkeypatch.setattr("scytaledroid.Database.db_core.db_queries.run_sql", fake_run_sql)
    monkeypatch.setattr(
        report, "_load_network_context_coverage", lambda packages=None: coverage_rows
    )

    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["service_catalog_count"] >= 2
    assert summary["service_domain_map_count"] >= 2
    assert summary["observed_domain_rows"] == 3
    assert summary["unresolved_domain_rows"] == 1
    assert summary["packages_scanned"] == 1
    assert summary["packages_with_network_context_coverage"] == 2
    assert summary["network_context_state_counts"] == {"domain_ready": 1, "feature_only": 1}
    package_rows = (out_dir / "package_service_context.csv").read_text(encoding="utf-8")
    summary_rows = (out_dir / "package_service_summary.csv").read_text(encoding="utf-8")
    coverage_csv = (out_dir / "package_network_context_coverage.csv").read_text(encoding="utf-8")
    unresolved_rows = (out_dir / "unresolved_domains.csv").read_text(encoding="utf-8")
    assert "bbc_first_party" in package_rows
    assert "google_ads" in package_rows
    assert "bbc.mobile.news.ww" in summary_rows
    assert "domain_ready" in summary_rows
    assert "org.telegram.messenger" in coverage_csv
    assert "feature_only" in coverage_csv
    assert "mystery.example.org" in unresolved_rows


def test_generate_report_overlays_missing_repo_seed_service_maps(
    tmp_path: Path, monkeypatch
) -> None:
    service_rows = [
        {
            "service_key": "bbc_first_party",
            "display_name": "BBC First-Party Services",
            "owner_name": "BBC",
            "owner_class": "first_party",
            "service_category": "publisher",
            "primary_use_case": "news_content_and_api",
            "source_url": "https://www.bbc.com",
            "confidence": "high",
        },
    ]
    map_rows = [
        {
            "service_key": "bbc_first_party",
            "package_name_scope": "bbc.mobile.news.ww",
            "domain_pattern": "bbc.com",
            "match_type": "SUFFIX",
            "role_class": "publisher_api",
            "source_url": None,
            "confidence": "high",
        },
    ]
    observation_rows = [
        {
            "package_name": "bbc.mobile.news.ww",
            "display_name": "BBC News",
            "domain": "api.live.bbcx-internal.com",
            "root_domain": "bbcx-internal.com",
            "owner_class": "unknown",
            "role_class": "unknown",
            "total_hits": 30,
            "observed_run_count": 1,
        },
    ]

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        if query_name == "dynamic.service_context.report.services":
            return service_rows
        if query_name == "dynamic.service_context.report.maps":
            return map_rows
        if query_name == "dynamic.service_context.report.observations":
            return observation_rows
        raise AssertionError(f"unexpected query_name={query_name!r} sql={sql[:80]!r}")

    monkeypatch.setattr("scytaledroid.Database.db_core.db_queries.run_sql", fake_run_sql)
    monkeypatch.setattr(report, "_load_network_context_coverage", lambda packages=None: [])

    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["unresolved_domain_rows"] == 0
    package_rows = (out_dir / "package_service_context.csv").read_text(encoding="utf-8")
    unresolved_rows = (out_dir / "unresolved_domains.csv").read_text(encoding="utf-8")
    assert "api.live.bbcx-internal.com" in package_rows
    assert "bbc_first_party" in package_rows
    assert unresolved_rows == ""


def test_generate_report_resolves_new_reddit_runtime_hosts_from_seed_overlay(
    tmp_path: Path, monkeypatch
) -> None:
    observation_rows = [
        {
            "package_name": "com.reddit.frontpage",
            "display_name": "Reddit",
            "domain": "w3-reporting.reddit.com",
            "root_domain": "reddit.com",
            "owner_class": "first_party",
            "role_class": "first_party_telemetry_reporting",
            "total_hits": 12,
            "observed_run_count": 1,
        },
        {
            "package_name": "com.reddit.frontpage",
            "display_name": "Reddit",
            "domain": "alb.reddit.com",
            "root_domain": "reddit.com",
            "owner_class": "first_party",
            "role_class": "first_party_app_backend",
            "total_hits": 5,
            "observed_run_count": 1,
        },
    ]

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        if query_name in {
            "dynamic.service_context.report.services",
            "dynamic.service_context.report.maps",
        }:
            return []
        if query_name == "dynamic.service_context.report.observations":
            return observation_rows
        raise AssertionError(f"unexpected query_name={query_name!r} sql={sql[:80]!r}")

    monkeypatch.setattr("scytaledroid.Database.db_core.db_queries.run_sql", fake_run_sql)
    monkeypatch.setattr(report, "_load_network_context_coverage", lambda packages=None: [])

    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["unresolved_domain_rows"] == 0
    package_rows = (out_dir / "package_service_context.csv").read_text(encoding="utf-8")
    assert "w3-reporting.reddit.com" in package_rows
    assert "first_party_telemetry_reporting" in package_rows
    assert "alb.reddit.com" in package_rows
    assert "first_party_app_backend" in package_rows


def test_generate_report_resolves_telegram_ip_context_from_observed_classification(
    tmp_path: Path, monkeypatch
) -> None:
    observation_rows = [
        {
            "package_name": "org.telegram.messenger",
            "display_name": "Telegram",
            "domain": "149.154.175.51",
            "root_domain": "149.154.160.0/20",
            "owner_class": "first_party",
            "role_class": "telegram_datacenter_transport",
            "confidence": "high",
            "total_hits": 210,
            "observed_run_count": 1,
        },
        {
            "package_name": "org.telegram.messenger",
            "display_name": "Telegram",
            "domain": "firebaselogging.googleapis.com",
            "root_domain": "googleapis.com",
            "owner_class": "third_party",
            "role_class": "google_api_platform",
            "confidence": "medium",
            "total_hits": 3,
            "observed_run_count": 1,
        },
    ]

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        if query_name == "dynamic.service_context.report.services":
            return []
        if query_name == "dynamic.service_context.report.maps":
            return []
        if query_name == "dynamic.service_context.report.observations":
            return observation_rows
        raise AssertionError(f"unexpected query_name={query_name!r} sql={sql[:80]!r}")

    monkeypatch.setattr("scytaledroid.Database.db_core.db_queries.run_sql", fake_run_sql)
    monkeypatch.setattr(report, "_load_network_context_coverage", lambda packages=None: [])

    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["unresolved_domain_rows"] == 0
    package_rows = (out_dir / "package_service_context.csv").read_text(encoding="utf-8")
    summary_rows = (out_dir / "package_service_summary.csv").read_text(encoding="utf-8")
    assert "149.154.175.51" in package_rows
    assert "telegram_platform" in package_rows
    assert "Telegram Messaging Platform" in package_rows
    assert "google_platform" in package_rows
    assert "telegram_platform:1" in summary_rows
