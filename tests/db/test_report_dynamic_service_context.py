from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from scripts.db import report_dynamic_service_context as report


def test_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_dynamic_service_context.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = (proc.stdout or "").lower()
    assert out.startswith("usage:")
    assert "service/provider context" in out
    assert "--package" in out


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

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        if query_name == "dynamic.service_context.report.services":
            return service_rows
        if query_name == "dynamic.service_context.report.maps":
            return map_rows
        if query_name == "dynamic.service_context.report.observations":
            return observation_rows
        raise AssertionError(f"unexpected query_name={query_name!r} sql={sql[:80]!r}")

    monkeypatch.setattr("scytaledroid.Database.db_core.db_queries.run_sql", fake_run_sql)

    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["service_catalog_count"] == 2
    assert summary["service_domain_map_count"] == 2
    assert summary["observed_domain_rows"] == 3
    assert summary["unresolved_domain_rows"] == 1
    assert summary["packages_scanned"] == 1
    package_rows = (out_dir / "package_service_context.csv").read_text(encoding="utf-8")
    summary_rows = (out_dir / "package_service_summary.csv").read_text(encoding="utf-8")
    unresolved_rows = (out_dir / "unresolved_domains.csv").read_text(encoding="utf-8")
    assert "bbc_first_party" in package_rows
    assert "google_ads" in package_rows
    assert "bbc.mobile.news.ww" in summary_rows
    assert "mystery.example.org" in unresolved_rows
