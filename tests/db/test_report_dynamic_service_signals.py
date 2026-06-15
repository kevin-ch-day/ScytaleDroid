from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from scripts.db import report_dynamic_service_signals as report


def test_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_dynamic_service_signals.py"
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
    assert "dynamic privacy/security/context signals" in out


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
    assert summary["signal_observation_rows"] == 2
    assert summary["focus_area_hit_counts"]["privacy"] == 5
    assert summary["focus_area_hit_counts"]["mixed"] == 3
    signal_rows = (out_dir / "package_signal_rows.csv").read_text(encoding="utf-8")
    summary_rows = (out_dir / "package_signal_summary.csv").read_text(encoding="utf-8")
    assert "third_party_advertising" in signal_rows
    assert "push_or_engagement_platform" in signal_rows
    assert "bbc.mobile.news.ww" in summary_rows
