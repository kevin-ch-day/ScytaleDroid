from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.db import report_dynamic_unresolved_domains as report


def test_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_dynamic_unresolved_domains.py"
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
    assert "unresolved" in out
    assert "--package" in out


def test_generate_report_groups_unknown_domains_and_candidate_service_matches(tmp_path: Path, monkeypatch) -> None:
    unresolved = [
        {
            "package_name": "bbc.mobile.news.ww",
            "display_name": "BBC News",
            "observed_domain": "api.permutive.com",
            "root_domain": "permutive.com",
            "indicator_type": "dns",
            "indicator_source": "top_dns",
            "classification_basis": "unclassified",
            "total_hits": 7,
            "observation_rows": 1,
            "observed_run_count": 1,
            "first_seen_at_utc": "2026-06-15 19:32:44",
            "last_seen_at_utc": "2026-06-15 19:38:04",
        },
        {
            "package_name": "com.cnn.mobile.android.phone",
            "display_name": "CNN",
            "observed_domain": "idsync.rlcdn.com",
            "root_domain": "rlcdn.com",
            "indicator_type": "sni",
            "indicator_source": "top_sni",
            "classification_basis": "unclassified",
            "total_hits": 4,
            "observation_rows": 1,
            "observed_run_count": 1,
            "first_seen_at_utc": "2026-06-15 19:39:43",
            "last_seen_at_utc": "2026-06-15 19:46:11",
        },
        {
            "package_name": "bbc.mobile.news.ww",
            "display_name": "BBC News",
            "observed_domain": "mystery.example.net",
            "root_domain": "example.net",
            "indicator_type": "dns",
            "indicator_source": "top_dns",
            "classification_basis": "unclassified",
            "total_hits": 2,
            "observation_rows": 1,
            "observed_run_count": 1,
            "first_seen_at_utc": "2026-06-15 19:47:52",
            "last_seen_at_utc": "2026-06-15 19:52:42",
        },
    ]
    services = [
        {
            "service_key": "permutive",
            "display_name": "Permutive",
            "owner_name": "Permutive",
            "owner_class": "third_party",
            "service_category": "audience_personalization",
            "primary_use_case": "publisher_audience_activation",
            "source_url": "https://permutive.com/",
            "confidence": "high",
        },
        {
            "service_key": "liveramp",
            "display_name": "LiveRamp",
            "owner_name": "LiveRamp",
            "owner_class": "third_party",
            "service_category": "identity_and_adtech",
            "primary_use_case": "identity_resolution_and_cookie_sync",
            "source_url": "https://liveramp.com/",
            "confidence": "high",
        },
    ]
    maps = [
        {
            "service_key": "permutive",
            "package_name_scope": "",
            "domain_pattern": "permutive.com",
            "match_type": "SUFFIX",
            "role_class": "audience_personalization",
            "source_url": "https://permutive.com/",
            "confidence": "high",
        },
        {
            "service_key": "liveramp",
            "package_name_scope": "",
            "domain_pattern": "rlcdn.com",
            "match_type": "SUFFIX",
            "role_class": "identity_sync",
            "source_url": "https://liveramp.com/",
            "confidence": "high",
        },
    ]

    def fake_run_sql(_sql, _params=(), *, fetch="one", dictionary=True, query_name=None):  # noqa: ANN001,ARG001
        if query_name == "dynamic.unresolved_domains.rows":
            return unresolved
        if query_name == "dynamic.unresolved_domains.services":
            return services
        if query_name == "dynamic.unresolved_domains.maps":
            return maps
        raise AssertionError(f"unexpected query_name={query_name!r}")

    class _FakeCoreQ:
        run_sql = staticmethod(fake_run_sql)

    monkeypatch.setattr("scytaledroid.Database.db_core.db_queries.run_sql", fake_run_sql)
    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["unresolved_domain_rows"] == 3
    assert summary["unresolved_root_domain_rows"] == 3
    assert summary["packages_with_unresolved_domains"] == 2
    assert summary["candidate_service_match_rows"] == 2
    assert summary["no_service_match_rows"] == 1
    assert summary["candidate_service_counts"]["permutive"] == 1
    assert summary["candidate_service_counts"]["liveramp"] == 1

    rows_csv = (out_dir / "unresolved_domain_rows.csv").read_text(encoding="utf-8")
    roots_csv = (out_dir / "unresolved_root_domains.csv").read_text(encoding="utf-8")
    pkg_csv = (out_dir / "package_unresolved_summary.csv").read_text(encoding="utf-8")
    payload = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))

    assert "api.permutive.com" in rows_csv
    assert "candidate_service_match" in rows_csv
    assert "mystery.example.net" in rows_csv
    assert "permutive.com" in roots_csv
    assert "bbc.mobile.news.ww" in pkg_csv
    assert payload["candidate_service_hit_totals"]["permutive"] == 7
    assert payload["candidate_service_hit_totals"]["liveramp"] == 4


def test_generate_report_overlays_missing_repo_seed_candidate_matches(tmp_path: Path, monkeypatch) -> None:
    unresolved = [
        {
            "package_name": "bbc.mobile.news.ww",
            "display_name": "BBC News",
            "observed_domain": "api.live.bbcx-internal.com",
            "root_domain": "bbcx-internal.com",
            "indicator_type": "dns",
            "indicator_source": "top_dns",
            "classification_basis": "unclassified",
            "total_hits": 30,
            "observation_rows": 1,
            "observed_run_count": 1,
            "first_seen_at_utc": "2026-06-29 12:24:16",
            "last_seen_at_utc": "2026-06-29 12:28:45",
        },
    ]
    services = [
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
    maps = [
        {
            "service_key": "bbc_first_party",
            "package_name_scope": "bbc.mobile.news.ww",
            "domain_pattern": "bbc.com",
            "match_type": "SUFFIX",
            "role_class": "publisher_api",
            "source_url": "https://www.bbc.com",
            "confidence": "high",
        },
    ]

    def fake_run_sql(_sql, _params=(), *, fetch="one", dictionary=True, query_name=None):  # noqa: ANN001,ARG001
        if query_name == "dynamic.unresolved_domains.rows":
            return unresolved
        if query_name == "dynamic.unresolved_domains.services":
            return services
        if query_name == "dynamic.unresolved_domains.maps":
            return maps
        raise AssertionError(f"unexpected query_name={query_name!r}")

    monkeypatch.setattr("scytaledroid.Database.db_core.db_queries.run_sql", fake_run_sql)
    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["candidate_service_match_rows"] == 1
    rows_csv = (out_dir / "unresolved_domain_rows.csv").read_text(encoding="utf-8")
    assert "bbc_first_party" in rows_csv
    assert "candidate_service_match" in rows_csv
