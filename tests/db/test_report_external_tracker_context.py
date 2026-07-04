from __future__ import annotations

import json
import sys
from pathlib import Path

from scripts.db import report_external_tracker_context as report


def test_extract_domain_tokens_normalizes_tracker_patterns() -> None:
    pattern = r"www\.googletagmanager\.com|.*\.estimote\.com|inmobi\.com|sdkm\.w\.inmobi\.com"
    tokens = report._extract_domain_tokens(pattern)
    assert "googletagmanager.com" in tokens
    assert "estimote.com" in tokens
    assert "inmobi.com" in tokens


def test_classify_overlap_confidence_separates_generic_and_specific_roots() -> None:
    assert report._classify_overlap_confidence("google.com") == ("low", "generic_root_overlap")
    assert report._classify_overlap_confidence("amazonaws.com") == (
        "low",
        "generic_infrastructure_overlap",
    )
    assert report._classify_overlap_confidence("newrelic.com") == (
        "medium",
        "specific_root_overlap",
    )


def test_summarize_unmatched_domains_rolls_up_packages() -> None:
    rows = report._summarize_unmatched_domains(
        [
            {
                "package_name": "com.example.one",
                "root_domain": "example.com",
                "sample_count": 2,
                "http_sample_count": 1,
                "https_sample_count": 1,
            },
            {
                "package_name": "com.example.two",
                "root_domain": "example.com",
                "sample_count": 3,
                "http_sample_count": 0,
                "https_sample_count": 3,
            },
        ]
    )
    assert rows[0]["root_domain"] == "example.com"
    assert rows[0]["package_count"] == 2
    assert rows[0]["sample_rows"] == 5


def test_main_generates_bundle_from_mocked_db(tmp_path: Path, monkeypatch) -> None:
    runs = [
        report.RunPackage(
            static_run_id=101,
            package_name="com.example.app",
            display_name="Example App",
            session_stamp="20260614-smoke",
            session_label="20260614-smoke",
            scope_label="All harvested apps",
        )
    ]
    package_domains = [
        {
            "static_run_id": 101,
            "package_name": "com.example.app",
            "root_domain": "newrelic.com",
            "sample_count": 2,
            "http_sample_count": 0,
            "https_sample_count": 2,
        },
        {
            "static_run_id": 101,
            "package_name": "com.example.app",
            "root_domain": "example.com",
            "sample_count": 1,
            "http_sample_count": 1,
            "https_sample_count": 0,
        },
    ]
    tracker_rows = [
        {
            "tracker_name": "New Relic",
            "tracker_id_external": "900",
            "domain_tokens": ["newrelic.com"],
            "code_signature": "com.newrelic.",
            "website": "https://newrelic.com",
            "categories": ["Crash reporting"],
        }
    ]

    class _FakeDbConfig:
        DB_CONFIG = {"engine": "mysql"}

    class _FakeDbQueries:
        @staticmethod
        def run_sql(sql, params=(), *, fetch="all", dictionary=True, query_name=None):  # noqa: ANN001,ARG001
            raise AssertionError(f"unexpected query_name: {query_name}")

    monkeypatch.setattr(report, "_load_runs", lambda core_q, session=None: runs)
    monkeypatch.setattr(report, "_load_package_domains", lambda core_q, run_ids: package_domains)
    monkeypatch.setattr(
        report, "_load_external_tracker_domains", lambda core_q: (tracker_rows, [], "2026-06-14")
    )
    monkeypatch.setitem(sys.modules, "scytaledroid.Database.db_core.db_config", _FakeDbConfig)
    monkeypatch.setitem(sys.modules, "scytaledroid.Database.db_core.db_queries", _FakeDbQueries)

    rc = report.main(["--output-dir", str(tmp_path)])
    assert rc == 0

    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert summary["snapshot_date"] == "2026-06-14"
    assert summary["package_count"] == 1
    assert summary["package_with_any_overlap_count"] == 1
    assert summary["package_with_medium_overlap_count"] == 1
    assert summary["package_with_low_overlap_count"] == 0
    assert summary["no_db_writes"] is True
    assert "risk" not in (tmp_path / "summary.json").read_text(encoding="utf-8").lower()

    package_rows = (tmp_path / "package_tracker_context.csv").read_text(encoding="utf-8")
    assert "Example App" in package_rows
    overlap_rows = (tmp_path / "tracker_context_overlaps.csv").read_text(encoding="utf-8")
    assert "New Relic" in overlap_rows
