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


def test_root_domain_quality_separates_static_string_noise() -> None:
    assert report._root_domain_quality("example.com") == ("valid", "")
    assert report._root_domain_quality("http") == ("noisy", "not_a_valid_domain")
    assert report._root_domain_quality("bamgrid.comenable_atmos;height") == (
        "noisy",
        "not_a_valid_domain",
    )


def test_overlap_rows_include_curated_service_context_and_noisy_queue() -> None:
    runs = [
        report.RunPackage(
            static_run_id=101,
            package_name="com.cnn.mobile.android.phone",
            display_name="CNN",
            session_stamp="20260614-smoke",
            session_label="20260614-smoke",
            scope_label="All harvested apps",
        )
    ]
    package_domains = [
        {
            "static_run_id": 101,
            "root_domain": "fwmrm.net",
            "sample_count": 4,
            "http_sample_count": 4,
            "https_sample_count": 0,
        },
        {
            "static_run_id": 101,
            "root_domain": "http",
            "sample_count": 1,
            "http_sample_count": 1,
            "https_sample_count": 0,
        },
    ]
    tracker_rows = [
        {
            "tracker_name": "FreeWheel",
            "tracker_id_external": "224",
            "domain_tokens": ["fwmrm.net"],
            "code_signature": "com.freewheel.",
            "website": "https://www.freewheel.com/",
            "categories": ["Advertisement"],
        }
    ]

    overlap_rows, unmatched_rows, noisy_rows, _ = report._build_overlap_rows(runs, package_domains, tracker_rows)

    assert not unmatched_rows
    assert noisy_rows[0]["root_domain"] == "http"
    assert noisy_rows[0]["root_domain_quality"] == "noisy"
    assert overlap_rows[0]["tracker_name"] == "FreeWheel"
    assert overlap_rows[0]["curated_service_key"] == "freewheel"
    assert overlap_rows[0]["curated_service_confidence"] == "high"


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


def test_domain_research_candidates_separate_static_refs_and_curated_context() -> None:
    rows = report._build_domain_research_candidates(
        [
            {
                "root_domain": "hamcrest.org",
                "package_count": 2,
                "sample_rows": 3,
                "example_packages": "org.thoughtcrime.securesms",
                "curated_service_keys": "",
                "curated_service_confidences": "",
            },
            {
                "root_domain": "stats.mainroll.com",
                "package_count": 1,
                "sample_rows": 1,
                "example_packages": "com.pinterest",
                "curated_service_keys": "mainroll",
                "curated_service_confidences": "high",
            },
            {
                "root_domain": "onetrust.com",
                "package_count": 2,
                "sample_rows": 3,
                "example_packages": "com.mcdonalds.app, com.glance.lockscreenm",
                "curated_service_keys": "",
                "curated_service_confidences": "",
            },
        ]
    )

    by_domain = {str(row["root_domain"]): row for row in rows}
    assert by_domain["hamcrest.org"]["candidate_class"] == "static_library_or_standard_reference"
    assert by_domain["hamcrest.org"]["suggested_action"] == "do_not_map_as_runtime_service"
    assert by_domain["stats.mainroll.com"]["candidate_class"] == "already_curated_context"
    assert by_domain["onetrust.com"]["candidate_class"] == "research_candidate_shared_or_repeated"


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
        {
            "static_run_id": 101,
            "package_name": "com.example.app",
            "root_domain": "http",
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
    assert summary["unmatched_root_domain_count"] == 1
    assert summary["unmatched_without_curated_context_count"] == 1
    assert summary["domain_research_candidate_count"] == 1
    assert summary["domain_research_candidate_class_counts"] == {"likely_first_party_or_brand_reference": 1}
    assert summary["noisy_static_root_domain_count"] == 1
    assert summary["no_db_writes"] is True
    assert "risk" not in (tmp_path / "summary.json").read_text(encoding="utf-8").lower()

    package_rows = (tmp_path / "package_tracker_context.csv").read_text(encoding="utf-8")
    assert "Example App" in package_rows
    overlap_rows = (tmp_path / "tracker_context_overlaps.csv").read_text(encoding="utf-8")
    assert "New Relic" in overlap_rows
    noisy_rows = (tmp_path / "noisy_static_root_domains.csv").read_text(encoding="utf-8")
    assert "http" in noisy_rows
    research_rows = (tmp_path / "domain_research_candidates.csv").read_text(encoding="utf-8")
    assert "example.com" in research_rows
