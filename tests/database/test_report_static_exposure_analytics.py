"""Unit tests for experimental static exposure analytics report helpers."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from scripts.db import report_static_exposure_analytics as report
from scytaledroid.StaticAnalysis.modules.categories import resolve_category_with_provenance


def test_help_is_safe_without_pythonpath() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_static_exposure_analytics.py"
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
    assert "--session" in out
    assert "--include-partial" in out
    assert "exposure" in out


def test_family_mapping_routes_crypto_into_code_measurement() -> None:
    assert report._family_from_finding("CRYPTO", None) == "CODE"
    assert report._family_from_finding(None, "MASVS-RESILIENCE-1") == "RESILIENCE"
    assert report._family_from_finding("NETWORK", None) == "NETWORK"


def test_jensen_shannon_distance_zero_for_identical_distributions() -> None:
    value = report._jensen_shannon_distance([0.5, 0.5], [0.5, 0.5])
    assert value == 0.0


def test_build_evidence_gap_row_counts_missing_surfaces() -> None:
    run = report.RunSelection(
        static_run_id=42,
        package_name="com.example.app",
        display_name="Example",
        raw_category="User",
        category="Uncategorized",
        category_source="initial_selection",
        category_confidence="low",
        category_reason="raw category",
        category_needs_review=False,
        session_stamp="20260612-all-full",
        session_label="20260612-all-full",
        scope_label="All harvested apps",
        profile_key="UNCLASSIFIED",
        publisher_key="VENDOR_MISC",
        catalog_category_name=None,
        version_code=100,
        version_name="1.0",
        base_apk_sha256=None,
        artifact_set_hash="abc",
        apk_set_id=None,
        run_class="CANONICAL",
        identity_valid=True,
        detector_metrics=None,
        repro_bundle=None,
        analysis_matrices=None,
        analysis_indicators=None,
        workload_profile=None,
    )
    row = report._build_evidence_gap_row(
        run,
        {"evidence_ref_count": 3},
        has_permission_matrix=True,
        has_findings=True,
        has_string_summary=False,
        has_apk_set=False,
        has_handoff=False,
    )
    assert row["evidence_ref_count"] == 3
    assert row["evidence_gap_count"] == 4
    assert row["has_permission_matrix"] is True
    assert "has_base_apk_sha256" in row["warning"]


def test_curated_seed_beats_generic_category() -> None:
    resolved = resolve_category_with_provenance(
        "com.chase.sig.android",
        {
            "category": "User",
            "category_name": "User",
            "display_name": "Chase",
            "profile_key": "UNCLASSIFIED",
            "publisher_key": "VENDOR_MISC",
        },
    )
    assert resolved.category == "Finance"
    assert resolved.source.startswith("curated_seed")
    assert resolved.confidence == "high"


def test_new_curated_seed_exact_mapping_resolves_with_high_confidence() -> None:
    resolved = resolve_category_with_provenance(
        "com.squareup.cash",
        {
            "category": "User",
            "category_name": "User",
            "display_name": "Cash App",
            "profile_key": "UNCLASSIFIED",
            "publisher_key": "VENDOR_MISC",
        },
    )
    assert resolved.category == "Finance"
    assert resolved.source == "curated_seed_exact"
    assert resolved.confidence == "high"


def test_profile_category_beats_generic_user_bucket() -> None:
    resolved = resolve_category_with_provenance(
        "com.example.dailynews",
        {
            "category": "User",
            "category_name": "User",
            "display_name": "Daily News",
            "profile_key": "NEWS",
            "publisher_key": "VENDOR_MISC",
        },
    )
    assert resolved.category == "News"
    assert resolved.source == "profile_key"


def test_system_google_package_not_misclassified_as_generic_user_app() -> None:
    resolved = resolve_category_with_provenance(
        "android.autoinstalls.config.motorola.layout",
        {
            "category": "System",
            "category_name": "System",
            "display_name": "Motorola Auto-Install Layout",
            "profile_key": "SYSTEM_CORE",
            "publisher_key": "ANDROID_AOSP",
            "owner_role": "System",
            "source": "System",
        },
    )
    assert resolved.category == "Platform / system"
    assert resolved.source == "role_classification"


def test_low_confidence_package_remains_review() -> None:
    resolved = resolve_category_with_provenance(
        "com.example.unknownthing",
        {
            "category": "User",
            "category_name": "User",
            "display_name": "Unknown Thing",
            "profile_key": "UNCLASSIFIED",
            "publisher_key": "VENDOR_MISC",
            "review_needed": True,
        },
    )
    assert resolved.category == "Unknown / review"
    assert resolved.needs_review is True
    assert resolved.confidence == "low"


def test_taxonomy_gap_package_stays_review_flagged_with_explicit_source() -> None:
    resolved = resolve_category_with_provenance(
        "com.dd.doordash",
        {
            "category": "User",
            "category_name": "User",
            "display_name": "DoorDash",
            "profile_key": "UNCLASSIFIED",
            "publisher_key": "VENDOR_MISC",
        },
    )
    assert resolved.category == "Unknown / review"
    assert resolved.source == "taxonomy_gap_review"
    assert resolved.needs_review is True


def test_review_bucket_distinguishes_taxonomy_gap_ambiguous_and_labeled_review() -> None:
    taxonomy_gap = report.RunSelection(
        static_run_id=1,
        package_name="com.dd.doordash",
        display_name="DoorDash",
        raw_category="User",
        category="Unknown / review",
        category_source="taxonomy_gap_review",
        category_confidence="medium",
        category_reason="taxonomy gap",
        category_needs_review=True,
        session_stamp=None,
        session_label=None,
        scope_label=None,
        profile_key="UNCLASSIFIED",
        publisher_key="VENDOR_MISC",
        catalog_category_name=None,
        version_code=None,
        version_name=None,
        base_apk_sha256=None,
        artifact_set_hash=None,
        apk_set_id=None,
        run_class=None,
        identity_valid=None,
        detector_metrics=None,
        repro_bundle=None,
        analysis_matrices=None,
        analysis_indicators=None,
        workload_profile=None,
    )
    ambiguous = report.RunSelection(
        static_run_id=2,
        package_name="com.example.unknown",
        display_name="Unknown",
        raw_category="User",
        category="Unknown / review",
        category_source="review_fallback",
        category_confidence="low",
        category_reason="review",
        category_needs_review=True,
        session_stamp=None,
        session_label=None,
        scope_label=None,
        profile_key="UNCLASSIFIED",
        publisher_key="VENDOR_MISC",
        catalog_category_name=None,
        version_code=None,
        version_name=None,
        base_apk_sha256=None,
        artifact_set_hash=None,
        apk_set_id=None,
        run_class=None,
        identity_valid=None,
        detector_metrics=None,
        repro_bundle=None,
        analysis_matrices=None,
        analysis_indicators=None,
        workload_profile=None,
    )
    labeled = report.RunSelection(
        static_run_id=3,
        package_name="com.example.vendor",
        display_name="Vendor App",
        raw_category="User",
        category="Platform / system",
        category_source="role_classification",
        category_confidence="medium",
        category_reason="system-core metadata without stronger distinction",
        category_needs_review=True,
        session_stamp=None,
        session_label=None,
        scope_label=None,
        profile_key="SYSTEM_CORE",
        publisher_key="VENDOR_MISC",
        catalog_category_name=None,
        version_code=None,
        version_name=None,
        base_apk_sha256=None,
        artifact_set_hash=None,
        apk_set_id=None,
        run_class=None,
        identity_valid=None,
        detector_metrics=None,
        repro_bundle=None,
        analysis_matrices=None,
        analysis_indicators=None,
        workload_profile=None,
    )
    assert report._review_bucket_for_run(taxonomy_gap) == "taxonomy_gap_review"
    assert report._review_bucket_for_run(ambiguous) == "ambiguous_review"
    assert report._review_bucket_for_run(labeled) == "labeled_review"


def test_conservative_label_heuristic_can_resolve_finance() -> None:
    resolved = resolve_category_with_provenance(
        "com.schwab.mobile",
        {
            "category": "User",
            "category_name": "User",
            "display_name": "Schwab Mobile",
            "profile_key": "UNCLASSIFIED",
            "publisher_key": "VENDOR_MISC",
        },
    )
    assert resolved.category == "Finance"
    assert resolved.source.startswith("heuristic")


def test_category_coverage_summary_counts_sources() -> None:
    rows = [
        report.RunSelection(
            static_run_id=1,
            package_name="com.a",
            display_name="A",
            raw_category="User",
            category="Finance",
            category_source="curated_seed_exact",
            category_confidence="high",
            category_reason="seed",
            category_needs_review=False,
            session_stamp=None,
            session_label=None,
            scope_label=None,
            profile_key="UNCLASSIFIED",
            publisher_key="VENDOR_MISC",
            catalog_category_name=None,
            version_code=None,
            version_name=None,
            base_apk_sha256=None,
            artifact_set_hash=None,
            apk_set_id=None,
            run_class=None,
            identity_valid=None,
            detector_metrics=None,
            repro_bundle=None,
            analysis_matrices=None,
            analysis_indicators=None,
            workload_profile=None,
        ),
        report.RunSelection(
            static_run_id=2,
            package_name="com.b",
            display_name="B",
            raw_category="User",
            category="Unknown / review",
            category_source="unresolved",
            category_confidence="low",
            category_reason="review",
            category_needs_review=True,
            session_stamp=None,
            session_label=None,
            scope_label=None,
            profile_key="UNCLASSIFIED",
            publisher_key="VENDOR_MISC",
            catalog_category_name=None,
            version_code=None,
            version_name=None,
            base_apk_sha256=None,
            artifact_set_hash=None,
            apk_set_id=None,
            run_class=None,
            identity_valid=None,
            detector_metrics=None,
            repro_bundle=None,
            analysis_matrices=None,
            analysis_indicators=None,
            workload_profile=None,
        ),
    ]
    summary = report._category_coverage_summary(rows)
    assert summary["before_distribution"]["User"] == 2
    assert summary["after_distribution"]["Finance"] == 1
    assert summary["after_distribution"]["Unknown / review"] == 1
    assert summary["curated_category_count"] == 1
    assert summary["after_unknown_review_count"] == 1
    assert summary["review_flagged_count"] == 1


def test_review_queue_summary_breaks_down_review_buckets() -> None:
    rows = [
        report.RunSelection(
            static_run_id=1,
            package_name="com.dd.doordash",
            display_name="DoorDash",
            raw_category="User",
            category="Unknown / review",
            category_source="taxonomy_gap_review",
            category_confidence="medium",
            category_reason="taxonomy gap",
            category_needs_review=True,
            session_stamp=None,
            session_label=None,
            scope_label=None,
            profile_key="UNCLASSIFIED",
            publisher_key="VENDOR_MISC",
            catalog_category_name=None,
            version_code=None,
            version_name=None,
            base_apk_sha256=None,
            artifact_set_hash=None,
            apk_set_id=None,
            run_class=None,
            identity_valid=None,
            detector_metrics=None,
            repro_bundle=None,
            analysis_matrices=None,
            analysis_indicators=None,
            workload_profile=None,
        ),
        report.RunSelection(
            static_run_id=2,
            package_name="com.example.unknown",
            display_name="Unknown",
            raw_category="User",
            category="Unknown / review",
            category_source="review_fallback",
            category_confidence="low",
            category_reason="review",
            category_needs_review=True,
            session_stamp=None,
            session_label=None,
            scope_label=None,
            profile_key="UNCLASSIFIED",
            publisher_key="VENDOR_MISC",
            catalog_category_name=None,
            version_code=None,
            version_name=None,
            base_apk_sha256=None,
            artifact_set_hash=None,
            apk_set_id=None,
            run_class=None,
            identity_valid=None,
            detector_metrics=None,
            repro_bundle=None,
            analysis_matrices=None,
            analysis_indicators=None,
            workload_profile=None,
        ),
        report.RunSelection(
            static_run_id=3,
            package_name="com.example.vendor",
            display_name="Vendor App",
            raw_category="User",
            category="Platform / system",
            category_source="role_classification",
            category_confidence="medium",
            category_reason="system-core metadata without stronger distinction",
            category_needs_review=True,
            session_stamp=None,
            session_label=None,
            scope_label=None,
            profile_key="SYSTEM_CORE",
            publisher_key="VENDOR_MISC",
            catalog_category_name=None,
            version_code=None,
            version_name=None,
            base_apk_sha256=None,
            artifact_set_hash=None,
            apk_set_id=None,
            run_class=None,
            identity_valid=None,
            detector_metrics=None,
            repro_bundle=None,
            analysis_matrices=None,
            analysis_indicators=None,
            workload_profile=None,
        ),
    ]
    summary = report._category_coverage_summary(rows)
    queue = summary["review_queue"]
    assert queue["bucket_distribution"] == {
        "ambiguous_review": 1,
        "labeled_review": 1,
        "taxonomy_gap_review": 1,
    }
    assert queue["source_distribution"] == {
        "review_fallback": 1,
        "role_classification": 1,
        "taxonomy_gap_review": 1,
    }
    assert queue["labeled_category_distribution"] == {"Platform / system": 1}


def test_category_resolution_gaps_include_review_bucket() -> None:
    rows = [
        report.RunSelection(
            static_run_id=1,
            package_name="com.example.vendor",
            display_name="Vendor App",
            raw_category="User",
            category="Platform / system",
            category_source="role_classification",
            category_confidence="medium",
            category_reason="system-core metadata without stronger distinction",
            category_needs_review=True,
            session_stamp=None,
            session_label=None,
            scope_label=None,
            profile_key="SYSTEM_CORE",
            publisher_key="VENDOR_MISC",
            catalog_category_name=None,
            version_code=None,
            version_name=None,
            base_apk_sha256=None,
            artifact_set_hash=None,
            apk_set_id=None,
            run_class=None,
            identity_valid=None,
            detector_metrics=None,
            repro_bundle=None,
            analysis_matrices=None,
            analysis_indicators=None,
            workload_profile=None,
        )
    ]
    gaps = report._build_category_resolution_gaps(rows)
    assert gaps[0]["review_bucket"] == "labeled_review"
