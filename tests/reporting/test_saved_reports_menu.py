from __future__ import annotations

from pathlib import Path

from scytaledroid.Reporting.saved_reports_menu import (
    classify_report_bundle,
    discover_report_bundle_roots,
    find_saved_report_entries,
)


def test_saved_report_entries_include_static_exposure_bundles(tmp_path: Path) -> None:
    base_dir = tmp_path / "reports"
    bundle = base_dir / "static_exposure_privacy" / "20260710T120000Z"
    (bundle / "manifest").mkdir(parents=True)
    (bundle / "report").mkdir()
    (bundle / "manifest" / "report_manifest.json").write_text("{}", encoding="utf-8")
    (bundle / "report" / "findings_summary.txt").write_text("summary\n", encoding="utf-8")

    entries = find_saved_report_entries(base_dir)

    assert len(entries) == 1
    assert entries[0].path == bundle
    assert entries[0].is_bundle is True
    assert entries[0].report_type == "Static Exposure"


def test_saved_report_entries_keep_standalone_markdown_reports(tmp_path: Path) -> None:
    base_dir = tmp_path / "reports"
    report = base_dir / "static_analysis" / "sample.md"
    report.parent.mkdir(parents=True)
    report.write_text("# Sample\n", encoding="utf-8")

    entries = find_saved_report_entries(base_dir)

    assert len(entries) == 1
    assert entries[0].path == report
    assert entries[0].is_bundle is False
    assert entries[0].report_type == "Static analysis"


def test_bundle_discovery_deduplicates_manifest_and_summary_markers(tmp_path: Path) -> None:
    base_dir = tmp_path / "reports"
    bundle = base_dir / "static_exposure_privacy" / "20260710T120000Z"
    (bundle / "manifest").mkdir(parents=True)
    (bundle / "report").mkdir()
    (bundle / "manifest" / "report_manifest.json").write_text("{}", encoding="utf-8")
    (bundle / "report" / "findings_summary.txt").write_text("summary\n", encoding="utf-8")

    assert discover_report_bundle_roots(base_dir) == [bundle]
    assert classify_report_bundle(bundle, base_dir) == "Static Exposure"
