from __future__ import annotations

from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.StaticAnalysis.core import ManifestSummary, StaticAnalysisReport
from scytaledroid.StaticAnalysis.persistence.reports import list_reports, save_report


def _sample_report(*, session_stamp: str = "20260328-rda-full") -> StaticAnalysisReport:
    return StaticAnalysisReport(
        file_path="/tmp/base.apk",
        relative_path=None,
        file_name="base.apk",
        file_size=123,
        hashes={"sha256": "a" * 64},
        manifest=ManifestSummary(
            package_name="com.example.app",
            version_code="123",
            version_name="1.2.3",
            app_label="Example",
        ),
        metadata={
            "artifact": "base.apk",
            "session_stamp": session_stamp,
        },
        generated_at="2026-03-28T15:58:13+00:00",
    )


def test_save_report_defaults_to_both_json_mode(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")
    monkeypatch.setattr(app_config, "OUTPUT_DIR", "output")
    monkeypatch.setattr(app_config, "STATIC_REPORT_JSON_MODE", "both")
    monkeypatch.setattr(app_config, "STATIC_HTML_MODE", "latest")

    saved = save_report(_sample_report())

    assert saved.json_path == (
        Path("data")
        / "static_analysis"
        / "reports"
        / "latest"
        / ("a" * 64 + ".json")
    )
    assert saved.json_path.exists()
    archive_copy = (
        tmp_path
        / "data"
        / "static_analysis"
        / "reports"
        / "archive"
        / "20260328-rda-full"
        / ("a" * 64 + ".json")
    )
    assert archive_copy.exists()


def test_save_report_archive_mode_writes_session_archive_json(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")
    monkeypatch.setattr(app_config, "OUTPUT_DIR", "output")
    monkeypatch.setattr(app_config, "STATIC_REPORT_JSON_MODE", "archive")
    monkeypatch.setattr(app_config, "STATIC_HTML_MODE", "latest")

    saved = save_report(_sample_report())

    assert saved.json_path == (
        Path("data")
        / "static_analysis"
        / "reports"
        / "archive"
        / "20260328-rda-full"
        / ("a" * 64 + ".json")
    )
    assert saved.json_path.exists()
    assert not (tmp_path / "data" / "static_analysis" / "reports" / "latest").exists()


def test_list_reports_prefers_latest_and_dedupes_archive_copy(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")
    monkeypatch.setattr(app_config, "OUTPUT_DIR", "output")
    monkeypatch.setattr(app_config, "STATIC_REPORT_JSON_MODE", "both")
    monkeypatch.setattr(app_config, "STATIC_HTML_MODE", "latest")

    save_report(_sample_report())

    reports = list_reports()

    assert len(reports) == 1
    assert reports[0].path == (
        Path("data")
        / "static_analysis"
        / "reports"
        / "latest"
        / ("a" * 64 + ".json")
    )


def test_save_report_enriches_metadata_with_normalized_and_manifest_package_names(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")
    monkeypatch.setattr(app_config, "OUTPUT_DIR", "output")
    monkeypatch.setattr(app_config, "STATIC_REPORT_JSON_MODE", "latest")
    monkeypatch.setattr(app_config, "STATIC_HTML_MODE", "latest")

    report = StaticAnalysisReport(
        file_path="/tmp/base.apk",
        relative_path=None,
        file_name="base.apk",
        file_size=123,
        hashes={"sha256": "b" * 64},
        manifest=ManifestSummary(
            package_name="mnn.Android",
            version_code="123",
            version_name="1.2.3",
            app_label="Example",
        ),
        metadata={
            "artifact": "base.apk",
            "session_stamp": "20260328-rda-full",
            "package_name": "mnn.android",
        },
        generated_at="2026-03-28T15:58:13+00:00",
    )

    saved = save_report(report)
    payload = saved.json_path.read_text(encoding="utf-8")

    assert '"normalized_package_name": "mnn.android"' in payload
    assert '"manifest_package_name": "mnn.Android"' in payload
    assert '"package_case_mismatch": true' in payload
