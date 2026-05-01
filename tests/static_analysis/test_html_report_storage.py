from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.StaticAnalysis.core import ManifestSummary, StaticAnalysisReport
from scytaledroid.StaticAnalysis.reporting.html import save_html_report
from scytaledroid.Utils.System import util_actions


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


def test_save_html_report_defaults_to_latest_mode(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(app_config, "STATIC_HTML_MODE", "latest")

    path = save_html_report(_sample_report(), output_root=tmp_path)

    assert path == tmp_path / "reports" / "static" / "latest" / "com.example.app" / "base.html"
    assert path.exists()
    assert not (tmp_path / "reports" / "static" / "archive").exists()


def test_save_html_report_archive_mode_writes_session_archive_path(tmp_path: Path) -> None:
    path = save_html_report(_sample_report(), output_root=tmp_path, mode="archive")

    assert path == (
        tmp_path
        / "reports"
        / "static"
        / "archive"
        / "20260328-rda-full"
        / "com.example.app"
        / "base.html"
    )
    assert path.exists()
    assert not (tmp_path / "reports" / "static" / "latest").exists()


def test_save_html_report_both_mode_writes_latest_and_archive(tmp_path: Path) -> None:
    path = save_html_report(_sample_report(), output_root=tmp_path, mode="both")
    latest = tmp_path / "reports" / "static" / "latest" / "com.example.app" / "base.html"
    archive = (
        tmp_path
        / "reports"
        / "static"
        / "archive"
        / "20260328-rda-full"
        / "com.example.app"
        / "base.html"
    )

    assert path == latest
    assert latest.exists()
    assert archive.exists()


def test_clean_static_analysis_artifacts_prunes_legacy_and_new_html_roots(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")
    monkeypatch.setattr(app_config, "OUTPUT_DIR", "output")

    stale_files = [
        tmp_path / "output" / "reports" / "static_analysis" / "pkg" / "legacy.html",
        tmp_path / "output" / "reports" / "static" / "latest" / "pkg" / "base.html",
        tmp_path / "output" / "reports" / "static" / "archive" / "sess" / "pkg" / "base.html",
        tmp_path / "data" / "static_analysis" / "reports" / "report.json",
    ]
    for path in stale_files:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("stale", encoding="utf-8")
        old = datetime.now(UTC) - timedelta(days=2)
        os.utime(path, (old.timestamp(), old.timestamp()))

    util_actions.clean_static_analysis_artifacts(retention_days=1)

    for path in stale_files:
        assert not path.exists()
