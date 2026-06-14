from __future__ import annotations

from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.StaticAnalysis.core import ManifestSummary, StaticAnalysisReport
from scytaledroid.StaticAnalysis.persistence import reports as reports_store
from scytaledroid.StaticAnalysis.persistence.reports import list_reports, reports_for_package, save_report


def _sample_report(
    *,
    session_stamp: str = "20260328-rda-full",
    sha256: str = "a" * 64,
    version_code: str = "123",
    version_name: str = "1.2.3",
    generated_at: str = "2026-03-28T15:58:13+00:00",
) -> StaticAnalysisReport:
    return StaticAnalysisReport(
        file_path="/tmp/base.apk",
        relative_path=None,
        file_name="base.apk",
        file_size=123,
        hashes={"sha256": sha256},
        manifest=ManifestSummary(
            package_name="com.example.app",
            version_code=version_code,
            version_name=version_name,
            app_label="Example",
        ),
        metadata={
            "artifact": "base.apk",
            "session_stamp": session_stamp,
        },
        generated_at=generated_at,
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


def test_list_reports_reuses_warm_cache_without_rescan(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")
    monkeypatch.setattr(app_config, "OUTPUT_DIR", "output")
    monkeypatch.setattr(app_config, "STATIC_REPORT_JSON_MODE", "both")
    monkeypatch.setattr(app_config, "STATIC_HTML_MODE", "latest")

    save_report(_sample_report())
    first = list_reports()

    monkeypatch.setattr(
        reports_store,
        "_iter_report_paths",
        lambda: (_ for _ in ()).throw(AssertionError("cache should avoid archive rescan")),
    )

    second = list_reports()

    assert len(first) == 1
    assert [entry.path for entry in second] == [entry.path for entry in first]


def test_save_report_updates_warm_cache_for_later_reads(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")
    monkeypatch.setattr(app_config, "OUTPUT_DIR", "output")
    monkeypatch.setattr(app_config, "STATIC_REPORT_JSON_MODE", "both")
    monkeypatch.setattr(app_config, "STATIC_HTML_MODE", "latest")

    save_report(_sample_report())
    warm = list_reports()
    assert len(warm) == 1

    monkeypatch.setattr(
        reports_store,
        "_iter_report_paths",
        lambda: (_ for _ in ()).throw(AssertionError("warm cache should be updated incrementally")),
    )

    save_report(
        _sample_report(
            sha256="b" * 64,
            version_code="124",
            version_name="1.2.4",
            generated_at="2026-03-29T15:58:13+00:00",
        )
    )
    reports = list_reports()

    assert len(reports) == 2
    assert reports[0].report.hashes["sha256"] == "b" * 64
    assert reports[1].report.hashes["sha256"] == "a" * 64


def test_reports_for_package_uses_cached_package_index(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")
    monkeypatch.setattr(app_config, "OUTPUT_DIR", "output")
    monkeypatch.setattr(app_config, "STATIC_REPORT_JSON_MODE", "both")
    monkeypatch.setattr(app_config, "STATIC_HTML_MODE", "latest")

    save_report(_sample_report())
    save_report(
        StaticAnalysisReport(
            file_path="/tmp/other.apk",
            relative_path=None,
            file_name="other.apk",
            file_size=321,
            hashes={"sha256": "c" * 64},
            manifest=ManifestSummary(
                package_name="com.other.app",
                version_code="1",
                version_name="1.0",
                app_label="Other",
            ),
            metadata={"artifact": "other.apk", "session_stamp": "20260328-rda-full"},
            generated_at="2026-03-30T15:58:13+00:00",
        )
    )
    list_reports()

    monkeypatch.setattr(
        reports_store,
        "list_reports",
        lambda: (_ for _ in ()).throw(AssertionError("package index should satisfy lookup from warm cache")),
    )

    reports = reports_for_package("com.example.app")

    assert len(reports) == 1
    assert reports[0].report.manifest.package_name == "com.example.app"


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


def test_save_report_warm_cache_uses_enriched_metadata_shape(tmp_path: Path, monkeypatch) -> None:
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
        hashes={"sha256": "d" * 64},
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

    save_report(report)
    stored = list_reports()[0].report

    assert stored.metadata["normalized_package_name"] == "mnn.android"
    assert stored.metadata["manifest_package_name"] == "mnn.Android"
    assert stored.metadata["package_case_mismatch"] is True


def test_save_report_logs_execution_id(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")
    monkeypatch.setattr(app_config, "OUTPUT_DIR", "output")
    monkeypatch.setattr(app_config, "STATIC_REPORT_JSON_MODE", "latest")
    monkeypatch.setattr(app_config, "STATIC_HTML_MODE", "latest")

    captured: dict[str, object] = {}

    def _capture(_message, *, category=None, extra=None):
        captured["category"] = category
        captured["extra"] = dict(extra or {})

    monkeypatch.setattr(reports_store.log, "info", _capture)

    save_report(_sample_report(), execution_id="exec-123")

    assert captured["category"] == "static_analysis"
    assert captured["extra"]["event"] == "report.saved"
    assert captured["extra"]["execution_id"] == "exec-123"
