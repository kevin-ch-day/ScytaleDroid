from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from scytaledroid.StaticAnalysis.cli.core.models import RunParameters
from scytaledroid.StaticAnalysis.cli.execution import scan_report as sr


@pytest.fixture
def stub_artifact(tmp_path: Path) -> MagicMock:
    p = tmp_path / "stub.apk"
    p.write_bytes(b"stub")
    art = MagicMock()
    art.path = p
    art.metadata = {"package_name": "com.example.stub", "category": "Uncategorized"}
    art.artifact_label = "base"
    art.display_path = str(p)
    art.package_name = "com.example.stub"
    return art


def test_generate_report_accumulates_analyze_and_persist(
    monkeypatch: pytest.MonkeyPatch,
    stub_artifact: MagicMock,
    tmp_path: Path,
) -> None:
    sink: dict[str, float] = {}
    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="All",
        dry_run=False,
        persistence_ready=True,
    )

    fake_report = MagicMock()
    fake_report.metadata = {"duration_seconds": 0.05}
    fake_report.detector_results = []

    def _fake_analyze(*_args: object, **_kwargs: object) -> MagicMock:
        return fake_report

    class _Saved:
        json_path = tmp_path / "out.json"

    monkeypatch.setattr(sr, "analyze_apk", _fake_analyze)
    monkeypatch.setattr(sr, "save_report", lambda _r: _Saved())

    report, path, err, skipped = sr.generate_report(
        stub_artifact,
        tmp_path,
        params,
        phase_timing_sink=sink,
    )
    assert report is fake_report
    assert path == _Saved.json_path
    assert err is None
    assert skipped is False
    assert sink.get("analyze_apk_wall_s", 0.0) > 0.0
    assert sink.get("persist_wall_s", 0.0) > 0.0


def test_generate_report_legacy_save_report_signature_still_supported(
    monkeypatch: pytest.MonkeyPatch,
    stub_artifact: MagicMock,
    tmp_path: Path,
) -> None:
    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="All",
        dry_run=False,
        persistence_ready=True,
    )

    fake_report = MagicMock()
    fake_report.metadata = {"duration_seconds": 0.05}
    fake_report.detector_results = []

    class _Saved:
        json_path = tmp_path / "legacy.json"

    calls: list[str] = []

    monkeypatch.setattr(sr, "analyze_apk", lambda *_a, **_k: fake_report)

    def _legacy_save_report(_report: object) -> _Saved:
        calls.append("legacy")
        return _Saved()

    monkeypatch.setattr(sr, "save_report", _legacy_save_report)

    report, path, err, skipped = sr.generate_report(
        stub_artifact,
        tmp_path,
        params,
    )

    assert report is fake_report
    assert path == _Saved.json_path
    assert err is None
    assert skipped is False
    assert calls == ["legacy"]
