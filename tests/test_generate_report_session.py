from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.execution import scan_flow
from scytaledroid.StaticAnalysis.cli.models import RunParameters


class StubArtifact:
    def __init__(self):
        self.path = Path("/tmp/app.apk")
        self.metadata = {"session_stamp": "20240101-000000"}
        self.artifact_label = "base"
        self.display_path = "base.apk"


def test_generate_report_overrides_session(monkeypatch, tmp_path):
    captured = {}

    def fake_analyze(path, *, metadata, storage_root, config):  # noqa: ANN001
        captured["metadata"] = metadata
        return SimpleNamespace(
            detector_results=[],
            metadata={},
            hashes={"sha256": "abc"},
            manifest=SimpleNamespace(package_name="com.example", version_code=1, version_name="1.0", min_sdk=None, target_sdk=None),
            manifest_flags=SimpleNamespace(uses_cleartext_traffic=False, allow_backup=False, request_legacy_external_storage=False, network_security_config=None),
            permissions=SimpleNamespace(declared=(), dangerous=(), custom=()),
            exported_components=SimpleNamespace(total=lambda: 0),
        )

    monkeypatch.setattr(scan_flow, "analyze_apk", fake_analyze)
    monkeypatch.setattr(scan_flow, "build_analysis_config", lambda params: {})
    monkeypatch.setattr(scan_flow, "save_report", lambda report: SimpleNamespace(json_path=tmp_path / "report.json", html_path=None, view={}))

    params = RunParameters(profile="full", scope="app", scope_label="com.example", session_stamp="20251212-121212")

    report, *_ = scan_flow.generate_report(StubArtifact(), tmp_path, params)

    assert captured["metadata"]["session_stamp"] == "20251212-121212"
    assert report is not None
