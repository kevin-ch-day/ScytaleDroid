from __future__ import annotations

from pathlib import Path

from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.core.target_manager import TargetManager


def _ctx(tmp_path: Path) -> RunContext:
    run_dir = tmp_path / "run"
    return RunContext(
        dynamic_run_id="r1",
        package_name="com.facebook.katana",
        duration_seconds=180,
        scenario_id="basic_usage",
        run_dir=run_dir,
        artifacts_dir=run_dir / "artifacts",
        analysis_dir=run_dir / "analysis",
        notes_dir=run_dir / "notes",
        interactive=True,
        device_serial="SERIAL123",
    )


def test_read_package_dump_falls_back_when_unknown_argument(monkeypatch, tmp_path: Path) -> None:
    manager = TargetManager()
    ctx = _ctx(tmp_path)
    calls: list[list[str]] = []

    def fake_run_shell(_serial: str, cmd: list[str]) -> str:
        calls.append(cmd)
        if cmd[:3] == ["dumpsys", "package", "--user"]:
            return "Unknown argument: --user; use -h for help"
        return "Package [com.facebook.katana]\n  versionCode=468616494 minSdk=28 targetSdk=35\n"

    monkeypatch.setattr("scytaledroid.DynamicAnalysis.core.target_manager.adb_shell.run_shell", fake_run_shell)
    out = manager._read_package_dump(ctx)
    assert "versionCode=468616494" in out
    assert len(calls) == 2
    assert calls[0] == ["dumpsys", "package", "--user", "0", "com.facebook.katana"]
    assert calls[1] == ["dumpsys", "package", "com.facebook.katana"]


def test_extract_version_code_scoped_to_package_block() -> None:
    manager = TargetManager()
    dump = """
Package [com.other.app]
  versionCode=1 minSdk=21 targetSdk=34
Package [com.facebook.katana]
  versionCode=468616494 minSdk=28 targetSdk=35
"""
    assert manager._extract_version_code(dump, "com.facebook.katana") == "468616494"

