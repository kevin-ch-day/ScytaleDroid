from __future__ import annotations

from pathlib import Path

import pytest


class _Completed:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_adb_pull_skips_when_dest_exists_and_no_overwrite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from scytaledroid.DeviceAnalysis.harvest import common

    dest = tmp_path / "base.apk"
    dest.write_bytes(b"old")

    called = {"count": 0}

    def _fake_run(*args, **kwargs):
        called["count"] += 1
        return _Completed(returncode=0)

    monkeypatch.setattr(common.adb_client, "run_adb_command", _fake_run)

    ok = common.adb_pull(
        adb_path="adb",
        serial="SERIAL",
        source_path="/data/app/base.apk",
        dest_path=dest,
        package_name="pkg",
        verbose=False,
        overwrite_existing=False,
    )
    assert ok is True
    assert called["count"] == 0
    assert dest.read_bytes() == b"old"


def test_adb_pull_overwrites_when_requested(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from scytaledroid.DeviceAnalysis.harvest import common

    dest = tmp_path / "base.apk"
    dest.write_bytes(b"old")

    called = {"count": 0}

    def _fake_run(args, **kwargs):
        # args is command without adb binary (see runner)
        called["count"] += 1
        # simulate adb pull writing the file
        # last arg is the destination path
        Path(args[-1]).write_bytes(b"new")
        return _Completed(returncode=0)

    monkeypatch.setattr(common.adb_client, "run_adb_command", _fake_run)

    ok = common.adb_pull(
        adb_path="adb",
        serial="SERIAL",
        source_path="/data/app/base.apk",
        dest_path=dest,
        package_name="pkg",
        verbose=False,
        overwrite_existing=True,
    )
    assert ok is True
    assert called["count"] == 1
    assert dest.read_bytes() == b"new"

