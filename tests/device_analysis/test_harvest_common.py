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


def test_adb_pull_returns_path_stale_error_for_stale_remote_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scytaledroid.DeviceAnalysis.harvest import common
    from scytaledroid.DeviceAnalysis.harvest.models import ArtifactError

    dest = tmp_path / "base.apk"

    monkeypatch.setattr(
        common.adb_client,
        "run_adb_command",
        lambda *_args, **_kwargs: _Completed(
            returncode=1,
            stderr="failed to stat remote object '/data/app/base.apk': No such file or directory",
        ),
    )

    result = common.adb_pull(
        adb_path="adb",
        serial="SERIAL",
        source_path="/data/app/base.apk",
        dest_path=dest,
        package_name="pkg",
        verbose=False,
        overwrite_existing=False,
    )

    assert isinstance(result, ArtifactError)
    assert result.reason == "path_stale"


def test_iter_harvest_package_manifest_paths_sorted_and_skips_missing(tmp_path: Path) -> None:
    from scytaledroid.DeviceAnalysis.harvest import common

    assert common.iter_harvest_package_manifest_paths(tmp_path / "nope") == []

    d1 = tmp_path / "a" / "x"
    d2 = tmp_path / "b"
    d1.mkdir(parents=True)
    d2.mkdir(parents=True)
    (d1 / "harvest_package_manifest.json").write_text("{}", encoding="utf-8")
    (d2 / "harvest_package_manifest.json").write_text("{}", encoding="utf-8")

    paths = common.iter_harvest_package_manifest_paths(tmp_path)
    assert len(paths) == 2
    assert paths[0].name == "harvest_package_manifest.json"
    assert paths[0].as_posix() < paths[1].as_posix()
