from __future__ import annotations

import sys
from pathlib import Path

from scytaledroid.Utils.System import mercury_storage, workspace_maintenance_menu


def test_user_media_mount_uses_requested_user() -> None:
    assert mercury_storage.user_media_mount(user="analyst") == Path(
        "/run/media/analyst/MERCURY_DATA_V2"
    )


def test_configured_mercury_mountpoint_accepts_new_host_path(monkeypatch) -> None:
    monkeypatch.setenv("SCYTALEDROID_MERCURY_MOUNTPOINT", "/srv/scytaledroid-mercury")

    assert mercury_storage.configured_mercury_mountpoint() == Path("/srv/scytaledroid-mercury")


def test_run_mount_command_capture() -> None:
    result = mercury_storage.run_mount_command(
        (sys.executable, "-c", "print('mounted-ok')"),
        capture=True,
    )

    assert result.ok
    assert result.command[0] == sys.executable
    assert result.stdout.strip() == "mounted-ok"
    assert result.stderr == ""


def test_mercury_storage_status_reports_mount_and_alias(
    monkeypatch,
    tmp_path: Path,
) -> None:
    mountpoint = tmp_path / "MERCURY_DATA_V2"
    mountpoint.mkdir()
    alias_target = tmp_path / "media" / "MERCURY_DATA_V2" / "scytaledroid_artifacts"
    alias_target.mkdir(parents=True)
    (mountpoint / "scytaledroid_artifacts").symlink_to(alias_target)
    device = tmp_path / "by-label" / "MERCURY_DATA_V2"
    device.parent.mkdir()
    device.touch()

    monkeypatch.setattr(mercury_storage, "MERCURY_V2_DEVICE", device)
    monkeypatch.setattr(mercury_storage, "MERCURY_V2_MOUNTPOINT", mountpoint)
    monkeypatch.setattr(
        mercury_storage,
        "user_media_mount",
        lambda: tmp_path / "media" / "MERCURY_DATA_V2",
    )
    monkeypatch.setattr(
        mercury_storage.os.path,
        "ismount",
        lambda path: Path(path) in {mountpoint, tmp_path / "media" / "MERCURY_DATA_V2"},
    )

    status = mercury_storage.mercury_storage_status()

    assert status.device_exists is True
    assert status.mountpoint_exists is True
    assert status.mountpoint_mounted is True
    assert status.user_media_mounted is True
    assert status.compatibility_alias_exists is True
    assert status.compatibility_alias_target == str(alias_target)


def test_quick_checker_sha_skipped_only_status_is_success() -> None:
    level, message = workspace_maintenance_menu._mercury_checker_status_line(
        {
            "status": "WARN",
            "findings": ["Canonical SHA-256 byte verification was skipped."],
        },
        verify_sha256=False,
    )

    assert level == "success"
    assert message == "Quick APK store checker status: OK (SHA-256 skipped)"


def test_checker_blocked_status_stays_blocked() -> None:
    level, message = workspace_maintenance_menu._mercury_checker_status_line(
        {
            "status": "BLOCKED",
            "findings": ["Canonical APK store contains broken APK symlinks."],
        },
        verify_sha256=False,
    )

    assert level == "blocked"
    assert message == "Quick APK store checker status: BLOCKED"


def test_workspace_dynamic_index_root_uses_canonical_data_root(monkeypatch, tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    output_root = tmp_path / "output"
    monkeypatch.setattr(workspace_maintenance_menu.app_config, "DATA_DIR", str(data_root))
    monkeypatch.setattr(workspace_maintenance_menu.app_config, "OUTPUT_DIR", str(output_root))
    monkeypatch.setattr(workspace_maintenance_menu.app_config, "DYNAMIC_EVIDENCE_ROOT", "data/evidence/dynamic")

    assert workspace_maintenance_menu._dynamic_evidence_index_root() == data_root / "evidence" / "dynamic"
