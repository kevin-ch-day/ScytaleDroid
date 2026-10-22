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


def test_configured_cold_apk_store_root_uses_explicit_new_host_path(monkeypatch) -> None:
    monkeypatch.setenv("SCYTALEDROID_COLD_APK_STORE_ROOT", "/srv/cold-apks")

    assert mercury_storage.configured_cold_apk_store_root() == Path("/srv/cold-apks")


def test_run_mount_command_capture() -> None:
    result = mercury_storage.run_mount_command(
        (sys.executable, "-c", "print('mounted-ok')"),
        capture=True,
    )

    assert result.ok
    assert result.command[0] == sys.executable
    assert result.stdout.strip() == "mounted-ok"
    assert result.stderr == ""


def _fake_device(tmp_path: Path, label: str = "MERCURY_DATA_V2") -> Path:
    device = tmp_path / "by-label" / label
    device.parent.mkdir(exist_ok=True)
    device.touch()
    return device


def _patch_probes(monkeypatch, *, targets=(), uuid=None) -> None:
    monkeypatch.setattr(mercury_storage, "device_mount_targets", lambda _device: tuple(Path(t) for t in targets))
    monkeypatch.setattr(mercury_storage, "device_filesystem_uuid", lambda _device: uuid)


def test_mercury_storage_status_reports_mount_and_alias(
    monkeypatch,
    tmp_path: Path,
) -> None:
    mountpoint = tmp_path / "MERCURY_DATA_V2"
    mountpoint.mkdir()
    alias_target = tmp_path / "media" / "MERCURY_DATA_V2" / "scytaledroid_artifacts"
    alias_target.mkdir(parents=True)
    (mountpoint / "scytaledroid_artifacts").symlink_to(alias_target)
    device = _fake_device(tmp_path)

    monkeypatch.setenv("SCYTALEDROID_MERCURY_MOUNTPOINT", str(mountpoint))
    monkeypatch.setattr(mercury_storage, "configured_mercury_device", lambda: device)
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
    _patch_probes(monkeypatch, targets=(mountpoint,))

    status = mercury_storage.mercury_storage_status()

    assert status.device_exists is True
    assert status.mountpoint_exists is True
    assert status.mountpoint_mounted is True
    assert status.user_media_mounted is True
    assert status.compatibility_alias_exists is True
    assert status.compatibility_alias_target == str(alias_target)
    assert status.mounted_elsewhere == ()


def test_label_and_uuid_settings_are_read_at_call_time(monkeypatch) -> None:
    monkeypatch.delenv("SCYTALEDROID_MERCURY_LABEL", raising=False)
    monkeypatch.delenv("SCYTALEDROID_MERCURY_UUID", raising=False)
    assert mercury_storage.configured_mercury_label() == "MERCURY_DATA_V2"
    assert mercury_storage.configured_mercury_uuid() is None

    monkeypatch.setenv("SCYTALEDROID_MERCURY_LABEL", "MERCURY_DATA")
    monkeypatch.setenv("SCYTALEDROID_MERCURY_UUID", " ABC-123 ")
    assert mercury_storage.configured_mercury_device() == Path("/dev/disk/by-label/MERCURY_DATA")
    assert mercury_storage.configured_mercury_uuid() == "abc-123"
    assert mercury_storage.user_media_mount(user="analyst") == Path("/run/media/analyst/MERCURY_DATA")


def test_mountpoint_default_stays_v2_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("SCYTALEDROID_MERCURY_MOUNTPOINT", raising=False)
    assert mercury_storage.configured_mercury_mountpoint() == Path("/mnt/MERCURY_DATA_V2")


def test_device_mount_targets_parses_findmnt_and_escapes(monkeypatch) -> None:
    calls = []

    def fake_run(command, *, capture=False):
        calls.append(tuple(command))
        return mercury_storage.CommandResult(tuple(command), 0, "/mnt/MERCURY_DATA\n/mnt/with\\x20space\n", "")

    monkeypatch.setattr(mercury_storage, "run_mount_command", fake_run)

    targets = mercury_storage.device_mount_targets(Path("/dev/sdb1"))

    assert calls == [("findmnt", "-rn", "-o", "TARGET", "-S", "/dev/sdb1")]
    assert targets == (Path("/mnt/MERCURY_DATA"), Path("/mnt/with space"))


def test_device_mount_targets_empty_when_not_mounted(monkeypatch) -> None:
    monkeypatch.setattr(
        mercury_storage,
        "run_mount_command",
        lambda command, *, capture=False: mercury_storage.CommandResult(tuple(command), 1, "", ""),
    )
    assert mercury_storage.device_mount_targets(Path("/dev/sdb1")) == ()


def test_status_detects_device_mounted_elsewhere(monkeypatch, tmp_path: Path) -> None:
    device = _fake_device(tmp_path)
    preferred = tmp_path / "MERCURY_DATA_V2"
    monkeypatch.setenv("SCYTALEDROID_MERCURY_MOUNTPOINT", str(preferred))
    monkeypatch.setattr(mercury_storage, "configured_mercury_device", lambda: device)
    monkeypatch.setattr(mercury_storage.os.path, "ismount", lambda _path: False)
    _patch_probes(monkeypatch, targets=("/mnt/MERCURY_DATA",))

    status = mercury_storage.mercury_storage_status()

    assert status.mountpoint_mounted is False
    assert status.mounted_elsewhere == (Path("/mnt/MERCURY_DATA"),)


def test_status_flags_uuid_mismatch_only_when_configured(monkeypatch, tmp_path: Path) -> None:
    device = _fake_device(tmp_path)
    monkeypatch.setattr(mercury_storage, "configured_mercury_device", lambda: device)
    monkeypatch.setattr(mercury_storage.os.path, "ismount", lambda _path: False)
    _patch_probes(monkeypatch, uuid="other-uuid")

    monkeypatch.delenv("SCYTALEDROID_MERCURY_UUID", raising=False)
    assert mercury_storage.mercury_storage_status().uuid_mismatch is False

    monkeypatch.setenv("SCYTALEDROID_MERCURY_UUID", "expected-uuid")
    status = mercury_storage.mercury_storage_status()
    assert status.uuid_mismatch is True
    assert status.device_uuid == "other-uuid"

    _patch_probes(monkeypatch, uuid="expected-uuid")
    assert mercury_storage.mercury_storage_status().uuid_mismatch is False


def _record_commands(monkeypatch, *, fail_on: str | None = None) -> list[tuple[str, ...]]:
    calls: list[tuple[str, ...]] = []

    def fake_run(command, *, capture=False):
        argv = tuple(command)
        calls.append(argv)
        code = 1 if fail_on and fail_on in argv else 0
        return mercury_storage.CommandResult(argv, code, "", "")

    monkeypatch.setattr(mercury_storage, "run_mount_command", fake_run)
    return calls


def test_mount_creates_missing_mountpoint_through_sudo(monkeypatch, tmp_path: Path) -> None:
    mountpoint = tmp_path / "not-yet"
    monkeypatch.setenv("SCYTALEDROID_MERCURY_MOUNTPOINT", str(mountpoint))
    monkeypatch.setenv("SCYTALEDROID_MERCURY_LABEL", "MERCURY_DATA")
    calls = _record_commands(monkeypatch)

    result = mercury_storage.mount_mercury_v2_at_mnt()

    assert result.ok
    assert calls == [
        ("sudo", "mkdir", "-p", "--", str(mountpoint)),
        ("sudo", "mount", "/dev/disk/by-label/MERCURY_DATA", str(mountpoint)),
    ]
    assert not mountpoint.exists()  # no unprivileged mkdir


def test_mount_skips_mkdir_when_mountpoint_exists(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SCYTALEDROID_MERCURY_MOUNTPOINT", str(tmp_path))
    calls = _record_commands(monkeypatch)

    mercury_storage.mount_mercury_v2_at_mnt()

    assert [c[1] for c in calls] == ["mount"]


def test_mount_stops_when_sudo_mkdir_fails(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SCYTALEDROID_MERCURY_MOUNTPOINT", str(tmp_path / "missing"))
    calls = _record_commands(monkeypatch, fail_on="mkdir")

    result = mercury_storage.mount_mercury_v2_at_mnt()

    assert not result.ok
    assert result.command[1] == "mkdir"
    assert len(calls) == 1


def test_run_mount_command_reports_missing_executable() -> None:
    result = mercury_storage.run_mount_command(("scytaledroid-no-such-binary",), capture=True)

    assert result.returncode == 127
    assert "could not run scytaledroid-no-such-binary" in result.stderr


def _menu_status(**overrides) -> mercury_storage.MercuryStorageStatus:
    values = dict(
        label="MERCURY_DATA_V2",
        device_path=Path("/dev/disk/by-label/MERCURY_DATA_V2"),
        device_exists=True,
        mountpoint=Path("/mnt/MERCURY_DATA_V2"),
        mountpoint_exists=False,
        mountpoint_mounted=False,
        user_media_mount=Path("/run/media/analyst/MERCURY_DATA_V2"),
        user_media_mounted=False,
        compatibility_alias_exists=False,
        compatibility_alias_target=None,
    )
    values.update(overrides)
    return mercury_storage.MercuryStorageStatus(**values)


def test_menu_refuses_second_mount_and_hides_option(monkeypatch) -> None:
    status = _menu_status(device_mount_targets=(Path("/mnt/MERCURY_DATA"),))

    refusal = workspace_maintenance_menu._mercury_mount_refusal(status)
    keys = [item.key for item in workspace_maintenance_menu._mercury_menu_items(status)]

    assert refusal is not None and "already mounted at /mnt/MERCURY_DATA" in refusal
    assert "SCYTALEDROID_MERCURY_MOUNTPOINT=/mnt/MERCURY_DATA" in refusal
    assert "2" not in keys

    monkeypatch.setattr(workspace_maintenance_menu.mercury_storage, "mercury_storage_status", lambda: status)
    monkeypatch.setattr(workspace_maintenance_menu.prompt_utils, "press_enter_to_continue", lambda *a, **k: None)
    monkeypatch.setattr(
        workspace_maintenance_menu.mercury_storage,
        "mount_mercury_v2_at_mnt",
        lambda: (_ for _ in ()).throw(AssertionError("must not mount")),
    )
    workspace_maintenance_menu._mount_mercury_preferred()


def test_menu_refuses_uuid_mismatch_and_allows_clean_mount() -> None:
    mismatch = _menu_status(expected_uuid="want", device_uuid="got")
    assert "expected want" in (workspace_maintenance_menu._mercury_mount_refusal(mismatch) or "")

    clean = _menu_status()
    assert workspace_maintenance_menu._mercury_mount_refusal(clean) is None
    assert "2" in [item.key for item in workspace_maintenance_menu._mercury_menu_items(clean)]


def test_menu_action_errors_become_messages(monkeypatch, capsys) -> None:
    monkeypatch.setattr(workspace_maintenance_menu.prompt_utils, "press_enter_to_continue", lambda *a, **k: None)

    def boom() -> None:
        raise PermissionError(13, "Permission denied", "/mnt/MERCURY_DATA_V2")

    workspace_maintenance_menu._run_mercury_action(boom)

    assert "Mercury storage action failed" in capsys.readouterr().out


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
