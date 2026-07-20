"""Mercury external storage mount helpers for operator menus."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

MERCURY_V2_LABEL = "MERCURY_DATA_V2"
MERCURY_V2_DEVICE = Path(f"/dev/disk/by-label/{MERCURY_V2_LABEL}")


def configured_mercury_mountpoint() -> Path:
    """Return the host-specific Mercury mountpoint without changing its label."""

    configured = str(os.environ.get("SCYTALEDROID_MERCURY_MOUNTPOINT", "") or "").strip()
    return Path(configured or "/mnt/MERCURY_DATA_V2").expanduser()


def configured_cold_apk_store_root() -> Path:
    """Return the optional external APK-byte store root for this host."""

    configured = str(os.environ.get("SCYTALEDROID_COLD_APK_STORE_ROOT", "") or "").strip()
    if configured:
        return Path(configured).expanduser()
    return configured_mercury_mountpoint() / "scytaledroid_artifacts" / "apk_store" / "cold"


MERCURY_V2_MOUNTPOINT = configured_mercury_mountpoint()


@dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


@dataclass(frozen=True)
class MercuryStorageStatus:
    label: str
    device_path: Path
    device_exists: bool
    mountpoint: Path
    mountpoint_exists: bool
    mountpoint_mounted: bool
    user_media_mount: Path
    user_media_mounted: bool
    compatibility_alias_exists: bool
    compatibility_alias_target: str | None


def user_media_mount(*, user: str | None = None) -> Path:
    username = (user or os.environ.get("USER") or "").strip() or "secadmin"
    return Path("/run/media") / username / MERCURY_V2_LABEL


def mercury_storage_status() -> MercuryStorageStatus:
    alias = MERCURY_V2_MOUNTPOINT / "scytaledroid_artifacts"
    alias_target: str | None = None
    if alias.is_symlink():
        try:
            alias_target = os.readlink(alias)
        except OSError:
            alias_target = None

    media_mount = user_media_mount()
    return MercuryStorageStatus(
        label=MERCURY_V2_LABEL,
        device_path=MERCURY_V2_DEVICE,
        device_exists=MERCURY_V2_DEVICE.exists(),
        mountpoint=MERCURY_V2_MOUNTPOINT,
        mountpoint_exists=MERCURY_V2_MOUNTPOINT.exists(),
        mountpoint_mounted=os.path.ismount(MERCURY_V2_MOUNTPOINT),
        user_media_mount=media_mount,
        user_media_mounted=os.path.ismount(media_mount),
        compatibility_alias_exists=alias.is_symlink(),
        compatibility_alias_target=alias_target,
    )


def run_mount_command(command: Sequence[str], *, capture: bool = False) -> CommandResult:
    """Run an operator command, inheriting stdin so sudo can prompt in the TUI."""

    argv = tuple(str(part) for part in command)
    if capture:
        proc = subprocess.run(
            argv,
            text=True,
            capture_output=True,
            check=False,
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
    else:
        proc = subprocess.run(argv, check=False)
        stdout = ""
        stderr = ""
    return CommandResult(
        command=argv,
        returncode=int(proc.returncode),
        stdout=stdout,
        stderr=stderr,
    )


def mount_mercury_v2_at_mnt() -> CommandResult:
    MERCURY_V2_MOUNTPOINT.mkdir(parents=True, exist_ok=True)
    return run_mount_command(("sudo", "mount", str(MERCURY_V2_DEVICE), str(MERCURY_V2_MOUNTPOINT)))


def unmount_mercury_v2_from_mnt() -> CommandResult:
    return run_mount_command(("sudo", "umount", str(MERCURY_V2_MOUNTPOINT)))


def mount_mercury_v2_user_session() -> CommandResult:
    return run_mount_command(("udisksctl", "mount", "-b", str(MERCURY_V2_DEVICE)))


def unmount_mercury_v2_user_session() -> CommandResult:
    return run_mount_command(("udisksctl", "unmount", "-b", str(MERCURY_V2_DEVICE)))


__all__ = [
    "CommandResult",
    "configured_cold_apk_store_root",
    "configured_mercury_mountpoint",
    "MERCURY_V2_DEVICE",
    "MERCURY_V2_LABEL",
    "MERCURY_V2_MOUNTPOINT",
    "MercuryStorageStatus",
    "mercury_storage_status",
    "mount_mercury_v2_at_mnt",
    "mount_mercury_v2_user_session",
    "run_mount_command",
    "unmount_mercury_v2_from_mnt",
    "unmount_mercury_v2_user_session",
    "user_media_mount",
]
