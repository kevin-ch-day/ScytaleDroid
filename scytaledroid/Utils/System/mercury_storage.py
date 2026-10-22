"""Mercury external storage mount helpers for operator menus."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

MERCURY_V2_LABEL = "MERCURY_DATA_V2"
MERCURY_V2_DEVICE = Path(f"/dev/disk/by-label/{MERCURY_V2_LABEL}")
_DEFAULT_MERCURY_MOUNTPOINT = "/mnt/MERCURY_DATA_V2"


def _setting(name: str) -> str:
    return str(os.environ.get(name, "") or "").strip()


def configured_mercury_label() -> str:
    """Return the filesystem label used to find the Mercury disk."""

    return _setting("SCYTALEDROID_MERCURY_LABEL") or MERCURY_V2_LABEL


def configured_mercury_uuid() -> str | None:
    """Return the optional filesystem UUID the labelled Mercury disk must carry."""

    return _setting("SCYTALEDROID_MERCURY_UUID").lower() or None


def configured_mercury_device() -> Path:
    return Path("/dev/disk/by-label") / configured_mercury_label()


def configured_mercury_mountpoint() -> Path:
    """Return the host-specific Mercury mountpoint without changing its label."""

    return Path(_setting("SCYTALEDROID_MERCURY_MOUNTPOINT") or _DEFAULT_MERCURY_MOUNTPOINT).expanduser()


def configured_cold_apk_store_root() -> Path:
    """Return the optional external APK-byte store root for this host."""

    configured = _setting("SCYTALEDROID_COLD_APK_STORE_ROOT")
    if configured:
        return Path(configured).expanduser()
    return configured_mercury_mountpoint() / "scytaledroid_artifacts" / "apk_store" / "cold"


# Import-time snapshot kept for callers that read the constant; prefer the
# configured_* functions, which honour settings changed after import.
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
    device_mount_targets: tuple[Path, ...] = ()
    device_uuid: str | None = None
    expected_uuid: str | None = None

    @property
    def uuid_mismatch(self) -> bool:
        return bool(self.expected_uuid and self.device_exists and self.device_uuid != self.expected_uuid)

    @property
    def mounted_elsewhere(self) -> tuple[Path, ...]:
        """Mounts of the labelled device other than the preferred or user-session paths."""

        skip = {self.mountpoint, self.user_media_mount}
        return tuple(target for target in self.device_mount_targets if target not in skip)


def user_media_mount(*, user: str | None = None) -> Path:
    username = (user or os.environ.get("USER") or "").strip() or "secadmin"
    return Path("/run/media") / username / configured_mercury_label()


def run_mount_command(command: Sequence[str], *, capture: bool = False) -> CommandResult:
    """Run an operator command, inheriting stdin so sudo can prompt in the TUI."""

    argv = tuple(str(part) for part in command)
    try:
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
    except OSError as exc:
        return CommandResult(command=argv, returncode=127, stdout="", stderr=f"could not run {argv[0]}: {exc}")
    return CommandResult(
        command=argv,
        returncode=int(proc.returncode),
        stdout=stdout,
        stderr=stderr,
    )


def device_mount_targets(device: Path) -> tuple[Path, ...]:
    """Return every path where ``device`` is currently mounted (empty when unknown)."""

    result = run_mount_command(("findmnt", "-rn", "-o", "TARGET", "-S", str(device)), capture=True)
    if not result.ok:
        return ()
    targets = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line:
            # findmnt -r escapes whitespace as \x20.
            targets.append(Path(re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), line)))
    return tuple(targets)


def device_filesystem_uuid(device: Path) -> str | None:
    result = run_mount_command(("lsblk", "-dno", "UUID", str(device)), capture=True)
    value = result.stdout.strip().lower() if result.ok else ""
    return value or None


def mercury_storage_status() -> MercuryStorageStatus:
    mountpoint = configured_mercury_mountpoint()
    device = configured_mercury_device()
    alias = mountpoint / "scytaledroid_artifacts"
    alias_target: str | None = None
    if alias.is_symlink():
        try:
            alias_target = os.readlink(alias)
        except OSError:
            alias_target = None

    device_exists = device.exists()
    resolved_device = Path(os.path.realpath(device)) if device_exists else device
    expected_uuid = configured_mercury_uuid()
    media_mount = user_media_mount()
    return MercuryStorageStatus(
        label=configured_mercury_label(),
        device_path=device,
        device_exists=device_exists,
        mountpoint=mountpoint,
        mountpoint_exists=mountpoint.exists(),
        mountpoint_mounted=os.path.ismount(mountpoint),
        user_media_mount=media_mount,
        user_media_mounted=os.path.ismount(media_mount),
        compatibility_alias_exists=alias.is_symlink(),
        compatibility_alias_target=alias_target,
        device_mount_targets=device_mount_targets(resolved_device) if device_exists else (),
        device_uuid=device_filesystem_uuid(resolved_device) if device_exists and expected_uuid else None,
        expected_uuid=expected_uuid,
    )


def mount_mercury_v2_at_mnt() -> CommandResult:
    """Create the mountpoint through sudo when missing, then mount the labelled device."""

    mountpoint = configured_mercury_mountpoint()
    if not mountpoint.exists():
        created = run_mount_command(("sudo", "mkdir", "-p", "--", str(mountpoint)))
        if not created.ok:
            return created
    return run_mount_command(("sudo", "mount", str(configured_mercury_device()), str(mountpoint)))


def unmount_mercury_v2_from_mnt() -> CommandResult:
    return run_mount_command(("sudo", "umount", str(configured_mercury_mountpoint())))


def mount_mercury_v2_user_session() -> CommandResult:
    return run_mount_command(("udisksctl", "mount", "-b", str(configured_mercury_device())))


def unmount_mercury_v2_user_session() -> CommandResult:
    return run_mount_command(("udisksctl", "unmount", "-b", str(configured_mercury_device())))


__all__ = [
    "CommandResult",
    "configured_cold_apk_store_root",
    "configured_mercury_device",
    "configured_mercury_label",
    "configured_mercury_mountpoint",
    "configured_mercury_uuid",
    "device_filesystem_uuid",
    "device_mount_targets",
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
