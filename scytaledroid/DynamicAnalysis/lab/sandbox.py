"""Rootless, network-disconnected launcher for the pinned benign fixture only."""

from __future__ import annotations

import hashlib
from pathlib import Path

FIXTURE_PACKAGE = "org.scytaledroid.labfixture"
FIXTURE_SHA256 = "f9d7ffa39c5eaa8ca36bd32b41230946d12ed58651e5b048bab675e502206dbd"
BACKEND = "android_emulator_kvm_bwrap_benign_v1"
NETWORK_PROFILE = "private_netns_no_external_interface_v1"


def verify_fixture(apk: Path) -> str:
    """Refuse every APK except this reviewed, locally built benign fixture."""
    with Path(apk).open("rb") as stream:
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
    if sha != FIXTURE_SHA256:
        raise ValueError("Only the pinned benign acceptance APK is authorized")
    return sha


def sandbox_command(*, sdk: Path, workspace: Path, fixture: Path, guest_script: Path) -> list[str]:
    """Expose only tools, KVM, one fixture and a fresh per-run workspace.

    No caller-supplied command, serial, network flag or extra mount is accepted.
    The host HOME, USB, database sockets and host ADB are never mounted.
    """
    verify_fixture(fixture)
    sdk, workspace, fixture, guest_script = [
        Path(p).resolve(strict=True) for p in (sdk, workspace, fixture, guest_script)
    ]
    if (
        not sdk.is_dir()
        or not workspace.is_dir()
        or sdk == workspace
        or sdk in workspace.parents
        or workspace in sdk.parents
    ):
        raise ValueError("SDK and workspace must be separate directories")
    if not (sdk / "emulator/emulator").is_file() or not (sdk / "platform-tools/adb").is_file():
        raise ValueError("Dedicated SDK is incomplete")
    if workspace == Path.home() or workspace == Path("/"):
        raise ValueError("Refusing broad workspace mount")
    return [
        "/usr/bin/bwrap",
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/bin",
        "/bin",
        "--ro-bind",
        "/etc/ld.so.cache",
        "/etc/ld.so.cache",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--dev-bind",
        "/dev/kvm",
        "/dev/kvm",
        "--tmpfs",
        "/tmp",
        "--ro-bind",
        str(sdk),
        "/sdk",
        "--bind",
        str(workspace),
        "/work",
        "--ro-bind",
        str(fixture),
        "/fixture.apk",
        "--ro-bind",
        str(guest_script),
        "/runner.py",
        "--setenv",
        "PATH",
        "/usr/bin:/sdk/platform-tools",
        "--setenv",
        "HOME",
        "/work/home",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "ANDROID_SDK_ROOT",
        "/sdk",
        "--setenv",
        "ANDROID_HOME",
        "/sdk",
        "--setenv",
        "ANDROID_AVD_HOME",
        "/work/avds",
        "--setenv",
        "ANDROID_USER_HOME",
        "/work/home/.android",
        "--setenv",
        "ANDROID_ADB_SERVER_PORT",
        "5038",
        "--setenv",
        "ADB_SERVER_SOCKET",
        "localfilesystem:/work/adb-server.sock",
        "--chdir",
        "/work",
        "/usr/bin/python3",
        "/runner.py",
    ]
