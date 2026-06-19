"""Shared package-manager shell command policy for inventory-facing ADB calls."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterable
from collections.abc import Sequence
from typing import TypeVar

from scytaledroid.DeviceAnalysis.adb import cache as adb_cache

_DISABLED_USER_TOKENS = {"", "none", "off", "auto"}
_UNSUPPORTED_MARKERS = (
    "unknown option",
    "unknown argument",
    "bad argument",
    "error: unknown option",
    "error: unknown argument",
)
_DUMPSYS_PACKAGE_USER_SUPPORT_CACHE_KEY = "__capability:dumpsys_package_user__"
_T = TypeVar("_T")


def configured_user_id() -> str | None:
    """Return the configured Android user id for package-manager calls.

    The default is user ``0`` for analyst-owned physical devices. Set
    ``SCYTALEDROID_ADB_PACKAGE_USER_ID=none`` to omit explicit ``--user``.
    """

    raw = os.getenv("SCYTALEDROID_ADB_PACKAGE_USER_ID", "0").strip()
    if raw.lower() in _DISABLED_USER_TOKENS:
        return None
    return raw


def list_packages_commands(*args: str) -> list[list[str]]:
    user_id = configured_user_id()
    commands: list[list[str]] = []
    for prefix in (["cmd", "package", "list", "packages"], ["pm", "list", "packages"]):
        if user_id is not None:
            commands.append([*prefix, *args, "--user", user_id])
        commands.append([*prefix, *args])
    return _dedupe_commands(commands)


def path_commands(package_name: str) -> list[list[str]]:
    user_id = configured_user_id()
    commands: list[list[str]] = []
    for prefix in (["cmd", "package", "path"], ["pm", "path"]):
        if user_id is not None:
            commands.append([*prefix, "--user", user_id, package_name])
        commands.append([*prefix, package_name])
    return _dedupe_commands(commands)


def metadata_dump_commands(
    package_name: str,
    *,
    user_scoped_supported: bool | None = None,
) -> list[list[str]]:
    user_id = configured_user_id()
    commands: list[list[str]] = []
    if user_id is not None and user_scoped_supported is not False:
        commands.append(["dumpsys", "package", "--user", user_id, package_name])
    commands.append(["dumpsys", "package", package_name])
    commands.append(["cmd", "package", "dump-package", package_name])
    commands.append(["pm", "dump", package_name])
    return _dedupe_commands(commands)


def output_indicates_unsupported(text: str | None) -> bool:
    haystack = str(text or "").strip().lower()
    return any(marker in haystack for marker in _UNSUPPORTED_MARKERS)


def completed_indicates_unsupported(completed: subprocess.CompletedProcess[str] | None) -> bool:
    if completed is None:
        return True
    stdout = getattr(completed, "stdout", "")
    stderr = getattr(completed, "stderr", "")
    if completed.returncode == 0:
        return output_indicates_unsupported(stdout) or output_indicates_unsupported(stderr)
    stderr = str(stderr or "").strip()
    stdout = str(stdout or "").strip()
    return output_indicates_unsupported(stderr) or output_indicates_unsupported(stdout)


def is_user_scoped_dumpsys_package_command(command: Sequence[str]) -> bool:
    tokens = list(command)
    return len(tokens) >= 5 and tokens[:2] == ["dumpsys", "package"] and "--user" in tokens


def output_looks_package_specific(text: str | None, package_name: str) -> bool:
    haystack = str(text or "")
    if not haystack.strip():
        return False
    lowered = haystack.lower()
    package_name = str(package_name or "").strip()
    if package_name and f"Package [{package_name}]" in haystack:
        return True
    markers = (
        "packageName=",
        "versionCode=",
        "versionName=",
        "firstInstallTime=",
        "lastUpdateTime=",
        "installerPackageName=",
    )
    if any(marker in haystack for marker in markers):
        return True
    return "sha-256" in lowered or "signer" in lowered or "signatures=" in lowered


def dumpsys_package_user_support_cache_key() -> str:
    return _DUMPSYS_PACKAGE_USER_SUPPORT_CACHE_KEY


def read_supported_metadata_dump(
    serial: str,
    package_name: str,
    *,
    run_command,
    is_successful,
    extract_text,
    is_unsupported=None,
    accept_text=None,
) -> tuple[_T | None, Sequence[str] | None]:
    """Return the first acceptable package dump and cache user-scoped support.

    ``accept_text`` can reject a successful command while still allowing later
    fallbacks such as ``cmd package dump-package`` or ``pm dump``.
    """

    last_supported: tuple[_T, Sequence[str]] | None = None
    user_scoped_supported = adb_cache.PACKAGE_COMMAND_SUPPORT_CACHE.get(
        (serial, dumpsys_package_user_support_cache_key())
    )
    for command in metadata_dump_commands(
        package_name,
        user_scoped_supported=user_scoped_supported,
    ):
        try:
            result = run_command(command)
        except RuntimeError:
            continue
        if not is_successful(result):
            continue
        text = extract_text(result)
        unsupported = is_unsupported(result) if is_unsupported is not None else output_indicates_unsupported(text)
        if unsupported:
            if is_user_scoped_dumpsys_package_command(command):
                adb_cache.PACKAGE_COMMAND_SUPPORT_CACHE.set(
                    (serial, dumpsys_package_user_support_cache_key()),
                    False,
                )
            continue
        if is_user_scoped_dumpsys_package_command(command):
            adb_cache.PACKAGE_COMMAND_SUPPORT_CACHE.set(
                (serial, dumpsys_package_user_support_cache_key()),
                True,
            )
        last_supported = (result, command)
        if accept_text is None or accept_text(text):
            return result, command
    if last_supported is not None:
        return last_supported
    return None, None


def _dedupe_commands(commands: Iterable[list[str]]) -> list[list[str]]:
    seen: set[tuple[str, ...]] = set()
    unique: list[list[str]] = []
    for command in commands:
        key = tuple(command)
        if key in seen:
            continue
        seen.add(key)
        unique.append(command)
    return unique


__all__ = [
    "completed_indicates_unsupported",
    "configured_user_id",
    "dumpsys_package_user_support_cache_key",
    "is_user_scoped_dumpsys_package_command",
    "list_packages_commands",
    "metadata_dump_commands",
    "output_indicates_unsupported",
    "output_looks_package_specific",
    "path_commands",
    "read_supported_metadata_dump",
]
