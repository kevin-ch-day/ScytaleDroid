"""Shared package-manager shell command policy for inventory-facing ADB calls."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterable

_DISABLED_USER_TOKENS = {"", "none", "off", "auto"}
_UNSUPPORTED_MARKERS = (
    "unknown option",
    "unknown argument",
    "bad argument",
    "error: unknown option",
    "error: unknown argument",
)


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


def metadata_dump_commands(package_name: str) -> list[list[str]]:
    user_id = configured_user_id()
    commands: list[list[str]] = []
    if user_id is not None:
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
    "list_packages_commands",
    "metadata_dump_commands",
    "output_indicates_unsupported",
    "path_commands",
]
