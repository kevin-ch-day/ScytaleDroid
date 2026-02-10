"""Package metadata helpers."""

from __future__ import annotations

import re

from scytaledroid.DeviceAnalysis.adb import cache as adb_cache
from scytaledroid.DeviceAnalysis.adb import client as adb_client
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def get_package_paths(
    serial: str,
    package_name: str,
    refresh: bool = False,
    *,
    allow_fallbacks: bool = False,
) -> list[str]:
    """Return canonical APK paths for a package using ``pm path``."""
    cache_key = (serial, package_name)
    if not refresh:
        cached = adb_cache.PACKAGE_PATH_CACHE.get(cache_key)
        if cached is not None:
            return cached

    paths: list[str] = []
    completed = adb_client.run_shell_command(serial, ["pm", "path", package_name], timeout=15)
    if completed.returncode == 0:
        for line in completed.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("package:"):
                paths.append(stripped.split(":", 1)[1].strip())

    if not paths:
        if not allow_fallbacks:
            log.warning(
                "Inventory fallback blocked: pm path returned no entries.",
                category="inventory",
                extra={
                    "event": "inventory.fallback_blocked",
                    "reason": "pm_path_empty",
                    "serial": serial,
                    "package": package_name,
                },
            )
            raise RuntimeError(
                "Inventory fallback blocked (pm path empty). "
                "Enable inventory fallbacks in the Device Analysis menu to proceed."
            )
        log.warning(
            "Inventory fallback invoked: pm path returned no entries; "
            "using pm list packages -f.",
            category="inventory",
            extra={
                "event": "inventory.fallback",
                "reason": "pm_path_empty",
                "serial": serial,
                "package": package_name,
            },
        )
        fallback = adb_client.run_shell_command(
            serial,
            ["pm", "list", "packages", "-f", package_name],
            timeout=15,
        )
        if fallback.returncode == 0:
            for line in fallback.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("package:") and "=" in stripped:
                    apk_path, _ = stripped.removeprefix("package:").rsplit("=", 1)
                    paths.append(apk_path.strip())

    adb_cache.PACKAGE_PATH_CACHE.set(cache_key, paths)
    return paths


def get_package_metadata(
    serial: str,
    package_name: str,
    refresh: bool = False,
) -> dict[str, str | None]:
    """Return metadata for a package via ``pm dump`` (cached)."""
    cache_key = (serial, package_name)
    if not refresh:
        cached = adb_cache.PACKAGE_META_CACHE.get(cache_key)
        if cached is not None:
            return cached

    try:
        completed = adb_client.run_shell_command(serial, ["pm", "dump", package_name], timeout=25)
    except RuntimeError:
        return {}

    if completed.returncode != 0:
        return {}

    metadata: dict[str, str | None] = {"package_name": package_name}
    version_code_pattern = re.compile(r"versionCode=(\d+)")
    version_name_pattern = re.compile(r"versionName=([^\s]+)")

    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("application-label:"):
            metadata["app_label"] = stripped.split(":", 1)[1].strip().strip("'")
        elif stripped.startswith("application-label-") and "app_label" not in metadata:
            metadata["app_label"] = stripped.split(":", 1)[1].strip().strip("'")
        elif stripped.startswith("packageName="):
            metadata["package_name"] = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("userId="):
            metadata["user_id"] = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("firstInstallTime="):
            metadata["first_install"] = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("lastUpdateTime="):
            metadata["last_update"] = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("installerPackageName="):
            metadata["installer"] = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("versionCode="):
            match = version_code_pattern.search(stripped)
            if match:
                metadata["version_code"] = match.group(1)
        elif stripped.startswith("versionName="):
            match = version_name_pattern.search(stripped)
            if match:
                metadata["version_name"] = match.group(1)

    adb_cache.PACKAGE_META_CACHE.set(cache_key, metadata)
    return metadata
