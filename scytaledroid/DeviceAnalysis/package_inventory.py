"""Package inventory helpers."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.adb import client as adb_client
from scytaledroid.DeviceAnalysis.adb import package_manager as adb_package_manager
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def list_packages(serial: str) -> list[str]:
    """Return package names via package-manager list commands."""
    for command in adb_package_manager.list_packages_commands():
        completed = adb_client.run_shell_command(serial, command, timeout=15)
        if completed.returncode != 0 or adb_package_manager.completed_indicates_unsupported(completed):
            continue
        packages: list[str] = []
        for line in completed.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("package:"):
                packages.append(stripped.split(":", 1)[1].strip())
        if packages:
            return packages
    return []


def list_packages_with_versions(
    serial: str,
    *,
    allow_fallbacks: bool = False,
) -> list[tuple[str, str | None, str | None]]:
    """Return package identifiers with portable version identity.

    ``version_code`` is the live inventory identity field. ``version_name`` is
    best-effort and may be absent from package-list output on modern Android
    builds (for example Android 15 on the attached Motorola test device).
    """

    try:
        for command in adb_package_manager.list_packages_commands("--show-versioncode"):
            candidate = adb_client.run_shell_command(serial, command, timeout=20)
            if candidate.returncode != 0 or adb_package_manager.completed_indicates_unsupported(candidate):
                continue
            parsed = _parse_package_listing(candidate.stdout)
            if parsed:
                return parsed
    except RuntimeError:
        pass

    # Fallback to basic package names if versionCode listing is unsupported.
    if not allow_fallbacks:
        log.warning(
            "Inventory fallback blocked: pm --show-versioncode unsupported.",
            category="inventory",
            extra={
                "event": "inventory.fallback_blocked",
                "reason": "pm_list_versioncode_unsupported",
                "serial": serial,
            },
        )
        raise RuntimeError(
            "Inventory fallback blocked (pm --show-versioncode unsupported). "
            "Enable inventory fallbacks in the Device Analysis menu to proceed."
        )
    log.warning(
        "Inventory fallback invoked: pm --show-versioncode unsupported; "
        "using package-only listing.",
        category="inventory",
        extra={
            "event": "inventory.fallback",
            "reason": "pm_list_versioncode_unsupported",
            "serial": serial,
        },
    )
    return [(package, None, None) for package in list_packages(serial)]


def _parse_package_listing(output: str) -> list[tuple[str, str | None, str | None]]:
    packages: list[tuple[str, str | None, str | None]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line.startswith("package:"):
            continue

        package_name: str | None = None
        version_code: str | None = None
        version_name: str | None = None

        for token in line.split():
            if token.startswith("package:"):
                package_name = token.split(":", 1)[1].strip()
                # pm list packages --show-version* can include path=package; keep only the package id.
                if "=" in package_name:
                    package_name = package_name.rsplit("=", 1)[-1].strip()
            elif token.startswith("versionCode:"):
                version_code = token.split(":", 1)[1].strip()
            elif token.startswith("versionName:"):
                version_name = token.split(":", 1)[1].strip()

        if package_name:
            cleaned = package_name.strip()
            if cleaned:
                packages.append((cleaned, version_code or None, version_name or None))

    return packages
