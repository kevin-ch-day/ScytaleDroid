"""Package inventory helpers."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis import adb_client
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def list_packages(serial: str) -> list[str]:
    """Return package names via ``pm list packages``."""
    completed = adb_client.run_shell_command(serial, ["pm", "list", "packages"], timeout=15)
    if completed.returncode != 0:
        return []

    packages: list[str] = []
    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("package:"):
            packages.append(stripped.split(":", 1)[1].strip())
    return packages


def list_packages_with_versions(
    serial: str,
    *,
    allow_fallbacks: bool = False,
) -> list[tuple[str, str | None, str | None]]:
    """Return package identifiers along with version metadata when available."""

    attempts = [
        ["pm", "list", "packages", "--show-versioncode", "--show-versionname"],
        ["pm", "list", "packages", "--show-versioncode"],
    ]

    for command in attempts:
        try:
            completed = adb_client.run_shell_command(serial, command, timeout=20)
        except RuntimeError:
            continue

        if completed.returncode != 0:
            continue

        parsed = _parse_package_listing(completed.stdout)
        if parsed:
            return parsed

    # Fallback to basic package names if newer flags are unsupported.
    if not allow_fallbacks:
        log.warning(
            "Inventory fallback blocked: pm --show-version* unsupported.",
            category="inventory",
            extra={
                "event": "inventory.fallback_blocked",
                "reason": "pm_list_versions_unsupported",
                "serial": serial,
            },
        )
        raise RuntimeError(
            "Inventory fallback blocked (pm --show-version* unsupported). "
            "Enable inventory fallbacks in the Device Analysis menu to proceed."
        )
    log.warning(
        "Inventory fallback invoked: pm --show-version* unsupported; "
        "using package-only listing.",
        category="inventory",
        extra={
            "event": "inventory.fallback",
            "reason": "pm_list_versions_unsupported",
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
            packages.append((package_name, version_code or None, version_name or None))

    return packages