"""Package metadata helpers."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.adb import cache as adb_cache
from scytaledroid.DeviceAnalysis.adb import client as adb_client
from scytaledroid.DeviceAnalysis.adb import package_manager as adb_package_manager
from scytaledroid.DeviceAnalysis.identity import compute_signer_set_hash, extract_signer_digests
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def _normalize_optional_text(value: str | None) -> str | None:
    text = str(value or "").strip()
    if not text or text.lower() in {"null", "none"}:
        return None
    return text


def _parse_package_metadata_output(
    package_name: str,
    output: str,
) -> dict[str, str | None]:
    metadata: dict[str, str | None] = {"package_name": package_name}
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("application-label:"):
            metadata["app_label"] = stripped.split(":", 1)[1].strip().strip("'")
        elif stripped.startswith("application-label-") and "app_label" not in metadata:
            metadata["app_label"] = stripped.split(":", 1)[1].strip().strip("'")
        elif stripped.startswith("packageName="):
            metadata["package_name"] = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("userId="):
            metadata["user_id"] = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("appId=") and "user_id" not in metadata:
            metadata["user_id"] = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("firstInstallTime="):
            metadata["first_install"] = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("lastUpdateTime="):
            metadata["last_update"] = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("installerPackageName="):
            metadata["installer"] = _normalize_optional_text(stripped.split("=", 1)[1])
        elif stripped.startswith("versionName=") and "version_name" not in metadata:
            # Version identity is sourced from `pm list packages --show-versioncode`.
            # Keep versionName as best-effort ancillary metadata only.
            value = stripped.split("=", 1)[1].strip()
            if value:
                metadata["version_name"] = value

    signer_digests = extract_signer_digests(output)
    if signer_digests:
        metadata["signer_cert_digest"] = signer_digests[0]
        metadata["signer_set_hash"] = compute_signer_set_hash(signer_digests)
    return metadata


def _has_inventory_relevant_metadata(metadata: dict[str, str | None]) -> bool:
    for key in ("app_label", "user_id", "first_install", "last_update", "installer", "version_name"):
        if str(metadata.get(key) or "").strip():
            return True
    return False


def get_package_paths(
    serial: str,
    package_name: str,
    refresh: bool = False,
    *,
    allow_fallbacks: bool = False,
) -> list[str]:
    """Return canonical APK paths for a package using package-manager path commands."""
    cache_key = (serial, package_name)
    if not refresh:
        cached = adb_cache.PACKAGE_PATH_CACHE.get(cache_key)
        if cached is not None:
            return cached

    paths: list[str] = []
    for command in adb_package_manager.path_commands(package_name):
        completed = adb_client.run_shell_command(serial, command, timeout=15)
        if completed.returncode != 0 or adb_package_manager.completed_indicates_unsupported(completed):
            continue
        for line in completed.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("package:"):
                paths.append(stripped.split(":", 1)[1].strip())
        if paths:
            break

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
        for command in adb_package_manager.list_packages_commands("-f", package_name):
            fallback = adb_client.run_shell_command(serial, command, timeout=15)
            if fallback.returncode != 0 or adb_package_manager.completed_indicates_unsupported(fallback):
                continue
            for line in fallback.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("package:") and "=" in stripped:
                    apk_path, _ = stripped.removeprefix("package:").rsplit("=", 1)
                    paths.append(apk_path.strip())
            if paths:
                break

    adb_cache.PACKAGE_PATH_CACHE.set(cache_key, paths)
    return paths


def get_package_metadata(
    serial: str,
    package_name: str,
    refresh: bool = False,
) -> dict[str, str | None]:
    """Return metadata for a package via package dumps (cached)."""
    cache_key = (serial, package_name)
    if not refresh:
        cached = adb_cache.PACKAGE_META_CACHE.get(cache_key)
        if cached is not None:
            return cached

    metadata: dict[str, str | None] = {"package_name": package_name}
    completed, _command = adb_package_manager.read_supported_metadata_dump(
        serial,
        package_name,
        run_command=lambda command: adb_client.run_shell_command(serial, command, timeout=25),
        is_successful=lambda result: result.returncode == 0,
        extract_text=lambda result: result.stdout,
        is_unsupported=adb_package_manager.completed_indicates_unsupported,
        accept_text=lambda text: _has_inventory_relevant_metadata(
            _parse_package_metadata_output(package_name, text)
        ),
    )
    if completed is not None:
        metadata = _parse_package_metadata_output(package_name, completed.stdout)

    adb_cache.PACKAGE_META_CACHE.set(cache_key, metadata)
    return metadata
