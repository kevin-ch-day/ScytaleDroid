"""Bulk ADB parsers to reduce per-package shell calls during inventory collection.

This module is intentionally UI-free and can be wired into package_collection
to replace per-package `adb shell` invocations with one or two bulk queries
(`pm list packages`, optional `dumpsys package`) and local parsing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime

from scytaledroid.DeviceAnalysis.adb import client as adb_client
from scytaledroid.DeviceAnalysis.adb import package_manager as adb_package_manager
from scytaledroid.DeviceAnalysis.adb import shell as adb_shell
from scytaledroid.DeviceAnalysis.identity import compute_signer_set_hash, extract_signer_digests
from scytaledroid.Utils.LoggingUtils import logging_utils as log


@dataclass
class BulkPackageEntry:
    package_name: str
    apk_path: str | None
    user: str | None
    uid: int | None
    installer: str | None = None
    version_code: str | None = None


def _parse_pm_list_line(line: str) -> BulkPackageEntry | None:
    line = line.strip()
    if not line or not line.startswith("package:"):
        return None

    tokens = line.split()
    package_token = tokens[0]
    payload = package_token.removeprefix("package:").strip()
    apk_path: str | None = None
    name = payload
    if "=" in payload:
        apk_path, name = payload.rsplit("=", 1)
        apk_path = apk_path.strip() or None
    name = name.strip()
    if not name:
        return None

    uid: str | None = None
    user: str | None = None
    installer: str | None = None
    version_code: str | None = None
    for token in tokens[1:]:
        if token.startswith("uid:") or token.startswith("uid="):
            uid = token.split(":", 1)[1] if ":" in token else token.split("=", 1)[1]
        elif token.startswith("user:") or token.startswith("user="):
            user = token.split(":", 1)[1] if ":" in token else token.split("=", 1)[1]
        elif token.startswith("installer=") or token.startswith("installerPackageName="):
            installer_value = token.split("=", 1)[1].strip()
            installer = None if installer_value.lower() in {"", "null", "none"} else installer_value
        elif token.startswith("versionCode:") or token.startswith("versionCode="):
            version_code = token.split(":", 1)[1] if ":" in token else token.split("=", 1)[1]

    try:
        uid_int = int(uid) if uid else None
    except ValueError:
        uid_int = None
    return BulkPackageEntry(
        package_name=name,
        apk_path=apk_path,
        user=user,
        uid=uid_int,
        installer=installer,
        version_code=(version_code.strip() or None) if version_code else None,
    )


def list_packages_bulk(serial: str) -> list[BulkPackageEntry]:
    """Return package entries via one compatible bulk package-manager list call."""
    output = ""
    for command in adb_package_manager.list_packages_commands("-f", "-i", "-U", "--show-versioncode"):
        completed = adb_client.run_shell_command(serial, command, timeout=20)
        if completed.returncode != 0 or adb_package_manager.completed_indicates_unsupported(completed):
            continue
        output = completed.stdout or ""
        if output:
            break
    entries: list[BulkPackageEntry] = []
    if not output:
        log.warning("Bulk package list returned no output", category="inventory")
        return entries
    for line in output.splitlines():
        entry = _parse_pm_list_line(line)
        if entry:
            entries.append(entry)
    return entries


_DUMPSYS_PKG_RE = re.compile(r"^\s*Package \[(?P<name>[^\]]+)\]")
_DUMPSYS_USER_RE = re.compile(r"^\s*User\s+\d+:")


def _normalize_optional_text(value: str | None) -> str | None:
    text = str(value or "").strip()
    if not text or text.lower() in {"null", "none"}:
        return None
    return text


def _parse_inventory_timestamp(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def _parse_optional_int(value: object) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _candidate_rank(metadata: dict[str, object]) -> tuple[object, ...]:
    last_update = _parse_inventory_timestamp(metadata.get("last_update"))
    first_install = _parse_inventory_timestamp(metadata.get("first_install"))
    version_code = _parse_optional_int(metadata.get("version_code"))
    installer_present = bool(_normalize_optional_text(metadata.get("installer")))
    app_label_present = bool(_normalize_optional_text(metadata.get("app_label")))
    populated_fields = sum(1 for value in metadata.values() if _normalize_optional_text(value) is not None)
    epoch_floor = datetime(2000, 1, 1, tzinfo=UTC)
    return (
        1 if (last_update and last_update >= epoch_floor) else 0,
        last_update or datetime.min.replace(tzinfo=UTC),
        1 if installer_present else 0,
        1 if (first_install and first_install >= epoch_floor) else 0,
        first_install or datetime.min.replace(tzinfo=UTC),
        version_code if version_code is not None else -1,
        1 if app_label_present else 0,
        populated_fields,
    )


def _merge_duplicate_package_metadata(
    existing: dict[str, object],
    candidate: dict[str, object],
) -> dict[str, object]:
    preferred, secondary = (
        (candidate, existing)
        if _candidate_rank(candidate) >= _candidate_rank(existing)
        else (existing, candidate)
    )
    merged = dict(preferred)
    for key, value in secondary.items():
        if key not in merged or _normalize_optional_text(merged.get(key)) is None:
            merged[key] = value
    return merged


def reconstruct_apk_paths(metadata: dict[str, object] | None) -> list[str] | None:
    """Reconstruct ``pm path`` output from parsed dumpsys metadata when safe."""

    if not metadata:
        return None
    code_path = _normalize_optional_text(metadata.get("code_path"))
    if not code_path:
        return None
    if code_path.startswith("/apex/") or "/overlay/" in code_path:
        return None

    split_names_raw = metadata.get("split_names")
    split_names: list[str] = []
    if isinstance(split_names_raw, list):
        split_names = [str(value).strip() for value in split_names_raw if str(value).strip()]
    if not split_names:
        split_names = ["base"]

    if code_path.endswith(".apk"):
        if split_names == ["base"]:
            return [code_path]
        code_dir = code_path.rsplit("/", 1)[0]
    else:
        code_dir = code_path.rstrip("/")

    if not code_dir:
        return None

    leaf = code_dir.rsplit("/", 1)[-1]
    only_base = len(split_names) == 1 and split_names[0] == "base"
    if code_path.endswith(".apk"):
        base_path = code_path
    elif code_path.startswith("/data/") or not only_base:
        base_path = f"{code_dir}/base.apk"
    else:
        base_path = f"{code_dir}/{leaf}.apk"

    paths = [base_path]
    for split_name in split_names:
        if split_name == "base":
            continue
        paths.append(f"{code_dir}/split_{split_name}.apk")
    return paths


def parse_dumpsys_package(raw: str) -> dict[str, dict[str, object]]:
    """Parse ``dumpsys package packages`` into package metadata.

    This intentionally extracts only the stable inventory-relevant subset:
    version name, installer, update/install timestamps, and app/user id.
    Richer fields like signer digests and application labels still come from
    targeted ``pm dump`` calls where higher fidelity is required.
    """
    results: dict[str, dict[str, object]] = {}
    current: str | None = None
    current_metadata: dict[str, object] | None = None
    current_lines: list[str] = []

    def _finalize_current() -> None:
        nonlocal current_metadata
        if not current or not current_lines or current_metadata is None:
            return
        signer_digests = extract_signer_digests("\n".join(current_lines))
        if signer_digests:
            current_metadata["signer_cert_digest"] = signer_digests[0]
            current_metadata["signer_set_hash"] = compute_signer_set_hash(signer_digests)
        existing = results.get(current)
        if existing is not None:
            results[current] = _merge_duplicate_package_metadata(existing, current_metadata)
        else:
            results[current] = dict(current_metadata)
        current_metadata = None

    for line in raw.splitlines():
        m = _DUMPSYS_PKG_RE.search(line)
        if m:
            _finalize_current()
            current = m.group("name")
            current_metadata = {"package_name": current}
            current_lines = [line]
            continue
        if current is None or current_metadata is None:
            continue

        current_lines.append(line)
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("application-label:"):
            current_metadata["app_label"] = stripped.split(":", 1)[1].strip().strip("'")
        elif stripped.startswith("application-label-") and "app_label" not in current_metadata:
            current_metadata["app_label"] = stripped.split(":", 1)[1].strip().strip("'")
        elif stripped.startswith("codePath="):
            current_metadata["code_path"] = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("appId="):
            current_metadata["user_id"] = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("versionName=") and "version_name" not in current_metadata:
            current_metadata["version_name"] = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("splits="):
            split_text = stripped.split("=", 1)[1].strip()
            if split_text.startswith("[") and split_text.endswith("]"):
                current_metadata["split_names"] = [
                    value.strip()
                    for value in split_text[1:-1].split(",")
                    if value.strip()
                ]
        elif stripped.startswith("lastUpdateTime="):
            current_metadata["last_update"] = stripped.split("=", 1)[1].strip()
        elif stripped.startswith("installerPackageName="):
            current_metadata["installer"] = _normalize_optional_text(
                stripped.split("=", 1)[1]
            )
        elif stripped.startswith("firstInstallTime=") and "first_install" not in current_metadata:
            current_metadata["first_install"] = stripped.split("=", 1)[1].strip()
        elif _DUMPSYS_USER_RE.match(line) and "firstInstallTime=" in line and "first_install" not in current_metadata:
            current_metadata["first_install"] = line.split("firstInstallTime=", 1)[1].strip()
        elif stripped.startswith("versionCode=") and "version_code" not in current_metadata:
            current_metadata["version_code"] = stripped.split("=", 1)[1].split()[0].strip()

    _finalize_current()
    return results


def dumpsys_package_bulk(serial: str) -> dict[str, dict[str, object]]:
    """Fetch and parse `dumpsys package` once for richer metadata (optional)."""
    raw = adb_shell.run_shell(serial, ["dumpsys", "package", "packages"], check=False)
    if not raw:
        return {}
    return parse_dumpsys_package(raw)


__all__ = [
    "BulkPackageEntry",
    "list_packages_bulk",
    "dumpsys_package_bulk",
    "parse_dumpsys_package",
    "reconstruct_apk_paths",
]
