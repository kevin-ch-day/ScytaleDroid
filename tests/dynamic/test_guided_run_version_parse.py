from __future__ import annotations

from scytaledroid.DeviceAnalysis.adb import cache as adb_cache
from scytaledroid.DynamicAnalysis.controllers.guided_run import _extract_version_code_from_dump
from scytaledroid.DynamicAnalysis.controllers.guided_run_checks import (
    read_observed_version_code_details,
)


def test_extract_version_code_prefers_min_sdk_line() -> None:
    dump = """
Random header
versionCode=1
Package [com.facebook.katana]
  userId=10123
  versionName=548.1.0.51.64
  versionCode=468616494 minSdk=28 targetSdk=35
  signatures=PackageSignatures{abc}
"""
    assert _extract_version_code_from_dump(dump, "com.facebook.katana") == "468616494"


def test_extract_version_code_scopes_to_requested_package_block() -> None:
    dump = """
Package [com.other.app]
  versionCode=1 minSdk=21 targetSdk=34
Package [com.facebook.katana]
  versionCode=468616494 minSdk=28 targetSdk=35
"""
    assert _extract_version_code_from_dump(dump, "com.facebook.katana") == "468616494"


def test_extract_version_code_prefers_max_candidate_within_package_block() -> None:
    dump = """
Something
  versionCode=1 minSdk=21 targetSdk=34
Other noise
Package [com.facebook.katana]
  userId=10234
  versionName=1.0
  versionCode=468616494 minSdk=24 targetSdk=34
  versionCode=468616400 minSdk=24 targetSdk=34
"""
    assert _extract_version_code_from_dump(dump, "com.facebook.katana") == "468616494"


def test_extract_version_code_fallback_without_package_block() -> None:
    dump = "versionCode=321 minSdk=24 targetSdk=34"
    assert _extract_version_code_from_dump(dump, "com.example.missing") == "321"


def test_read_observed_version_code_details_skips_user_scoped_probe_after_cache() -> None:
    adb_cache.PACKAGE_COMMAND_SUPPORT_CACHE.clear()
    calls: list[list[str]] = []

    def _run_shell(_serial: str, command: list[str]) -> str:
        calls.append(command)
        if command[:3] == ["dumpsys", "package", "--user"]:
            return "Unknown argument: --user; use -h for help"
        return "Package [com.example.app]\n  versionCode=321 minSdk=24 targetSdk=34\n"

    def _extract(dump: str, package_name: str) -> dict[str, str]:
        return {
            "version_code": _extract_version_code_from_dump(dump, package_name) or "",
            "pattern": "versionCode",
            "matched_line": "versionCode=321 minSdk=24 targetSdk=34",
        }

    first = read_observed_version_code_details(
        "SER123",
        "com.example.app",
        run_shell_fn=_run_shell,
        extract_details_fn=_extract,
    )
    second = read_observed_version_code_details(
        "SER123",
        "com.example.other",
        run_shell_fn=_run_shell,
        extract_details_fn=_extract,
    )

    assert first["command"] == "dumpsys package com.example.app"
    assert second["command"] == "dumpsys package com.example.other"
    assert calls == [
        ["dumpsys", "package", "--user", "0", "com.example.app"],
        ["dumpsys", "package", "com.example.app"],
        ["dumpsys", "package", "com.example.other"],
    ]


def test_read_observed_version_code_details_falls_back_to_cmd_dump_package() -> None:
    adb_cache.PACKAGE_COMMAND_SUPPORT_CACHE.clear()
    calls: list[list[str]] = []

    def _run_shell(_serial: str, command: list[str]) -> str:
        calls.append(command)
        if command[:2] == ["dumpsys", "package"]:
            return "Packages:\n"
        if command[:3] == ["cmd", "package", "dump-package"]:
            return "Package [com.example.app]\n  versionCode=321 minSdk=24 targetSdk=34\n"
        return ""

    def _extract(dump: str, package_name: str) -> dict[str, str]:
        return {
            "version_code": _extract_version_code_from_dump(dump, package_name) or "",
            "pattern": "versionCode",
            "matched_line": "versionCode=321 minSdk=24 targetSdk=34",
        }

    result = read_observed_version_code_details(
        "SER123",
        "com.example.app",
        run_shell_fn=_run_shell,
        extract_details_fn=_extract,
    )

    assert result["version_code"] == "321"
    assert result["command"] == "cmd package dump-package com.example.app"
    assert calls == [
        ["dumpsys", "package", "--user", "0", "com.example.app"],
        ["dumpsys", "package", "com.example.app"],
        ["cmd", "package", "dump-package", "com.example.app"],
    ]
