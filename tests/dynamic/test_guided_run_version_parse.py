from __future__ import annotations

from scytaledroid.DynamicAnalysis.controllers.guided_run import _extract_version_code_from_dump


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


def test_extract_version_code_fallback_without_package_block() -> None:
    dump = "versionCode=321 minSdk=24 targetSdk=34"
    assert _extract_version_code_from_dump(dump, "com.example.missing") == "321"

