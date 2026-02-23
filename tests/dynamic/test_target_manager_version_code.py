from __future__ import annotations

from scytaledroid.DynamicAnalysis.core.target_manager import TargetManager


def test_extract_version_code_prefers_max_candidate() -> None:
    # Simulate a dumpsys output that contains unrelated versionCode=1 lines
    # before the real package versionCode.
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
    mgr = TargetManager()
    assert mgr._extract_version_code(dump, "com.facebook.katana") == "468616494"


def test_extract_version_code_fallback_prefers_max() -> None:
    dump = """
Some header
  versionCode=1 minSdk=21 targetSdk=34
  versionCode=99 minSdk=21 targetSdk=34
"""
    mgr = TargetManager()
    assert mgr._extract_version_code(dump, "com.unknown.app") == "99"

