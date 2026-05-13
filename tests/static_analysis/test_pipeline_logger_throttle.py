"""Unit tests for per-APK third-party logger reconfiguration policy."""

from __future__ import annotations

from scytaledroid.StaticAnalysis.core.pipeline import _next_apk_logger_reconfigure


def test_logger_reconfigure_always_debug() -> None:
    assert _next_apk_logger_reconfigure("debug", None) == (True, None)
    assert _next_apk_logger_reconfigure("debug", "summary") == (True, None)


def test_logger_reconfigure_first_non_debug() -> None:
    assert _next_apk_logger_reconfigure("summary", None) == (True, "summary")
    assert _next_apk_logger_reconfigure("normal", None) == (True, "normal")


def test_logger_skip_when_same_non_debug_verbosity() -> None:
    assert _next_apk_logger_reconfigure("summary", "summary") == (False, "summary")


def test_logger_reconfigure_when_non_debug_verbosity_changes() -> None:
    assert _next_apk_logger_reconfigure("detail", "summary") == (True, "detail")
