"""Profiles and helpers for Static Analysis menu flow."""

from __future__ import annotations

PROFILE_BASELINE: tuple[str, ...] = ("permissions", "strings")
PROFILE_FULL: tuple[str, ...] = (
    "permissions",
    "strings",
    "webview",
    "nsc",
    "ipc",
    "crypto",
    "sdk",
    "dynload",
    "storage_surface",
)


def run_modules_for_profile(profile: str) -> tuple[str, ...]:
    profile = (profile or "").lower()
    if profile == "full":
        return PROFILE_FULL
    if profile in {"lightweight", "baseline"}:
        return PROFILE_BASELINE
    # default: treat as baseline
    return PROFILE_BASELINE


__all__ = ["PROFILE_BASELINE", "PROFILE_FULL", "run_modules_for_profile"]
