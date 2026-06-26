"""Messaging-specific helpers for guided dynamic runs."""

from __future__ import annotations

from typing import Any


def is_messaging_package_or_category(
    package_name: str,
    *,
    category_lookup: Any,
    messaging_packages: set[str] | tuple[str, ...] | list[str],
) -> bool:
    pkg_lc = str(package_name or "").strip().lower()
    if not pkg_lc:
        return False
    category = str(category_lookup(pkg_lc) or "").strip().lower()
    if category == "messaging":
        return True
    return pkg_lc in {str(p).lower() for p in messaging_packages}


def canonical_baseline_profile_for_package(
    package_name: str,
    *,
    is_messaging_package_or_category_fn: Any,
) -> str:
    if is_messaging_package_or_category_fn(package_name):
        return "baseline_connected"
    return "baseline_idle"


def is_messaging_connected_baseline(
    *,
    package_name: str,
    run_profile: str,
    messaging_activity: str | None,
    is_messaging_package_or_category_fn: Any,
) -> bool:
    return (
        is_messaging_package_or_category_fn(package_name)
        and str(run_profile or "").strip().lower() == "baseline_connected"
        and str(messaging_activity or "").strip().lower() in {"", "connected_idle"}
    )


def messaging_baseline_connected_insufficient_duration_streak(
    recent_runs: list[Any],
    *,
    package_name: str,
    is_messaging_package_or_category_fn: Any,
) -> int:
    if not is_messaging_package_or_category_fn(package_name):
        return 0
    streak = 0
    for r in recent_runs:
        prof = str(getattr(r, "run_profile", "") or "").strip().lower()
        reason = str(getattr(r, "invalid_reason_code", "") or "").strip().upper()
        if prof == "baseline_connected" and getattr(r, "valid", None) is False and reason == "INSUFFICIENT_DURATION":
            streak += 1
            continue
        break
    return streak


def apply_messaging_baseline_countability_policy(
    *,
    package_name: str,
    run_profile: str,
    messaging_activity: str | None,
    counts_toward_completion: bool,
    is_messaging_package_or_category_fn: Any,
) -> tuple[bool, str | None]:
    if not counts_toward_completion:
        return counts_toward_completion, None
    if not is_messaging_package_or_category_fn(package_name):
        return counts_toward_completion, None
    if not str(run_profile or "").strip().lower().startswith("baseline"):
        return counts_toward_completion, None
    activity = str(messaging_activity or "").strip().lower()
    if activity in {"", "none"}:
        return False, "MESSAGING_BASELINE_NONE_EXPLORATORY"
    return counts_toward_completion, None


def prompt_messaging_baseline_setup(*, menu_utils: Any, prompt_utils: Any) -> str:
    print()
    menu_utils.print_header("Messaging Baseline Setup")
    print("This app uses the messaging baseline policy.")
    print()
    print("Countable baseline evidence requires:")
    print("  - app is open")
    print("  - an existing conversation thread is visible")
    print("  - no message sending")
    print("  - no call initiation")
    print("  - no account-changing action")
    print()
    print("Choose:")
    print("1) Run connected-idle baseline")
    print("   counts toward baseline quota if checks pass")
    print("2) Switch to manual interaction")
    print("   use if the app is not ready for connected-idle baseline")
    print("0) Cancel")
    return prompt_utils.get_choice(
        ["1", "2", "0"],
        default="1",
        prompt="› Choose [1]: ",
        invalid_message="Choose 1, 2, or 0.",
    )


__all__ = [
    "apply_messaging_baseline_countability_policy",
    "canonical_baseline_profile_for_package",
    "is_messaging_connected_baseline",
    "is_messaging_package_or_category",
    "messaging_baseline_connected_insufficient_duration_streak",
    "prompt_messaging_baseline_setup",
]
