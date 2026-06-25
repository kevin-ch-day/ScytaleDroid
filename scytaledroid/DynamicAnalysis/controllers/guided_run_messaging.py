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


def confirm_messaging_connected_baseline_ready(*, menu_utils: Any, prompt_utils: Any) -> bool:
    print()
    menu_utils.print_header("Messaging Baseline Check")
    print("This baseline requires an existing conversation thread to be open and visible.")
    print("Do not send messages or start calls.")
    return prompt_utils.prompt_yes_no("Ready now?", default=True)


def handle_messaging_connected_baseline_not_ready(*, prompt_utils: Any, status_messages: Any) -> str | None:
    print(
        status_messages.status(
            "Connected-thread baseline is not ready. Without a visible conversation thread, this run is likely low-signal and may be excluded.",
            level="warn",
        )
    )
    fallback_interaction = "interaction_manual"
    fallback_label = "manual interaction"
    if prompt_utils.prompt_yes_no(f"Switch to {fallback_label} now?", default=True):
        return fallback_interaction
    return None


__all__ = [
    "apply_messaging_baseline_countability_policy",
    "canonical_baseline_profile_for_package",
    "confirm_messaging_connected_baseline_ready",
    "handle_messaging_connected_baseline_not_ready",
    "is_messaging_connected_baseline",
    "is_messaging_package_or_category",
    "messaging_baseline_connected_insufficient_duration_streak",
]
