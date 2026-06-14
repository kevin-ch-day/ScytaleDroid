"""Shared stale-path replan outcome semantics for harvest flows."""

from __future__ import annotations

from collections.abc import Sequence

from .models import PackagePlan

STALE_REPLAN_SUCCESS_OUTCOMES = frozenset(
    {
        "path_stale_refreshed_and_retried",
        "path_stale_package_updated_since_inventory",
        "path_stale_package_paths_changed_since_inventory",
        "path_stale_blocked_before_pull",
    }
)

STALE_REPLAN_FAILURE_OUTCOMES = frozenset(
    {
        "path_stale_package_no_longer_accessible",
        "path_stale_replan_failed",
    }
)


def classify_stale_replan_outcome(
    *,
    refreshed_plan: PackagePlan,
    drift_reasons: Sequence[str],
) -> str:
    if refreshed_plan.skip_reason == "no_paths":
        return "path_stale_package_no_longer_accessible"
    if refreshed_plan.skip_reason:
        return "path_stale_blocked_before_pull"
    if "version_code_changed" in drift_reasons:
        return "path_stale_package_updated_since_inventory"
    if "artifact_set_changed" in drift_reasons:
        return "path_stale_package_paths_changed_since_inventory"
    return "path_stale_refreshed_and_retried"


def stale_replan_outcome_text(outcome: str) -> tuple[str, str]:
    mapping = {
        "path_stale_refreshed_and_retried": (
            "path stale; refreshed package paths and retried",
            "warn",
        ),
        "path_stale_package_updated_since_inventory": (
            "path stale; package appears updated since inventory snapshot",
            "warn",
        ),
        "path_stale_package_paths_changed_since_inventory": (
            "path stale; package paths changed since inventory snapshot",
            "warn",
        ),
        "path_stale_blocked_before_pull": (
            "path stale; blocked before pull",
            "warn",
        ),
        "path_stale_package_no_longer_accessible": (
            "path stale; replan failed because package is no longer accessible",
            "error",
        ),
        "path_stale_replan_failed": (
            "path stale; targeted replan failed",
            "error",
        ),
    }
    return mapping.get(outcome, ("path stale; replan required", "warn"))


def build_stale_replan_details(
    *,
    refreshed_plan: PackagePlan,
    drift_reasons: Sequence[str],
) -> dict[str, object]:
    refreshed_inventory = refreshed_plan.inventory
    return {
        "refresh_failed": False,
        "refreshed_skip_reason": refreshed_plan.skip_reason,
        "refreshed_policy_filtered_reason": refreshed_plan.policy_filtered_reason,
        "refreshed_primary_path": refreshed_inventory.primary_path,
        "refreshed_apk_paths": list(refreshed_inventory.apk_paths),
        "refreshed_split_count": refreshed_inventory.split_count,
        "refreshed_version_code": refreshed_inventory.version_code,
        "refreshed_version_name": refreshed_inventory.version_name,
        "drift_reasons": list(drift_reasons),
    }


def is_successful_stale_replan_outcome(outcome: str | None) -> bool:
    return str(outcome or "").strip() in STALE_REPLAN_SUCCESS_OUTCOMES


def is_failed_stale_replan_outcome(outcome: str | None) -> bool:
    return str(outcome or "").strip() in STALE_REPLAN_FAILURE_OUTCOMES


__all__ = [
    "STALE_REPLAN_FAILURE_OUTCOMES",
    "STALE_REPLAN_SUCCESS_OUTCOMES",
    "build_stale_replan_details",
    "classify_stale_replan_outcome",
    "is_failed_stale_replan_outcome",
    "is_successful_stale_replan_outcome",
    "stale_replan_outcome_text",
]
