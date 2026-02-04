"""Planner helpers for APK pull workflows."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis import harvest
from collections.abc import Mapping
from typing import Any

from scytaledroid.DeviceAnalysis.apk.models import PlanResolution


def include_system_partitions(selection: harvest.ScopeSelection, is_rooted: bool) -> bool:
    return selection.kind in {"families", "everything"} and is_rooted


def build_plan(
    selection: harvest.ScopeSelection,
    *,
    is_rooted: bool,
    pull_mode: str,
    verbose: bool,
    guard_metadata: Mapping[str, object] | None,
) -> PlanResolution:
    plan = harvest.build_harvest_plan(
        selection.packages,
        include_system_partitions=include_system_partitions(selection, is_rooted),
    )
    stats = compute_plan_stats(plan, policy=selection.metadata.get("policy"))
    return PlanResolution(
        plan=plan,
        selection=selection,
        stats=stats,
        pull_mode=pull_mode,
        verbose=verbose,
        guard_metadata=guard_metadata,
    )


def compute_plan_stats(plan: Any, *, policy: str | None = None) -> dict[str, int | str]:
    scheduled_packages = sum(1 for pkg in plan.packages if not pkg.skip_reason)
    blocked_packages = sum(1 for pkg in plan.packages if pkg.skip_reason)
    scheduled_files = sum(len(pkg.artifacts) for pkg in plan.packages if not pkg.skip_reason)
    policy_blocked = sum(1 for pkg in plan.packages if pkg.skip_reason == "policy_non_root")
    if not policy:
        policy = ",".join(sorted(plan.policy_filtered.keys())) if plan.policy_filtered else "none"
    return {
        "scheduled_packages": scheduled_packages,
        "blocked_packages": blocked_packages,
        "scheduled_files": scheduled_files,
        "policy_blocked": policy_blocked,
        "policy": policy,
    }
