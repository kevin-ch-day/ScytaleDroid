"""Translate scoped inventory entries into concrete harvest plans."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

from . import rules
from .models import ArtifactPlan, HarvestPlan, InventoryRow, PackagePlan


def build_harvest_plan(
    packages: Sequence[InventoryRow],
    *,
    include_system_partitions: bool = False,
) -> HarvestPlan:
    """Construct the harvest plan and capture policy filtering diagnostics."""

    planned_packages: list[PackagePlan] = []
    policy_filtered: dict[str, int] = defaultdict(int)
    plan_logger = None
    try:
        from scytaledroid.Utils.LoggingUtils import logging_events as log_events
        from scytaledroid.Utils.LoggingUtils.logging_context import RunContext, get_run_logger

        run_ctx = RunContext(
            subsystem="harvest",
            device_serial=None,
            device_model=None,
            run_id="HARVEST-PLAN",
            scope=None,
            profile=None,
        )
        plan_logger = get_run_logger("harvest", run_ctx)
        plan_logger.info(
            "Harvest policy.filter (planning)",
            extra={
                "event": log_events.POLICY_FILTER,
                "note": "planning start",
                "candidate_packages": len(packages),
            },
        )
    except Exception:
        plan_logger = None

    for row in packages:
        plan = _build_package_plan(row, include_system_partitions)
        planned_packages.append(plan)
        if plan.policy_filtered_count:
            reason = plan.policy_filtered_reason or "policy"
            policy_filtered[reason] += plan.policy_filtered_count

    if plan_logger:
        plan_logger.info(
            "Harvest policy.filter (planning complete)",
            extra={
                "event": log_events.POLICY_FILTER,
                "note": "planning complete",
                "candidate_packages": len(packages),
                "policy_filtered": dict(sorted(policy_filtered.items())),
            },
        )

    return HarvestPlan(
        packages=planned_packages,
        policy_filtered=dict(sorted(policy_filtered.items())),
        failures=[],
    )


def _build_package_plan(
    row: InventoryRow,
    include_system_partitions: bool,
) -> PackagePlan:
    readable_paths: list[str] = []
    filtered = 0
    policy_reason: str | None = None
    for path in row.apk_paths:
        if include_system_partitions or rules.is_user_path(path):
            readable_paths.append(path)
        else:
            filtered += 1
            if policy_reason is None:
                policy_reason = "non_root_paths"

    artifacts = [
        _build_artifact_plan(row, source_path)
        for source_path in readable_paths
    ]

    total_paths = len(row.apk_paths)
    skip_reason = None
    if total_paths == 0:
        skip_reason = "no_paths"
    elif not readable_paths and filtered:
        skip_reason = "policy_non_root"

    return PackagePlan(
        inventory=row,
        artifacts=artifacts,
        total_paths=total_paths,
        policy_filtered_count=filtered,
        policy_filtered_reason=policy_reason,
        skip_reason=skip_reason,
    )


def _build_artifact_plan(row: InventoryRow, source_path: str) -> ArtifactPlan:
    name = Path(source_path).name
    artifact, is_split = _artifact_identifier(name)
    file_name = rules.canonical_filename(row.package_name, row.version_code or "unknown", artifact)
    return ArtifactPlan(
        source_path=source_path,
        artifact=artifact,
        file_name=file_name,
        is_split_member=is_split,
    )


def _artifact_identifier(source_name: str) -> tuple[str, bool]:
    cleaned = source_name.strip()
    if cleaned.lower() == "base.apk":
        return "base", False
    if cleaned.lower().endswith(".apk"):
        cleaned = cleaned[:-4]
    safe = cleaned.replace(" ", "_") or "artifact"
    return safe, True


__all__ = ["build_harvest_plan"]