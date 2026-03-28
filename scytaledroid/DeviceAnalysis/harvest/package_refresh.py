"""Live-device refresh and replan helpers for package harvest."""

from __future__ import annotations

from collections.abc import Sequence

from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .models import ArtifactPlan, ArtifactResult, InventoryRow, PackagePlan


def next_unwritten_artifact_index(plan: PackagePlan, written: Sequence[ArtifactResult]) -> int:
    written_files = {artifact.file_name for artifact in written}
    for index, artifact in enumerate(plan.artifacts, start=1):
        if artifact.file_name not in written_files:
            return index
    return len(plan.artifacts) + 1


def replan_package_after_stale_path(
    *,
    serial: str,
    plan: PackagePlan,
) -> tuple[PackagePlan | None, tuple[str, ...]]:
    try:
        refreshed_inventory = refresh_inventory_row_from_device(serial, plan.inventory)
    except Exception as exc:
        log.warning(
            f"Failed to refresh package plan for {plan.inventory.package_name}: {exc}",
            category="device",
        )
        return None, ("package_refresh_failed",)

    from . import planner as harvest_planner

    refreshed_harvest_plan = harvest_planner.build_harvest_plan(
        [refreshed_inventory],
        include_system_partitions=include_system_partitions_for_plan(plan),
    )
    if not refreshed_harvest_plan.packages:
        return None, ("package_refresh_failed",)
    refreshed_plan = refreshed_harvest_plan.packages[0]

    drift_reasons: list[str] = []
    if refreshed_plan.inventory.version_code != plan.inventory.version_code:
        drift_reasons.append("version_code_changed")
    elif refreshed_plan.inventory.version_name != plan.inventory.version_name:
        drift_reasons.append("version_name_changed")
    if package_plan_identity(refreshed_plan) != package_plan_identity(plan):
        drift_reasons.append("artifact_set_changed")
    if refreshed_plan.skip_reason:
        drift_reasons.append(f"refreshed_skip:{refreshed_plan.skip_reason}")
    return refreshed_plan, tuple(sorted(set(drift_reasons)))


def refresh_inventory_row_from_device(serial: str, inventory: InventoryRow) -> InventoryRow:
    from scytaledroid.DeviceAnalysis.adb import packages as adb_packages
    from scytaledroid.DeviceAnalysis.runtime_flags import allow_inventory_fallbacks

    allow_fallbacks = allow_inventory_fallbacks()
    refreshed_paths = adb_packages.get_package_paths(
        serial,
        inventory.package_name,
        refresh=True,
        allow_fallbacks=allow_fallbacks,
    )
    metadata = adb_packages.get_package_metadata(
        serial,
        inventory.package_name,
        refresh=True,
    )
    version_code = inventory.version_code
    version_name = inventory.version_name
    try:
        versions = adb_packages.list_packages_with_versions(serial, allow_fallbacks=allow_fallbacks)
    except Exception:
        versions = []
    for package_name, refreshed_version_code, refreshed_version_name in versions:
        if str(package_name).strip().lower() != inventory.package_name.lower():
            continue
        version_code = maybe_str(refreshed_version_code) or version_code
        version_name = maybe_str(refreshed_version_name) or version_name
        break
    version_name = maybe_str(metadata.get("version_name")) or version_name
    raw = dict(inventory.raw)
    raw.update(
        {
            "package_name": inventory.package_name,
            "app_label": maybe_str(metadata.get("app_label")) or inventory.app_label,
            "installer": maybe_str(metadata.get("installer")) or inventory.installer,
            "version_name": version_name,
            "version_code": version_code,
            "primary_path": refreshed_paths[0] if refreshed_paths else None,
            "apk_paths": list(refreshed_paths),
            "split_count": len(refreshed_paths),
        }
    )
    return InventoryRow(
        raw=raw,
        package_name=inventory.package_name,
        app_label=maybe_str(raw.get("app_label")),
        installer=maybe_str(raw.get("installer")),
        category=inventory.category,
        primary_path=maybe_str(raw.get("primary_path")),
        profile_key=inventory.profile_key,
        profile=inventory.profile,
        version_name=maybe_str(raw.get("version_name")),
        version_code=maybe_str(raw.get("version_code")),
        apk_paths=[str(path).strip() for path in refreshed_paths if str(path).strip()],
        split_count=len(refreshed_paths),
    )


def include_system_partitions_for_plan(plan: PackagePlan) -> bool:
    from . import rules

    return any(
        str(path).strip() and not rules.is_user_path(str(path))
        for path in plan.inventory.apk_paths
    )


def package_plan_identity(plan: PackagePlan) -> tuple[tuple[str, str, bool], ...]:
    return tuple(sorted(artifact_plan_identity(artifact) for artifact in plan.artifacts))


def artifact_plan_identity(artifact: ArtifactPlan) -> tuple[str, str, bool]:
    return (artifact.artifact, artifact.file_name, bool(artifact.is_split_member))


def maybe_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


__all__ = [
    "next_unwritten_artifact_index",
    "replan_package_after_stale_path",
    "refresh_inventory_row_from_device",
]
