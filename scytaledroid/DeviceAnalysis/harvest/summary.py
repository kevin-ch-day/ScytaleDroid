"""Render harvest summaries for analysts."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from scytaledroid.Utils.DisplayUtils import status_messages, text_blocks
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .common import normalise_local_path
from .models import (
    ArtifactSummary,
    HarvestPlan,
    HarvestResult,
    PackageHarvestResult,
    PullResult,
    ScopeSelection,
)


_EXCLUSION_LABELS = {
    "family_excluded": "Family excluded (com.android./com.motorola. not Play)",
    "google_core": "Google core modules (not Play/allow-list)",
    "not_in_scope": "Not in scope (no Play installer or /data path)",
}

_POLICY_LABELS = {
    "non_root_paths": "System/vendor/mainline (non-root policy)",
}

_SKIP_LABELS = {
    "policy_non_root": "System/vendor/mainline filtered by policy",
    "no_paths": "Package returned no APK paths",
    "app_definition_failed": "Failed to record app definition",
    "dedupe_sha256": "Duplicate artifact (sha256 dedupe)",
}


def render_plan_summary(
    selection: ScopeSelection,
    plan: HarvestPlan,
    *,
    is_rooted: bool,
    include_system_partitions: bool,
) -> None:
    """Present a concise overview of the planned harvest prior to execution."""

    scheduled_packages = sum(1 for pkg in plan.packages if not pkg.skip_reason)
    blocked_packages = sum(1 for pkg in plan.packages if pkg.skip_reason)
    scheduled_files = sum(len(pkg.artifacts) for pkg in plan.packages if not pkg.skip_reason)
    blocked_text = f" (blocked {blocked_packages})" if blocked_packages else ""
    card_lines = [
        f"Scope    : {selection.label}",
        f"Packages : {scheduled_packages}{blocked_text}",
        f"Artifacts: ~{scheduled_files}",
    ]

    if plan.policy_filtered:
        policy_details = _format_policy_details(plan.policy_filtered)
        card_lines.append(f"Policy   : {policy_details}")
    if not include_system_partitions and not is_rooted:
        card_lines.append("Policy   : System/vendor filtered (non-root)")

    print()
    print(text_blocks.boxed(card_lines, width=70))

    _print_exclusions(selection.metadata.get("excluded_counts"))
    _print_sample_focus(selection)


def preview_plan(plan: HarvestPlan, *, limit: int = 10) -> None:
    """Display a short preview of package/artifact combinations."""

    samples: List[str] = []
    for package in plan.packages:
        if package.skip_reason:
            continue
        for artifact in package.artifacts:
            samples.append(f"{package.inventory.package_name}/{artifact.file_name}")
            if len(samples) >= limit:
                break
        if len(samples) >= limit:
            break

    print()
    print(text_blocks.headline("Dry-run preview", width=70))
    if not samples:
        print(status_messages.status("No readable artifacts scheduled.", level="warn"))
        return
    for item in samples:
        print(status_messages.status(item))


def print_package_result(result: PullResult, *, verbose: bool = False) -> None:
    """Emit per-package harvest results with apk_id references."""

    if not verbose and not (result.errors or result.skipped):
        return

    plan = result.plan
    inventory = plan.inventory
    header = (
        f"{inventory.display_name()}"
        f" ({inventory.package_name})"
        f" v{inventory.version_code or '?'}"
        f" ({inventory.version_name or 'n/a'})"
        f" installer={inventory.installer or 'unknown'}"
    )
    level = "info" if verbose else "warn"
    print(status_messages.status(header, level=level))

    if verbose:
        for artifact in result.ok:
            apk_id_text = artifact.apk_id if artifact.apk_id is not None else "?"
            print(
                status_messages.status(
                    f"  ✓ apk_id={apk_id_text} {artifact.file_name}", level="success"
                )
            )

    for error in result.errors:
        print(status_messages.status(f"  ✗ {error.source_path}: {error.reason}", level="error"))
    for reason in result.skipped:
        print(status_messages.status(f"  ⤷ skipped: {_describe_reason(reason, _SKIP_LABELS)}", level="warn"))


def render_harvest_summary(
    plan: HarvestPlan,
    results: Sequence[PullResult],
    *,
    selection: ScopeSelection,
    pull_mode: str = "legacy",
    serial: Optional[str] = None,
    run_timestamp: Optional[str] = None,
    guard_brief: Optional[str] = None,
    log_summary: bool = True,
) -> None:
    """Render the end-of-run summary with diagnostics."""

    harvest_result = _build_harvest_result(
        plan,
        results,
        selection,
        serial=serial,
        run_timestamp=run_timestamp,
        guard_brief=guard_brief,
    )

    total_packages = len(plan.packages)
    files_written = sum(
        1
        for package in harvest_result.packages
        for artifact in package.artifacts
        if artifact.status == "written"
    )
    pull_errors = sum(len(package.errors) for package in harvest_result.packages)
    skip_counter: Counter[str] = Counter()
    for result in results:
        skip_counter.update(result.skipped)

    print()
    print(text_blocks.headline("APK Harvest Summary", width=70))
    print(status_messages.status(f"Scope: {selection.label}"))
    print(status_messages.status(f"Pull mode: {pull_mode}"))
    metadata = selection.metadata or {}
    guard_policy = metadata.get("inventory_policy")
    if guard_policy:
        policy_label = "Quick harvest" if guard_policy == "quick" else "Inventory refresh"
        stale_level = metadata.get("inventory_stale_level")
        if isinstance(stale_level, str) and stale_level:
            policy_label = f"{policy_label} (stale={stale_level})"
        print(status_messages.status(f"Inventory policy: {policy_label}"))
    guard_brief_value = guard_brief or metadata.get("inventory_guard_brief")
    if metadata.get("render_guard_in_summary") and guard_brief_value:
        print(status_messages.status(guard_brief_value, level="info"))
    scope_hash_changed = metadata.get("inventory_scope_hash_changed")
    if scope_hash_changed:
        print(
            status_messages.status(
                "Selected scope differs from the last recorded inventory.",
                level="warn",
            )
        )
    print(status_messages.status(f"Packages processed: {total_packages}"))
    print(status_messages.status(f"Files written: {files_written}"))
    if pull_errors:
        print(status_messages.status(f"Pull errors: {pull_errors}", level="warn"))
    dedupe_skips = sum(result.skipped.count("dedupe_sha256") for result in results)
    if dedupe_skips:
        print(
            status_messages.status(
                f"Artifacts skipped (dedupe): {dedupe_skips}", level="info"
            )
        )

    if plan.policy_filtered:
        policy_details = _format_policy_details(plan.policy_filtered)
        print(status_messages.status(f"Filtered before pull (policy): {policy_details}", level="warn"))
    if skip_counter:
        skip_parts = ", ".join(
            f"{_describe_reason(reason, _SKIP_LABELS)}={count}"
            for reason, count in sorted(skip_counter.items())
        )
        print(status_messages.status(f"Skipped packages: {skip_parts}", level="warn"))

    denied = sorted(
        {
            result.plan.inventory.package_name
            for result in results
            for error in result.errors
            if "permission" in error.reason.lower()
        }
    )
    if denied:
        print(status_messages.status("Permission denied (requires root):", level="warn"))
        for package in denied:
            print(status_messages.status(f"  - {package}", level="warn"))

    _print_exclusions(metadata.get("excluded_counts"))
    _print_top_packages(results)
    _print_sample_focus(selection)

    output_root = _run_output_root(harvest_result)
    if output_root:
        print()
        print(status_messages.status("Artifacts saved under:", level="info"))
        print(status_messages.status(f"  {output_root}", level="info"))
        shown = 0
        for package in harvest_result.packages:
            dest = _package_dest_dir(package)
            if not dest:
                continue
            label = f"  • {package.app_label} ({package.package_name}) → {dest}"
            print(status_messages.status(label, level="info"))
            shown += 1
            if shown >= 5:
                break

    no_new = _packages_without_writes(harvest_result)
    if no_new:
        print()
        print(text_blocks.headline("No new artifacts", width=70))
        for package, reason in no_new:
            suffix = f" — {reason}" if reason else ""
            print(
                status_messages.status(
                    f" • {package.app_label} ({package.package_name}){suffix}",
                    level="warn",
                )
            )

    delta_summary = metadata.get("package_delta_summary")
    if delta_summary:
        print()
        print(
            text_blocks.headline(
                "Package changes since last snapshot", width=70
            )
        )
        _print_package_delta_summary(delta_summary)

    print()
    print(status_messages.status("Next steps:", level="info"))
    print(status_messages.status("  • Review metadata via view sd_app_catalog_flags", level="info"))
    print(
        status_messages.status(
            "  • Run static analysis on harvested APKs (see docs/static_analysis)", level="info"
        )
    )

    if log_summary:
        _log_harvest_summary(
            harvest_result,
            no_new,
            output_root,
            metadata,
            pull_mode,
            total_packages,
            files_written,
        )


def _print_top_packages(results: Sequence[PullResult], limit: int = 5) -> None:
    scored = []
    for result in results:
        ok_count = sum(
            1 for artifact in result.ok if getattr(artifact, "status", "written") == "written"
        )
        err_count = len(result.errors)
        if ok_count or err_count or result.skipped:
            scored.append((ok_count, err_count, result))
    if not scored:
        return

    scored.sort(key=lambda item: (-item[0], item[1], item[2].plan.inventory.package_name))

    print()
    print(text_blocks.headline("Per-package results (top)", width=70))
    for ok_count, err_count, result in scored[:limit]:
        skipped = ",".join(result.skipped) if result.skipped else "0"
        summary = (
            f"- {result.plan.inventory.display_name()} "
            f"({result.plan.inventory.package_name}) "
            f"ok:{ok_count} err:{err_count} skip:{skipped}"
        )
        print(status_messages.status(summary))


__all__ = [
    "preview_plan",
    "print_package_result",
    "render_harvest_summary",
    "render_plan_summary",
]


def _print_exclusions(excluded: object) -> None:
    if not excluded:
        return

    try:
        items = sorted(((str(reason), int(count)) for reason, count in dict(excluded).items()), key=lambda x: x[0])
    except Exception:
        return

    print(status_messages.status("Skipped (by scope):", level="info"))
    for reason, count in items:
        label = _describe_reason(reason, _EXCLUSION_LABELS)
        print(status_messages.status(f"  - {label}: {count}", level="info"))


def _describe_reason(code: str, mapping: Dict[str, str]) -> str:
    return mapping.get(code, code)


def _format_policy_details(policy_counts: Dict[str, int]) -> str:
    parts = []
    for reason, count in sorted(policy_counts.items()):
        label = _describe_reason(reason, _POLICY_LABELS)
        parts.append(f"{label}={count}")
    if not parts:
        total = sum(policy_counts.values())
        return str(total)
    return ", ".join(parts)


def _print_sample_focus(selection: ScopeSelection) -> None:
    samples = selection.metadata.get("sample_names")
    if not samples:
        return
    preview = ", ".join(samples)
    if len(selection.packages) > len(samples):
        preview += ", …"
    print(status_messages.status(f"Focus packages: {preview}"))


def _build_harvest_result(
    plan: HarvestPlan,
    results: Sequence[PullResult],
    selection: ScopeSelection,
    *,
    serial: Optional[str],
    run_timestamp: Optional[str],
    guard_brief: Optional[str],
) -> HarvestResult:
    metadata = selection.metadata or {}
    harvest_result = HarvestResult(
        serial=serial,
        run_timestamp=run_timestamp,
        scope_name=selection.label,
        guard_brief=guard_brief or metadata.get("inventory_guard_brief"),
    )

    harvest_result.meta.update(
        {
            "inventory_policy": metadata.get("inventory_policy"),
            "inventory_stale_level": metadata.get("inventory_stale_level"),
            "package_delta_summary": metadata.get("package_delta_summary"),
        }
    )

    for pull in results:
        inventory = pull.plan.inventory
        package_result = PackageHarvestResult(
            package_name=inventory.package_name,
            app_label=inventory.display_name(),
            skipped_reasons=list(pull.skipped),
            errors=list(pull.errors),
        )

        for artifact in pull.ok:
            dest_path_obj = (
                artifact.dest_path
                if isinstance(artifact.dest_path, Path)
                else Path(str(artifact.dest_path))
            )
            package_result.artifacts.append(
                ArtifactSummary(
                    file_name=artifact.file_name,
                    status=getattr(artifact, "status", "written"),
                    dest_path=normalise_local_path(dest_path_obj),
                    sha256=getattr(artifact, "sha256", None),
                    skip_reason=getattr(artifact, "skip_reason", None),
                )
            )

        harvest_result.packages.append(package_result)

    return harvest_result


def _package_dest_dir(package: PackageHarvestResult) -> Optional[str]:
    for artifact in package.artifacts:
        if artifact.dest_path:
            dest = Path(artifact.dest_path)
            return str(dest.parent)
    return None


def _run_output_root(result: HarvestResult) -> Optional[str]:
    if not (result.serial and result.run_timestamp):
        return None
    return f"data/apks/device_apks/{result.serial}/{result.run_timestamp}/"


def _packages_without_writes(
    harvest_result: HarvestResult,
) -> List[tuple[PackageHarvestResult, Optional[str]]]:
    packages: List[tuple[PackageHarvestResult, Optional[str]]] = []
    for package in harvest_result.packages:
        has_written = any(artifact.status == "written" for artifact in package.artifacts)
        if has_written:
            continue
        reason = None
        if package.skipped_reasons:
            reason = _describe_reason(package.skipped_reasons[0], _SKIP_LABELS)
        elif package.errors:
            reason = package.errors[0].reason
        packages.append((package, reason))
    return packages


def _print_package_delta_summary(summary: Dict[str, object], *, limit: int = 10) -> None:
    updated = summary.get("updated") or []
    added = summary.get("added") or []
    removed = summary.get("removed") or []

    if updated:
        print(status_messages.status("Updated:", level="info"))
        for entry in updated[:limit]:
            if not isinstance(entry, dict):
                continue
            package = entry.get("package") or entry.get("package_name") or "unknown"
            before = entry.get("before") or entry.get("from") or entry.get("previous") or "?"
            after = entry.get("after") or entry.get("to") or entry.get("current") or "?"
            print(status_messages.status(f" • {package}: {before} → {after}", level="info"))

    if added:
        print(status_messages.status("Added:", level="info"))
        for package in added[:limit]:
            print(status_messages.status(f" • {package}", level="info"))

    if removed:
        print(status_messages.status("Removed:", level="info"))
        for package in removed[:limit]:
            print(status_messages.status(f" • {package}", level="info"))


def _log_harvest_summary(
    harvest_result: HarvestResult,
    no_new: List[tuple[PackageHarvestResult, Optional[str]]],
    output_root: Optional[str],
    metadata: Dict[str, object],
    pull_mode: str,
    total_packages: int,
    files_written: int,
) -> None:
    payload = {
        "event": "apk_harvest_summary",
        "serial": harvest_result.serial,
        "run_timestamp": harvest_result.run_timestamp,
        "scope": harvest_result.scope_name,
        "pull_mode": pull_mode,
        "packages_processed": total_packages,
        "files_written": files_written,
        "output_root": output_root,
        "guard_brief": harvest_result.guard_brief,
        "package_delta_summary": metadata.get("package_delta_summary"),
        "no_new_artifacts": [
            {
                "package": package.package_name,
                "label": package.app_label,
                "reason": reason,
            }
            for package, reason in no_new
        ],
    }

    log.info(json.dumps(payload, default=str), category="device_analysis")
