"""Render harvest summaries for analysts."""

from __future__ import annotations

from collections import Counter
from typing import Dict, List, Sequence

from scytaledroid.Utils.DisplayUtils import status_messages, text_blocks

from .models import HarvestPlan, PullResult, ScopeSelection


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
) -> None:
    """Render the end-of-run summary with diagnostics."""

    total_packages = len(plan.packages)
    files_written = sum(len(result.ok) for result in results)
    pull_errors = sum(len(result.errors) for result in results)
    skip_counter: Counter[str] = Counter()
    for result in results:
        skip_counter.update(result.skipped)

    print()
    print(text_blocks.headline("APK Harvest Summary", width=70))
    print(status_messages.status(f"Scope: {selection.label}"))
    print(status_messages.status(f"Pull mode: {pull_mode}"))
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

    _print_exclusions(selection.metadata.get("excluded_counts"))
    _print_top_packages(results)
    _print_sample_focus(selection)

    print()
    print(status_messages.status("Next steps:", level="info"))
    print(status_messages.status("  • Review metadata via view sd_app_catalog_flags", level="info"))
    print(
        status_messages.status(
            "  • Run static analysis on harvested APKs (see docs/static_analysis)", level="info"
        )
    )


def _print_top_packages(results: Sequence[PullResult], limit: int = 5) -> None:
    scored = []
    for result in results:
        ok_count = len(result.ok)
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
