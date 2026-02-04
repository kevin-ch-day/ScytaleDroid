"""Render harvest summaries for analysts."""

from __future__ import annotations

import os
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import status_messages, text_blocks
from scytaledroid.Utils.LoggingUtils import logging_engine
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
from .views import render_harvest_summary_structured, render_scope_overview

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


@dataclass
class HarvestRunMetrics:
    """Aggregate statistics for a completed harvest run."""

    total_packages: int
    blocked_packages: int
    executed_packages: int
    planned_artifacts: int
    artifacts_written: int
    artifacts_failed: int
    artifact_status_counter: Counter[str]
    packages_with_writes: int
    packages_with_errors: int
    packages_failed: int
    packages_skipped_runtime: int
    runtime_skips: Counter[str]
    preflight_skips: Counter[str]

    @property
    def dedupe_skips(self) -> int:
        """Number of artifacts skipped due to deduplication."""

        return self.runtime_skips.get("dedupe_sha256", 0)

    @property
    def packages_successful(self) -> int:
        """Packages that wrote artifacts without triggering errors."""

        return max(self.packages_with_writes - self.packages_with_partial_errors, 0)

    @property
    def runtime_skip_total(self) -> int:
        """Total skips encountered during pull execution."""

        return sum(self.runtime_skips.values())

    @property
    def artifact_status_excluding_written(self) -> Counter[str]:
        """Return artifact status counts without successful writes."""

        counter = Counter(self.artifact_status_counter)
        counter.pop("written", None)
        return counter

    @property
    def packages_with_partial_errors(self) -> int:
        """Packages that wrote artifacts but also surfaced errors."""

        return max(self.packages_with_errors - self.packages_failed, 0)

    @classmethod
    def from_run(
        cls,
        plan: HarvestPlan,
        harvest_result: HarvestResult,
        results: Sequence[PullResult],
    ) -> HarvestRunMetrics:
        """Compute aggregate statistics from the executed harvest."""

        total_packages = len(plan.packages)
        preflight_skips: Counter[str] = Counter()
        blocked_package_names = set()
        planned_artifacts = 0
        for package in plan.packages:
            if package.skip_reason:
                preflight_skips[package.skip_reason] += 1
                blocked_package_names.add(package.inventory.package_name)
                continue
            planned_artifacts += len(package.artifacts)

        artifact_status_counter: Counter[str] = Counter()
        packages_with_writes = 0
        packages_with_errors = 0
        packages_failed = 0
        packages_skipped_runtime = 0

        for package in harvest_result.packages:
            has_written = False
            for artifact in package.artifacts:
                status = artifact.status or "unknown"
                artifact_status_counter[status] += 1
                if status == "written":
                    has_written = True

            has_errors = bool(package.errors)
            has_skips = bool(package.skipped_reasons)

            if has_written:
                packages_with_writes += 1
            if has_errors:
                packages_with_errors += 1
                if not has_written:
                    packages_failed += 1
            if (
                has_skips
                and not has_written
                and not has_errors
                and package.package_name not in blocked_package_names
            ):
                packages_skipped_runtime += 1

        runtime_skips: Counter[str] = Counter()
        for result in results:
            runtime_skips.update(result.skipped)

        for reason, count in preflight_skips.items():
            remaining = runtime_skips.get(reason, 0) - count
            if remaining > 0:
                runtime_skips[reason] = remaining
            elif reason in runtime_skips:
                del runtime_skips[reason]

        artifacts_written = artifact_status_counter.get("written", 0)
        artifacts_failed = sum(len(result.errors) for result in results)

        executed_packages = total_packages - len(blocked_package_names)

        return cls(
            total_packages=total_packages,
            blocked_packages=len(blocked_package_names),
            executed_packages=executed_packages,
            planned_artifacts=planned_artifacts,
            artifacts_written=artifacts_written,
            artifacts_failed=artifacts_failed,
            artifact_status_counter=artifact_status_counter,
            packages_with_writes=packages_with_writes,
            packages_with_errors=packages_with_errors,
            packages_failed=packages_failed,
            packages_skipped_runtime=packages_skipped_runtime,
            runtime_skips=runtime_skips,
            preflight_skips=preflight_skips,
        )


def render_plan_summary(
    selection: ScopeSelection,
    plan: HarvestPlan,
    *,
    is_rooted: bool,
    include_system_partitions: bool,
    show_boxed: bool = False,
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

    if show_boxed:
        print()
        print(text_blocks.boxed(card_lines, width=70))

    _print_scope_filtering(selection)
    _print_exclusion_samples(selection.metadata.get("excluded_samples"))
    _print_exclusions(selection.metadata.get("excluded_counts"))
    _print_sample_focus(selection)

    # Structured, formatter-based overview for transcripts/screenshots.
    render_scope_overview(
        selection=selection,
        plan=plan,
        is_rooted=is_rooted,
        include_system_partitions=include_system_partitions,
    )


def preview_plan(plan: HarvestPlan, *, limit: int = 10) -> None:
    """Display a short preview of package/artifact combinations."""

    samples: list[str] = []
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

    # If nothing was pulled and all skips are due to non-root policy, suppress noise (counts already shown elsewhere).
    if (
        not verbose
        and not result.ok
        and not result.errors
        and result.skipped
        and all(reason == "policy_non_root" for reason in result.skipped)
    ):
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
    filtered_skips = []
    for reason in result.skipped:
        if not verbose and reason == "policy_non_root":
            continue  # suppress noisy per-package policy skips; counts shown elsewhere
        filtered_skips.append(reason)
    for reason in filtered_skips:
        print(status_messages.status(f"  ⤷ skipped: {_describe_reason(reason, _SKIP_LABELS)}", level="warn"))


def render_harvest_summary(
    plan: HarvestPlan,
    results: Sequence[PullResult],
    *,
    selection: ScopeSelection,
    pull_mode: str = "inventory",
    serial: str | None = None,
    run_timestamp: str | None = None,
    guard_brief: str | None = None,
    run_id: str | None = None,
    harvest_logger: logging_engine.ContextAdapter | None = None,
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

    metrics = HarvestRunMetrics.from_run(plan, harvest_result, results)
    files_written = metrics.artifacts_written
    pull_errors = metrics.artifacts_failed

    simple_mode = _harvest_simple_mode()
    if not simple_mode:
        print()
        print(text_blocks.headline("APK Harvest Summary", width=70))

    metadata = selection.metadata or {}
    summary_lines = _build_summary_card_lines(
        selection_label=selection.label,
        pull_mode=pull_mode,
        metadata=metadata,
        guard_brief=guard_brief,
        metrics=metrics,
        pull_errors=pull_errors,
    )
    scope_hash_changed = metadata.get("inventory_scope_hash_changed")

    quiet_mode = _harvest_quiet_mode()

    if simple_mode:
        print()
        status = "success"
        if metrics.packages_failed or metrics.packages_with_partial_errors:
            status = "partial"
        print(status_messages.status(f"status: {status}", level="success" if status == "success" else "warn"))
        print(
            status_messages.status(
                (
                    "packages: "
                    f"{metrics.total_packages} "
                    f"(clean={metrics.packages_successful} "
                    f"partial={metrics.packages_with_partial_errors} "
                    f"failed={metrics.packages_failed})"
                ),
                level="info",
            )
        )
        print(
            status_messages.status(
                (
                    "artifacts: "
                    f"{metrics.planned_artifacts} planned / "
                    f"{metrics.artifacts_written} written / "
                    f"{metrics.artifacts_failed} failed"
                ),
                level="info",
            )
        )
        output_root = _run_output_root(harvest_result)
        if output_root:
            print(status_messages.status(f"output: {output_root}", level="info"))
        if metadata.get("delta_filter_applied"):
            delta_total = metadata.get("delta_filter_total")
            delta_matched = metadata.get("delta_filter_matched")
            parts: list[str] = []
            if delta_total is not None:
                parts.append(f"changed={delta_total}")
            if delta_matched is not None:
                parts.append(f"matched_in_scope={delta_matched}")
            detail = f" ({', '.join(parts)})" if parts else ""
            print(status_messages.status(f"delta: applied{detail}", level="info"))
        if metrics.preflight_skips or metrics.runtime_skips:
            skip_parts: list[str] = []
            if metrics.preflight_skips:
                total = sum(metrics.preflight_skips.values())
                skip_parts.append(f"preflight={total}")
            if metrics.runtime_skips:
                total = sum(metrics.runtime_skips.values())
                skip_parts.append(f"runtime={total}")
            print(
                status_messages.status(
                    f"skips: {', '.join(skip_parts)}",
                    level="info",
                )
            )
        return

    if not simple_mode:
        print(text_blocks.boxed(summary_lines, width=70))

    highlights = _harvest_highlights(metrics, pull_errors)
    if highlights and not quiet_mode:
        print()
        print(text_blocks.headline("Highlights", width=70))
        for level, message in highlights:
            print(status_messages.status(message, level=level))

    if scope_hash_changed:
        print(
            status_messages.status(
                "Selected scope differs from the last recorded inventory.",
                level="warn",
            )
        )
    if pull_errors:
        print(status_messages.status("Review package errors above before re-running.", level="warn"))

    if plan.policy_filtered and not quiet_mode:
        policy_details = _format_policy_details(plan.policy_filtered)
        print(status_messages.status(f"Filtered before pull (policy): {policy_details}", level="warn"))
    if (metrics.preflight_skips or metrics.runtime_skips) and not quiet_mode:
        print()
        print(text_blocks.headline("Skipped packages", width=70))
        if metrics.preflight_skips:
            print(status_messages.status("Pre-flight filters:", level="info"))
            for reason, count in sorted(metrics.preflight_skips.items()):
                label = _describe_reason(reason, _SKIP_LABELS)
                print(status_messages.status(f"- {label}: {count}", level="info"))
        if metrics.runtime_skips:
            print(status_messages.status("During pull:", level="warn"))
            for reason, count in sorted(metrics.runtime_skips.items()):
                label = _describe_reason(reason, _SKIP_LABELS)
                print(status_messages.status(f"- {label}: {count}", level="warn"))

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
        if not quiet_mode:
            for package in denied:
                print(status_messages.status(f"  - {package}", level="warn"))

    if not quiet_mode:
        _print_exclusions(metadata.get("excluded_counts"))
        _print_exclusion_samples(metadata.get("excluded_samples"))
        _print_top_packages(
            results,
            limit=10 if _should_compact_view(selection, metrics, plan) else 5,
        )
        _print_sample_focus(selection)

    output_root = _run_output_root(harvest_result)
    if output_root and not simple_mode:
        print()
        print(status_messages.status("Artifacts saved under:", level="info"))
        print(status_messages.status(f"  {output_root}", level="info"))
        if not quiet_mode:
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
    if no_new and not quiet_mode:
        _print_no_new_summary(no_new)

    delta_summary = metadata.get("package_delta_summary")
    if delta_summary and not quiet_mode:
        print()
        print(
            text_blocks.headline(
                "Package changes since last snapshot", width=70
            )
        )
        _print_package_delta_summary(delta_summary)

    # Structured forensic-style summary (non-boxed) for transcripts/screenshots.
    if not quiet_mode:
        render_harvest_summary_structured(
            selection_label=selection.label,
            metrics=metrics,
            pull_mode=pull_mode,
            output_root=normalise_local_path(Path(output_root)) if output_root else None,
            preflight_skips=metrics.preflight_skips,
            runtime_skips=metrics.runtime_skips,
            policy_filtered=plan.policy_filtered,
            session_stamp=run_timestamp,
        )

    # Emit policy.filter details for scope shrinking
    if plan.policy_filtered:
        try:
            from scytaledroid.Utils.LoggingUtils import logging_events as log_events
            from scytaledroid.Utils.LoggingUtils.logging_context import RunContext, get_run_logger

            run_ctx = RunContext(
                subsystem="harvest",
                device_serial=serial,
                device_model=None,
                run_id=run_id or (run_timestamp or "HARVEST-RUN"),
                scope=selection.label,
                profile=pull_mode,
            )
            logger = harvest_logger or get_run_logger("harvest", run_ctx)
            logger.info(
                "Harvest policy.filter",
                extra={
                    "event": log_events.POLICY_FILTER,
                    "scope": selection.label,
                    "candidates": int(metadata.get("candidate_count") or 0),
                    "kept": int(metadata.get("selected_count") or metrics.total_packages),
                    "filtered_counts": plan.policy_filtered,
                },
            )
        except Exception:
            pass

    if not quiet_mode:
        print()
        print(status_messages.status("Next steps:", level="info"))
        print(status_messages.status("  • Review metadata via Database tools → Run database queries", level="info"))
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
            metrics.total_packages,
            files_written,
            harvest_logger=harvest_logger,
            run_id=run_id,
        )
        # Emit structured RUN_END to harvest logger for reproducibility.
        try:
            run_ctx = RunContext(
                subsystem="harvest",
                device_serial=harvest_result.device_serial if hasattr(harvest_result, "device_serial") else None,
                device_model=None,
                run_id=run_id or (run_timestamp or "HARVEST-RUN"),
                scope=selection.label,
                profile=pull_mode,
            )
            log_adapter = harvest_logger or get_run_logger("harvest", run_ctx)
            payload = {
                "event": log_events.RUN_END,
                "scope": selection.label,
                "pull_mode": pull_mode,
                "packages_total": metrics.total_packages,
                "packages_executed": metrics.executed_packages,
                "packages_blocked": metrics.blocked_packages,
                "artifacts_planned": metrics.planned_artifacts,
                "artifacts_written": metrics.artifacts_written,
                "artifacts_failed": metrics.artifacts_failed,
                "preflight_skips": dict(metrics.preflight_skips),
                "runtime_skips": dict(metrics.runtime_skips),
                "policy_filtered": plan.policy_filtered,
                "session_stamp": run_timestamp,
                "output_root": normalise_local_path(Path(output_root)) if output_root else None,
            }
            log_adapter.info("Harvest RUN_END", extra=payload)
        except Exception:
            pass


def _build_summary_card_lines(
    *,
    selection_label: str,
    pull_mode: str,
    metadata: dict[str, object],
    guard_brief: str | None,
    metrics: HarvestRunMetrics,
    pull_errors: int,
) -> list[str]:
    pull_label = {
        "quick": "Quick pull",
        "inventory": "Snapshot pull",
    }.get(pull_mode, pull_mode)

    lines = [
        _format_card_line("Scope", selection_label),
        _format_card_line("Pull", pull_label),
    ]

    package_pairs = _format_breakdown_pairs(
        [
            (metrics.packages_successful, "clean"),
            (metrics.packages_with_partial_errors, "partial issues"),
            (metrics.packages_failed, "failed"),
            (metrics.packages_skipped_runtime, "runtime skipped"),
            (metrics.blocked_packages, "blocked"),
        ]
    )
    lines.append(
        _format_card_line("Packages", f"{metrics.total_packages} total", package_pairs)
    )

    if metrics.planned_artifacts:
        artifact_value = f"{metrics.artifacts_written}/{metrics.planned_artifacts} saved"
    else:
        artifact_value = f"{metrics.artifacts_written} saved"

    artifact_pairs: list[tuple[int, str]] = []
    if metrics.artifacts_failed:
        artifact_pairs.append((metrics.artifacts_failed, "failed"))
    if metrics.dedupe_skips:
        artifact_pairs.append((metrics.dedupe_skips, "deduped"))
    for status, count in metrics.artifact_status_excluding_written.items():
        artifact_pairs.append((count, status.replace("_", " ")))

    artifact_breakdown = _format_breakdown_pairs(artifact_pairs)
    lines.append(_format_card_line("Artifacts", artifact_value, artifact_breakdown))

    guard_policy = metadata.get("inventory_policy")
    if guard_policy:
        policy_label = "Quick harvest" if guard_policy == "quick" else "Inventory refresh"
        stale_level = metadata.get("inventory_stale_level")
        if isinstance(stale_level, str) and stale_level:
            policy_label = f"{policy_label} (stale={stale_level})"
        lines.append(f"Policy  : {policy_label}")

    guard_brief_value = guard_brief or metadata.get("inventory_guard_brief")
    if metadata.get("render_guard_in_summary") and guard_brief_value:
        lines.append(f"Guard   : {guard_brief_value}")

    if metrics.runtime_skips:
        runtime_breakdown = _format_breakdown_pairs(
            [
                (
                    count,
                    _compact_label(_describe_reason(reason, _SKIP_LABELS)),
                )
                for reason, count in metrics.runtime_skips.items()
            ],
            limit=3,
        )
        lines.append(
            _format_card_line(
                "Runtime",
                f"{metrics.runtime_skip_total} skip(s)",
                runtime_breakdown,
            )
        )

    if pull_errors:
        lines.append(_format_card_line("Errors", f"{pull_errors} artifact(s)"))

    # Echo how the scope shrank from candidates to kept packages.
    candidates = int(metadata.get("candidate_count") or 0)
    selected = int(metadata.get("selected_count") or metrics.total_packages or 0)
    excluded_counts = metadata.get("excluded_counts") or {}
    if not candidates:
        candidates = selected + sum(int(v) for v in excluded_counts.values())
    if candidates:
        filtered = max(candidates - selected, 0)
        detail = f"kept {selected} of {candidates} candidates"
        breakdown = []
        for reason, count in sorted(excluded_counts.items()):
            if not count:
                continue
            label = _describe_reason(reason, _EXCLUSION_LABELS)
            breakdown.append(f"{label}={count}")
        if breakdown:
            detail = f"{detail} (filtered {filtered}: {', '.join(breakdown)})"
        else:
            detail = f"{detail} (filtered {filtered})"
        lines.append(_format_card_line("Scope", detail))

    return lines


def _harvest_highlights(
    metrics: HarvestRunMetrics, pull_errors: int
) -> list[tuple[str, str]]:
    highlights: list[tuple[str, str]] = []

    if metrics.packages_successful:
        highlights.append(
            (
                "success",
                f"{_count_phrase(metrics.packages_successful, 'package')} harvested cleanly",
            )
        )

    if metrics.packages_with_partial_errors:
        highlights.append(
            (
                "warn",
                (
                    f"{_count_phrase(metrics.packages_with_partial_errors, 'package')} "
                    "finished with partial errors"
                ),
            )
        )

    if metrics.packages_failed:
        highlights.append(
            (
                "error",
                f"{_count_phrase(metrics.packages_failed, 'package')} failed to save artifacts",
            )
        )

    if metrics.runtime_skip_total:
        top_reason = metrics.runtime_skips.most_common(1)
        if top_reason:
            reason_label = _describe_reason(top_reason[0][0], _SKIP_LABELS)
            detail = f" (top: {_compact_label(reason_label)})"
        else:
            detail = ""
        highlights.append(
            (
                "warn",
                f"{_count_phrase(metrics.runtime_skip_total, 'runtime skip')}{detail}",
            )
        )

    if pull_errors:
        highlights.append(
            (
                "warn",
                f"{_count_phrase(pull_errors, 'artifact error')} encountered",
            )
        )

    return highlights


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
    "HarvestRunMetrics",
    "preview_plan",
    "print_package_result",
    "render_harvest_summary",
    "render_plan_summary",
    "is_harvest_simple_mode",
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


def _print_exclusion_samples(samples: object) -> None:
    """
    Surface a few example package names that were filtered by scope policy,
    so it's obvious which apps were skipped.
    """
    if not samples:
        return
    try:
        entries = ((str(reason), list(names)) for reason, names in dict(samples).items())
    except Exception:
        return
    for reason, names in entries:
        if not names:
            continue
        label = _describe_reason(reason, _EXCLUSION_LABELS)
        preview = ", ".join(names)
        print(status_messages.status(f"  ↳ {label}: {preview}", level="info"))


def _print_scope_filtering(selection: ScopeSelection) -> None:
    """
    Show how many packages were in the candidate set vs how many remain after
    scope policy filters. Helps analysts understand why a category shrank.
    """
    meta = selection.metadata or {}
    candidates = int(meta.get("candidate_count") or 0)
    selected = int(meta.get("selected_count") or len(selection.packages) or 0)
    if not candidates:
        return
    dropped = max(candidates - selected, 0)
    msg = f"Scope kept {selected} of {candidates} candidate package(s)"
    if dropped:
        msg = f"{msg} (filtered out {dropped})"
    print(status_messages.status(msg, level="info"))


def _describe_reason(code: str, mapping: dict[str, str]) -> str:
    return mapping.get(code, code)


def _compact_label(label: str) -> str:
    if not label:
        return label
    return label.split(" (", 1)[0]


def _format_card_line(label: str, value: str, breakdown: Sequence[str | None] = None) -> str:
    line = f"{label:<8}: {value}"
    if breakdown:
        line = f"{line} ({' • '.join(breakdown)})"
    return line


def _count_phrase(count: int, noun: str) -> str:
    suffix = "" if count == 1 else "s"
    return f"{count} {noun}{suffix}"


def _format_breakdown_pairs(
    pairs: Sequence[tuple[int, str]],
    *,
    limit: int = 4,
) -> list[str]:
    formatted: list[str] = []
    for count, label in sorted(pairs, key=lambda item: (-item[0], item[1])):
        if not count:
            continue
        formatted.append(f"{count} {label}")
        if len(formatted) >= limit:
            break
    return formatted


def _format_policy_details(policy_counts: dict[str, int]) -> str:
    parts = []
    for reason, count in sorted(policy_counts.items()):
        label = _describe_reason(reason, _POLICY_LABELS)
        parts.append(f"{label}={count}")
    if not parts:
        total = sum(policy_counts.values())
        return str(total)
    return ", ".join(parts)


def _print_sample_focus(selection: ScopeSelection) -> None:
    # Prefer live package list; fall back to metadata if needed.
    live_samples = [pkg.display_name() for pkg in selection.packages[:5]]
    samples = live_samples or selection.metadata.get("sample_names")
    if not samples:
        print(status_messages.status("Focus packages: none in scope (filtered by policy)", level="info"))
        return
    preview = ", ".join(samples)
    if len(selection.packages) > len(samples):
        preview += ", …"
    print(status_messages.status(f"Focus packages: {preview}", level="info"))


def _build_harvest_result(
    plan: HarvestPlan,
    results: Sequence[PullResult],
    selection: ScopeSelection,
    *,
    serial: str | None,
    run_timestamp: str | None,
    guard_brief: str | None,
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


def _package_dest_dir(package: PackageHarvestResult) -> str | None:
    for artifact in package.artifacts:
        if artifact.dest_path:
            dest = Path(artifact.dest_path)
            return str(dest.parent)
    return None


def _run_output_root(result: HarvestResult) -> str | None:
    if not (result.serial and result.run_timestamp):
        return None
    base = Path(app_config.DATA_DIR) / "device_apks" / result.serial / result.run_timestamp
    return str(base)


def _packages_without_writes(
    harvest_result: HarvestResult,
) -> list[tuple[PackageHarvestResult, str | None]]:
    packages: list[tuple[PackageHarvestResult, str | None]] = []
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


def _should_compact_view(selection: ScopeSelection, metrics: HarvestRunMetrics, plan: HarvestPlan) -> bool:
    """
    Decide if console output should be compacted due to large scope/skip volumes.
    """
    meta = selection.metadata or {}
    candidates = int(meta.get("candidate_count") or 0)
    selected = int(meta.get("selected_count") or metrics.total_packages or 0)
    excluded_counts = meta.get("excluded_counts") or {}
    filtered = max(candidates - selected, 0) if candidates else 0
    policy_filtered = sum(int(v) for v in excluded_counts.values() if v)

    if filtered > 100 or policy_filtered > 100:
        return True
    if metrics.total_packages > 100:
        return True
    if metrics.planned_artifacts and metrics.planned_artifacts > 1000:
        return True
    return False


def _harvest_quiet_mode() -> bool:
    if _harvest_simple_mode():
        return True
    return os.getenv("SCYTALEDROID_HARVEST_QUIET", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _harvest_simple_mode() -> bool:
    return os.getenv("SCYTALEDROID_HARVEST_SIMPLE", "1").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def is_harvest_simple_mode() -> bool:
    return _harvest_simple_mode()



def _print_no_new_summary(no_new: list[tuple[PackageHarvestResult, str | None]]) -> None:
    """
    Summarize packages with no new artifacts, grouped by skip reason, with small samples.
    """
    if not no_new:
        return
    print()
    print(text_blocks.headline("No new artifacts", width=70))

    # Group by reason
    grouped: dict[str, list[str]] = {}
    for package, reason in no_new:
        key = reason or "Skipped"
        grouped.setdefault(key, []).append(package.display_name())

    for reason, names in sorted(grouped.items(), key=lambda item: -len(item[1])):
        count = len(names)
        samples = ", ".join(names[:5])
        suffix = f" … +{count - 5} more" if count > 5 else ""
        print(
            status_messages.status(
                f"• {reason}: {count} ({samples}{suffix})",
                level="warn",
            )
        )


def _print_package_delta_summary(summary: dict[str, object], *, limit: int = 10) -> None:
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
    no_new: list[tuple[PackageHarvestResult, str | None]],
    output_root: str | None,
    metadata: dict[str, object],
    pull_mode: str,
    total_packages: int,
    files_written: int,
    *,
    harvest_logger: logging_engine.ContextAdapter | None = None,
    run_id: str | None = None,
) -> None:
    payload = {
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
    if run_id:
        payload.setdefault("run_id", run_id)
    payload["event"] = "harvest.summary.report"

    extra = logging_engine.ensure_trace(payload)
    if harvest_logger is not None:
        harvest_logger.info("harvest.summary.report", extra=extra)
    else:
        log.info("Harvest summary", category="device_analysis", extra=extra)
