"""Render harvest summaries for analysts."""

from __future__ import annotations

import os
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from scytaledroid.DeviceAnalysis.services import artifact_store
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
from .summary_format_helpers import compact_label, count_phrase, format_card_line
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
    # DB mirror/index warnings (filesystem artifacts remain canonical).
    "app_definition_failed": "DB mirror: failed to record app definition (non-fatal)",
    "split_group_failed": "DB mirror: failed to record split group (non-fatal)",
    "apk_record_failed": "DB mirror: failed to record APK metadata (non-fatal)",
    "artifact_path_failed": "DB mirror: failed to record artifact path (non-fatal)",
    "source_path_failed": "DB mirror: failed to record source path (non-fatal)",
    "dedupe_sha256": "Duplicate artifact (sha256 dedupe)",
}

# Reasons that should never be presented as "skips" when artifacts were written.
_NON_FATAL_NOTES = {
    "app_definition_failed",
    "split_group_failed",
    "apk_record_failed",
    "artifact_path_failed",
    "source_path_failed",
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
    packages_drifted: int
    packages_with_mirror_failures: int
    packages_skipped_runtime: int
    runtime_skips: Counter[str]
    runtime_notes: Counter[str]
    preflight_skips: Counter[str]
    # Optional: which packages produced non-fatal runtime notes (e.g., DB mirror issues).
    # Kept out of strict contracts; used only to make operator output actionable.
    runtime_note_packages: dict[str, list[str]] = field(default_factory=dict)

    @property
    def dedupe_skips(self) -> int:
        """Number of artifacts skipped due to deduplication."""

        return self.runtime_skips.get("dedupe_sha256", 0)

    @property
    def packages_successful(self) -> int:
        """Packages that wrote artifacts without triggering errors."""

        return max(
            self.packages_with_writes - self.packages_with_partial_errors - self.packages_drifted,
            0,
        )

    @property
    def runtime_skip_total(self) -> int:
        """Total skips encountered during pull execution."""

        return sum(self.runtime_skips.values())

    @property
    def runtime_note_total(self) -> int:
        """Total non-fatal notes encountered during pull execution."""

        return sum(self.runtime_notes.values())

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
        packages_drifted = 0
        packages_skipped_runtime = 0
        packages_with_mirror_failures = 0

        for package in harvest_result.packages:
            has_written = False
            for artifact in package.artifacts:
                status = artifact.status or "unknown"
                artifact_status_counter[status] += 1
                if status == "written":
                    has_written = True

            has_errors = bool(package.errors)
            has_skips = bool(package.skipped_reasons)
            if package.capture_status == "drifted":
                packages_drifted += 1
            if package.persistence_status == "mirror_failed":
                packages_with_mirror_failures += 1

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
        runtime_notes: Counter[str] = Counter()
        runtime_note_packages: dict[str, set[str]] = {}
        for result in results:
            # If we wrote artifacts, DB mirror failures should be treated as notes rather than skips.
            wrote_any = bool(result.ok)
            for reason in result.skipped:
                if wrote_any and reason in _NON_FATAL_NOTES:
                    runtime_notes[reason] += 1
                    try:
                        pkg = (result.plan.inventory.package_name or "").strip()
                    except Exception:
                        pkg = ""
                    if pkg:
                        runtime_note_packages.setdefault(str(reason), set()).add(pkg)
                else:
                    runtime_skips[reason] += 1

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
            packages_drifted=packages_drifted,
            packages_with_mirror_failures=packages_with_mirror_failures,
            packages_skipped_runtime=packages_skipped_runtime,
            runtime_skips=runtime_skips,
            runtime_notes=runtime_notes,
            runtime_note_packages={k: sorted(v) for k, v in runtime_note_packages.items()},
            preflight_skips=preflight_skips,
        )


@dataclass
class HarvestRuntimeNoteSummary:
    """Structured summary of non-fatal runtime note interpretation."""

    total: int
    top_reasons: list[tuple[str, int]]
    affected_package_count: int
    packages_by_reason: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class HarvestRunReport:
    """Authoritative interpreted run summary for harvest rendering."""

    harvest_result: HarvestResult
    metrics: HarvestRunMetrics
    pull_errors: int
    files_written: int
    status: str
    status_level: str
    metadata: dict[str, object]
    scope_hash_changed: bool
    policy_filtered: dict[str, int]
    policy_details: str | None
    excluded_counts: dict[str, int]
    excluded_samples: dict[str, object]
    denied_packages: list[str]
    top_package_limit: int
    summary_card_lines: list[str]
    highlights: list[tuple[str, str]]
    artifacts_root: str | None
    receipts_root: str | None
    runtime_note_summary: HarvestRuntimeNoteSummary | None
    no_new: list[tuple[PackageHarvestResult, str | None]]
    delta_summary: dict[str, object] | None
    copy_line: str
    delta_line: str | None
    skip_counts_line: str | None
    package_rollup_line: str
    artifact_rollup_line: str


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


def build_harvest_run_report(
    plan: HarvestPlan,
    results: Sequence[PullResult],
    *,
    selection: ScopeSelection,
    pull_mode: str = "inventory",
    serial: str | None = None,
    run_timestamp: str | None = None,
    guard_brief: str | None = None,
    harvest_session_root: Path | str | None = None,
) -> HarvestRunReport:
    """Build the authoritative interpreted harvest run report."""

    harvest_result = _build_harvest_result(
        plan,
        results,
        selection,
        serial=serial,
        run_timestamp=run_timestamp,
        guard_brief=guard_brief,
    )
    metrics = HarvestRunMetrics.from_run(plan, harvest_result, results)
    pull_errors = metrics.artifacts_failed
    metadata = selection.metadata or {}
    status, status_level = _derive_harvest_status(metrics)
    runtime_note_summary = _build_runtime_note_summary(metrics)
    artifacts_root = _run_artifacts_root(serial=serial, result=harvest_result)
    if harvest_session_root is not None:
        artifacts_root = str(Path(harvest_session_root).expanduser().resolve())
    receipts_root = _run_receipts_root(harvest_result)
    delta_summary = metadata.get("package_delta_summary")

    return HarvestRunReport(
        harvest_result=harvest_result,
        metrics=metrics,
        pull_errors=pull_errors,
        files_written=metrics.artifacts_written,
        status=status,
        status_level=status_level,
        metadata=metadata,
        scope_hash_changed=bool(metadata.get("inventory_scope_hash_changed")),
        policy_filtered=dict(plan.policy_filtered),
        policy_details=_format_policy_details(plan.policy_filtered) if plan.policy_filtered else None,
        excluded_counts=dict(metadata.get("excluded_counts") or {}),
        excluded_samples=dict(metadata.get("excluded_samples") or {}),
        denied_packages=_collect_denied_packages(results),
        top_package_limit=10 if _should_compact_view(selection, metrics, plan) else 5,
        summary_card_lines=_build_summary_card_lines(
            selection_label=selection.label,
            pull_mode=pull_mode,
            metadata=metadata,
            guard_brief=guard_brief,
            metrics=metrics,
            pull_errors=pull_errors,
        ),
        highlights=_harvest_highlights(metrics, pull_errors),
        artifacts_root=artifacts_root,
        receipts_root=receipts_root,
        runtime_note_summary=runtime_note_summary,
        no_new=_packages_without_writes(harvest_result),
        delta_summary=delta_summary if isinstance(delta_summary, dict) else None,
        copy_line=_build_copy_line(
            selection_label=selection.label,
            metadata=metadata,
            status=status,
            metrics=metrics,
            runtime_note_summary=runtime_note_summary,
        ),
        delta_line=_build_delta_line(metadata),
        skip_counts_line=_build_skip_counts_line(metrics),
        package_rollup_line=(
            "packages: "
            f"total={metrics.total_packages} "
            f"executed={metrics.executed_packages} "
            f"blocked={metrics.blocked_packages} "
            f"(clean={metrics.packages_successful} "
            f"partial={metrics.packages_with_partial_errors} "
            f"failed={metrics.packages_failed})"
        ),
        artifact_rollup_line=(
            "artifacts: "
            f"{metrics.planned_artifacts} planned / "
            f"{metrics.artifacts_written} written / "
            f"{metrics.artifacts_failed} failed"
        ),
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
    harvest_session_root: Path | str | None = None,
) -> None:
    """Render the end-of-run summary with diagnostics."""
    report = build_harvest_run_report(
        plan,
        results,
        selection=selection,
        pull_mode=pull_mode,
        serial=serial,
        run_timestamp=run_timestamp,
        guard_brief=guard_brief,
        harvest_session_root=harvest_session_root,
    )
    harvest_result = report.harvest_result
    metrics = report.metrics

    simple_mode = _harvest_simple_mode()
    if not simple_mode:
        print()
        print(text_blocks.headline("APK Harvest Summary", width=70))
    metadata = report.metadata

    quiet_mode = _harvest_quiet_mode()

    if simple_mode:
        print()
        print(
            status_messages.status(
                _operator_harvest_finish_line(report, run_id=run_id),
                level=report.status_level,
            )
        )
        log.info(report.copy_line, category="device")
        if _harvest_transcript_copy_stdout():
            print(status_messages.status(report.copy_line, level="info"))
        art_disp = _storage_path_display(report.artifacts_root)
        rc_disp = _storage_path_display(report.receipts_root)
        path_line_parts: list[str] = []
        if run_timestamp:
            path_line_parts.append(f"session={run_timestamp}")
        if art_disp:
            path_line_parts.append(f"artifacts {art_disp}")
        if rc_disp:
            path_line_parts.append(f"receipts {rc_disp}")
        if path_line_parts:
            print(status_messages.status(" · ".join(path_line_parts), level="info"))
        if report.delta_line:
            print(status_messages.status(report.delta_line, level="info"))
        if report.runtime_note_summary:
            top = report.runtime_note_summary.top_reasons[:2]
            note_text = ", ".join(f"{reason}={count}" for reason, count in top)
            if report.runtime_note_summary.total > sum(c for _r, c in top):
                note_text = f"{note_text}, ..."
            note_line = (
                f"notes: db_mirror={report.runtime_note_summary.total} ({note_text})"
                + (
                    f" affected_pkgs={report.runtime_note_summary.affected_package_count}"
                    if report.runtime_note_summary.affected_package_count
                    else ""
                )
            )
            print(status_messages.status(note_line, level="info"))
            if report.runtime_note_summary.packages_by_reason:
                # Default: if only a few packages are affected, print them inline to avoid forcing
                # operators to re-run with verbose flags just to answer "which packages?".
                # Verbose mode prints full per-reason detail regardless of count.
                if _harvest_verbose_mode():
                    for reason, pkgs in sorted(report.runtime_note_summary.packages_by_reason.items()):
                        if not pkgs:
                            continue
                        joined = ", ".join(pkgs)
                        print(status_messages.status(f"notes detail: {reason}: {joined}", level="info"))
                else:
                    for reason, pkgs in sorted(report.runtime_note_summary.packages_by_reason.items()):
                        if not pkgs:
                            continue
                        if len(pkgs) <= 10:
                            joined = ", ".join(pkgs)
                            print(status_messages.status(f"notes pkgs: {reason}: {joined}", level="info"))

        if report.skip_counts_line and not _skip_counts_redundant_with_finish_line(report):
            print(status_messages.status(report.skip_counts_line, level="info"))

        # Compact mode: avoid duplicating rollups shown in dashboard-style menus downstream.
        # Leave the evidence path + notes/skips lines intact.
        if _harvest_compact_mode():
            return

        # Non-compact: print the human-readable rollups as well.
        print(status_messages.status(report.package_rollup_line, level="info"))
        print(status_messages.status(report.artifact_rollup_line, level="info"))
        return

    if not simple_mode:
        print(text_blocks.boxed(report.summary_card_lines, width=70))

    if report.highlights and not quiet_mode:
        print()
        print(text_blocks.headline("Highlights", width=70))
        for level, message in report.highlights:
            print(status_messages.status(message, level=level))

    if report.scope_hash_changed:
        print(
            status_messages.status(
                "Selected scope differs from the last recorded inventory.",
                level="warn",
            )
        )
    if report.pull_errors:
        print(status_messages.status("Review package errors above before re-running.", level="warn"))

    if report.policy_details and not quiet_mode:
        print(status_messages.status(f"Filtered before pull (policy): {report.policy_details}", level="warn"))
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

    if report.denied_packages:
        print(status_messages.status("Permission denied (requires root):", level="warn"))
        if not quiet_mode:
            for package in report.denied_packages:
                print(status_messages.status(f"  - {package}", level="warn"))

    if not quiet_mode:
        _print_exclusions(report.excluded_counts)
        _print_exclusion_samples(report.excluded_samples)
        _print_top_packages(
            results,
            limit=report.top_package_limit,
        )
        _print_sample_focus(selection)

    if report.artifacts_root and not simple_mode:
        print()
        print(status_messages.status("Artifacts saved under:", level="info"))
        print(status_messages.status(f"  {report.artifacts_root}", level="info"))
        if report.receipts_root:
            print(status_messages.status("Receipts saved under:", level="info"))
            print(status_messages.status(f"  {report.receipts_root}", level="info"))
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

    if report.no_new and not quiet_mode:
        _print_no_new_summary(report.no_new)

    if report.delta_summary and not quiet_mode:
        print()
        print(
            text_blocks.headline(
                "Package changes since last snapshot", width=70
            )
        )
        _print_package_delta_summary(report.delta_summary)

    # Structured forensic-style summary (non-boxed) for transcripts/screenshots.
    if not quiet_mode:
        render_harvest_summary_structured(
            selection_label=selection.label,
            metrics=metrics,
            pull_mode=pull_mode,
            output_root=normalise_local_path(Path(report.artifacts_root)) if report.artifacts_root else None,
            receipts_root=normalise_local_path(Path(report.receipts_root)) if report.receipts_root else None,
            preflight_skips=metrics.preflight_skips,
            runtime_skips=metrics.runtime_skips,
            policy_filtered=report.policy_filtered,
            session_stamp=run_timestamp,
        )

    # Emit policy.filter details for scope shrinking
    if report.policy_filtered:
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
                    "filtered_counts": report.policy_filtered,
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
            report.no_new,
            report.artifacts_root,
            metadata,
            pull_mode,
            metrics.total_packages,
            report.files_written,
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
                "policy_filtered": report.policy_filtered,
                "session_stamp": run_timestamp,
                "output_root": normalise_local_path(Path(report.artifacts_root)) if report.artifacts_root else None,
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
        format_card_line("Scope", selection_label),
        format_card_line("Pull", pull_label),
    ]

    package_pairs = _format_breakdown_pairs(
        [
            (metrics.executed_packages, "executed"),
            (metrics.blocked_packages, "blocked"),
        ]
    )
    lines.append(
        format_card_line("Packages", f"{metrics.total_packages} total", package_pairs)
    )

    outcome_pairs = _format_breakdown_pairs(
        [
            (metrics.packages_successful, "clean"),
            (metrics.packages_with_partial_errors, "partial issues"),
            (metrics.packages_failed, "failed"),
            (metrics.packages_skipped_runtime, "runtime skipped"),
        ]
    )
    if outcome_pairs:
        lines.append(format_card_line("Results", "executed outcomes", outcome_pairs))

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
    lines.append(format_card_line("Artifacts", artifact_value, artifact_breakdown))

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
                    compact_label(_describe_reason(reason, _SKIP_LABELS)),
                )
                for reason, count in metrics.runtime_skips.items()
            ],
            limit=3,
        )
        lines.append(
            format_card_line(
                "Runtime",
                f"{metrics.runtime_skip_total} skip(s)",
                runtime_breakdown,
            )
        )

    if pull_errors:
        lines.append(format_card_line("Errors", f"{pull_errors} artifact(s)"))

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
        lines.append(format_card_line("Scope", detail))

    return lines


def _harvest_highlights(
    metrics: HarvestRunMetrics, pull_errors: int
) -> list[tuple[str, str]]:
    highlights: list[tuple[str, str]] = []

    if metrics.packages_successful:
        highlights.append(
            (
                "success",
                f"{count_phrase(metrics.packages_successful, 'package')} harvested cleanly",
            )
        )

    if metrics.packages_with_partial_errors:
        highlights.append(
            (
                "warn",
                (
                    f"{count_phrase(metrics.packages_with_partial_errors, 'package')} "
                    "finished with partial errors"
                ),
            )
        )

    if metrics.packages_failed:
        highlights.append(
            (
                "error",
                f"{count_phrase(metrics.packages_failed, 'package')} failed to save artifacts",
            )
        )

    if metrics.runtime_skip_total:
        top_reason = metrics.runtime_skips.most_common(1)
        if top_reason:
            reason_label = _describe_reason(top_reason[0][0], _SKIP_LABELS)
            detail = f" (top: {compact_label(reason_label)})"
        else:
            detail = ""
        highlights.append(
            (
                "warn",
                f"{count_phrase(metrics.runtime_skip_total, 'runtime skip')}{detail}",
            )
        )

    if pull_errors:
        highlights.append(
            (
                "warn",
                f"{count_phrase(pull_errors, 'artifact error')} encountered",
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
    "HarvestRunReport",
    "HarvestRuntimeNoteSummary",
    "build_harvest_run_report",
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


def _harvest_transcript_copy_stdout() -> bool:
    """Paste-friendly [COPY] line for transcripts; logs always carry the full string."""

    return os.getenv("SCYTALEDROID_HARVEST_COPY_LINE", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _operator_harvest_finish_line(report: HarvestRunReport, *, run_id: str | None = None) -> str:
    m = report.metrics
    scope = getattr(report.harvest_result, "scope_name", None) or "unknown"
    parts = [
        f"Harvest finished ({report.status})",
        f"scope={scope}",
        f"pulled {m.executed_packages}/{m.total_packages} packages",
    ]
    if run_id:
        parts.append(f"run_id={run_id}")
    if m.blocked_packages:
        parts.append(f"skipped {m.blocked_packages} (preflight/policy)")
    if m.planned_artifacts:
        parts.append(f"artifacts {m.artifacts_written}/{m.planned_artifacts} written")
    return " · ".join(parts)


def _storage_path_display(path_str: str | None) -> str | None:
    if not path_str:
        return None
    try:
        return artifact_store.repo_relative_path(Path(path_str))
    except Exception:
        return path_str


def _skip_counts_redundant_with_finish_line(report: HarvestRunReport) -> bool:
    """Single preflight bucket matching all blocked packages — already spelled out above."""

    m = report.metrics
    if not m.preflight_skips or m.runtime_skips:
        return False
    return sum(m.preflight_skips.values()) == m.blocked_packages and len(m.preflight_skips) == 1


def _derive_harvest_status(metrics: HarvestRunMetrics) -> tuple[str, str]:
    status = "success"
    if metrics.packages_with_mirror_failures and metrics.executed_packages and (
        metrics.packages_with_mirror_failures >= metrics.executed_packages
    ):
        status = "degraded_db_mirror_total_loss"
    elif metrics.packages_with_mirror_failures:
        status = "degraded"
    elif metrics.packages_drifted or metrics.packages_failed or metrics.packages_with_partial_errors:
        status = "partial"

    level = "success" if status == "success" else "warn"
    if status == "degraded_db_mirror_total_loss":
        level = "error"
    return status, level


def _build_runtime_note_summary(metrics: HarvestRunMetrics) -> HarvestRuntimeNoteSummary | None:
    if not metrics.runtime_notes:
        return None

    affected = set()
    for pkgs in (metrics.runtime_note_packages or {}).values():
        affected.update(pkgs)
    return HarvestRuntimeNoteSummary(
        total=metrics.runtime_note_total,
        top_reasons=metrics.runtime_notes.most_common(),
        affected_package_count=len(affected),
        packages_by_reason=dict(metrics.runtime_note_packages or {}),
    )


def _build_copy_line(
    *,
    selection_label: str,
    metadata: dict[str, object],
    status: str,
    metrics: HarvestRunMetrics,
    runtime_note_summary: HarvestRuntimeNoteSummary | None,
) -> str:
    harvest_mode = metadata.get("harvest_mode") or ""
    delta_applied = bool(metadata.get("delta_filter_applied"))
    note_pkg_count = runtime_note_summary.affected_package_count if runtime_note_summary else 0
    return (
        "[COPY] harvest "
        f"scope={selection_label!r} "
        f"status={status} "
        f"packages_total={metrics.total_packages} "
        f"packages_executed={metrics.executed_packages} "
        f"packages_blocked={metrics.blocked_packages} "
        f"clean={metrics.packages_successful} "
        f"partial={metrics.packages_with_partial_errors} "
        f"failed={metrics.packages_failed} "
        f"drifted={metrics.packages_drifted} "
        f"mirror_failed={metrics.packages_with_mirror_failures} "
        f"artifacts_planned={metrics.planned_artifacts} "
        f"artifacts_written={metrics.artifacts_written} "
        f"artifacts_failed={metrics.artifacts_failed} "
        f"harvest_mode={harvest_mode!s} "
        f"delta_applied={'true' if delta_applied else 'false'} "
        f"runtime_notes={metrics.runtime_note_total} "
        f"runtime_note_pkgs={note_pkg_count} "
        f"runtime_skips={sum(metrics.runtime_skips.values())}"
    )


def _build_delta_line(metadata: dict[str, object]) -> str | None:
    if not metadata.get("delta_filter_applied"):
        return None
    delta_total = metadata.get("delta_filter_total")
    delta_matched = metadata.get("delta_filter_matched")
    parts: list[str] = []
    if delta_total is not None:
        parts.append(f"changed={delta_total}")
    if delta_matched is not None:
        parts.append(f"matched_in_scope={delta_matched}")
    detail = f" ({', '.join(parts)})" if parts else ""
    return f"delta: applied{detail}"


def _build_skip_counts_line(metrics: HarvestRunMetrics) -> str | None:
    if not (metrics.preflight_skips or metrics.runtime_skips):
        return None
    skip_parts: list[str] = []
    if metrics.preflight_skips:
        skip_parts.append(f"preflight={sum(metrics.preflight_skips.values())}")
    if metrics.runtime_skips:
        skip_parts.append(f"runtime={sum(metrics.runtime_skips.values())}")
    if not skip_parts:
        return None
    return f"skips: {', '.join(skip_parts)}"


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


def _collect_denied_packages(results: Sequence[PullResult]) -> list[str]:
    return sorted(
        {
            result.plan.inventory.package_name
            for result in results
            for error in result.errors
            if "permission" in error.reason.lower()
        }
    )


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
            preflight_reason=pull.preflight_reason,
            mirror_failure_reasons=list(pull.mirror_failure_reasons),
            drift_reasons=list(pull.drift_reasons),
            capture_status=pull.capture_status,
            persistence_status=pull.persistence_status,
            research_status=pull.research_status,
            manifest_path=normalise_local_path(pull.package_manifest_path) if pull.package_manifest_path else None,
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


def _run_receipts_root(result: HarvestResult) -> str | None:
    if not result.run_timestamp:
        return None
    base = artifact_store.harvest_receipts_root() / result.run_timestamp
    return str(base)


def _run_artifacts_root(*, serial: str | None, result: HarvestResult) -> str | None:
    if not serial:
        return None
    harvest_base = artifact_store.device_apks_root().resolve()
    for pkg in result.packages:
        manifest_raw = pkg.manifest_path
        if not manifest_raw:
            continue
        manifest = Path(str(manifest_raw))
        if manifest.is_absolute():
            candidate = manifest.parent.parent
        else:
            candidate = (harvest_base / manifest).resolve().parent.parent
        try:
            candidate.relative_to(harvest_base / serial.strip())
        except ValueError:
            continue
        return str(candidate.resolve())
    if result.run_timestamp:
        ts = str(result.run_timestamp).strip()
        serial_p = harvest_base / serial.strip()
        if len(ts) == 8 and ts.isdigit():
            return str((serial_p / ts).resolve())
        if len(ts) > 9 and ts[8] == "_" and ts[:8].isdigit():
            return str((serial_p / ts[:8] / ts[9:]).resolve())
        return str((serial_p / "runs" / ts).resolve())
    return None


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


def _harvest_compact_mode() -> bool:
    # Default to compact operator output for harvest; detailed logs are available via verbose flags.
    return os.getenv("SCYTALEDROID_HARVEST_COMPACT", "1").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _harvest_verbose_mode() -> bool:
    # When enabled, include extra operator-facing detail (e.g., list affected packages for notes).
    return os.getenv("SCYTALEDROID_HARVEST_VERBOSE", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }



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
