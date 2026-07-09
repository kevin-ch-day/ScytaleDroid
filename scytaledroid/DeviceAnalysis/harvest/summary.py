"""Render harvest summaries for analysts."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

from scytaledroid.DeviceAnalysis.services import artifact_store
from scytaledroid.Utils.DisplayUtils import status_messages, text_blocks
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .common import normalise_local_path
from .models import (
    HarvestPlan,
    HarvestResult,
    PackageHarvestResult,
    PullResult,
    ScopeSelection,
)
from .report_model import (
    EXCLUSION_LABELS as _EXCLUSION_LABELS,
    SKIP_LABELS as _SKIP_LABELS,
    HarvestRunMetrics,
    HarvestRunReport,
    HarvestRuntimeNoteSummary,
    _build_summary_card_lines,
    _format_policy_details,
    build_harvest_run_report,
)
from .views import render_harvest_summary_structured, render_scope_overview


def render_plan_summary(
    selection: ScopeSelection,
    plan: HarvestPlan,
    *,
    is_rooted: bool,
    include_system_partitions: bool,
    show_boxed: bool = False,
) -> None:
    """Present a concise overview of the planned harvest prior to execution."""

    in_inventory = len(plan.packages)
    scheduled_packages = sum(1 for pkg in plan.packages if not pkg.skip_reason)
    blocked_packages = sum(1 for pkg in plan.packages if pkg.skip_reason)
    policy_blocked = sum(1 for pkg in plan.packages if pkg.skip_reason == "policy_non_root")
    scope_blocked = max(blocked_packages - policy_blocked, 0)
    scheduled_files = sum(len(pkg.artifacts) for pkg in plan.packages if not pkg.skip_reason)
    card_lines = [
        f"Scope              : {selection.label}",
        f"Inventory scope    : {in_inventory} packages",
        f"Eligible to pull   : {scheduled_packages} packages",
        f"Blocked by policy  : {policy_blocked} packages",
        f"Blocked by scope   : {scope_blocked} packages",
        f"Est. artifacts     : ~{scheduled_files} APK paths (splits separate)",
    ]

    if plan.policy_filtered:
        policy_details = _format_policy_details(plan.policy_filtered)
        card_lines.append(f"Path policy detail : {policy_details}")
    if not include_system_partitions and not is_rooted:
        card_lines.append("Device policy      : non-root (system/vendor paths blocked)")

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
    harvest_session_root: Path | str | None = None,
    report: HarvestRunReport | None = None,
) -> None:
    """Render the end-of-run summary with diagnostics."""
    if report is None:
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
        f"attempted {m.executed_packages} eligible package(s) under policy",
        f"{m.total_packages} package row(s) in this harvest plan",
    ]
    if run_id:
        parts.append(f"run_id={run_id}")
    if m.blocked_packages:
        parts.append(f"policy-blocked {m.blocked_packages} (skipped before pull)")
    if m.planned_artifacts:
        artifact_summary = f"artifacts {m.artifacts_written}/{m.planned_artifacts} written"
        if m.artifacts_reused_from_library:
            artifact_summary = (
                f"{artifact_summary}, {m.artifacts_reused_from_library} reused from APK library"
            )
        parts.append(f"{artifact_summary} (APK paths, splits count separately)")
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

def _package_dest_dir(package: PackageHarvestResult) -> str | None:
    for artifact in package.artifacts:
        if artifact.dest_path:
            dest = Path(artifact.dest_path)
            return str(dest.parent)
    return None

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
