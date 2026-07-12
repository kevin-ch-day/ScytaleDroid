"""Pure harvest report builders shared by CLI summary rendering."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from scytaledroid.DeviceAnalysis.services import artifact_store

from . import stale_replan
from .common import normalise_local_path
from .models import (
    ArtifactSummary,
    HarvestPlan,
    HarvestResult,
    PackageHarvestResult,
    PullResult,
    ScopeSelection,
)
from .status import HarvestRunStatus, build_harvest_run_status
from .summary_format_helpers import compact_label, count_phrase, format_card_line

EXCLUSION_LABELS = {
    "family_excluded": "Family excluded (com.android./com.motorola. not Play)",
    "google_core": "Google core modules (not Play/allow-list)",
    "not_in_scope": "Not in scope (no Play installer or /data path)",
}

POLICY_LABELS = {
    "non_root_paths": "System/vendor/mainline (non-root policy)",
}

SKIP_LABELS = {
    "policy_non_root": "System/vendor/mainline filtered by policy",
    "no_paths": "Package returned no APK paths",
    "apk_library_hit": "APK library reuse (already indexed)",
    # DB mirror/index warnings (filesystem artifacts remain canonical).
    "app_definition_failed": "DB mirror: failed to record app definition (non-fatal)",
    "split_group_failed": "DB mirror: failed to record split group (non-fatal)",
    "apk_record_failed": "DB mirror: failed to record APK metadata (non-fatal)",
    "artifact_path_failed": "DB mirror: failed to record artifact path (non-fatal)",
    "source_path_failed": "DB mirror: failed to record source path (non-fatal)",
    "dedupe_sha256": "Duplicate artifact (sha256 dedupe)",
}

# Reasons that should never be presented as "skips" when artifacts were written.
NON_FATAL_NOTES = {
    "app_definition_failed",
    "split_group_failed",
    "apk_record_failed",
    "artifact_path_failed",
    "source_path_failed",
}


def _describe_reason(code: str, mapping: dict[str, str]) -> str:
    return mapping.get(code, code)


def _result_flag(result: PullResult, name: str, default: bool = False) -> bool:
    """Return boolean result flags with backward-compatible defaults."""

    return bool(getattr(result, name, default))


def _result_text(result: PullResult, name: str) -> str | None:
    """Return optional text attributes from result-like objects safely."""

    value = getattr(result, name, None)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


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
    reviewed_packages: int = 0
    eligible_packages: int = 0
    harvested_packages: int = 0
    path_stale_packages: int = 0
    replanned_packages: int = 0
    replan_success_packages: int = 0
    replan_failed_packages: int = 0
    replan_recovered_packages: int = 0
    write_db_requested: bool = False
    write_db_effective: bool = True

    @property
    def dedupe_skips(self) -> int:
        """Number of artifacts skipped due to deduplication."""

        return self.runtime_skips.get("dedupe_sha256", 0)

    @property
    def artifacts_reused_from_library(self) -> int:
        """Number of APK artifact paths resolved from the APK library."""

        return self.artifact_status_counter.get("library_hit", 0)

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
            wrote_any = bool(result.ok)
            for reason in result.skipped:
                if wrote_any and reason in NON_FATAL_NOTES:
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

        executed_packages = sum(1 for result in results if not result.preflight_reason)
        eligible_packages = total_packages - len(blocked_package_names)
        harvested_packages = sum(1 for result in results if result.ok)
        path_stale_packages = sum(1 for result in results if _result_flag(result, "stale_replan_required"))
        replanned_packages = sum(1 for result in results if _result_text(result, "stale_replan_outcome"))
        replan_success_packages = sum(
            1
            for result in results
            if stale_replan.is_successful_stale_replan_outcome(
                _result_text(result, "stale_replan_outcome")
            )
        )
        replan_failed_packages = sum(
            1
            for result in results
            if stale_replan.is_failed_stale_replan_outcome(
                _result_text(result, "stale_replan_outcome")
            )
        )
        replan_recovered_packages = sum(
            1
            for result in results
            if stale_replan.is_recovered_stale_replan_result(
                _result_text(result, "stale_replan_outcome"),
                _result_text(result, "capture_status"),
            )
        )

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
            reviewed_packages=len(results),
            eligible_packages=eligible_packages,
            harvested_packages=harvested_packages,
            path_stale_packages=path_stale_packages,
            replanned_packages=replanned_packages,
            replan_success_packages=replan_success_packages,
            replan_failed_packages=replan_failed_packages,
            replan_recovered_packages=replan_recovered_packages,
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
    status_summary: HarvestRunStatus
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
    write_db_requested: bool | None = None,
    write_db_effective: bool | None = None,
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
    if write_db_requested is not None:
        metrics.write_db_requested = bool(write_db_requested)
    elif metrics.packages_with_mirror_failures > 0:
        metrics.write_db_requested = True
    if write_db_effective is not None:
        metrics.write_db_effective = bool(write_db_effective)
    elif metrics.packages_with_mirror_failures >= metrics.executed_packages and metrics.executed_packages > 0:
        metrics.write_db_effective = False
    pull_errors = metrics.artifacts_failed
    metadata = selection.metadata or {}
    status_summary = _derive_harvest_status(metrics, results)
    status = status_summary.status
    status_level = status_summary.status_level
    runtime_note_summary = _build_runtime_note_summary(metrics)
    artifacts_root = _run_artifacts_root(serial=serial, result=harvest_result)
    if harvest_session_root is not None:
        artifacts_root = str(Path(harvest_session_root).expanduser().resolve())
    receipts_root = _run_receipts_root(harvest_result)
    delta_summary = metadata.get("package_delta_summary")

    return HarvestRunReport(
        harvest_result=harvest_result,
        metrics=metrics,
        status_summary=status_summary,
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
            f"packages: total={metrics.total_packages} reviewed={metrics.reviewed_packages} "
            f"eligible={metrics.eligible_packages} attempted={metrics.executed_packages} "
            f"blocked={metrics.blocked_packages} clean={metrics.packages_successful} "
            f"partial={metrics.packages_with_partial_errors} failed={metrics.packages_failed} "
            f"drifted={metrics.packages_drifted} mirror_failed={metrics.packages_with_mirror_failures} "
            f"runtime_skipped={metrics.packages_skipped_runtime}"
        ),
        artifact_rollup_line=(
            f"artifacts: planned={metrics.planned_artifacts} written={metrics.artifacts_written} "
            f"failed={metrics.artifacts_failed} deduped={metrics.dedupe_skips}"
        ),
    )


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
            (metrics.reviewed_packages, "reviewed"),
            (metrics.eligible_packages, "eligible"),
            (metrics.executed_packages, "attempted"),
            (metrics.blocked_packages, "blocked before pull"),
        ]
    )
    lines.append(format_card_line("Packages", f"{metrics.total_packages} total", package_pairs))

    library_reuse_packages = metrics.runtime_skips.get("apk_library_hit", 0)
    operator_runtime_skipped = max(metrics.packages_skipped_runtime - library_reuse_packages, 0)
    outcome_pairs = _format_breakdown_pairs(
        [
            (metrics.packages_successful, "pulled clean"),
            (metrics.harvested_packages, "resolved"),
            (metrics.packages_with_partial_errors, "partial issues"),
            (metrics.packages_failed, "failed"),
            (operator_runtime_skipped, "runtime skipped"),
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
        if set(metrics.runtime_skips) == {"apk_library_hit"}:
            lines.append(
                format_card_line(
                    "Reuse",
                    f"{metrics.runtime_skip_total} package(s) already in APK library",
                )
            )
        else:
            runtime_breakdown = _format_breakdown_pairs(
                [
                    (count, compact_label(_describe_reason(reason, SKIP_LABELS)))
                    for reason, count in metrics.runtime_skips.items()
                ],
                limit=3,
            )
            lines.append(
                format_card_line("Runtime", f"{metrics.runtime_skip_total} skip(s)", runtime_breakdown)
            )

    replan_pairs = _format_breakdown_pairs(
        [
            (metrics.path_stale_packages, "path stale"),
            (metrics.replanned_packages, "replanned"),
            (metrics.replan_recovered_packages, "recovered"),
            (metrics.replan_success_packages, "replan ok"),
            (metrics.replan_failed_packages, "replan failed"),
        ]
    )
    if replan_pairs:
        lines.append(format_card_line("Replan", "stale-path triage", replan_pairs))

    if pull_errors:
        lines.append(format_card_line("Errors", f"{pull_errors} artifact(s)"))

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
            label = _describe_reason(reason, EXCLUSION_LABELS)
            breakdown.append(f"{label}={count}")
        if breakdown:
            detail = f"{detail} (filtered {filtered}: {', '.join(breakdown)})"
        else:
            detail = f"{detail} (filtered {filtered})"
        lines.append(format_card_line("Scope", detail))

    return lines


def _harvest_highlights(metrics: HarvestRunMetrics, pull_errors: int) -> list[tuple[str, str]]:
    highlights: list[tuple[str, str]] = []

    if metrics.packages_successful:
        highlights.append(
            (
                "success",
                f"{count_phrase(metrics.packages_successful, 'package')} pulled cleanly",
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
        if set(metrics.runtime_skips) == {"apk_library_hit"}:
            highlights.append(
                (
                    "info",
                    f"{count_phrase(metrics.runtime_skip_total, 'package')} reused from APK library",
                )
            )
        elif top_reason:
            reason_label = _describe_reason(top_reason[0][0], SKIP_LABELS)
            detail = f" (top: {compact_label(reason_label)})"
            highlights.append(
                (
                    "warn",
                    f"{count_phrase(metrics.runtime_skip_total, 'runtime skip')}{detail}",
                )
            )
        else:
            highlights.append(("warn", f"{count_phrase(metrics.runtime_skip_total, 'runtime skip')}"))

    if pull_errors:
        highlights.append(
            ("warn", f"{count_phrase(pull_errors, 'artifact error')} encountered")
        )

    return highlights


def _derive_harvest_status(
    metrics: HarvestRunMetrics,
    results: Sequence[PullResult],
) -> HarvestRunStatus:
    library_reuse_packages = metrics.runtime_skips.get("apk_library_hit", 0)
    operator_runtime_skips = max(metrics.packages_skipped_runtime - library_reuse_packages, 0)
    return build_harvest_run_status(
        packages_total=metrics.total_packages,
        packages_reviewed=metrics.reviewed_packages,
        eligible_count=metrics.eligible_packages,
        attempted_count=metrics.executed_packages,
        harvested_count=metrics.harvested_packages,
        blocked_preflight_count=metrics.blocked_packages,
        skipped_count=operator_runtime_skips,
        failed_count=metrics.packages_failed,
        partial_count=metrics.packages_with_partial_errors,
        drifted_count=metrics.packages_drifted,
        path_stale_count=metrics.path_stale_packages,
        replanned_count=metrics.replanned_packages,
        replan_success_count=metrics.replan_success_packages,
        replan_failed_count=metrics.replan_failed_packages,
        replan_recovered_count=metrics.replan_recovered_packages,
        device_unavailable=any(
            error.reason == "device_unavailable"
            for result in results
            for error in result.errors
        ),
        mirror_failed_count=metrics.packages_with_mirror_failures,
        write_db_requested=metrics.write_db_requested,
        write_db_effective=metrics.write_db_effective,
    )


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
        library_hits = metrics.runtime_skips.get("apk_library_hit", 0)
        other_runtime = sum(metrics.runtime_skips.values()) - library_hits
        if library_hits:
            skip_parts.append(f"runtime_reused={library_hits}")
        if other_runtime:
            skip_parts.append(f"runtime={other_runtime}")
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
        label = _describe_reason(reason, POLICY_LABELS)
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
            reason = _describe_reason(package.skipped_reasons[0], SKIP_LABELS)
        elif package.errors:
            reason = package.errors[0].reason
        packages.append((package, reason))
    return packages


def _should_compact_view(selection: ScopeSelection, metrics: HarvestRunMetrics, plan: HarvestPlan) -> bool:
    """Decide if console output should be compacted due to large scope/skip volumes."""

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
