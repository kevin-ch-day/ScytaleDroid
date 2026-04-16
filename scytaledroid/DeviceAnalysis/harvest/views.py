"""CLI views for harvest using the shared formatter (forensic style).

These helpers are intentionally presentation-only. They take already-computed
metrics/selection objects and render readable summaries with the `[RUN]`,
`[RESULT]`, and `[EVIDENCE]` prefixes used across the workstation.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from scytaledroid.ui import formatter

from .models import HarvestPlan, ScopeSelection

if TYPE_CHECKING:  # pragma: no cover
    from .summary import HarvestRunMetrics


def render_scope_overview(
    selection: ScopeSelection,
    plan: HarvestPlan,
    *,
    is_rooted: bool,
    include_system_partitions: bool,
) -> None:
    """Print a concise scope overview before execution."""

    scheduled_packages = sum(1 for pkg in plan.packages if not pkg.skip_reason)
    blocked_packages = sum(1 for pkg in plan.packages if pkg.skip_reason)
    scheduled_files = sum(len(pkg.artifacts) for pkg in plan.packages if not pkg.skip_reason)
    blocked_text = f" (blocked {blocked_packages})" if blocked_packages else ""

    formatter.print_header("APK Harvest · RUN START")
    print(
        formatter.format_kv_block(
            "[RUN]",
            {
                "Scope": selection.label,
                "Packages": f"{scheduled_packages}{blocked_text}",
                "Artifacts": f"~{scheduled_files}",
            },
        )
    )
    print()

    if plan.policy_filtered:
        print("[RESULT] Filtered by policy:")
        for reason, count in plan.policy_filtered.items():
            print(f"  - {reason}: {count}")
        print()

    policy_lines = []
    if plan.policy_filtered:
        policy_lines.append("Policy filters applied")
    if not include_system_partitions and not is_rooted:
        policy_lines.append("System/vendor excluded (non-root)")
    if policy_lines:
        print(formatter.format_kv_block("[META]", {"Policy": "; ".join(policy_lines)}))
        print()


def render_harvest_summary_structured(
    *,
    selection_label: str,
    metrics: HarvestRunMetrics,
    pull_mode: str,
    output_root: str | None = None,
    receipts_root: str | None = None,
    preflight_skips: Mapping[str, int] | None = None,
    runtime_skips: Mapping[str, int] | None = None,
    policy_filtered: Mapping[str, int] | None = None,
    session_stamp: str | None = None,
) -> None:
    """Structured end-of-run summary (non-boxed, formatter-based)."""

    formatter.print_header("APK Harvest · RUN SUMMARY")
    run_pairs = {
        "Scope": selection_label,
        "Harvest mode": pull_mode,
    }
    if session_stamp:
        run_pairs["Session"] = session_stamp
    print(formatter.format_kv_block("[RUN]", run_pairs))
    print()

    result_pairs = {
        "Packages": (
            f"total={metrics.total_packages}  "
            f"executed={metrics.executed_packages}  "
            f"blocked={metrics.blocked_packages}"
        ),
        "Artifacts": (
            f"planned={metrics.planned_artifacts}  "
            f"written={metrics.artifacts_written}  "
            f"failed={metrics.artifacts_failed}"
        ),
        "Packages (outcome)": (
            f"clean={metrics.packages_successful}  "
            f"partial={metrics.packages_with_partial_errors}  "
            f"failed={metrics.packages_failed}  "
            f"drifted={metrics.packages_drifted}  "
            f"mirror_failed={metrics.packages_with_mirror_failures}  "
            f"runtime_skipped={metrics.packages_skipped_runtime}"
        ),
    }
    print(formatter.format_kv_block("[RESULT]", result_pairs))
    print()

    if policy_filtered:
        print("[RESULT] Filtered before pull (policy):")
        for reason, count in policy_filtered.items():
            print(f"  - {reason}: {count}")
        print()

    if preflight_skips:
        print("[RESULT] Pre-flight skips:")
        for reason, count in preflight_skips.items():
            print(f"  - {reason}: {count}")
        print()

    if runtime_skips:
        print("[RESULT] Runtime skips:")
        for reason, count in runtime_skips.items():
            print(f"  - {reason}: {count}")
        print()

    evidence_pairs: dict[str, str] = {}
    if output_root:
        evidence_pairs["Artifacts root"] = output_root
    if receipts_root:
        evidence_pairs["Receipts root"] = receipts_root
    if evidence_pairs:
        print(formatter.format_kv_block("[EVIDENCE]", evidence_pairs))
        print()
