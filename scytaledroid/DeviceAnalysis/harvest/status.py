"""Authoritative harvest run status/count contract."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class HarvestRunStatus:
    """Stable harvest status/count summary shared across runner, reports, and menus."""

    packages_total: int
    packages_reviewed: int
    eligible_count: int
    attempted_count: int
    harvested_count: int
    blocked_preflight_count: int
    skipped_count: int
    failed_count: int
    partial_count: int
    drifted_count: int
    path_stale_count: int
    replanned_count: int
    replan_success_count: int
    replan_failed_count: int
    status: str
    status_reason: str
    status_level: str
    operator_summary: str

    def to_context_dict(self) -> dict[str, object]:
        """Serialize the stable status/count surface for operation results."""

        return {
            "harvest_status": self.status,
            "harvest_status_level": self.status_level,
            "harvest_status_reason": self.status_reason,
            "harvest_operator_summary": self.operator_summary,
            "packages": self.harvested_count,
            "packages_total": self.packages_total,
            "packages_blocked": self.blocked_preflight_count,
            "packages_reviewed": self.packages_reviewed,
            "packages_eligible": self.eligible_count,
            "packages_executed": self.attempted_count,
            "packages_harvested": self.harvested_count,
            "packages_blocked_preflight": self.blocked_preflight_count,
            "packages_partial": self.partial_count,
            "packages_failed": self.failed_count,
            "packages_drifted": self.drifted_count,
            "packages_replanned": self.replanned_count,
            "packages_path_stale": self.path_stale_count,
        }


def build_harvest_run_status(
    *,
    packages_total: int,
    packages_reviewed: int,
    eligible_count: int,
    attempted_count: int,
    harvested_count: int,
    blocked_preflight_count: int,
    skipped_count: int,
    failed_count: int,
    partial_count: int,
    drifted_count: int,
    path_stale_count: int,
    replanned_count: int,
    replan_success_count: int,
    replan_failed_count: int,
    device_unavailable: bool = False,
    mirror_failed_count: int = 0,
    write_db_requested: bool = False,
    write_db_effective: bool = True,
) -> HarvestRunStatus:
    """Construct the authoritative harvest status/count summary."""

    if device_unavailable:
        status = "aborted_device_unavailable"
        status_reason = "device_unavailable"
        status_level = "error"
    elif eligible_count <= 0:
        status = "no_eligible_packages"
        status_reason = "no_eligible_packages"
        status_level = "warn"
    elif write_db_requested and attempted_count > 0 and (
        mirror_failed_count >= attempted_count or not write_db_effective
    ):
        status = "degraded_db_mirror_total_loss"
        status_reason = "db_mirror_total_loss"
        status_level = "error"
    elif write_db_requested and mirror_failed_count > 0:
        status = "degraded"
        status_reason = "db_mirror_partial_loss"
        status_level = "warn"
    elif failed_count > 0 or partial_count > 0 or drifted_count > 0:
        status = "partial"
        status_reason = "package_failures_or_drift"
        status_level = "warn"
    else:
        status = "success"
        status_reason = "completed_clean"
        status_level = "success"

    operator_summary = _build_operator_summary(
        packages_total=packages_total,
        packages_reviewed=packages_reviewed,
        eligible_count=eligible_count,
        attempted_count=attempted_count,
        harvested_count=harvested_count,
        blocked_preflight_count=blocked_preflight_count,
        skipped_count=skipped_count,
        failed_count=failed_count,
        partial_count=partial_count,
        drifted_count=drifted_count,
        replanned_count=replanned_count,
        replan_failed_count=replan_failed_count,
        status=status,
    )

    return HarvestRunStatus(
        packages_total=packages_total,
        packages_reviewed=packages_reviewed,
        eligible_count=eligible_count,
        attempted_count=attempted_count,
        harvested_count=harvested_count,
        blocked_preflight_count=blocked_preflight_count,
        skipped_count=skipped_count,
        failed_count=failed_count,
        partial_count=partial_count,
        drifted_count=drifted_count,
        path_stale_count=path_stale_count,
        replanned_count=replanned_count,
        replan_success_count=replan_success_count,
        replan_failed_count=replan_failed_count,
        status=status,
        status_reason=status_reason,
        status_level=status_level,
        operator_summary=operator_summary,
    )


def build_harvest_run_status_from_runtime_stats(
    stats: Mapping[str, int],
    *,
    run_error: str | None,
    write_db_requested: bool,
    write_db_effective: bool,
) -> HarvestRunStatus:
    """Build the authoritative status from runner-time package counters."""

    return build_harvest_run_status(
        packages_total=int(stats.get("packages_total", 0)),
        packages_reviewed=min(
            int(stats.get("packages_reviewed", 0)),
            int(stats.get("packages_total", 0)),
        ),
        eligible_count=int(stats.get("packages_eligible", 0)),
        attempted_count=int(stats.get("packages_attempted", 0)),
        harvested_count=int(stats.get("packages_harvested", 0)),
        blocked_preflight_count=int(stats.get("packages_skipped", 0)),
        skipped_count=int(stats.get("packages_runtime_skipped", 0)),
        failed_count=int(stats.get("packages_failed", 0)),
        partial_count=int(stats.get("packages_partial", 0)),
        drifted_count=int(stats.get("packages_drifted", 0)),
        path_stale_count=int(stats.get("packages_path_stale", 0)),
        replanned_count=int(stats.get("packages_replanned", 0)),
        replan_success_count=int(stats.get("packages_replan_success", 0)),
        replan_failed_count=int(stats.get("packages_replan_failed", 0)),
        device_unavailable=run_error == "device_unavailable",
        mirror_failed_count=int(stats.get("packages_mirror_failed", 0)),
        write_db_requested=write_db_requested,
        write_db_effective=write_db_effective,
    )


def _build_operator_summary(
    *,
    packages_total: int,
    packages_reviewed: int,
    eligible_count: int,
    attempted_count: int,
    harvested_count: int,
    blocked_preflight_count: int,
    skipped_count: int,
    failed_count: int,
    partial_count: int,
    drifted_count: int,
    replanned_count: int,
    replan_failed_count: int,
    status: str,
) -> str:
    line = (
        f"reviewed {packages_reviewed}/{packages_total}"
        f" · eligible {eligible_count}"
        f" · attempted {attempted_count}"
        f" · harvested {harvested_count}"
    )
    if blocked_preflight_count > 0:
        line += f" · blocked before pull {blocked_preflight_count}"
    if skipped_count > 0:
        line += f" · skipped {skipped_count}"
    if replanned_count > 0:
        line += f" · replanned {replanned_count}"
        if replan_failed_count > 0:
            line += f" (failed {replan_failed_count})"
    if failed_count or partial_count or drifted_count:
        line += (
            " · issues "
            f"(failed={failed_count} drifted={drifted_count} partial={partial_count})"
        )
    elif status == "no_eligible_packages":
        line += " · no eligible packages"
    else:
        line += " · OK"
    return line


__all__ = [
    "HarvestRunStatus",
    "build_harvest_run_status",
    "build_harvest_run_status_from_runtime_stats",
]
