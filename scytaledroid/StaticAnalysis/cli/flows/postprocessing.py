"""Post-summary coordination helpers for static analysis runs."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from scytaledroid.Utils.DisplayUtils import status_messages
from .session_finalizer import finalize_session_run_map

from ..core.models import RunOutcome, RunParameters, ScopeSelection
from ..core.run_context import StaticRunContext


@dataclass(frozen=True)
class LinkagePlan:
    """Gate state for session linkage and permission refresh work."""

    blocked_reason: str | None
    missing_id_packages: tuple[str, ...] = ()


@dataclass(frozen=True)
class PostSummaryResult:
    """Result of post-summary session coordination."""

    linkage_blocked_reason: str | None
    missing_id_packages: tuple[str, ...] = ()
    permission_refresh_error: Exception | None = None
    run_map_built: bool = False


def build_linkage_plan(
    outcome: RunOutcome,
    *,
    persistence_ready: bool,
    summary_render_failed: bool,
) -> LinkagePlan:
    """Determine whether follow-on linkage work is allowed for this run."""

    if summary_render_failed:
        return LinkagePlan(
            blocked_reason="Run summary finalization failed; skipping run_map and permission refresh."
        )
    if outcome.aborted:
        return LinkagePlan(
            blocked_reason="Run interrupted; skipping run_map and permission refresh."
        )
    if not persistence_ready:
        return LinkagePlan(
            blocked_reason="Persistence gate failed; skipping run_map and permission refresh."
        )
    if not outcome.results:
        return LinkagePlan(
            blocked_reason="No analyzable artifacts; skipping run_map and permission refresh."
        )

    missing_id_packages = tuple(
        result.package_name for result in outcome.results if not result.static_run_id
    )
    if missing_id_packages:
        return LinkagePlan(
            blocked_reason=(
                "static_run_id missing for one or more apps; "
                "skipping run_map and permission refresh."
            ),
            missing_id_packages=missing_id_packages,
        )

    return LinkagePlan(blocked_reason=None)


def run_post_summary_postprocessing(
    *,
    outcome: RunOutcome,
    params: RunParameters,
    selection: ScopeSelection,
    run_ctx: StaticRunContext,
    summary_render_failed: bool,
    required_fields: Sequence[str],
    emit_postprocessing_step: Callable[..., None],
    build_session_run_map: Callable[..., dict[str, Any] | None],
    validate_run_map: Callable[..., None],
    persist_session_run_links: Callable[..., None],
    emit_missing_run_ids_artifact: Callable[..., None],
    execute_permission_scan: Callable[..., None],
    emit_phase_transition: Callable[..., None] | None = None,
) -> PostSummaryResult:
    """Run post-summary linkage, audit, and permission refresh coordination."""

    linkage_plan = build_linkage_plan(
        outcome,
        persistence_ready=bool(params.persistence_ready),
        summary_render_failed=summary_render_failed,
    )
    linkage_warning_printed = False
    run_map: dict[str, Any] | None = None
    run_map_built = False

    if params.session_stamp:
        if linkage_plan.blocked_reason:
            print(status_messages.status(linkage_plan.blocked_reason, level="warn"))
            linkage_warning_printed = True
        else:
            emit_postprocessing_step("Evidence and audit finalization", run_ctx=run_ctx)
            try:
                result = finalize_session_run_map(
                    outcome,
                    params.session_stamp,
                    allow_overwrite=bool(params.run_map_overwrite),
                    required_fields=required_fields,
                    build_session_run_map=build_session_run_map,
                    validate_run_map=validate_run_map,
                    persist_session_run_links_cb=persist_session_run_links,
                )
                run_map = result.run_map
                run_map_built = bool(result.run_map)
            except Exception as exc:
                if params.strict_persistence:
                    raise RuntimeError(
                        f"Failed to build run map for session {params.session_stamp}: {exc}"
                    ) from exc
                print(
                    status_messages.status(
                        f"Failed to build run map for session {params.session_stamp}: {exc}",
                        level="error",
                    )
                )
                run_map = None

    emit_postprocessing_step("Writing persistence audit", run_ctx=run_ctx)
    emit_missing_run_ids_artifact(
        outcome=outcome,
        session_stamp=params.session_stamp,
        linkage_blocked_reason=linkage_plan.blocked_reason,
        missing_id_packages=list(linkage_plan.missing_id_packages),
    )

    permission_refresh_error: Exception | None = None
    if params.permission_snapshot_refresh and params.profile in {"full", "lightweight"}:
        if linkage_plan.blocked_reason:
            if not linkage_warning_printed:
                print()
                print(status_messages.status(linkage_plan.blocked_reason, level="warn"))
        else:
            try:
                if emit_phase_transition is not None:
                    emit_phase_transition(
                        phase="permission_snapshot_parity",
                        status="running",
                        extra={"applications": len(outcome.results or [])},
                    )
                emit_postprocessing_step("Permission snapshot parity", run_ctx=run_ctx)
                parity_counts = {"changed": 0, "skipped": 0}

                def _parity_progress(payload: Mapping[str, object]) -> None:
                    try:
                        index = int(payload.get("index") or 0)
                        total = int(payload.get("total") or 0)
                    except Exception:
                        return
                    if index <= 0 or total <= 0:
                        return
                    package_name = str(payload.get("package_name") or "")
                    app_label = str(payload.get("app_label") or package_name or "")
                    report_source = str(payload.get("report_source") or "")
                    if report_source == "saved_report":
                        parity_counts["skipped"] += 1
                    else:
                        parity_counts["changed"] += 1
                    if index == 1 or index == total or index % 10 == 0:
                        print(
                            status_messages.status(
                                (
                                    f"Parity: {index}/{total} app(s) | "
                                    f"changed={parity_counts['changed']} "
                                    f"skipped={parity_counts['skipped']} | {app_label}"
                                ),
                                level="info",
                            )
                        )
                    if emit_phase_transition is not None:
                        emit_phase_transition(
                            phase="permission_snapshot_parity",
                            status="running",
                            extra={
                                "app_index": index,
                                "app_total": total,
                                "package_name": package_name,
                                "app_label": app_label,
                                "report_source": report_source,
                            },
                        )

                refresh_summary = execute_permission_scan(
                    selection,
                    params,
                    persist_detections=True,
                    run_map=run_map,
                    require_run_map=True,
                    compact_output=True,
                    fail_on_persist_error=True,
                    silent_output=True,
                    reuse_saved_reports=True,
                    progress_callback=_parity_progress,
                )
                refreshed_apps = None
                snapshot_path = None
                if isinstance(refresh_summary, dict):
                    refreshed_apps = refresh_summary.get("persisted_apps")
                    snapshot_path = refresh_summary.get("snapshot_path")
                    refreshed_processed = refresh_summary.get("processed_apps")
                    if refreshed_processed is not None:
                        summary_bits = [f"{refreshed_processed} app(s)"]
                    else:
                        summary_bits = []
                else:
                    summary_bits = []
                if refreshed_apps is not None:
                    summary_bits.append(f"{refreshed_apps} apps")
                if snapshot_path:
                    summary_bits.append(f"output={snapshot_path}")
                summary_suffix = " | ".join(summary_bits) if summary_bits else "completed"
                print(
                    status_messages.status(
                        (
                            "Permission snapshot parity complete: "
                            f"checked={parity_counts['changed'] + parity_counts['skipped']} "
                            f"changed={parity_counts['changed']} "
                            f"skipped={parity_counts['skipped']} "
                            f"errors=0"
                            + (f" | {summary_suffix}" if summary_suffix else "")
                        ),
                        level="info",
                    )
                )
                if emit_phase_transition is not None:
                    emit_phase_transition(
                        phase="permission_snapshot_parity",
                        status="completed",
                        extra={
                            "applications": len(outcome.results or []),
                            "processed_apps": refresh_summary.get("processed_apps") if isinstance(refresh_summary, dict) else None,
                            "persisted_apps": refresh_summary.get("persisted_apps") if isinstance(refresh_summary, dict) else None,
                            "snapshot_path": snapshot_path,
                        },
                    )
            except Exception as exc:
                permission_refresh_error = exc
                if emit_phase_transition is not None:
                    emit_phase_transition(
                        phase="permission_snapshot_parity",
                        status="failed",
                        extra={"error_class": exc.__class__.__name__, "error_message": str(exc)},
                    )
    elif params.profile in {"full", "lightweight"}:
        emit_postprocessing_step(
            "Permission snapshot refresh skipped (disabled)",
            run_ctx=run_ctx,
        )
        print(
            status_messages.status(
                (
                    "Post-run permission refresh skipped. Enable it in Advanced options "
                    "or set SCYTALEDROID_STATIC_REFRESH_PERMISSION_SNAPSHOT=1."
                ),
                level="info",
            )
        )

    return PostSummaryResult(
        linkage_blocked_reason=linkage_plan.blocked_reason,
        missing_id_packages=linkage_plan.missing_id_packages,
        permission_refresh_error=permission_refresh_error,
        run_map_built=run_map_built,
    )
