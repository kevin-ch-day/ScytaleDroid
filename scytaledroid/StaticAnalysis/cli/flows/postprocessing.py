"""Post-summary coordination helpers for static analysis runs."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from scytaledroid.Utils.DisplayUtils import status_messages

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
) -> PostSummaryResult:
    """Run post-summary linkage, audit, and permission refresh coordination."""

    linkage_plan = build_linkage_plan(
        outcome,
        persistence_ready=bool(params.persistence_ready),
        summary_render_failed=summary_render_failed,
    )
    linkage_warning_printed = False
    run_map: dict[str, Any] | None = None

    if params.session_stamp:
        if linkage_plan.blocked_reason:
            print(status_messages.status(linkage_plan.blocked_reason, level="warn"))
            linkage_warning_printed = True
        else:
            emit_postprocessing_step("Building session run map", run_ctx=run_ctx)
            try:
                run_map = build_session_run_map(
                    outcome,
                    params.session_stamp,
                    allow_overwrite=bool(params.run_map_overwrite),
                )
                if run_map:
                    _validate_required_run_map_fields(run_map, required_fields)
                    validate_run_map(run_map, params.session_stamp)
                    persist_session_run_links(params.session_stamp, run_map)
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

    emit_postprocessing_step("Writing persistence audit artifacts", run_ctx=run_ctx)
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
                emit_postprocessing_step(
                    "Re-rendering permission snapshot for parity",
                    run_ctx=run_ctx,
                )
                execute_permission_scan(
                    selection,
                    params,
                    persist_detections=True,
                    run_map=run_map,
                    require_run_map=True,
                    compact_output=True,
                    fail_on_persist_error=True,
                )
            except Exception as exc:
                permission_refresh_error = exc
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
    )


def _validate_required_run_map_fields(
    run_map: dict[str, Any],
    required_fields: Sequence[str],
) -> None:
    for entry in run_map.get("apps", []):
        missing = [
            field
            for field in ("static_run_id", *required_fields)
            if entry.get(field) in (None, "")
        ]
        if missing:
            raise RuntimeError(
                "run_map incomplete for package "
                f"{entry.get('package')}: missing {', '.join(missing)}"
            )

