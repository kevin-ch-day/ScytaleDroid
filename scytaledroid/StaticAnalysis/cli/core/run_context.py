"""Immutable static-run context used to freeze execution/display configuration."""

from __future__ import annotations

from dataclasses import dataclass

from .run_specs import StaticRunSpec


@dataclass(frozen=True)
class StaticRunContext:
    run_mode: str
    quiet: bool
    batch: bool
    noninteractive: bool
    show_splits: bool
    scan_splits_enabled: bool
    session_stamp: str | None
    persistence_ready: bool
    paper_grade_requested: bool
    batch_id: str | None = None
    #: Resolved CPU budget from ``RunParameters.workers`` (``auto`` → ``os.cpu_count()``).
    #: Artifact analysis remains serial today; this is the seam for future parallel dispatch.
    resolved_worker_count: int | None = None


def build_static_run_context(spec: StaticRunSpec) -> StaticRunContext:
    from ..flows.static_run_helpers import resolve_workers

    batch = spec.run_mode == "batch" or spec.noninteractive
    resolved = resolve_workers(spec.params.workers)
    return StaticRunContext(
        run_mode=spec.run_mode,
        quiet=spec.quiet,
        batch=batch,
        noninteractive=spec.noninteractive,
        show_splits=bool(spec.params.show_split_summaries),
        scan_splits_enabled=bool(spec.params.scan_splits),
        session_stamp=spec.params.session_stamp,
        persistence_ready=bool(spec.params.persistence_ready),
        paper_grade_requested=bool(spec.params.paper_grade_requested),
        batch_id=spec.batch_id,
        resolved_worker_count=int(resolved),
    )


__all__ = ["StaticRunContext", "build_static_run_context"]
