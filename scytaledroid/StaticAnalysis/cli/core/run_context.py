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
    session_stamp: str | None
    persistence_ready: bool
    paper_grade_requested: bool


def build_static_run_context(spec: StaticRunSpec) -> StaticRunContext:
    batch = spec.run_mode == "batch" or spec.noninteractive
    return StaticRunContext(
        run_mode=spec.run_mode,
        quiet=spec.quiet,
        batch=batch,
        noninteractive=spec.noninteractive,
        show_splits=bool(spec.params.show_split_summaries),
        session_stamp=spec.params.session_stamp,
        persistence_ready=bool(spec.params.persistence_ready),
        paper_grade_requested=bool(spec.params.paper_grade_requested),
    )


__all__ = ["StaticRunContext", "build_static_run_context"]
