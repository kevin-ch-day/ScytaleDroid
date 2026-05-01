"""Views for compact static analysis CLI startup output."""

from __future__ import annotations

from collections.abc import Sequence

from ..core.run_context import StaticRunContext


def render_run_start(
    *,
    profile_label: str,
    target: str,
    modules: Sequence[str],
    workers_desc: str,
    run_ctx: StaticRunContext | None = None,
) -> None:
    if run_ctx is not None and run_ctx.quiet and run_ctx.batch:
        return
    detector_count = len(tuple(modules or ()))
    target_value = target
    if target and target.startswith("Profile:"):
        target_value = target.split(":", 1)[1].strip() or target
    print("Static Analysis")
    print("───────────────")
    print(f"{profile_label} | workers={workers_desc} | detectors={detector_count}")
    if target_value and target_value != "All apps":
        print(f"Target: {target_value}")
    print()
