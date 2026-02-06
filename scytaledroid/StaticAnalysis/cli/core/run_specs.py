"""Pure run-spec builders for static analysis (no IO, no prompts)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .models import RunParameters, ScopeSelection


@dataclass(frozen=True)
class StaticRunSpec:
    selection: ScopeSelection
    params: RunParameters
    base_dir: Path
    run_mode: str = "interactive"  # interactive | batch | diagnostic
    quiet: bool = False
    noninteractive: bool = False
    batch_id: str | None = None


def build_static_run_spec(
    *,
    selection: ScopeSelection,
    params: RunParameters,
    base_dir: Path,
    run_mode: str = "interactive",
    quiet: bool = False,
    noninteractive: bool = False,
    batch_id: str | None = None,
) -> StaticRunSpec:
    return StaticRunSpec(
        selection=selection,
        params=params,
        base_dir=base_dir,
        run_mode=run_mode,
        quiet=quiet,
        noninteractive=noninteractive,
        batch_id=batch_id,
    )


__all__ = ["StaticRunSpec", "build_static_run_spec"]
