"""Static analysis service façade to decouple UI from pipeline orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from scytaledroid.StaticAnalysis.cli.runner import launch_scan_flow
from scytaledroid.Utils.LoggingUtils import logging_utils as log


class StaticServiceError(RuntimeError):
    """Raised when a static analysis run cannot be completed."""


def run_scan(selection: Any, params: Any, base_dir: Path, *, study_tag: Optional[str] = None) -> Any:
    """
    Run the static analysis scan flow and return the outcome.

    Parameters
    ----------
    selection : object
        Scope selection produced by the static scope picker.
    params : object
        RunParameters instance (or compatible) used by the runner.
    base_dir : Path
        Root directory containing harvested APKs.
    study_tag : str | None
        Optional tag to label the run for research/reproducibility.
    """
    # Attach study tag to params when supported.
    if study_tag and hasattr(params, "study_tag"):
        try:
            setattr(params, "study_tag", study_tag)
        except Exception:
            pass
    try:
        return launch_scan_flow(selection, params, base_dir)
    except Exception as exc:
        log.error(f"Static analysis failed: {exc}", category="static")
        raise StaticServiceError(str(exc)) from exc


__all__ = ["run_scan", "StaticServiceError"]
