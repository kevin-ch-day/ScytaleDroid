"""Static analysis service façade to decouple UI from pipeline orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone
import os

from scytaledroid.StaticAnalysis.cli.runner import launch_scan_flow
from scytaledroid.Utils.LoggingUtils import logging_utils as log


class StaticServiceError(RuntimeError):
    """Raised when a static analysis run cannot be completed."""


@dataclass(frozen=True)
class RunResult:
    outcome: Any
    pipeline_version: Optional[str]
    catalog_versions: Optional[str]
    config_hash: Optional[str]
    study_tag: Optional[str]
    run_started_utc: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


def run_scan(
    selection: Any,
    params: Any,
    base_dir: Path,
    *,
    study_tag: Optional[str] = None,
    pipeline_version: Optional[str] = None,
    catalog_versions: Optional[str] = None,
    config_hash: Optional[str] = None,
) -> RunResult:
    """
    Run the static analysis scan flow and return the outcome with metadata.

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
    pipeline_version : str | None
        Pipeline version identifier.
    catalog_versions : str | None
        Permission/catalog version identifiers.
    config_hash : str | None
        Hash of static analysis configuration for reproducibility.
    """
    # Attach study tag to params when supported.
    if study_tag and hasattr(params, "study_tag"):
        try:
            setattr(params, "study_tag", study_tag)
        except Exception:
            pass
    if pipeline_version and hasattr(params, "analysis_version"):
        try:
            setattr(params, "analysis_version", pipeline_version)
        except Exception:
            pass
    # Default metadata fallbacks (env vars allow overrides)
    effective_study_tag = study_tag or os.getenv("SCYTALEDROID_STUDY_TAG")
    effective_pipeline_version = pipeline_version or os.getenv("SCYTALEDROID_PIPELINE_VERSION")
    effective_catalog_versions = catalog_versions or os.getenv("SCYTALEDROID_CATALOG_VERSIONS")
    effective_config_hash = config_hash or os.getenv("SCYTALEDROID_CONFIG_HASH")

    try:
        outcome = launch_scan_flow(selection, params, base_dir)
        return RunResult(
            outcome=outcome,
            pipeline_version=getattr(params, "analysis_version", effective_pipeline_version),
            catalog_versions=effective_catalog_versions,
            config_hash=effective_config_hash,
            study_tag=effective_study_tag,
        )
    except Exception as exc:
        log.error(f"Static analysis failed: {exc}", category="static")
        raise StaticServiceError(str(exc)) from exc


__all__ = ["run_scan", "StaticServiceError", "RunResult"]
