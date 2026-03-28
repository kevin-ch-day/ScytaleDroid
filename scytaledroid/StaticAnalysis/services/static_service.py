"""Static analysis service façade to decouple UI from pipeline orchestration."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.StaticAnalysis.cli.core.run_specs import build_static_run_spec
from scytaledroid.StaticAnalysis.cli.flows.headless_run import _check_session_uniqueness
from scytaledroid.StaticAnalysis.cli.flows.run_dispatch import execute_run_spec_detailed
from scytaledroid.Utils.LoggingUtils import logging_utils as log

_RUN_LOCK = threading.Lock()


class StaticServiceError(RuntimeError):
    """Raised when a static analysis run cannot be completed."""


@dataclass(frozen=True)
class RunResult:
    outcome: Any
    completed: bool
    session_stamp: str | None
    session_label: str | None
    detail: str | None
    pipeline_version: str | None
    catalog_versions: str | None
    config_hash: str | None
    study_tag: str | None
    run_started_utc: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )


def _primary_package_name(selection: Any) -> str | None:
    groups = tuple(getattr(selection, "groups", ()) or ())
    if not groups:
        return None
    package_name = getattr(groups[0], "package_name", None)
    if package_name:
        return str(package_name)
    return None


def run_scan(
    selection: Any,
    params: Any,
    base_dir: Path,
    *,
    study_tag: str | None = None,
    pipeline_version: str | None = None,
    catalog_versions: str | None = None,
    config_hash: str | None = None,
    allow_session_reuse: bool = True,
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
    # Default metadata fallbacks (env vars allow overrides)
    effective_study_tag = study_tag or os.getenv("SCYTALEDROID_STUDY_TAG")
    effective_pipeline_version = pipeline_version or os.getenv("SCYTALEDROID_PIPELINE_VERSION")
    effective_catalog_versions = catalog_versions or os.getenv("SCYTALEDROID_CATALOG_VERSIONS")
    effective_config_hash = config_hash or os.getenv("SCYTALEDROID_CONFIG_HASH")
    effective_params = params
    replacement_fields: dict[str, object] = {}
    if effective_study_tag and hasattr(params, "study_tag"):
        replacement_fields["study_tag"] = effective_study_tag
    if effective_pipeline_version and hasattr(params, "analysis_version"):
        replacement_fields["analysis_version"] = effective_pipeline_version
    if effective_catalog_versions and hasattr(params, "catalog_versions"):
        replacement_fields["catalog_versions"] = effective_catalog_versions
    if effective_config_hash and hasattr(params, "config_hash"):
        replacement_fields["config_hash"] = effective_config_hash
    if replacement_fields:
        try:
            effective_params = replace(params, **replacement_fields)
        except Exception:
            effective_params = params

    try:
        package_name = _primary_package_name(selection)
        if package_name:
            _check_session_uniqueness(
                getattr(effective_params, "session_stamp", None),
                package_name,
                allow_session_reuse,
                dry_run=bool(getattr(effective_params, "dry_run", False)),
            )
        spec = build_static_run_spec(
            selection=selection,
            params=effective_params,
            base_dir=base_dir,
            run_mode="batch",
            quiet=True,
            noninteractive=True,
        )
        with _RUN_LOCK:
            execution = execute_run_spec_detailed(spec)
        return RunResult(
            outcome=execution.outcome,
            completed=execution.completed,
            session_stamp=getattr(execution.params, "session_stamp", None),
            session_label=getattr(execution.params, "session_label", None),
            detail=execution.detail,
            pipeline_version=getattr(execution.params, "analysis_version", effective_pipeline_version),
            catalog_versions=effective_catalog_versions,
            config_hash=effective_config_hash,
            study_tag=effective_study_tag,
        )
    except SystemExit as exc:
        detail = str(exc) or "Static analysis cancelled."
        return RunResult(
            outcome=None,
            completed=False,
            session_stamp=getattr(effective_params, "session_stamp", None),
            session_label=getattr(effective_params, "session_label", None),
            detail=detail,
            pipeline_version=getattr(effective_params, "analysis_version", effective_pipeline_version),
            catalog_versions=effective_catalog_versions,
            config_hash=effective_config_hash,
            study_tag=effective_study_tag,
        )
    except Exception as exc:
        log.error(f"Static analysis failed: {exc}", category="static")
        raise StaticServiceError(str(exc)) from exc


__all__ = ["run_scan", "StaticServiceError", "RunResult"]
