"""Scan execution helpers for static analysis CLI."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Mapping, MutableMapping, Optional, Sequence, Tuple

from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ...core import (
    AnalysisConfig,
    StaticAnalysisError,
    StaticAnalysisReport,
    analyze_apk,
)
from ...core.findings import SeverityLevel
from ...persistence import ReportStorageError, save_report
from ..models import AppRunResult, ArtifactOutcome, RunOutcome, RunParameters, ScopeSelection


def execute_scan(selection: ScopeSelection, params: RunParameters, base_dir: Path) -> RunOutcome:
    """Execute static analysis across all scoped artifacts."""

    started_at = datetime.utcnow()
    results: list[AppRunResult] = []
    warnings: list[str] = []
    failures: list[str] = []

    for group_index, group in enumerate(selection.groups, start=1):
        app_result = AppRunResult(group.package_name, getattr(group, "category", "Uncategorized"))
        results.append(app_result)

        for artifact_index, artifact in enumerate(group.artifacts, start=1):
            progress_label = f"[{group_index}/{len(selection.groups)}] {group.package_name}"
            if len(group.artifacts) > 1:
                progress_label += f" ({artifact_index}/{len(group.artifacts)})"

            _, summary = _execute_single_artifact(progress_label, artifact, params, selection, base_dir)
            if summary is None:
                failures.append(f"No report generated for {artifact.display_path}")
                continue

            app_result.artifacts.append(summary)

    finished_at = datetime.utcnow()
    return RunOutcome(results, started_at, finished_at, selection, base_dir, warnings, failures)


def _execute_single_artifact(progress_label: str, artifact, params: RunParameters, selection: ScopeSelection, base_dir: Path):
    print(f"{progress_label} … analyzing {artifact.artifact_label or 'base'}")
    report, json_path, error, skipped = generate_report(artifact, base_dir, params)
    if skipped:
        return None, None

    if error:
        print(status_messages.status(error, level="error"))
        return error, None

    duration = report.metadata.get("duration_seconds", 0.0) if isinstance(report.metadata, Mapping) else 0.0
    summary = _summarize_artifact(artifact, report, json_path, duration)
    print(f"{progress_label} … done ({format_duration(duration)})")
    return report, summary


def _summarize_artifact(artifact, report: StaticAnalysisReport, json_path: Optional[Path], duration: float) -> ArtifactOutcome:
    severity = Counter[str]()
    for result in report.detector_results:
        for finding in result.findings:
            severity[_severity_token(finding.severity_gate)] += 1

    return ArtifactOutcome(
        label=artifact.artifact_label or artifact.display_path,
        report=report,
        severity=severity,
        duration_seconds=duration,
        saved_path=str(json_path) if json_path else None,
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        metadata=artifact.metadata,
    )


def generate_report(artifact, base_dir: Path, params: RunParameters):
    metadata_payload: MutableMapping[str, object] = dict(artifact.metadata)
    metadata_payload.setdefault("run_profile", params.profile)
    metadata_payload.setdefault("run_scope", params.scope)
    metadata_payload.setdefault("run_scope_label", params.scope_label)
    metadata_payload.setdefault("selected_tests", list(params.selected_tests))

    try:
        report = analyze_apk(
            artifact.path,
            metadata=metadata_payload,
            storage_root=base_dir,
            config=build_analysis_config(params),
        )
    except StaticAnalysisError as exc:
        return None, None, str(exc), True

    if params.dry_run:
        return report, None, "dry-run (not persisted)", True

    try:
        saved_paths = save_report(report)
        return report, saved_paths.json_path, None, False
    except ReportStorageError as exc:
        log.error(str(exc), category="static_analysis")
        return report, None, str(exc), False


def build_analysis_config(params: RunParameters) -> AnalysisConfig:
    profile_map = {
        "metadata": "quick",
        "permissions": "quick",
        "lightweight": "quick",
        "full": "full",
        "split": "quick",
        "strings": "quick",
        "webview": "quick",
        "nsc": "quick",
        "ipc": "quick",
        "crypto": "quick",
        "sdk": "quick",
    }
    profile = profile_map.get(params.profile, "full")
    enabled_detectors = _map_tests_to_detectors(params)
    enable_string_index = params.profile not in {"metadata", "permissions"}
    if params.profile == "custom" and any(test in params.selected_tests for test in ("secrets", "strings")):
        enable_string_index = True

    return AnalysisConfig(
        profile=profile,
        verbosity=params.log_level,
        enabled_detectors=enabled_detectors or None,
        enable_string_index=enable_string_index,
    )


def _map_tests_to_detectors(params: RunParameters) -> Tuple[str, ...]:
    if params.profile == "metadata":
        return ("integrity_identity",)
    if params.profile == "permissions":
        return ("permissions_profile",)
    if params.profile == "strings":
        return ("secrets", "webview", "network_surface")
    if params.profile == "webview":
        return ("webview_hygiene",)
    if params.profile == "nsc":
        return ("network_surface",)
    if params.profile == "ipc":
        return ("ipc_components", "provider_acl")
    if params.profile == "crypto":
        return ("crypto_hygiene",)
    if params.profile == "sdk":
        return ("sdk_inventory",)
    if params.profile != "custom":
        return tuple()

    mapping = {
        "manifest": ("integrity_identity", "manifest_baseline", "ipc_components", "provider_acl"),
        "provider_acl": ("provider_acl",),
        "nsc": ("network_surface",),
        "webview": ("webview",),
        "secrets": ("secrets",),
    }
    detectors: list[str] = []
    for test_key in params.selected_tests:
        value = mapping.get(test_key)
        if value:
            if isinstance(value, tuple):
                detectors.extend(value)
            else:
                detectors.append(value)
    return tuple(dict.fromkeys(detectors))


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    return f"{seconds:.2f} s"


def _severity_token(level: SeverityLevel) -> str:
    return {
        SeverityLevel.P0: "H",
        SeverityLevel.P1: "M",
        SeverityLevel.P2: "L",
        SeverityLevel.NOTE: "I",
    }.get(level, "I")


__all__ = [
    "execute_scan",
    "generate_report",
    "build_analysis_config",
    "format_duration",
]
