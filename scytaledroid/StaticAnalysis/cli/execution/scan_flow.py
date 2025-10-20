"""Scan execution helpers for static analysis CLI."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Iterable, Mapping, MutableMapping, Optional, Sequence, Tuple

from scytaledroid.Utils.DisplayUtils import severity, status_messages, summary_cards
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.System import output_prefs

from ...core import (
    AnalysisConfig,
    SecretsSamplerConfig,
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

        artifacts = _dedupe_artifacts(group.artifacts)
        for artifact_index, artifact in enumerate(artifacts, start=1):
            progress_label = _progress_label(
                group_index,
                len(selection.groups),
                artifact_index,
                len(artifacts),
                group.package_name,
            )

            report, summary, timings = _execute_single_artifact(
                progress_label,
                artifact,
                params,
                selection,
                base_dir,
            )
            if summary is None:
                failures.append(f"No report generated for {artifact.display_path}")
                continue

            app_result.artifacts.append(summary)
            if report is not None:
                _print_artifact_progress(progress_label, summary, timings)

    finished_at = datetime.utcnow()
    return RunOutcome(results, started_at, finished_at, selection, base_dir, warnings, failures)


def _execute_single_artifact(progress_label: str, artifact, params: RunParameters, selection: ScopeSelection, base_dir: Path):
    print(
        status_messages.step(
            f"Starting {artifact.artifact_label or 'base'}",
            label=progress_label,
        )
    )
    report, json_path, error, skipped = generate_report(artifact, base_dir, params)
    if skipped:
        return None, None, tuple()

    if error:
        print(status_messages.status(error, level="error"))
        return None, None, tuple()

    duration = report.metadata.get("duration_seconds", 0.0) if isinstance(report.metadata, Mapping) else 0.0
    timings = tuple(
        (result.detector_id or "detector", float(getattr(result, "duration_sec", 0.0) or 0.0))
        for result in getattr(report, "detector_results", [])
    )
    total_detector_time = sum(value for _, value in timings)
    if (duration or 0.0) <= 0.0 and total_detector_time > 0.0:
        duration = total_detector_time
    summary = _summarize_artifact(artifact, report, json_path, duration)
    print(
        status_messages.step(
            f"Finished {artifact.artifact_label or 'base'} ({format_duration(duration)})",
            label=progress_label,
            state="success",
        )
    )
    return report, summary, timings


def _print_artifact_progress(label: str, summary: ArtifactOutcome, timings: Iterable[tuple[str, float]]) -> None:
    detector_timings = [(name, dur) for name, dur in timings if dur > 0]
    severity_counts = getattr(summary, "severity", None)
    totals: dict[str, int] = {}
    if severity_counts:
        totals = severity.normalise_counts(severity_counts.items())

    card_items: list[summary_cards.SummaryCardItem] = []
    if summary.duration_seconds:
        card_items.append(
            summary_cards.summary_item(
                "Duration",
                format_duration(summary.duration_seconds),
                value_style="emphasis",
            )
        )
    if detector_timings:
        total_seconds = sum(duration for _, duration in detector_timings)
        card_items.append(
            summary_cards.summary_item("Detectors", len(detector_timings))
        )
        card_items.append(
            summary_cards.summary_item(
                "Detector time",
                format_duration(total_seconds),
            )
        )
    total_findings = sum(totals.values())
    if total_findings:
        style = "severity_high" if totals.get("high") else "emphasis"
        card_items.append(
            summary_cards.summary_item("Findings", total_findings, value_style=style)
        )
    if totals:
        card_items.extend(severity.severity_summary_items(totals, include_zero=False))

    if card_items:
        artifact_label = getattr(summary, "label", None) or label
        card_title = f"Artifact snapshot — {artifact_label}"
        print(
            summary_cards.format_summary_card(
                card_title,
                card_items,
                subtitle=label,
                width=82,
            )
        )

    if detector_timings and output_prefs.get().verbose:
        for name, duration in detector_timings:
            print(
                status_messages.step(
                    f"{name:<18} {format_duration(duration)}",
                    state="info",
                    indent=4,
                    show_icon=False,
                )
            )


def _progress_label(group_index: int, group_total: int, artifact_index: int, artifact_total: int, package_name: str) -> str:
    label = f"[{group_index}/{group_total}] {package_name}"
    if artifact_total > 1:
        label += f" ({artifact_index}/{artifact_total})"
    return label


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

def _dedupe_artifacts(artifacts: Sequence) -> list:
    """Return artifacts de-duplicated by digest + split label, preferring newest."""

    preferred: dict[tuple[str, str], tuple[object, float, int]] = {}
    for index, artifact in enumerate(artifacts):
        try:
            sha = getattr(artifact, "sha256", None)
        except Exception:
            sha = None
        try:
            split_label = getattr(artifact, "artifact_label", None) or getattr(artifact, "display_path", "")
        except Exception:
            split_label = ""
        key = (_normalise_digest(sha, artifact), split_label or "")
        mtime = _artifact_mtime(artifact)
        existing = preferred.get(key)
        if existing is None or mtime > existing[1]:
            preferred[key] = (artifact, mtime, index)
    ordered = sorted(preferred.values(), key=lambda item: item[2])
    return [item[0] for item in ordered]


def _normalise_digest(sha: Optional[str], artifact) -> str:
    if isinstance(sha, str) and sha.strip():
        return sha.strip().lower()
    alt = None
    try:
        alt = getattr(artifact, "apk_id", None)
    except Exception:
        alt = None
    if isinstance(alt, str) and alt.strip():
        return f"apk:{alt.strip().lower()}"
    try:
        path = getattr(artifact, "path", None)
        if path:
            return f"path:{Path(path).resolve()}"
    except Exception:
        pass
    return f"uid:{id(artifact)}"


def _artifact_mtime(artifact) -> float:
    try:
        path = getattr(artifact, "path", None)
        if path and Path(path).exists():
            return float(Path(path).stat().st_mtime)
    except Exception:
        return 0.0
    return 0.0


def generate_report(artifact, base_dir: Path, params: RunParameters):
    metadata_payload: MutableMapping[str, object] = dict(artifact.metadata)
    metadata_payload["run_profile"] = params.profile
    metadata_payload["run_scope"] = params.scope
    metadata_payload["run_scope_label"] = params.scope_label
    metadata_payload["selected_tests"] = list(params.selected_tests)
    if params.session_stamp:
        metadata_payload["session_stamp"] = params.session_stamp

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

    sampler = SecretsSamplerConfig(
        entropy_threshold=max(0.0, float(params.secrets_entropy)),
        hits_per_bucket=max(1, int(params.secrets_hits_per_bucket or 1)),
        scope=params.secrets_scope_canonical,
    )

    return AnalysisConfig(
        profile=profile,
        verbosity=params.log_level,
        enabled_detectors=enabled_detectors or None,
        enable_string_index=enable_string_index,
        secrets_sampler=sampler,
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
    if seconds <= 0:
        return "0 ms"
    if seconds < 1:
        millis = max(1, int(round(seconds * 1000)))
        return f"{millis} ms"
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
