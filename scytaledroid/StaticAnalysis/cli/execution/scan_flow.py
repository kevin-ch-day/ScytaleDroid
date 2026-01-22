"""Scan execution helpers for static analysis CLI."""

from __future__ import annotations

import os
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
from ..persistence.run_summary import create_static_run_ledger


_abort_requested = False
_abort_reason: Optional[str] = None
_abort_signal: Optional[str] = None


def request_abort(reason: str = "SIGINT", signal: str = "SIGINT") -> None:
    global _abort_requested, _abort_reason, _abort_signal
    if _abort_requested:
        return
    _abort_requested = True
    _abort_reason = reason
    _abort_signal = signal


def _abort_state() -> tuple[bool, Optional[str], Optional[str]]:
    return _abort_requested, _abort_reason, _abort_signal


def execute_scan(selection: ScopeSelection, params: RunParameters, base_dir: Path) -> RunOutcome:
    """Execute static analysis across all scoped artifacts."""

    global _abort_requested, _abort_reason, _abort_signal
    _abort_requested = False
    _abort_reason = None
    _abort_signal = None

    started_at = datetime.utcnow()
    results: list[AppRunResult] = []
    warnings: list[str] = []
    failures: list[str] = []
    completed_artifacts = 0
    total_artifacts = sum(len(_dedupe_artifacts(group.artifacts)) for group in selection.groups)

    for group_index, group in enumerate(selection.groups, start=1):
        abort_requested, _, _ = _abort_state()
        if abort_requested:
            break
        app_result = AppRunResult(group.package_name, getattr(group, "category", "Uncategorized"))
        base_artifact = next(iter(_dedupe_artifacts(group.artifacts)), None)
        metadata = getattr(base_artifact, "metadata", {}) if base_artifact else {}
        if isinstance(metadata, Mapping):
            display_name = metadata.get("app_label") or metadata.get("display_name")
            version_name = metadata.get("version_name")
            version_code_raw = metadata.get("version_code")
            min_sdk_raw = metadata.get("min_sdk")
            target_sdk_raw = metadata.get("target_sdk")
        else:
            display_name = None
            version_name = None
            version_code_raw = None
            min_sdk_raw = None
            target_sdk_raw = None

        def _coerce_int(value: object) -> Optional[int]:
            try:
                if value is None or value == "":
                    return None
                return int(value)  # type: ignore[arg-type]
            except Exception:
                return None

        static_run_id = None
        if params.session_stamp:
            static_run_id = create_static_run_ledger(
                package_name=group.package_name,
                session_stamp=params.session_stamp,
                scope_label=params.scope_label,
                profile=params.profile_label,
                display_name=str(display_name) if display_name else None,
                version_name=str(version_name) if version_name else None,
                version_code=_coerce_int(version_code_raw),
                min_sdk=_coerce_int(min_sdk_raw),
                target_sdk=_coerce_int(target_sdk_raw),
                run_started_utc=started_at.isoformat(timespec="seconds") + "Z",
                dry_run=params.dry_run,
            )
        app_result.static_run_id = static_run_id
        results.append(app_result)

        artifacts = _dedupe_artifacts(group.artifacts)
        for artifact_index, artifact in enumerate(artifacts, start=1):
            abort_requested, _, _ = _abort_state()
            if abort_requested:
                break
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
                completed_artifacts += 1
                if _abort_state()[0]:
                    break
                continue

            app_result.artifacts.append(summary)
            completed_artifacts += 1
            if report is not None:
                _print_artifact_progress(progress_label, summary, timings)
            if _abort_state()[0]:
                break
        if _abort_state()[0]:
            break

    finished_at = datetime.utcnow()
    abort_requested, abort_reason, abort_signal = _abort_state()
    return RunOutcome(
        results,
        started_at,
        finished_at,
        selection,
        base_dir,
        warnings,
        failures,
        aborted=abort_requested,
        abort_reason=abort_reason,
        abort_signal=abort_signal,
        completed_artifacts=completed_artifacts,
        total_artifacts=total_artifacts,
    )


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
            f"Finished {artifact.artifact_label or 'base'}",
            label=progress_label,
            state="success",
        )
    )
    return report, summary, timings


def _print_artifact_progress(label: str, summary: ArtifactOutcome, timings: Iterable[tuple[str, float]]) -> None:
    # Hide per-split banners unless explicitly enabled for debugging.
    show_splits = os.getenv("SCYTALEDROID_STATIC_SHOW_SPLITS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
        "y",
    }
    if not show_splits:
        return
    detector_timings = [(name, dur) for name, dur in timings if dur > 0]
    severity_counts = getattr(summary, "severity", None)
    totals: dict[str, int] = {}
    if severity_counts:
        totals = severity.normalise_counts(severity_counts.items())

    card_items: list[summary_cards.SummaryCardItem] = []
    # Suppress per-detector timing noise in the default UI; keep only findings counts.
    total_findings = sum(totals.values())
    if total_findings:
        style = "severity_high" if totals.get("high") else "emphasis"
        card_items.append(summary_cards.summary_item("Findings", total_findings, value_style=style))

    report = getattr(summary, "report", None)
    permission_summary = getattr(report, "permissions", None)
    if permission_summary:
        declared_set = set(permission_summary.declared or ())
        dangerous_set = set(permission_summary.dangerous or ())
        custom_set = set(permission_summary.custom or ())
        signature_set = declared_set - dangerous_set - custom_set
        if declared_set:
            perm_value = f"D:{len(dangerous_set)} S:{len(signature_set)} C:{len(custom_set)}"
            value_style = "severity_high" if dangerous_set else "emphasis"
            card_items.append(
                summary_cards.summary_item(
                    "Permissions",
                    perm_value,
                    value_style=value_style,
                )
            )
    if totals:
        card_items.extend(severity.severity_summary_items(totals, include_zero=False))

    metadata = getattr(summary, "metadata", None)
    package_name: Optional[str] = None
    filename: Optional[str] = getattr(summary, "label", None)
    if isinstance(metadata, Mapping):
        package_value = metadata.get("package_name")
        if isinstance(package_value, str) and package_value.strip():
            package_name = package_value.strip()
        artifact_hint = metadata.get("artifact")
        if isinstance(artifact_hint, str) and artifact_hint.strip():
            filename = artifact_hint.strip()
        else:
            display_hint = metadata.get("display_path")
            if isinstance(display_hint, str) and display_hint.strip():
                filename = display_hint.strip()
    if not package_name:
        after_bracket = label.split("]", 1)[-1].strip()
        if after_bracket:
            package_name = after_bracket
            if " (" in after_bracket and after_bracket.endswith(")"):
                package_name = after_bracket.rsplit("(", 1)[0].strip()
    if not filename:
        filename = label

    print()
    print(f"Package: {package_name or '<unknown>'}")
    print(f"Filename: {filename}")
    # Suppress duration to keep output compact; timings remain available in verbose logs.

    if card_items:
        bullet_items = [
            summary_cards.SummaryCardItem(
                item.label,
                item.value,
                label_style=item.label_style,
                value_style=item.value_style,
                bullet="• ",
            )
            for item in card_items
        ]
        print()
        print(
            summary_cards.format_summary_card(
                "Summary",
                bullet_items,
                width=48,
            )
        )
        print()

    # Suppress per-detector timing noise in the default menu view; timings remain available in logs.


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
