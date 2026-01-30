"""Scan execution helpers for static analysis CLI."""

from __future__ import annotations

import json
import os
import re
import textwrap
import time
from collections import Counter
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Mapping, MutableMapping, Optional, Sequence, Tuple

from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.DisplayUtils import status_messages

from scytaledroid.DeviceAnalysis.harvest.common import compute_hashes
from ...core import (
    AnalysisConfig,
    SecretsSamplerConfig,
    StaticAnalysisError,
    StaticAnalysisReport,
    analyze_apk,
)
from ...core.detector_runner import PIPELINE_STAGES
from ...core.findings import SeverityLevel
from ...modules import resolve_category
from ...core.repository import load_display_name_map
from ...persistence import ReportStorageError, save_report
from ..core.models import AppRunResult, ArtifactOutcome, RunOutcome, RunParameters, ScopeSelection
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
    dry_run_skipped = 0
    completed_artifacts = 0
    total_artifacts = sum(len(_dedupe_artifacts(group.artifacts)) for group in selection.groups)
    show_splits = _show_split_breakdown()
    display_name_map = load_display_name_map(selection.groups)
    progress = _PipelineProgress(total=total_artifacts, show_splits=show_splits)
    config_hash = _compute_config_hash(params)
    pipeline_version = os.getenv("SCYTALEDROID_PIPELINE_VERSION") or getattr(
        params, "analysis_version", None
    )

    for group in selection.groups:
        app_result = AppRunResult(group.package_name, getattr(group, "category", "Uncategorized"))
        identity = _compute_run_identity(group)
        manifest_sha256 = _artifact_manifest_sha256(group)
        run_signature = _run_signature_sha256(
            identity["base_apk_sha256"],
            identity["artifact_set_hash"],
            config_hash=config_hash,
            profile=params.profile_label,
            pipeline_version=pipeline_version,
            run_signature_version=identity["run_signature_version"],
        )
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

        if not display_name or str(display_name).strip().lower() == group.package_name.lower():
            display_name = display_name_map.get(group.package_name.lower()) or display_name

        def _coerce_int(value: object) -> Optional[int]:
            try:
                if value is None or value == "":
                    return None
                return int(value)  # type: ignore[arg-type]
            except Exception:
                return None

        app_result.app_label = str(display_name) if display_name else None
        app_result.version_name = str(version_name) if version_name else None
        app_result.version_code = _coerce_int(version_code_raw)
        app_result.min_sdk = _coerce_int(min_sdk_raw)
        app_result.target_sdk = _coerce_int(target_sdk_raw)
        app_result.identity_valid = identity.get("identity_valid")
        app_result.identity_error_reason = identity.get("identity_error_reason")
        app_result.base_apk_sha256 = identity.get("base_apk_sha256")
        app_result.artifact_set_hash = identity.get("artifact_set_hash")
        app_result.run_signature = run_signature
        app_result.run_signature_version = identity.get("run_signature_version")

        static_run_id = None
        if not identity["identity_valid"] and not params.dry_run:
            raise RuntimeError(
                "Run identity invalid; cannot proceed with static analysis. "
                f"Package={group.package_name}; reason={identity['identity_error_reason']}"
            )
        if params.session_stamp:
            static_run_id = create_static_run_ledger(
                package_name=group.package_name,
                session_stamp=params.session_stamp,
                scope_label=params.scope_label,
                category=group.category,
                profile=params.profile_label,
                display_name=str(display_name) if display_name else None,
                version_name=str(version_name) if version_name else None,
                version_code=_coerce_int(version_code_raw),
                min_sdk=_coerce_int(min_sdk_raw),
                target_sdk=_coerce_int(target_sdk_raw),
                sha256=identity["base_apk_sha256"],
                base_apk_sha256=identity["base_apk_sha256"],
                artifact_set_hash=identity["artifact_set_hash"],
                run_signature=run_signature,
                run_signature_version=identity["run_signature_version"],
                identity_valid=identity["identity_valid"],
                identity_error_reason=identity["identity_error_reason"],
                config_hash=config_hash,
                pipeline_version=pipeline_version,
                run_started_utc=started_at.isoformat(timespec="seconds") + "Z",
                dry_run=params.dry_run,
            )
        app_result.static_run_id = static_run_id
        results.append(app_result)
        abort_requested, _, _ = _abort_state()
        if abort_requested:
            break

        artifacts = _dedupe_artifacts(group.artifacts)
        app_result.discovered_artifacts = len(artifacts)
        last_report_for_app: StaticAnalysisReport | None = None
        if display_name or group.package_name:
            progress.flush_line()
            print()
            title = display_name or group.package_name
            print(f"Scanning App: {title}")
            print(f"Package: {group.package_name}")
            print(f"Checks: {len(PIPELINE_STAGES)} stages · Profile: {params.profile_label}")
            print("Status: running")
        app_start = time.monotonic()
        for artifact_index, artifact in enumerate(artifacts, start=1):
            abort_requested, _, _ = _abort_state()
            if abort_requested:
                break
            artifact_label = _artifact_label(artifact, display_name=display_name)
            progress.start(artifact_index, artifact_label)
            report, summary, timings, error_message, skipped = _execute_single_artifact(
                artifact,
                params,
                selection,
                base_dir,
                extra_metadata={
                    "artifact_manifest_sha256": manifest_sha256,
                    "config_hash": config_hash,
                    "pipeline_version": pipeline_version,
                    "base_apk_sha256": identity["base_apk_sha256"],
                    "artifact_set_hash": identity["artifact_set_hash"],
                    "run_signature": run_signature,
                    "run_signature_version": identity["run_signature_version"],
                    "identity_valid": identity["identity_valid"],
                    "identity_error_reason": identity["identity_error_reason"],
                },
            )
            if skipped:
                index_for_progress = completed_artifacts + 1
                if error_message:
                    if error_message == "dry-run (not persisted)":
                        dry_run_skipped += 1
                        app_result.persistence_skipped += 1
                        progress.skip(index_for_progress, artifact_label, error_message)
                    else:
                        app_result.failed_artifacts += 1
                        progress.error(index_for_progress, artifact_label, error_message)
                        failures.append(error_message)
                else:
                    if not params.dry_run:
                        app_result.failed_artifacts += 1
                        failures.append(f"No report generated for {artifact.display_path}")
                completed_artifacts += 1
                app_result.executed_artifacts += 1
                progress.finish(completed_artifacts, artifact_label)
                if _abort_state()[0]:
                    break
                continue

            if summary is None:
                index_for_progress = completed_artifacts + 1
                if error_message:
                    if error_message == "dry-run (not persisted)":
                        dry_run_skipped += 1
                        app_result.persistence_skipped += 1
                        progress.skip(index_for_progress, artifact_label, error_message)
                    else:
                        app_result.failed_artifacts += 1
                        progress.error(index_for_progress, artifact_label, error_message)
                        failures.append(error_message)
                else:
                    if not params.dry_run:
                        app_result.failed_artifacts += 1
                        failures.append(f"No report generated for {artifact.display_path}")
                completed_artifacts += 1
                app_result.executed_artifacts += 1
                progress.finish(completed_artifacts, artifact_label)
                if _abort_state()[0]:
                    break
                continue

            app_result.artifacts.append(summary)
            completed_artifacts += 1
            app_result.executed_artifacts += 1
            if summary.saved_path:
                app_result.persisted_artifacts += 1
            elif params.dry_run:
                app_result.persistence_skipped += 1
            warning_lines: list[str] = []
            if report is not None:
                warning_lines = _append_resource_warning(
                    warnings,
                    report,
                    group.package_name,
                    artifact.display_path,
                )
                last_report_for_app = report
            if report is not None:
                progress.finish(completed_artifacts, artifact_label)
            if warning_lines:
                progress.flush_line()
                print()
                for line in warning_lines:
                    print(status_messages.status(line, level="warn"))
                print()
            if _abort_state()[0]:
                progress.end()
                break
        app_result.duration_seconds = time.monotonic() - app_start
        if not _abort_state()[0]:
            progress.flush_line()
            print(status_messages.status("Completed scan", level="success"))
            if last_report_for_app is not None:
                metadata = getattr(last_report_for_app, "metadata", {}) or {}
                if isinstance(metadata, Mapping):
                    summary = metadata.get("pipeline_summary")
                    if isinstance(summary, Mapping):
                        total = summary.get("detector_total")
                        executed = summary.get("detector_executed")
                        skipped = summary.get("detector_skipped")
                        duration = summary.get("total_duration_sec")
                        status_counts = summary.get("status_counts") if isinstance(summary.get("status_counts"), Mapping) else {}
                        fail_count = int(status_counts.get("FAIL", 0) or 0)
                        warn_count = int(status_counts.get("WARN", 0) or 0)
                        ok_count = int(status_counts.get("OK", 0) or 0)
                        info_count = int(status_counts.get("INFO", 0) or 0)
                        error_count = int(summary.get("error_count", 0) or 0)
                        skipped_count = int(skipped or 0)
                        status_line = "Checks complete"
                        if executed is not None and total is not None:
                            status_line += f": {executed}/{total} executed"
                        status_line += f" · ok={ok_count} warn={warn_count} policy_fail={fail_count}"
                        if error_count:
                            status_line += f" error={error_count}"
                        if info_count:
                            status_line += f" info={info_count}"
                        if skipped_count:
                            status_line += f" skipped={skipped_count}"
                        if duration is not None:
                            status_line += f" · {duration:.1f}s"
                        print(status_line)
                        error_detectors = summary.get("error_detectors")
                        if params.verbose_output and isinstance(error_detectors, Sequence) and error_detectors:
                            for entry in error_detectors:
                                if not isinstance(entry, Mapping):
                                    continue
                                det = entry.get("detector") or "unknown"
                                reason = entry.get("reason") or "unspecified"
                                print(status_messages.status(f"Detector error: {det} — {reason}", level="warn"))
                        severity = summary.get("severity_counts") if isinstance(summary.get("severity_counts"), Mapping) else {}
                        if severity:
                            p0 = int(severity.get("P0", 0) or 0)
                            p1 = int(severity.get("P1", 0) or 0)
                            p2 = int(severity.get("P2", 0) or 0)
                            note = int(severity.get("NOTE", 0) or 0)
                            print(f"Findings: P0={p0} P1={p1} P2={p2} Note={note}")
                        slowest = summary.get("slowest_detectors")
                        if isinstance(slowest, Sequence) and slowest:
                            slow_parts = []
                            for entry in slowest[:3]:
                                if not isinstance(entry, Mapping):
                                    continue
                                det = entry.get("detector") or entry.get("section")
                                dur = entry.get("duration_sec")
                                if det and isinstance(dur, (int, float)):
                                    slow_parts.append(f"{det} {dur:.2f}s")
                            if slow_parts:
                                print("Slowest: " + "; ".join(slow_parts))
        if _abort_state()[0]:
            break

    progress.end()

    finished_at = datetime.utcnow()
    abort_requested, abort_reason, abort_signal = _abort_state()
    if params.dry_run:
        failures = []
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
        dry_run_skipped=dry_run_skipped,
    )


def _append_resource_warning(
    warnings: list[str],
    report: StaticAnalysisReport,
    package_name: str,
    artifact_label: str,
) -> list[str]:
    metadata = report.metadata
    if not isinstance(metadata, Mapping):
        return []
    fallback = metadata.get("resource_fallback")
    if isinstance(fallback, Mapping) and fallback.get("fallback_used"):
        reason = fallback.get("fallback_reason") or "aapt2"
        warnings.append(
            "Resource fallback used for APK parsing "
            f"(package={package_name}, artifact={artifact_label}, reason={reason})."
        )
    lines = metadata.get("resource_bounds_warnings")
    if not isinstance(lines, list) or not lines:
        return []
    counts: list[int] = []
    for line in lines:
        if not isinstance(line, str):
            continue
        match = re.search(r"Count:\\s*(\\d+)", line)
        if match:
            try:
                counts.append(int(match.group(1)))
            except ValueError:
                continue
    count_hint = f" counts={sorted(set(counts))}" if counts else ""
    warnings.append(
        "Resource table parser emitted bounds warnings "
        f"(package={package_name}, artifact={artifact_label}{count_hint}). "
        "String/resource results may be partial; re-run this APK if needed."
    )
    inline_lines = [
        "Resource table bounds warning (string/resource parsing).",
        f"Package: {package_name}",
    ]
    app_label = metadata.get("app_label")
    if isinstance(app_label, str) and app_label.strip() and app_label.strip() != package_name:
        inline_lines.append(f"App: {app_label.strip()}")
    inline_lines.append(f"Artifact: {artifact_label}")
    if counts:
        inline_lines.append(f"Count values: {', '.join(str(val) for val in sorted(set(counts)))}")
    inline_lines.append("String/resource results may be partial; re-run this APK if needed.")
    return inline_lines


def _execute_single_artifact(
    artifact,
    params: RunParameters,
    selection: ScopeSelection,
    base_dir: Path,
    *,
    extra_metadata: Mapping[str, object] | None = None,
):
    report, json_path, error, skipped = generate_report(
        artifact,
        base_dir,
        params,
        extra_metadata=extra_metadata,
    )
    if skipped:
        return None, None, tuple(), error, True

    if error:
        return None, None, tuple(), error, False

    duration = report.metadata.get("duration_seconds", 0.0) if isinstance(report.metadata, Mapping) else 0.0
    timings = tuple(
        (result.detector_id or "detector", float(getattr(result, "duration_sec", 0.0) or 0.0))
        for result in getattr(report, "detector_results", [])
    )
    total_detector_time = sum(value for _, value in timings)
    if (duration or 0.0) <= 0.0 and total_detector_time > 0.0:
        duration = total_detector_time
    summary = _summarize_artifact(artifact, report, json_path, duration)
    return report, summary, timings, None, False


def _show_split_breakdown() -> bool:
    return os.getenv("SCYTALEDROID_STATIC_SHOW_SPLITS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
        "y",
    }


class _PipelineProgress:
    def __init__(self, total: int, show_splits: bool) -> None:
        self.total = max(1, int(total))
        self.show_splits = show_splits
        self._start = time.monotonic()
        self._last_len = 0
        self._last_checkpoint = 0

    def start(self, index: int, label: str) -> None:
        if self.show_splits:
            return
        # Avoid in-place lines that can interleave with warnings from other emitters.
        return

    def finish(self, index: int, label: str) -> None:
        if self.show_splits:
            line = f"[{index:2d}/{self.total}] {label} OK"
            print(line)
            return
        if index == self.total or (index - self._last_checkpoint) >= 5:
            self._last_checkpoint = index
            elapsed = _format_elapsed(time.monotonic() - self._start)
            self._clear_line()
            tail = _truncate_label(label, 48)
            print(
                f"Completed {index}/{self.total} artifacts ({elapsed} elapsed) | last: {tail}"
            )

    def error(self, index: int, label: str, message: str) -> None:
        self._clear_line()
        tail = _truncate_label(label, 48)
        print(f"ERROR Artifact {index}/{self.total}: {tail} - {message}")

    def skip(self, index: int, label: str, message: str) -> None:
        self._clear_line()
        tail = _truncate_label(label, 48)
        print(f"SKIP Artifact {index}/{self.total}: {tail} - {message}")

    def end(self) -> None:
        if self.show_splits:
            return
        if self._last_len:
            self._clear_line()
            print()

    def flush_line(self) -> None:
        """Clear the in-place progress line before printing multiline output."""
        if self.show_splits:
            return
        self._clear_line()

    def _render_line(self, text: str) -> None:
        truncated = _truncate_label(text, 96)
        padded = truncated.ljust(self._last_len)
        self._last_len = max(self._last_len, len(truncated))
        print(f"\r{padded}", end="", flush=True)

    def _clear_line(self) -> None:
        if self._last_len:
            print(f"\r{' ' * self._last_len}\r", end="", flush=True)
            self._last_len = 0


def _format_elapsed(seconds: float) -> str:
    total = max(0, int(seconds))
    minutes = total // 60
    seconds = total % 60
    return f"{minutes:02d}:{seconds:02d}"


def _artifact_label(artifact, *, display_name: Optional[str] = None) -> str:
    label = getattr(artifact, "artifact_label", None) or getattr(artifact, "display_path", None)
    if isinstance(label, str) and label.strip():
        split_label = label.strip()
    else:
        split_label = "base"

    package = getattr(artifact, "package_name", None)
    app_label = None
    metadata = getattr(artifact, "metadata", None)
    if isinstance(metadata, Mapping):
        app_label = metadata.get("app_label") or metadata.get("display_name")
    display = None
    if isinstance(app_label, str) and app_label.strip():
        display = app_label.strip()
    elif isinstance(display_name, str) and display_name.strip():
        display = display_name.strip()
    elif isinstance(package, str) and package.strip():
        display = package.strip()

    if display:
        return f"{display} • {split_label}"
    return split_label


def _truncate_label(value: str, max_len: int) -> str:
    if len(value) <= max_len:
        return value
    return f"{value[: max_len - 3].rstrip()}..."


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


def generate_report(
    artifact,
    base_dir: Path,
    params: RunParameters,
    *,
    extra_metadata: Mapping[str, object] | None = None,
):
    metadata_payload: MutableMapping[str, object] = dict(artifact.metadata)
    metadata_payload["run_profile"] = params.profile
    metadata_payload["run_scope"] = params.scope
    metadata_payload["run_scope_label"] = params.scope_label
    metadata_payload["selected_tests"] = list(params.selected_tests)
    if params.session_stamp:
        metadata_payload["session_stamp"] = params.session_stamp
    if not metadata_payload.get("category"):
        package_name = getattr(artifact, "package_name", None)
        if not isinstance(package_name, str) or not package_name.strip():
            package_name = metadata_payload.get("package_name")
        if isinstance(package_name, str) and package_name.strip():
            metadata_payload["category"] = resolve_category(package_name, metadata_payload)
    if extra_metadata:
        metadata_payload.update(
            {
                key: value
                for key, value in extra_metadata.items()
                if value is not None
            }
        )

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


def _artifact_manifest_sha256(group) -> str | None:
    entries = []
    for artifact in _dedupe_artifacts(group.artifacts):
        sha = _artifact_sha256(artifact)
        meta = getattr(artifact, "metadata", {}) or {}
        label = None
        if isinstance(meta, Mapping):
            label = meta.get("split_name") or meta.get("split") or meta.get("artifact")
        label = str(label or artifact.path.name)
        entries.append({"split": label, "sha256": sha or "unknown"})
    if not entries:
        return None
    payload = {
        "package": group.package_name,
        "version": getattr(group, "version_display", None),
        "artifacts": sorted(entries, key=lambda item: item["split"]),
    }
    return sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _artifact_sha256(artifact) -> str | None:
    sha = getattr(artifact, "sha256", None)
    if isinstance(sha, str) and sha.strip():
        return sha.strip()
    try:
        hashes = compute_hashes(Path(artifact.path))
        sha = hashes.get("sha256")
        return sha.strip() if isinstance(sha, str) and sha.strip() else None
    except Exception:
        return None


def _split_name_for_artifact(artifact) -> str | None:
    meta = getattr(artifact, "metadata", {}) or {}
    if isinstance(meta, Mapping):
        name = meta.get("split_name") or meta.get("split") or meta.get("artifact")
        if isinstance(name, str) and name.strip():
            return name.strip().lower()
    try:
        stem = Path(artifact.path).stem
    except Exception:
        stem = None
    if isinstance(stem, str) and stem.strip():
        return stem.strip().lower()
    return None


def _compute_run_identity(group) -> dict:
    base = getattr(group, "base_artifact", None)
    identity = {
        "base_apk_sha256": None,
        "artifact_set_hash": None,
        "run_signature_version": "v1",
        "identity_valid": False,
        "identity_error_reason": None,
    }
    if base is None:
        identity["identity_error_reason"] = "missing_base_artifact"
        return identity

    base_sha = _artifact_sha256(base)
    if not base_sha:
        identity["identity_error_reason"] = "base_sha256_missing"
        return identity

    entries = []
    for artifact in _dedupe_artifacts(group.artifacts):
        sha = _artifact_sha256(artifact)
        if not sha:
            identity["identity_error_reason"] = "artifact_sha256_missing"
            return identity
        split_name = _split_name_for_artifact(artifact)
        if not split_name:
            identity["identity_error_reason"] = "split_name_missing"
            return identity
        is_base = artifact == base or not getattr(artifact, "is_split_member", True)
        entries.append({"split_name": split_name, "sha256": sha, "is_base": is_base})

    ordered = [e for e in entries if e["is_base"]]
    ordered.extend(sorted((e for e in entries if not e["is_base"]), key=lambda item: item["split_name"]))
    split_hashes = [e["sha256"] for e in ordered]
    artifact_set_hash = sha256(json.dumps(split_hashes).encode("utf-8")).hexdigest()

    identity["base_apk_sha256"] = base_sha
    identity["artifact_set_hash"] = artifact_set_hash
    identity["identity_valid"] = True
    return identity


def _compute_config_hash(params: RunParameters) -> str:
    payload = {
        "profile": params.profile,
        "profile_label": params.profile_label,
        "scope": params.scope,
        "selected_tests": list(params.selected_tests),
        "strings_mode": params.strings_mode,
        "string_min_entropy": params.string_min_entropy,
        "string_max_samples": params.string_max_samples,
        "string_cleartext_only": params.string_cleartext_only,
        "string_include_https_risk": params.string_include_https_risk,
        "secrets_entropy": params.secrets_entropy,
        "secrets_hits_per_bucket": params.secrets_hits_per_bucket,
        "secrets_scope": params.secrets_scope_canonical,
        "workers": params.workers,
        "reuse_cache": params.reuse_cache,
        "log_level": params.log_level,
        "trace_detectors": list(params.trace_detectors),
        "permission_snapshot_refresh": params.permission_snapshot_refresh,
    }
    return sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _run_signature_sha256(
    base_apk_sha256: str | None,
    artifact_set_hash: str | None,
    *,
    config_hash: str,
    profile: str,
    pipeline_version: str | None,
    run_signature_version: str,
) -> str:
    payload = {
        "base_apk_sha256": base_apk_sha256 or "unknown",
        "artifact_set_hash": artifact_set_hash or "unknown",
        "config_hash": config_hash,
        "profile": profile,
        "pipeline_version": pipeline_version or "",
        "run_signature_version": run_signature_version,
    }
    return sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


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
    if seconds < 60:
        return f"{seconds:.2f} sec"
    minutes = int(seconds // 60)
    remaining = int(round(seconds - minutes * 60))
    if remaining == 60:
        minutes += 1
        remaining = 0
    if minutes < 60:
        min_label = "min" if minutes == 1 else "mins"
        sec_label = "sec" if remaining == 1 else "secs"
        return f"{minutes} {min_label} {remaining} {sec_label}"
    hours = minutes // 60
    minutes = minutes % 60
    hr_label = "hr" if hours == 1 else "hrs"
    min_label = "min" if minutes == 1 else "mins"
    return f"{hours} {hr_label} {minutes} {min_label}"


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
