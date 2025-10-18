"""Core execution helpers for static analysis CLI."""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime
from pathlib import Path
from time import perf_counter
from typing import Iterable, Mapping, MutableMapping, Optional, Sequence

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.LoggingUtils.logging_engine import configure_third_party_loggers

from ..core import AnalysisConfig, StaticAnalysisError, StaticAnalysisReport, analyze_apk
from ..engine.strings import analyse_strings
from ..persistence import ReportStorageError, save_report
from ..modules.module_api import AppModuleContext
from ..modules.permissions import collect_permissions_and_sdk, print_permissions_block
from ..modules.permissions.render_postcard import render as render_permission_postcard
from ..modules.permissions.render_summary import render as render_after_run_summary
from ..modules.permissions.render_matrix import render_signals as render_signal_matrix
from ..modules.permissions.audit import PermissionAuditAccumulator
from ..modules.dynamic_loading import DynamicLoadModule
from ..modules.storage_surface import StorageSurfaceModule

from .masvs_menu import render_scoring_explainer_menu  # convenience export
from .models import AppRunResult, ArtifactOutcome, RunOutcome, RunParameters, ScopeSelection
from .db_persist import persist_run_summary
from .prompts import prompt_tuning
from .profiles import run_modules_for_profile
from .scope import format_scope_target
from .sections import SECTION_DEFINITIONS, extract_integrity_profiles
from .renderer import render_app_result, write_baseline_json


def configure_logging_for_cli(level: str) -> None:
    level = (level or "").strip().lower()
    if level not in {"debug", "info"}:
        level = "info"

    verbosity = "debug" if level == "debug" else "normal"
    configure_third_party_loggers(
        verbosity=verbosity,
        run_id="cli",
        debug_dir=str(Path(log.LOGS_DIR).resolve()) if hasattr(log, "LOGS_DIR") else None,
    )

    root_level = logging.DEBUG if level == "debug" else logging.INFO
    logging.getLogger().setLevel(root_level)

    androguard_level = logging.DEBUG if level == "debug" else logging.ERROR
    for name in ("androguard", "androguard.core", "androguard.core.axml"):
        logging.getLogger(name).setLevel(androguard_level)

    quiet_level = logging.DEBUG if level == "debug" else logging.WARNING
    for name in ("zipfile", "urllib3"):
        logging.getLogger(name).setLevel(quiet_level)


def launch_scan_flow(selection: ScopeSelection, params: RunParameters, base_dir: Path) -> None:
    scope_target = format_scope_target(selection)
    print()
    print(f"Running — {params.profile_label} static analysis")
    print(f"Target : {scope_target}")
    print(f"Profile: {params.profile_label}")
    print("-" * 41)

    configure_logging_for_cli(params.log_level)

    if params.profile == "permissions":
        execute_permission_scan(selection, params)
        return

    outcome = execute_scan(selection, params, base_dir)
    render_run_results(outcome, params)

    if params.profile in {"full", "lightweight"}:
        try:
            perm_params = prompt_tuning(params)
            print()
            print("-- Re-rendering Permission Analysis snapshot for parity --")
            execute_permission_scan(selection, perm_params, persist_detections=False)
        except Exception:
            pass


def execute_scan(selection: ScopeSelection, params: RunParameters, base_dir: Path) -> RunOutcome:
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


def execute_permission_scan(selection: ScopeSelection, params: RunParameters, *, persist_detections: bool = True) -> None:
    scope_groups = selection.groups
    if not scope_groups:
        print(status_messages.status("No scope groups resolved for permission scan.", level="warn"))
        return

    base_dir = Path(app_config.DATA_DIR) / "apks"
    accumulator = PermissionAuditAccumulator(
        scope_label=params.scope_label or selection.label,
        scope_type=selection.scope,
        total_groups=len(scope_groups),
    )

    for group in scope_groups:
        artifacts = group.artifacts
        if not artifacts:
            continue
        artifact = artifacts[0]
        report, _, error, skipped = generate_report(artifact, base_dir, params)
        if skipped or error:
            continue

        permissions, defined, sdk = collect_permissions_and_sdk(str(artifact.path))
        render_permission_postcard(group.package_name, group.package_name, permissions, defined, sdk=sdk, index=1, total=1)

        if persist_detections and report is not None:
            try:
                from scytaledroid.StaticAnalysis.persistence.permissions_db import persist_permissions_to_db

                counts = persist_permissions_to_db(report)
                total = sum(counts.values()) if isinstance(counts, dict) else 0
                print(status_messages.status(
                    f"Permission Analysis persisted: total={total} (fw={counts.get('framework', 0)}, vendor={counts.get('vendor', 0)}, unk={counts.get('unknown', 0)})",
                    level="info",
                ))
            except Exception:
                pass

        accumulator.observe(group.package_name, permissions, defined)

    accumulator.persist()


def generate_report(artifact, base_dir: Path, params: RunParameters):
    metadata_payload: MutableMapping[str, object] = dict(artifact.metadata)
    metadata_payload.setdefault("run_profile", params.profile)
    metadata_payload.setdefault("run_scope", params.scope)
    metadata_payload.setdefault("run_scope_label", params.scope_label)
    metadata_payload.setdefault("selected_tests", list(params.selected_tests))

    try:
        report = analyze_apk(artifact.path, metadata=metadata_payload, storage_root=base_dir, config=build_analysis_config(params))
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
    tests = tuple(run_modules_for_profile(params.profile)) if params.profile != "custom" else params.selected_tests
    return AnalysisConfig(
        profile=params.profile,
        selected_tests=tests,
        workers=params.workers,
        reuse_cache=params.reuse_cache,
        trace_detectors=params.trace_detectors,
    )


def render_run_results(outcome: RunOutcome, params: RunParameters) -> None:
    from .scope import format_scope_target

    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    print(f"Duration: {format_duration(outcome.duration_seconds)}")
    print()

    for index, app_result in enumerate(outcome.results, start=1):
        base_report = app_result.base_report()
        if base_report is None:
            warning = f"No report generated for {app_result.package_name}."
            print(status_messages.status(warning, level="warn"))
            continue

        string_data = analyse_strings(
            base_report.file_path,
            mode=params.strings_mode,
            min_entropy=params.string_min_entropy,
            max_samples=params.string_max_samples,
            cleartext_only=params.string_cleartext_only,
        )

        try:
            persist_run_summary(base_report, string_data, app_result.package_name)
        except Exception:
            pass

        total_duration = sum(artifact.duration_seconds for artifact in app_result.artifacts)
        lines, payload, finding_totals = render_app_result(
            base_report,
            signer=app_result.signer,
            split_count=len(app_result.artifacts),
            string_data=string_data,
            duration_seconds=total_duration,
        )

        for line in lines:
            print(line)

        try:
            saved_path = write_baseline_json(payload, package=app_result.package_name, profile=params.profile, scope=params.scope)
            print(f"  Saved baseline JSON → {saved_path.name}")
        except Exception:
            pass

        if index < len(outcome.results):
            print()

    if outcome.warnings:
        for message in sorted(set(outcome.warnings)):
            print(status_messages.status(message, level="warn"))
    if outcome.failures:
        for message in sorted(set(outcome.failures)):
            print(status_messages.status(message, level="error"))

    # Source-of-truth MASVS summary (DB-backed)
    try:
        from scytaledroid.Database.db_core import db_queries as _q

        rows = _q.run_sql(
            "SELECT masvs, MAX(cvss) AS worst, SUM(CASE WHEN severity IN ('High','Medium') THEN 1 ELSE 0 END) AS sev_ge_med,"  # noqa: E501
            " SUM(CASE WHEN severity='Low' THEN 1 ELSE 0 END) AS low, SUM(CASE WHEN severity='Info' THEN 1 ELSE 0 END) AS info"
            " FROM findings WHERE run_id=(SELECT MAX(run_id) FROM runs) GROUP BY masvs",
            fetch="all",
        ) or []
        if rows:
            by_area = {str(r[0] or "").upper(): r for r in rows}
            print()
            print("DB MASVS Summary")
            print("Area       High  Med   Low   Info  Status  Worst CVSS")
            for area in ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE"):
                r = by_area.get(area, (None, None, 0, 0, 0))
                sev_ge_med = int(r[2] or 0)
                low = int(r[3] or 0)
                info = int(r[4] or 0)
                status = "PASS" if sev_ge_med == 0 else "FAIL"
                worst = r[1] or "—"
                print(f"{area.title():<9}  {0:<4}  {sev_ge_med:<4}  {low:<4}  {info:<4}  {status:<5}  {worst}")
    except Exception:
        pass


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    return f"{seconds:.2f} s"


def _severity_token(level: SeverityLevel) -> str:
    return {SeverityLevel.P0: "H", SeverityLevel.P1: "M", SeverityLevel.P2: "L", SeverityLevel.NOTE: "I"}.get(level, "I")


__all__ = [
    "configure_logging_for_cli",
    "launch_scan_flow",
    "execute_scan",
    "execute_permission_scan",
    "generate_report",
    "build_analysis_config",
    "render_run_results",
    "format_duration",
]
