"""Formatting helpers for static analysis scan execution."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

from ..core.models import ScopeSelection


def _format_last_saved_phrase(seconds_ago: int | None) -> str:
    if seconds_ago is None:
        return "—"
    if seconds_ago <= 0:
        return "just now"
    if seconds_ago == 1:
        return "1s ago"
    return f"{seconds_ago}s ago"


def format_scan_progress_single_line(
    *,
    apps_completed: int,
    total_apps: int,
    artifacts_done: int,
    total_artifacts: int,
    current_app_label: str | None,
    current_package_name: str | None,
    agg_checks: Counter[str],
    last_report_seconds_ago: int | None,
    last_report_package: str | None,
    eta_text: str,
    activity: str = "active",
    archive_reports_written: int | None = None,
) -> str:
    """One-line heartbeat between full progress checkpoints (multi-app compact runs)."""

    label = str(current_app_label or current_package_name or "").strip() or "—"
    warn = int(agg_checks.get("warn", 0) or 0)
    fail = int(agg_checks.get("fail", 0) or 0)
    err = int(agg_checks.get("error", 0) or 0)
    eta_raw = str(eta_text or "").strip()
    eta_disp = f"~{eta_raw}" if eta_raw and eta_raw != "--" else "pending"
    last_phrase = _format_last_saved_phrase(last_report_seconds_ago)
    last_pkg = str(last_report_package or "").strip() or "—"
    arch = ""
    if archive_reports_written is not None and total_artifacts > 0:
        arch = f" · reports_persisted={archive_reports_written}/{total_artifacts}"
    return (
        f"[{apps_completed}/{total_apps} apps | {artifacts_done}/{total_artifacts} APKs] "
        f"{label} · {activity} · last_save {last_phrase} ({last_pkg})"
        f" · detector_warnings={warn} policy_failures={fail} execution_errors={err}"
        f" · ETA {eta_disp}{arch}"
    )


def _format_compact_activity_pulse(
    *,
    apps_completed: int,
    total_apps: int,
    artifacts_done: int,
    total_artifacts: int,
    current_app_label: str | None,
    current_package_name: str | None,
    agg_checks: Counter[str],
    last_saved_seconds_ago: int,
    last_package: str | None,
    archive_reports_written: int,
    eta_text: str,
) -> str:
    """Compatibility wrapper: delegate to :func:`format_scan_progress_single_line`."""

    return format_scan_progress_single_line(
        apps_completed=apps_completed,
        total_apps=total_apps,
        artifacts_done=artifacts_done,
        total_artifacts=total_artifacts,
        current_app_label=current_app_label,
        current_package_name=current_package_name,
        agg_checks=agg_checks,
        last_report_seconds_ago=last_saved_seconds_ago,
        last_report_package=last_package,
        eta_text=eta_text,
        activity="active",
        archive_reports_written=archive_reports_written,
    )


def _format_compact_progress_text(
    *,
    apps_completed: int,
    total_apps: int,
    artifacts_done: int,
    total_artifacts: int,
    agg_checks: Counter[str],
    elapsed_text: str,
    eta_text: str,
    current_app_label: str | None = None,
    current_package_name: str | None = None,
    recent_completions: list[str] | None = None,
    last_report_seconds_ago: int | None = None,
    last_report_package: str | None = None,
    archive_reports_written: int | None = None,
    eta_preliminary: bool = False,
    session_display: str | None = None,
    profile_display: str | None = None,
    scope_display: str | None = None,
    workers_display: str | None = None,
    dry_run: bool = False,
    include_legend: bool = True,
    include_run_context: bool = True,
) -> str:
    """Return the compact multi-line operator progress text."""

    lines: list[str] = []

    if include_run_context:
        lines.append("Run context")
        lines.append("-----------")
        lines.append(f"Session: {str(session_display or '').strip() or '-'}")
        lines.append(f"Analyzer profile: {str(profile_display or '').strip() or '-'}")
        lines.append(f"Scope: {str(scope_display or '').strip() or '-'}")
        lines.append(f"Workers: {str(workers_display or '').strip() or '-'}")
        if dry_run:
            lines.append("Mode: DRY-RUN (reports not persisted to DB/evidence paths as configured)")
        lines.append(f"Packages in run: {total_apps}")
        lines.append(f"APKs in run: {total_artifacts}")
        lines.append("")

    lines.append("Current app")
    lines.append("-----------")
    app_disp = str(current_app_label or "").strip() or "—"
    pkg_disp = str(current_package_name or "").strip() or "—"
    lines.append(f"App: {app_disp}")
    lines.append(f"Current package: {pkg_disp}")
    if total_apps > 0:
        ordinal = min(max(apps_completed, 0) + 1, total_apps)
        lines.append(f"App progress: {ordinal} / {total_apps} packages")
    else:
        lines.append("App progress: -")
    lines.append(f"Artifact progress: {artifacts_done} / {total_artifacts} APKs")
    lines.append(f"Elapsed: {elapsed_text}")
    eta_raw = str(eta_text or "").strip()
    no_eta = eta_raw in {"", "--"}
    if no_eta:
        eta_line = "ETA: not available yet (need a few completed APKs for a stable rate)"
        if eta_preliminary and total_artifacts > 0:
            eta_line += " - early in run; split-heavy apps will move this a lot"
    else:
        eta_line = f"ETA: ~{eta_raw}"
        if eta_preliminary and total_artifacts > 0:
            eta_line += " (preliminary - early estimate; split-heavy apps may skew)"
    lines.append(eta_line)

    arch = archive_reports_written
    arch_tail = ""
    if arch is not None and total_artifacts > 0:
        arch_tail = f" · Persisted JSON reports this session: {arch}/{total_artifacts}"

    if last_report_seconds_ago is None:
        lines.append("Last saved report: (none yet this session)" + arch_tail)
    else:
        saved_pkg = str(last_report_package or "").strip() or "—"
        age = _format_last_saved_phrase(last_report_seconds_ago)
        lines.append(f"Last saved report: {saved_pkg}, {age}" + arch_tail)

    warn = int(agg_checks.get("warn", 0) or 0)
    fail = int(agg_checks.get("fail", 0) or 0)
    err = int(agg_checks.get("error", 0) or 0)
    lines.append("")
    lines.append("Findings so far (session rollup)")
    lines.append("--------------------------------")
    lines.append(f"Detector warnings: {warn}")
    lines.append(f"Policy/finding failures: {fail}")
    if err == 0:
        lines.append("Execution errors: 0 (none - no analyzer/pipeline exceptions)")
    else:
        lines.append(
            f"Execution errors: {err} (investigate logs - these are not policy 'finding failures')"
        )

    if recent_completions:
        lines.append("")
        lines.append("Recent apps")
        lines.append("-----------")
        lines.extend(f"  {completion}" for completion in recent_completions[-2:])

    if include_legend:
        lines.append("")
        lines.append(
            "Legend: detector warnings = WARN-stage outcomes; policy/finding failures = policy + finding "
            "gates; execution errors = analyzer/pipeline exceptions (not policy findings)."
        )

    return "\n".join(lines)


def _load_v3_catalog_label_overrides(selection: ScopeSelection) -> dict[str, str]:
    """Return per-package display-name overrides for Profile v3 scans.

    Cohort-facing labels from the v3 catalog should appear in pipeline output
    even when APK metadata contains a different app label.
    """
    if selection.scope != "profile":
        return {}

    if not str(selection.label or "").strip().lower().startswith("profile v3"):
        return {}

    catalog_path = Path("profiles") / "profile_v3_app_catalog.json"

    try:
        payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    except Exception:
        return {}

    if not isinstance(payload, dict):
        return {}

    overrides: dict[str, str] = {}

    for pkg, meta in payload.items():
        if not isinstance(pkg, str) or not pkg.strip():
            continue

        if not isinstance(meta, Mapping):
            continue

        label = meta.get("app")
        if isinstance(label, str) and label.strip():
            overrides[pkg.strip().lower()] = label.strip()

    return overrides


def _artifact_label(artifact, *, display_name: str | None = None) -> str:
    """Return the operator-facing label for an artifact."""
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


def format_duration(seconds: float) -> str:
    """Format elapsed seconds for scan progress output."""
    if seconds <= 0:
        return "0 ms"

    if seconds < 1:
        millis = max(1, int(round(seconds * 1000)))
        return f"{millis} ms"

    if seconds < 60:
        whole = max(1, int(round(seconds)))
        sec_label = "sec" if whole == 1 else "secs"
        return f"{whole} {sec_label}"

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


__all__ = [
    "_artifact_label",
    "_format_compact_activity_pulse",
    "_format_compact_progress_text",
    "_load_v3_catalog_label_overrides",
    "format_duration",
    "format_scan_progress_single_line",
]
