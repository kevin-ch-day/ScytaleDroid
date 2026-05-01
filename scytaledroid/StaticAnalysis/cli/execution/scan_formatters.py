"""Formatting helpers for static analysis scan execution."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

from ..core.models import ScopeSelection


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
) -> str:
    """Return the compact multi-line operator progress text."""

    lines: list[str] = []

    if current_app_label:
        pkg = str(current_package_name or "").strip()
        primary = current_app_label
        if pkg and pkg.lower() not in primary.lower():
            primary = f"{current_app_label} — {pkg}"
        current_line = f"Working on: {primary}"
        # apps_completed counts finished apps; while scanning, UI shows next/ active ordinal.
        if total_apps > 0:
            ordinal = min(max(apps_completed, 0) + 1, total_apps)
            current_line += f" (app {ordinal}/{total_apps})"
        lines.append(current_line)

    lines.append(f"Progress: {artifacts_done}/{total_artifacts} artifacts")
    lines.append(f"elapsed {elapsed_text} (ETA ~{eta_text})")
    lines.append(f"warn={agg_checks['warn']} fail={agg_checks['fail']} error={agg_checks['error']}")
    if recent_completions:
        lines.append("Recent:")
        lines.extend(f"  {completion}" for completion in recent_completions[-2:])

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


__all__ = [
    "_artifact_label",
    "_format_compact_progress_text",
    "_load_v3_catalog_label_overrides",
    "format_duration",
]
