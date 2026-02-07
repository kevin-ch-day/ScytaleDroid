"""Utilities for cleaning up local dynamic evidence packs.

This is intentionally *local-only* cleanup (filesystem + dataset tracker JSON).
DB rows are treated as derived indices and are not deleted here.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config


@dataclass(frozen=True)
class PackageRunCounts:
    total_runs: int
    valid_runs: int
    baseline_valid_runs: int
    interactive_valid_runs: int
    quota_met: bool
    extra_valid_runs: int


@dataclass(frozen=True)
class RecentRun:
    run_id: str
    ended_at: str | None
    run_profile: str | None
    interaction_level: str | None
    messaging_activity: str | None
    valid: bool | None
    invalid_reason_code: str | None


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def dataset_tracker_counts(package_name: str) -> PackageRunCounts:
    """Return counts for a package from the dataset tracker (derived index)."""
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import load_dataset_tracker

    payload = load_dataset_tracker()
    apps = payload.get("apps") if isinstance(payload, dict) else {}
    entry = apps.get(package_name) if isinstance(apps, dict) else None
    runs = entry.get("runs") if isinstance(entry, dict) else []
    total = len(runs) if isinstance(runs, list) else 0
    valid = int(entry.get("valid_runs") or 0) if isinstance(entry, dict) else 0
    baseline_valid = int(entry.get("baseline_valid_runs") or 0) if isinstance(entry, dict) else 0
    interactive_valid = int(entry.get("interactive_valid_runs") or 0) if isinstance(entry, dict) else 0
    quota_met = bool(entry.get("quota_met")) if isinstance(entry, dict) else False
    extra_valid = int(entry.get("extra_valid_runs") or 0) if isinstance(entry, dict) else 0
    return PackageRunCounts(
        total_runs=total,
        valid_runs=valid,
        baseline_valid_runs=baseline_valid,
        interactive_valid_runs=interactive_valid,
        quota_met=quota_met,
        extra_valid_runs=extra_valid,
    )


def recent_tracker_runs(package_name: str, *, limit: int = 5) -> list[RecentRun]:
    """Return recent runs for a package from the dataset tracker (derived index)."""
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import load_dataset_tracker

    payload = load_dataset_tracker()
    apps = payload.get("apps") if isinstance(payload, dict) else {}
    entry = apps.get(package_name) if isinstance(apps, dict) else None
    runs = entry.get("runs") if isinstance(entry, dict) else []
    if not isinstance(runs, list):
        return []

    def _key(r: dict[str, Any]) -> str:
        ended = r.get("ended_at") or ""
        started = r.get("started_at") or ""
        return str(ended or started)

    recent = [r for r in runs if isinstance(r, dict)]
    recent.sort(key=_key, reverse=True)
    out: list[RecentRun] = []
    for r in recent[: max(int(limit), 0)]:
        valid = r.get("valid_dataset_run")
        if valid is True:
            valid_norm: bool | None = True
        elif valid is False:
            valid_norm = False
        else:
            valid_norm = None
        out.append(
            RecentRun(
                run_id=str(r.get("run_id") or ""),
                ended_at=(str(r.get("ended_at")) if r.get("ended_at") else None),
                run_profile=(str(r.get("run_profile")) if r.get("run_profile") else None),
                interaction_level=(
                    str(r.get("interaction_level")) if r.get("interaction_level") else None
                ),
                messaging_activity=(
                    str(r.get("messaging_activity")) if r.get("messaging_activity") else None
                ),
                valid=valid_norm,
                invalid_reason_code=(
                    str(r.get("invalid_reason_code")) if r.get("invalid_reason_code") else None
                ),
            )
        )
    return out


def find_dynamic_run_dirs(package_name: str) -> list[Path]:
    """Find local evidence pack dirs whose run_manifest.json targets package_name."""
    output_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    if not output_root.exists():
        return []
    matches: list[Path] = []
    for run_dir in sorted([p for p in output_root.iterdir() if p.is_dir()]):
        manifest_path = run_dir / "run_manifest.json"
        if not manifest_path.exists():
            continue
        payload = _load_json(manifest_path)
        target = payload.get("target") if isinstance(payload, dict) else None
        pkg = (target.get("package_name") if isinstance(target, dict) else None) or ""
        if str(pkg).strip().lower() == str(package_name).strip().lower():
            matches.append(run_dir)
    return matches


def reset_package_dataset_tracker(package_name: str) -> bool:
    """Remove the package entry from dataset_plan.json if present."""
    tracker_path = Path(app_config.DATA_DIR) / "archive" / "dataset_plan.json"
    if not tracker_path.exists():
        return True
    payload = _load_json(tracker_path)
    apps = payload.get("apps") if isinstance(payload, dict) else None
    if not isinstance(apps, dict):
        return True
    if package_name not in apps:
        return True
    del apps[package_name]
    tracker_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return True


def delete_dynamic_evidence_packs(package_name: str) -> int:
    """Delete local dynamic evidence packs for a package and return count removed."""
    run_dirs = find_dynamic_run_dirs(package_name)
    deleted = 0
    for run_dir in run_dirs:
        try:
            shutil.rmtree(run_dir)
            deleted += 1
        except OSError:
            # Best-effort; caller will report remaining.
            continue
    return deleted


__all__ = [
    "PackageRunCounts",
    "RecentRun",
    "dataset_tracker_counts",
    "recent_tracker_runs",
    "delete_dynamic_evidence_packs",
    "find_dynamic_run_dirs",
    "reset_package_dataset_tracker",
]
