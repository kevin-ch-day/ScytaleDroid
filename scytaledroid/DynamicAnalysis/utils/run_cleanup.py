"""Utilities for cleaning up local dynamic evidence packs.

This is intentionally *local-only* cleanup (filesystem + dataset tracker JSON).
DB rows are treated as derived indices and are not deleted here.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.research_cohort_archive import (
    resolve_dataset_plan_read_path,
    write_dataset_plan_payload,
)
from scytaledroid.DynamicAnalysis.utils.path_utils import (
    iter_dynamic_run_dirs,
    resolve_dynamic_run_dir,
)

_LEGACY_IN_PROGRESS_GRACE_S = 60 * 60


@dataclass(frozen=True)
class PackageRunCounts:
    total_runs: int
    valid_runs: int
    baseline_valid_runs: int
    interactive_valid_runs: int
    quota_met: bool
    extra_valid_runs: int
    baseline_extra_valid: int = 0
    baseline_low_signal_valid: int = 0
    baseline_not_idle_valid: int = 0
    interactive_extra_valid: int = 0
    interactive_low_signal_valid: int = 0


@dataclass(frozen=True)
class RecentRun:
    run_id: str
    ended_at: str | None
    run_profile: str | None
    interaction_level: str | None
    messaging_activity: str | None
    valid: bool | None
    invalid_reason_code: str | None
    pcap_failure_detail: str | None
    low_signal: bool | None


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _now_epoch_s() -> float:
    return datetime.now(UTC).timestamp()


def _process_is_alive(pid: int) -> bool:
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _marker_started_at_epoch(payload: dict[str, Any]) -> float | None:
    value = str(payload.get("started_at_utc") or "").strip()
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


def _active_in_progress_marker(marker_path: Path) -> bool:
    payload = _load_json(marker_path)
    host_pid = payload.get("host_pid")
    if isinstance(host_pid, int) and host_pid > 0:
        return _process_is_alive(host_pid)

    started_at = _marker_started_at_epoch(payload)
    if started_at is None:
        return False
    return (_now_epoch_s() - started_at) < _LEGACY_IN_PROGRESS_GRACE_S


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
    baseline_not_idle = sum(
        1
        for row in runs
        if isinstance(row, dict)
        and row.get("valid_dataset_run") is True
        and row.get("countable") is False
        and str(row.get("run_profile") or "").strip().lower() == "baseline_idle"
        and row.get("baseline_not_idle") is True
    )
    return PackageRunCounts(
        total_runs=total,
        valid_runs=valid,
        baseline_valid_runs=baseline_valid,
        interactive_valid_runs=interactive_valid,
        quota_met=quota_met,
        extra_valid_runs=extra_valid,
        baseline_not_idle_valid=baseline_not_idle,
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
        pcap_failure_detail = (
            str(r.get("pcap_failure_detail")) if r.get("pcap_failure_detail") else None
        )
        if valid_norm is False and not pcap_failure_detail:
            pcap_failure_detail = _derive_local_pcap_failure_detail(str(r.get("run_id") or ""))
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
                pcap_failure_detail=pcap_failure_detail,
                low_signal=(
                    True
                    if r.get("low_signal") is True
                    else (False if r.get("low_signal") is False else None)
                ),
            )
        )
    return out


def _derive_local_pcap_failure_detail(run_id: str) -> str | None:
    run_id_text = str(run_id or "").strip()
    if not run_id_text:
        return None
    run_dir = resolve_dynamic_run_dir(run_id_text)
    if run_dir is None or not run_dir.exists():
        return None
    try:
        from scytaledroid.DynamicAnalysis.pcap.diagnostics import dataset_pcap_failure_detail

        return dataset_pcap_failure_detail(run_dir, pcap_size_int=0)
    except Exception:
        return None


def find_dynamic_run_dirs(package_name: str) -> list[Path]:
    """Find local evidence pack dirs whose run_manifest.json targets package_name."""
    matches: list[Path] = []
    for run_dir in iter_dynamic_run_dirs():
        manifest_path = run_dir / "run_manifest.json"
        if not manifest_path.exists():
            continue
        payload = _load_json(manifest_path)
        target = payload.get("target") if isinstance(payload, dict) else None
        pkg = (target.get("package_name") if isinstance(target, dict) else None) or ""
        if str(pkg).strip().lower() == str(package_name).strip().lower():
            matches.append(run_dir)
    return matches


def find_incomplete_dynamic_run_dirs() -> list[Path]:
    """Return local dynamic run dirs missing run_manifest.json (orphan/incomplete)."""
    out: list[Path] = []
    for run_dir in iter_dynamic_run_dirs():
        manifest_path = run_dir / "run_manifest.json"
        if manifest_path.exists():
            continue
        marker_path = run_dir / "notes" / ".scytaledroid_in_progress"
        # Never treat an active run as incomplete, but do not let a stale marker
        # hide a killed/crashed run forever.
        if marker_path.exists() and _active_in_progress_marker(marker_path):
            continue
        out.append(run_dir)
    return out


def prune_incomplete_dynamic_run_dirs() -> int:
    """Delete orphan/incomplete dynamic run dirs and return count removed."""
    deleted = 0
    for run_dir in find_incomplete_dynamic_run_dirs():
        try:
            shutil.rmtree(run_dir)
            deleted += 1
        except OSError:
            continue
    return deleted


def reset_package_dataset_tracker(package_name: str) -> bool:
    """Remove the package entry from dataset_plan.json if present."""
    tracker_path = resolve_dataset_plan_read_path()
    if not tracker_path.exists():
        return True
    payload = _load_json(tracker_path)
    apps = payload.get("apps") if isinstance(payload, dict) else None
    if not isinstance(apps, dict):
        return True
    if package_name not in apps:
        return True
    del apps[package_name]
    write_dataset_plan_payload(payload)
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
    "find_incomplete_dynamic_run_dirs",
    "prune_incomplete_dynamic_run_dirs",
    "reset_package_dataset_tracker",
]
