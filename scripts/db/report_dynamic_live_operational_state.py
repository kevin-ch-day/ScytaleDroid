#!/usr/bin/env python3
"""Read-only live operational state report for the dynamic cohort queue.

This report reuses the same queue-preparation path as the Dynamic Analysis TUI so
operator-facing drift, quota, and capture-candidate decisions are grounded in the
same source of truth.

Outputs:
- summary.json
- drift_apps.csv
- capture_candidates.csv

The report is intentionally read-only:
- no DB writes
- no tracker mutation
- no evidence mutation
- no device-state mutation
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


@dataclass(frozen=True)
class DriftRow:
    package_name: str
    app: str
    status: str
    baseline: str
    interactive: str
    installed_build: str
    static_plan_build: str
    static_plan_version_name: str
    static_run_id: str
    lineage_state: str
    evidence_scope: str
    recommendation: str


@dataclass(frozen=True)
class CaptureCandidate:
    priority: int
    package_name: str
    app: str
    status: str
    next_action: str
    baseline: str
    interactive: str
    lineage_state: str
    likely_quota_impact: str
    rationale: str


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print summary JSON to stdout.")
    parser.add_argument(
        "--candidate-limit",
        type=int,
        default=5,
        help="Number of top capture candidates to include (default 5).",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Optional explicit output directory. Default: output/audit/dynamic_live_operational_state/<stamp>/",
    )
    return parser


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _default_output_dir() -> Path:
    return _REPO_ROOT / "output" / "audit" / "dynamic_live_operational_state" / _stamp()


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    rows = list(rows)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fieldnames})


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _lineage_rank(lineage_state: str) -> int:
    order = {
        "current_build_observed": 0,
        "current_build_db_only": 1,
        "historical_local_only": 2,
        "historical_db_only": 3,
        "no_evidence_anywhere": 4,
    }
    return order.get(str(lineage_state or ""), 9)


def _build_scope_text(row: Any) -> str:
    lineage_state = _norm_text(getattr(row, "lineage_state", ""))
    if getattr(row, "live_build_drift", False):
        if lineage_state == "current_build_observed":
            return "current-build evidence exists, but it is no longer live-current after device drift"
        if lineage_state == "current_build_db_only":
            return "DB-known current-build evidence exists, but live device drift blocks new current-build claims"
        return "older build evidence remains historically valid, but not live-current"
    if lineage_state == "current_build_observed":
        return "current-build evidence aligned"
    if lineage_state == "current_build_db_only":
        return "DB-only current-build evidence"
    if lineage_state == "historical_local_only":
        return "legacy local evidence only"
    if lineage_state == "historical_db_only":
        return "legacy DB-only evidence only"
    return "no evidence yet"


def _drift_rows(row_models: Sequence[Any], *, queue_status_label_fn, baseline_label_fn, interactive_label_fn) -> list[DriftRow]:
    rows: list[DriftRow] = []
    for row in row_models:
        if not getattr(row, "live_build_drift", False):
            continue
        rows.append(
            DriftRow(
                package_name=_norm_text(getattr(row, "package_name", "")),
                app=_norm_text(getattr(row, "display_name", "")),
                status=_norm_text(queue_status_label_fn(row)),
                baseline=_norm_text(baseline_label_fn(row)),
                interactive=_norm_text(interactive_label_fn(row)),
                installed_build=_norm_text(getattr(row, "live_observed_version_code", "")) or "unknown",
                static_plan_build=_norm_text(getattr(row, "live_expected_version_code", "")) or "unknown",
                static_plan_version_name=_norm_text(getattr(row, "live_expected_version_name", "")) or "unknown",
                static_run_id=_norm_text(getattr(row, "live_static_run_id", "")) or "unknown",
                lineage_state=_norm_text(getattr(row, "lineage_state", "")),
                evidence_scope=_build_scope_text(row),
                recommendation="refresh inventory/harvest/static before new live-current capture",
            )
        )
    return sorted(rows, key=lambda item: (item.app.lower(), item.package_name))


def _capture_candidate_priority(row: Any) -> tuple[int, int, int, int, str]:
    state = _norm_text(getattr(row, "lineage_state", ""))
    need_baseline = int(getattr(row, "need_baseline", 0) or 0)
    need_interactive = int(getattr(row, "need_interactive", 0) or 0)
    if need_baseline <= 0 and need_interactive > 0:
        phase_rank = 0
        remaining = need_interactive
    elif need_baseline > 0:
        phase_rank = 1
        remaining = need_baseline
    else:
        phase_rank = 9
        remaining = 99
    current_progress = -(
        int(getattr(row, "baseline_countable", 0) or 0)
        + int(getattr(row, "interactive_countable", 0) or 0)
    )
    return (
        phase_rank,
        _lineage_rank(state),
        remaining,
        current_progress,
        _norm_text(getattr(row, "display_name", "")).lower(),
    )


def _capture_candidates(
    row_models: Sequence[Any],
    *,
    queue_status_label_fn,
    baseline_label_fn,
    interactive_label_fn,
    recommended_reason_fn,
    candidate_limit: int,
) -> list[CaptureCandidate]:
    candidates: list[CaptureCandidate] = []
    filtered = [
        row
        for row in row_models
        if not getattr(row, "live_build_drift", False)
        and (int(getattr(row, "need_baseline", 0) or 0) > 0 or int(getattr(row, "need_interactive", 0) or 0) > 0)
    ]
    for priority, row in enumerate(sorted(filtered, key=_capture_candidate_priority)[: max(1, int(candidate_limit))], start=1):
        need_baseline = int(getattr(row, "need_baseline", 0) or 0)
        need_interactive = int(getattr(row, "need_interactive", 0) or 0)
        next_action = "interactive" if need_baseline <= 0 and need_interactive > 0 else "baseline"
        candidates.append(
            CaptureCandidate(
                priority=priority,
                package_name=_norm_text(getattr(row, "package_name", "")),
                app=_norm_text(getattr(row, "display_name", "")),
                status=_norm_text(queue_status_label_fn(row)),
                next_action=next_action,
                baseline=_norm_text(baseline_label_fn(row)),
                interactive=_norm_text(interactive_label_fn(row)),
                lineage_state=_norm_text(getattr(row, "lineage_state", "")),
                likely_quota_impact="YES",
                rationale=_norm_text(recommended_reason_fn(row)),
            )
        )
    return candidates


def _freeze_guidance(
    *,
    drift_count: int,
    capture_candidates: Sequence[CaptureCandidate],
    current_complete: int,
    current_in_progress: int,
    live_drift_checked: bool,
    dataset_apps_total: int,
) -> dict[str, str]:
    if dataset_apps_total <= 0:
        return {
            "mode": "empty_queue",
            "summary": "No dataset apps were resolved for the active cohort/queue. Check cohort selection, static-plan availability, and package grouping before capture.",
        }
    if not live_drift_checked:
        return {
            "mode": "select_device_first",
            "summary": "No selected device is active, so live build drift was not checked. Select a device before treating queue candidates as live-current capture targets.",
        }
    if drift_count <= 0:
        return {
            "mode": "live_current_capture_ready",
            "summary": "No live build drift detected; continue capture from the current queue state.",
        }
    if capture_candidates:
        return {
            "mode": "capture_non_drift_or_freeze_build_scoped",
            "summary": (
                f"{drift_count} app(s) drifted, but {len(capture_candidates)} non-drift quota-impact candidates remain. "
                "Either keep capturing non-drift apps now, or freeze the package with explicit build-scoped language."
            ),
        }
    if current_complete > 0 or current_in_progress > 0:
        return {
            "mode": "freeze_or_refresh_before_live_current_claims",
            "summary": (
                f"{drift_count} app(s) drifted and no safe non-drift capture candidates remain. "
                "Refresh harvest/static for drifted apps before further live-current claims, or freeze the package as build-scoped."
            ),
        }
    return {
        "mode": "refresh_required",
        "summary": "No usable live-current candidates remain; refresh drifted apps before more capture.",
    }


def summarize_prepared_view(
    *,
    prepared: Any,
    cohort_label: str,
    cohort_key: str | None,
    device_serial: str | None,
    device_label: str,
    candidate_limit: int,
    queue_status_label_fn,
    baseline_label_fn,
    interactive_label_fn,
    recommended_reason_fn,
) -> dict[str, Any]:
    row_models = list(getattr(prepared, "row_models", None) or [])
    drift_rows = _drift_rows(
        row_models,
        queue_status_label_fn=queue_status_label_fn,
        baseline_label_fn=baseline_label_fn,
        interactive_label_fn=interactive_label_fn,
    )
    candidates = _capture_candidates(
        row_models,
        queue_status_label_fn=queue_status_label_fn,
        baseline_label_fn=baseline_label_fn,
        interactive_label_fn=interactive_label_fn,
        recommended_reason_fn=recommended_reason_fn,
        candidate_limit=candidate_limit,
    )
    guidance = _freeze_guidance(
        drift_count=len(drift_rows),
        capture_candidates=candidates,
        current_complete=int(getattr(prepared, "current_build_ready_count", 0) or 0),
        current_in_progress=int(getattr(prepared, "current_build_in_progress_count", 0) or 0),
        live_drift_checked=bool(_norm_text(device_serial)),
        dataset_apps_total=int(getattr(prepared, "dataset_apps_total", 0) or 0),
    )
    evidence_summary = dict(getattr(prepared, "evidence_summary", None) or {})
    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "cohort": {
            "key": cohort_key,
            "label": cohort_label,
        },
        "device": {
            "serial": device_serial,
            "label": device_label,
            "live_drift_checked": bool(_norm_text(device_serial)),
        },
        "queue_summary": {
            "dataset_apps_total": int(getattr(prepared, "dataset_apps_total", 0) or 0),
            "current_build_complete": int(getattr(prepared, "current_build_ready_count", 0) or 0),
            "current_build_in_progress": int(getattr(prepared, "current_build_in_progress_count", 0) or 0),
            "current_build_review": int(getattr(prepared, "current_build_review_count", 0) or 0),
            "drifted_apps": len(drift_rows),
            "db_only_current_build_apps": int(getattr(prepared, "current_build_db_only_count", 0) or 0),
            "historical_local_only_apps": int(getattr(prepared, "historical_local_only_app_count", 0) or 0),
            "historical_db_only_apps": int(getattr(prepared, "historical_db_only_app_count", 0) or 0),
            "no_evidence_anywhere_apps": int(getattr(prepared, "no_evidence_anywhere_count", 0) or 0),
            "mixed_identity_apps": int(getattr(prepared, "mixed_identity_app_count", 0) or 0),
            "expected_quota_runs": int(getattr(prepared, "expected_runs", 0) or 0),
            "dataset_valid_runs_total": int(getattr(prepared, "dataset_valid_runs_total", 0) or 0),
        },
        "evidence_quota_summary": evidence_summary,
        "freeze_guidance": guidance,
        "drift_apps": [asdict(row) for row in drift_rows],
        "capture_candidates": [asdict(row) for row in candidates],
    }


def generate_report(*, candidate_limit: int, output_dir: Path | None = None) -> dict[str, Any]:
    from scytaledroid.DeviceAnalysis import device_manager
    from scytaledroid.DynamicAnalysis import app_queue_state
    from scytaledroid.DynamicAnalysis.menus import dynamic_menu
    from scytaledroid.DynamicAnalysis.research_cohort_runtime import (
        active_research_cohort_key,
        active_research_cohort_label,
    )
    from scytaledroid.StaticAnalysis.core.repository import group_artifacts

    device_serial = device_manager.get_active_serial()
    device_label = device_manager.describe_active_device()
    cohort_label = active_research_cohort_label()
    cohort_key = active_research_cohort_key()
    prepared = dynamic_menu._prepare_package_selection_view(group_artifacts(), device_serial=device_serial)
    if prepared is None:
        raise RuntimeError("dynamic package selection view could not be prepared")

    summary = summarize_prepared_view(
        prepared=prepared,
        cohort_label=cohort_label,
        cohort_key=cohort_key,
        device_serial=device_serial,
        device_label=device_label,
        candidate_limit=candidate_limit,
        queue_status_label_fn=app_queue_state.queue_status_label,
        baseline_label_fn=lambda row: app_queue_state.queue_baseline_runs_label(
            row,
            baseline_required=int(getattr(prepared.cfg, "baseline_required", 3) or 3),
        ),
        interactive_label_fn=lambda row: app_queue_state.queue_interactive_runs_label(
            row,
            interactive_required=int(getattr(prepared.cfg, "interactive_required", 4) or 4),
        ),
        recommended_reason_fn=app_queue_state.recommended_reason,
    )

    out_dir = output_dir or _default_output_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    _write_json(out_dir / "summary.json", summary)
    _write_csv(out_dir / "drift_apps.csv", summary["drift_apps"])
    _write_csv(out_dir / "capture_candidates.csv", summary["capture_candidates"])
    summary["output_files"] = {
        "summary_json": str((out_dir / "summary.json").resolve()),
        "drift_apps_csv": str((out_dir / "drift_apps.csv").resolve()),
        "capture_candidates_csv": str((out_dir / "capture_candidates.csv").resolve()),
    }
    _write_json(out_dir / "summary.json", summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    output_dir = Path(args.output_dir).resolve() if args.output_dir else None
    summary = generate_report(candidate_limit=max(1, int(args.candidate_limit)), output_dir=output_dir)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(json.dumps({"summary_json": summary["output_files"]["summary_json"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
