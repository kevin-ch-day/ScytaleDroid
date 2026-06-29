"""Dynamic analysis audit helpers for per-run logs and evidence artifacts."""

from __future__ import annotations

import json
import re
from pathlib import Path

from scytaledroid.Config import app_config


def dynamic_run_log_candidates(
    dynamic_run_id: str,
    *,
    logs_root: Path | None = None,
) -> tuple[Path | None, Path | None]:
    root = (logs_root or Path(app_config.LOGS_DIR)).expanduser().resolve() / "dynamic"
    run_id = dynamic_run_id.strip()
    if not run_id or not root.is_dir():
        return (None, None)

    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", run_id).strip("-") or "run"
    text_matches = sorted(root.glob(f"*_run-{slug}.log"))
    json_matches = sorted(root.glob(f"*_run-{slug}.jsonl"))
    return (
        text_matches[-1] if text_matches else None,
        json_matches[-1] if json_matches else None,
    )


def summarize_dynamic_run_artifacts(
    dynamic_run_id: str,
    *,
    logs_root: Path | None = None,
    evidence_root: Path | None = None,
) -> dict[str, object]:
    root = (evidence_root or (Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic")).expanduser().resolve()
    run_dir = root / dynamic_run_id
    text_log, json_log = dynamic_run_log_candidates(dynamic_run_id, logs_root=logs_root)
    events_path = run_dir / "notes" / "run_events.jsonl"
    monitor_path = run_dir / "notes" / "run_monitor.jsonl"
    pcap_report_path = run_dir / "analysis" / "pcap_report.json"
    pcap_features_path = run_dir / "analysis" / "pcap_features.json"
    overlap_path = run_dir / "analysis" / "static_dynamic_overlap.json"
    db_persistence_path = run_dir / "analysis" / "index" / "v1" / "db_persistence_status.json"

    latest_dataset_validity = _load_latest_event_details(events_path, event_type="dataset_validity")
    latest_derived_indexing = _load_latest_event_details(events_path, event_type="dynamic_derived_indexing_complete")

    return {
        "run_dir": str(run_dir),
        "run_dir_exists": run_dir.is_dir(),
        "dynamic_text_log": str(text_log) if text_log else None,
        "dynamic_json_log": str(json_log) if json_log else None,
        "events_path": str(events_path),
        "events_present": events_path.is_file(),
        "event_count": _jsonl_line_count(events_path),
        "monitor_path": str(monitor_path),
        "monitor_present": monitor_path.is_file(),
        "pcap_report_path": str(pcap_report_path),
        "pcap_report_present": pcap_report_path.is_file(),
        "pcap_features_path": str(pcap_features_path),
        "pcap_features_present": pcap_features_path.is_file(),
        "overlap_path": str(overlap_path),
        "overlap_present": overlap_path.is_file(),
        "db_persistence_status_path": str(db_persistence_path),
        "db_persistence_status": _load_json(db_persistence_path),
        "latest_dataset_validity": latest_dataset_validity,
        "latest_derived_indexing": latest_derived_indexing,
    }


def emit_dynamic_audit_report(
    dynamic_run_id: str,
    *,
    logs_root: Path | None = None,
    evidence_root: Path | None = None,
) -> None:
    summary = summarize_dynamic_run_artifacts(
        dynamic_run_id,
        logs_root=logs_root,
        evidence_root=evidence_root,
    )
    print("Dynamic analysis — run audit")
    print("----------------------------")
    print(f"Run ID        : {dynamic_run_id}")
    print(f"Run dir       : {summary['run_dir']} ({'present' if summary['run_dir_exists'] else 'missing'})")
    print(f"Dynamic log   : {summary['dynamic_text_log'] or '(not found)'}")
    print(f"Dynamic jsonl : {summary['dynamic_json_log'] or '(not found)'}")
    print(f"Run events    : {summary['events_path']} ({'present' if summary['events_present'] else 'missing'})")
    print(f"Event count   : {summary['event_count']}")
    print(f"Run monitor   : {summary['monitor_path']} ({'present' if summary['monitor_present'] else 'missing'})")
    print(f"PCAP report   : {summary['pcap_report_path']} ({'present' if summary['pcap_report_present'] else 'missing'})")
    print(f"PCAP features : {summary['pcap_features_path']} ({'present' if summary['pcap_features_present'] else 'missing'})")
    print(f"Overlap JSON  : {summary['overlap_path']} ({'present' if summary['overlap_present'] else 'missing'})")

    db_status = summary.get("db_persistence_status")
    if isinstance(db_status, dict):
        label = "ok" if db_status.get("ok") is True else str(db_status.get("error_code") or "failed")
        print(f"DB index      : {label}")

    dataset_validity = summary.get("latest_dataset_validity")
    if isinstance(dataset_validity, dict):
        print(
            "Dataset truth : "
            f"valid={dataset_validity.get('valid')} "
            f"countable={dataset_validity.get('countable')} "
            f"invalid_reason={dataset_validity.get('invalid_reason_code') or '—'}"
        )

    derived = summary.get("latest_derived_indexing")
    if isinstance(derived, dict):
        print(
            "Derived index : "
            f"features={derived.get('feature_rows', 0)} "
            f"indicators={derived.get('indicator_rows', 0)} "
            f"domains={derived.get('domain_rows', 0)}"
        )


def _load_json(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _load_latest_event_details(path: Path, *, event_type: str) -> dict[str, object] | None:
    if not path.exists():
        return None
    latest: dict[str, object] | None = None
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            if payload.get("event_type") != event_type:
                continue
            details = payload.get("details")
            if isinstance(details, dict):
                latest = details
    except OSError:
        return None
    return latest


def _jsonl_line_count(path: Path) -> int:
    if not path.exists():
        return 0
    try:
        return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    except OSError:
        return 0


__all__ = [
    "dynamic_run_log_candidates",
    "emit_dynamic_audit_report",
    "summarize_dynamic_run_artifacts",
]
