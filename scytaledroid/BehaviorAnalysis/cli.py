"""CLI entrypoints for BehaviorAnalysis MVP."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

from scytaledroid.BehaviorAnalysis.telemetry import (
    collect_process_sample,
    collect_network_sample,
    resolve_package_info,
    resolve_pid_uid,
)
from scytaledroid.BehaviorAnalysis.features import (
    build_windows,
    write_features_csv,
)
from scytaledroid.BehaviorAnalysis.models import score_windows
from scytaledroid.BehaviorAnalysis.report import build_behavior_report, write_anomaly_plot
from scytaledroid.BehaviorAnalysis.markers import append_marker
from scytaledroid.BehaviorAnalysis.schemas import (
    PROCESS_SCHEMA,
    NETWORK_SCHEMA,
    FEATURE_SCHEMA_HEADERS,
    SCORES_SCHEMA,
    validate_row,
)
from scytaledroid.Config import app_config
from scytaledroid.Database.tools.bootstrap import bootstrap_database
from scytaledroid.Utils.LoggingUtils import logging_utils as log


DEFAULT_SAMPLE_RATE = 2.0
DEFAULT_WINDOW_LENGTH = 60.0
DEFAULT_WINDOW_STEP = 10.0
FEATURE_SCHEMA_VERSION = "1"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _session_dir(session_id: str) -> Path:
    return Path(app_config.OUTPUT_DIR) / "behavior_sessions" / session_id


def _write_metadata(
    session_dir: Path,
    metadata: Dict[str, object],
) -> None:
    session_dir.mkdir(parents=True, exist_ok=True)
    meta_path = session_dir / "metadata.json"
    meta_path.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")


def _write_markers(session_dir: Path, markers: List[Dict[str, object]]) -> None:
    markers_path = session_dir / "markers.jsonl"
    with markers_path.open("w", encoding="utf-8") as handle:
        for entry in markers:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")


def behavior_run(args: argparse.Namespace) -> None:
    bootstrap_database()
    package = args.package
    duration_s = args.duration
    sample_rate = args.sample_rate
    scenario = args.scenario
    window_length = args.window_length
    window_step = args.window_step
    strict_schema = bool(args.strict_schema)

    session_id = args.session or _now().strftime("%Y%m%d-%H%M%S")
    session_dir = _session_dir(session_id)
    telemetry_dir = session_dir / "telemetry"
    features_dir = session_dir / "features"
    model_dir = session_dir / "model"
    plots_dir = session_dir / "plots"
    reports_dir = session_dir / "reports"
    for directory in (telemetry_dir, features_dir, model_dir, plots_dir, reports_dir):
        directory.mkdir(parents=True, exist_ok=True)

    device_info = resolve_package_info(package)
    uid, pid = resolve_pid_uid(package)
    capabilities = {
        "process_available": uid is not None,
        "network_available": uid is not None,
        "events_available": True,  # markers always available
    }
    telemetry_available = bool(uid)

    start = _now()
    end = start + timedelta(seconds=duration_s)
    markers: List[Dict[str, object]] = []
    process_rows: List[Dict[str, object]] = []
    network_rows: List[Dict[str, object]] = []
    missed_samples = 0
    network_source_summary: Dict[str, int] = {}

    while _now() < end:
        ts = _now()
        if uid:
            start_sample = time.time()
            process_rows.append(collect_process_sample(package, uid, pid, ts, strict=strict_schema))
            net_sample = collect_network_sample(uid, ts)
            network_rows.append(net_sample)
            src = str(net_sample.get("source") or "unknown")
            network_source_summary[src] = network_source_summary.get(src, 0) + 1
            elapsed = time.time() - start_sample
            if elapsed > sample_rate * 2:
                missed_samples += 1
        else:
            missed_samples += 1
        time.sleep(sample_rate)

    process_path = telemetry_dir / "process.csv"
    network_path = telemetry_dir / "network.csv"
    write_csv(process_path, process_rows, PROCESS_SCHEMA, strict=strict_schema)
    write_csv(network_path, network_rows, NETWORK_SCHEMA, strict=strict_schema)

    windows = build_windows(
        process_rows,
        network_rows,
        markers,
        window_length=window_length,
        window_step=window_step,
    )
    windows_path = features_dir / "windows.csv"
    write_features_csv(windows_path, windows)

    scores = score_windows(windows)
    model_backend = "sklearn" if scores else "fallback"
    if not scores:
        # fallback scoring is produced inside score_windows when sklearn missing
        scores = score_windows(windows, backend_hint="fallback")
        model_backend = "fallback"
    scores_path = model_dir / "scores.csv"
    write_csv(scores_path, scores, SCORES_SCHEMA, strict=strict_schema)

    plot_path = plots_dir / "anomaly_timeline.png"
    write_anomaly_plot(windows, scores, plot_path)

    metadata = {
        "session_id": session_id,
        "package": package,
        "scenario": scenario,
        "duration_s": duration_s,
        "sample_rate_s": sample_rate,
        "window_length_s": window_length,
        "window_step_s": window_step,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "training_mode": "in_session_quantile",
        "threshold_policy": "quantile_0.98",
        "device": device_info,
        "uid": uid,
        "pid": pid,
        "collector_capabilities": capabilities,
        "missed_sample_count": missed_samples,
        "network_source_summary": network_source_summary,
        "start_utc": start.isoformat(),
        "end_utc": _now().isoformat(),
        "git_commit": os.environ.get("SCYTALEDROID_GIT_HASH", "unknown"),
        "best_effort_network": any(row.get("best_effort") for row in network_rows),
        "model_backend": model_backend,
        "telemetry_available": telemetry_available,
        "uid_resolution": "success" if uid else "fail",
        "pid_resolution": "success" if pid else ("fail" if uid else "skip"),
        "target_package_installed": device_info.get("target_package_installed"),
    }
    print(f"SESSION_ID={session_id}")
    _write_metadata(session_dir, metadata)
    _write_markers(session_dir, markers)

    report_path = reports_dir / "behavior_report.md"
    build_behavior_report(
        metadata=metadata,
        markers=markers,
        windows=windows,
        scores=scores,
        plot_path=plot_path,
        report_path=report_path,
    )
    log.info(f"Behavior session complete: {session_dir}", category="behavior")


def write_csv(path: Path, rows: List[Dict[str, object]], schema, *, strict: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write(",".join(schema.headers) + "\n")
        for row in rows:
            cleaned = validate_row(schema, row, strict=strict)
            values = []
            for key in schema.headers:
                val = cleaned.get(key)
                if strict and val is None:
                    raise ValueError(f"Strict schema validation failed for {schema.name}:{key}")
                val = "" if val is None else val
                values.append(str(val))
            handle.write(",".join(values) + "\n")
        if not rows:
            # Always keep file non-empty with header even if no data
            pass


def _load_csv(path: Path) -> List[Dict[str, object]]:
    if not path.exists():
        return []
    rows: List[Dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    if not lines:
        return []
    headers = lines[0].split(",")
    for line in lines[1:]:
        if not line.strip():
            continue
        parts = line.split(",")
        row = {h: parts[idx] if idx < len(parts) else "" for idx, h in enumerate(headers)}
        rows.append(row)
    return rows


def behavior_mark(args: argparse.Namespace) -> None:
    session_dir = _session_dir(args.session)
    append_marker(session_dir, args.label)
    log.info(f"Marker appended to {session_dir}", category="behavior")


def behavior_report(args: argparse.Namespace) -> None:
    session_dir = _session_dir(args.session)
    metadata_path = session_dir / "metadata.json"
    if not metadata_path.exists():
        raise SystemExit(f"Missing metadata for session {args.session}")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    markers = []
    markers_path = session_dir / "markers.jsonl"
    if markers_path.exists():
        with markers_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                markers.append(json.loads(line))
    windows_path = session_dir / "features" / "windows.csv"
    scores_path = session_dir / "model" / "scores.csv"
    windows = _load_csv(windows_path)
    scores = _load_csv(scores_path)
    report_path = session_dir / "reports" / "behavior_report.md"
    plot_path = session_dir / "plots" / "anomaly_timeline.png"
    build_behavior_report(metadata, markers, windows, scores, plot_path, report_path)
    log.info(f"Report regenerated for session {args.session}", category="behavior")


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="behavior", description="Behavior analysis commands")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Run a behavior session")
    run_p.add_argument("--package", required=True, help="Target package name")
    run_p.add_argument("--duration", type=int, default=300, help="Duration seconds")
    run_p.add_argument("--sample-rate", type=float, default=DEFAULT_SAMPLE_RATE, help="Sample interval seconds")
    run_p.add_argument("--scenario", default="idle", help="Scenario label")
    run_p.add_argument("--session", help="Session id (defaults to timestamp)")
    run_p.add_argument("--window-length", type=float, default=DEFAULT_WINDOW_LENGTH)
    run_p.add_argument("--window-step", type=float, default=DEFAULT_WINDOW_STEP)
    run_p.add_argument("--strict-schema", action="store_true", help="Fail on schema/type validation errors.")
    run_p.set_defaults(func=behavior_run)

    mark_p = sub.add_parser("mark", help="Append a marker to a session")
    mark_p.add_argument("--session", required=True, help="Session id")
    mark_p.add_argument("--label", required=True, help="Marker label")
    mark_p.set_defaults(func=behavior_mark)

    report_p = sub.add_parser("report", help="Regenerate report for a session")
    report_p.add_argument("--session", required=True, help="Session id")
    report_p.set_defaults(func=behavior_report)
    return parser


def main(argv: Optional[List[str]] = None) -> None:
    parser = make_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
