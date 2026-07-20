#!/usr/bin/env python3
"""Read-only export of scripted interaction phases and phase-aware packet summaries."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=None, help="Optional explicit output directory.")
    return parser


def _dynamic_root() -> Path:
    from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root

    return dynamic_evidence_root()


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fieldnames})


def generate_report(*, output_dir: Path | None = None) -> dict[str, Any]:
    from scytaledroid.DynamicAnalysis.pcap.diagnostics import dataset_pcap_failure_detail
    from scytaledroid.DynamicAnalysis.pcap.interaction_phases import (
        build_interaction_timeline_from_run_dir,
        build_protocol_phase_marker_rows,
        phase_packet_transport_summary,
    )

    root = _dynamic_root()
    phase_rows: list[dict[str, Any]] = []
    marker_rows: list[dict[str, Any]] = []
    transport_rows: list[dict[str, Any]] = []

    scripted_runs_seen = 0
    complete_timelines = 0
    incomplete_timelines = 0
    runs_without_timeline = 0
    runs_without_transport_summary = 0
    transport_rows_skipped_missing_pcap = 0
    scripted_runs_with_timeline_but_no_pcap = 0
    scripted_runs_invalid_pcap = 0
    scripted_runs_valid_pcap = 0
    invalid_pcap_detail_counts: Counter[str] = Counter()

    for manifest_path in sorted(root.glob("*/run_manifest.json")):
        run_dir = manifest_path.parent
        manifest = _read_json(manifest_path) or {}
        operator = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
        target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
        run_profile = str(operator.get("run_profile") or "").strip().lower()
        if run_profile != "interaction_scripted":
            continue
        scripted_runs_seen += 1

        run_id = str(manifest.get("dynamic_run_id") or run_dir.name)
        package = str(target.get("package_name") or "").strip().lower()
        app_label = str(target.get("display_name") or target.get("app_label") or package)
        dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), dict) else {}
        pcap_available_raw = dataset.get("pcap_available")
        if pcap_available_raw is None:
            pcap_available = any(
                path.stat().st_size > 0
                for path in (run_dir / "artifacts" / "pcapdroid_capture").glob("*.pcap*")
                if path.is_file()
            )
        else:
            pcap_available = bool(pcap_available_raw)
        invalid_reason = str(dataset.get("invalid_reason_code") or "").strip().upper()
        pcap_size_bytes = int(dataset.get("pcap_size_bytes") or 0)
        pcap_failure_detail = str(dataset.get("pcap_failure_detail") or "").strip()
        if not pcap_failure_detail and (not pcap_available or invalid_reason.startswith("PCAP_")):
            pcap_failure_detail = str(dataset_pcap_failure_detail(run_dir, pcap_size_int=pcap_size_bytes) or "").strip()
        if pcap_available:
            scripted_runs_valid_pcap += 1
        elif invalid_reason.startswith("PCAP_"):
            scripted_runs_invalid_pcap += 1
            if pcap_failure_detail:
                invalid_pcap_detail_counts[pcap_failure_detail] += 1
        timeline = _read_json(run_dir / "analysis" / "interaction_timeline.json")
        if not isinstance(timeline, dict):
            timeline = build_interaction_timeline_from_run_dir(run_dir, manifest=manifest)
        if not isinstance(timeline, dict):
            runs_without_timeline += 1
            continue
        if not pcap_available:
            scripted_runs_with_timeline_but_no_pcap += 1
        if bool(timeline.get("timeline_complete")):
            complete_timelines += 1
        else:
            incomplete_timelines += 1

        for step in timeline.get("steps") or []:
            if not isinstance(step, dict):
                continue
            phase_rows.append(
                {
                    "package": package,
                    "app_label": app_label,
                    "run_id": run_id,
                    "run_profile": str(timeline.get("run_profile") or operator.get("run_profile") or ""),
                    "template_id": str(timeline.get("template_id") or ""),
                    "template_hash": str(timeline.get("template_hash") or ""),
                    "step_index": step.get("step_index"),
                    "step_id": step.get("step_id"),
                    "phase_label": step.get("phase_label"),
                    "planned_duration_sec": step.get("planned_duration_sec"),
                    "actual_duration_sec": step.get("actual_duration_sec"),
                    "actual_start_timestamp": step.get("actual_start_timestamp"),
                    "actual_end_timestamp": step.get("actual_end_timestamp"),
                    "operator_completed": step.get("operator_completed"),
                    "operator_result": step.get("operator_result"),
                    "step_outcome": step.get("step_outcome"),
                    "limitation_reason": step.get("limitation_reason"),
                    "account_context": step.get("account_context"),
                    "control_account": step.get("control_account"),
                    "control_account_mode": step.get("control_account_mode"),
                    "mutation_allowed": step.get("mutation_allowed"),
                    "mutation_candidate": step.get("mutation_candidate"),
                    "mutation_performed": step.get("mutation_performed"),
                    "cleanup_expected": step.get("cleanup_expected"),
                    "repeat_group": step.get("repeat_group"),
                    "repeat_index": step.get("repeat_index"),
                    "repeat_total": step.get("repeat_total"),
                    "repeat_max_total": step.get("repeat_max_total"),
                    "repeat_enabled": step.get("repeat_enabled"),
                    "branch_taken": step.get("branch_taken"),
                    "article_branch": step.get("article_branch"),
                    "subscription_wall_observed": step.get("subscription_wall_observed"),
                    "subscription_options_opened": step.get("subscription_options_opened"),
                    "return_home_performed": step.get("return_home_performed"),
                    "protocol_fit": step.get("protocol_fit"),
                    "notes_present": bool(str(step.get("operator_note") or step.get("notes") or "").strip()),
                    "operator_note": step.get("operator_note"),
                    "notes": step.get("notes"),
                    "timeline_complete": timeline.get("timeline_complete"),
                    "pcap_available": pcap_available,
                    "invalid_reason_code": invalid_reason,
                    "pcap_failure_detail": pcap_failure_detail,
                }
            )

        for row in build_protocol_phase_marker_rows(timeline):
            marker_rows.append(
                {
                    "package": package,
                    "app_label": app_label,
                    "run_id": run_id,
                    "template_id": str(timeline.get("template_id") or ""),
                    "marker_type": row.get("marker_type"),
                    "step_index": row.get("step_index"),
                    "step_id": row.get("step_id"),
                    "phase_id": row.get("phase_id"),
                    "phase_label": row.get("phase_label"),
                    "start_time": row.get("start_time"),
                    "end_time": row.get("end_time"),
                    "operator_result": row.get("operator_result"),
                    "step_outcome": row.get("step_outcome"),
                    "limitation_reason": row.get("limitation_reason"),
                    "account_context": row.get("account_context"),
                    "control_account": row.get("control_account"),
                    "control_account_mode": row.get("control_account_mode"),
                    "mutation_allowed": row.get("mutation_allowed"),
                    "mutation_candidate": row.get("mutation_candidate"),
                    "mutation_performed": row.get("mutation_performed"),
                    "cleanup_expected": row.get("cleanup_expected"),
                    "repeat_group": row.get("repeat_group"),
                    "repeat_index": row.get("repeat_index"),
                    "repeat_total": row.get("repeat_total"),
                    "repeat_max_total": row.get("repeat_max_total"),
                    "repeat_enabled": row.get("repeat_enabled"),
                    "branch_taken": row.get("branch_taken"),
                    "article_branch": row.get("article_branch"),
                    "subscription_wall_observed": row.get("subscription_wall_observed"),
                    "subscription_options_opened": row.get("subscription_options_opened"),
                    "return_home_performed": row.get("return_home_performed"),
                    "protocol_fit": row.get("protocol_fit"),
                }
            )

        run_transport_rows = phase_packet_transport_summary(run_dir, timeline=timeline, manifest=manifest)
        if not run_transport_rows:
            runs_without_transport_summary += 1
            if not pcap_available:
                transport_rows_skipped_missing_pcap += len(
                    [step for step in (timeline.get("steps") or []) if isinstance(step, dict)]
                )
        for row in run_transport_rows:
            transport_rows.append(
                {
                    "package": package,
                    "app_label": app_label,
                    "run_id": run_id,
                    "template_id": str(timeline.get("template_id") or ""),
                    "step_index": row.get("step_index"),
                    "step_id": row.get("step_id"),
                    "phase_label": row.get("phase_label"),
                    "step_outcome": row.get("step_outcome"),
                    "limitation_reason": row.get("limitation_reason"),
                    "packet_count": row.get("packet_count"),
                    "byte_count": row.get("byte_count"),
                    "tcp_packet_count": row.get("tcp_packet_count"),
                    "udp_packet_count": row.get("udp_packet_count"),
                    "tls_packet_count": row.get("tls_packet_count"),
                    "quic_packet_count": row.get("quic_packet_count"),
                    "dns_packet_count": row.get("dns_packet_count"),
                    "http_packet_count": row.get("http_packet_count"),
                    "cleartext_surface_flag": row.get("cleartext_surface_flag"),
                    "http_host_count": row.get("http_host_count"),
                    "http_hosts_sample": row.get("http_hosts_sample"),
                    "uplink_packet_count": row.get("uplink_packet_count"),
                    "downlink_packet_count": row.get("downlink_packet_count"),
                    "unknown_direction_packet_count": row.get("unknown_direction_packet_count"),
                    "visibility_loss_flag": row.get("visibility_loss_flag"),
                }
            )

    if output_dir is None:
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        output_dir = _REPO_ROOT / "output" / "audit" / "dynamic_interaction_phases" / stamp
    output_dir.mkdir(parents=True, exist_ok=True)

    phase_rows.sort(key=lambda row: (str(row.get("package") or ""), str(row.get("run_id") or ""), int(row.get("step_index") or 0)))
    marker_rows.sort(key=lambda row: (str(row.get("package") or ""), str(row.get("run_id") or ""), int(row.get("step_index") or 0), str(row.get("marker_type") or "")))
    transport_rows.sort(key=lambda row: (str(row.get("package") or ""), str(row.get("run_id") or ""), int(row.get("step_index") or 0)))

    phase_path = output_dir / "interaction_phase_summary.csv"
    marker_path = output_dir / "protocol_phase_markers.csv"
    transport_path = output_dir / "phase_packet_transport_summary.csv"
    summary_path = output_dir / "summary.json"

    _write_csv(
        phase_path,
        phase_rows,
        [
            "package",
            "app_label",
            "run_id",
            "run_profile",
            "template_id",
            "template_hash",
            "step_index",
            "step_id",
            "phase_label",
            "planned_duration_sec",
            "actual_duration_sec",
            "actual_start_timestamp",
            "actual_end_timestamp",
            "operator_completed",
            "operator_result",
            "step_outcome",
            "limitation_reason",
            "account_context",
            "control_account",
            "control_account_mode",
            "mutation_allowed",
            "mutation_candidate",
            "mutation_performed",
            "cleanup_expected",
            "repeat_group",
            "repeat_index",
            "repeat_total",
            "repeat_max_total",
            "repeat_enabled",
            "branch_taken",
            "article_branch",
            "subscription_wall_observed",
            "subscription_options_opened",
            "return_home_performed",
            "protocol_fit",
            "notes_present",
            "operator_note",
            "notes",
            "timeline_complete",
            "pcap_available",
            "invalid_reason_code",
            "pcap_failure_detail",
        ],
    )
    _write_csv(
        marker_path,
        marker_rows,
        [
            "package",
            "app_label",
            "run_id",
            "template_id",
            "marker_type",
            "step_index",
            "step_id",
            "phase_id",
            "phase_label",
            "start_time",
            "end_time",
            "operator_result",
            "step_outcome",
            "limitation_reason",
            "account_context",
            "control_account",
            "control_account_mode",
            "mutation_allowed",
            "mutation_candidate",
            "mutation_performed",
            "cleanup_expected",
            "repeat_group",
            "repeat_index",
            "repeat_total",
            "repeat_max_total",
            "repeat_enabled",
            "branch_taken",
            "article_branch",
            "subscription_wall_observed",
            "subscription_options_opened",
            "return_home_performed",
            "protocol_fit",
        ],
    )
    _write_csv(
        transport_path,
        transport_rows,
        [
            "package",
            "app_label",
            "run_id",
            "template_id",
            "step_index",
            "step_id",
            "phase_label",
            "step_outcome",
            "limitation_reason",
            "packet_count",
            "byte_count",
            "tcp_packet_count",
            "udp_packet_count",
            "tls_packet_count",
            "quic_packet_count",
            "dns_packet_count",
            "http_packet_count",
            "cleartext_surface_flag",
            "http_host_count",
            "http_hosts_sample",
            "uplink_packet_count",
            "downlink_packet_count",
            "unknown_direction_packet_count",
            "visibility_loss_flag",
        ],
    )

    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "dynamic_root": str(root.resolve()),
        "scripted_runs_seen": scripted_runs_seen,
        "phase_rows_exported": len(phase_rows),
        "marker_rows_exported": len(marker_rows),
        "transport_rows_exported": len(transport_rows),
        "timeline_complete_runs": complete_timelines,
        "timeline_incomplete_runs": incomplete_timelines,
        "runs_without_timeline": runs_without_timeline,
        "runs_without_transport_summary": runs_without_transport_summary,
        "transport_rows_skipped_missing_pcap": transport_rows_skipped_missing_pcap,
        "scripted_runs_with_timeline_but_no_pcap": scripted_runs_with_timeline_but_no_pcap,
        "scripted_runs_invalid_pcap": scripted_runs_invalid_pcap,
        "scripted_runs_valid_pcap": scripted_runs_valid_pcap,
        "scripted_runs_invalid_pcap_by_detail": dict(sorted(invalid_pcap_detail_counts.items())),
        "output_files": {
            "interaction_phase_summary_csv": str(phase_path.resolve()),
            "protocol_phase_markers_csv": str(marker_path.resolve()),
            "phase_packet_transport_summary_csv": str(transport_path.resolve()),
            "summary_json": str(summary_path.resolve()),
        },
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    output_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else None
    summary = generate_report(output_dir=output_dir)
    print(f"output_dir={Path(summary['output_files']['summary_json']).parent}")
    print(
        "scripted_runs_seen="
        f"{summary['scripted_runs_seen']} "
        f"timeline_complete_runs={summary['timeline_complete_runs']} "
        f"timeline_incomplete_runs={summary['timeline_incomplete_runs']}"
    )
    print(
        "phase_rows_exported="
        f"{summary['phase_rows_exported']} "
        f"marker_rows_exported={summary['marker_rows_exported']} "
        f"transport_rows_exported={summary['transport_rows_exported']}"
    )
    print(
        "scripted_runs_valid_pcap="
        f"{summary['scripted_runs_valid_pcap']} "
        f"scripted_runs_invalid_pcap={summary['scripted_runs_invalid_pcap']} "
        f"scripted_runs_with_timeline_but_no_pcap={summary['scripted_runs_with_timeline_but_no_pcap']} "
        f"transport_rows_skipped_missing_pcap={summary['transport_rows_skipped_missing_pcap']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
