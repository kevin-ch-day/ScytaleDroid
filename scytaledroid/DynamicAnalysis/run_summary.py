"""Dynamic run summary rendering."""

from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Utils.DisplayUtils import menu_utils, status_messages


def print_run_summary(result, duration_label: str) -> None:
    status = result.status or "unknown"
    duration_seconds = result.elapsed_seconds or result.duration_seconds
    print()
    menu_utils.print_header("Dynamic run summary")
    lines = [
        ("Package", result.package_name or "unknown"),
        ("Run ID", result.dynamic_run_id or "unknown"),
        ("Duration", f"{duration_label} ({duration_seconds}s)"),
        ("Status", status),
    ]
    if result.evidence_path:
        lines.append(("Evidence", result.evidence_path))
    status_messages.print_strip("Session", lines, width=70)

    run_dir = Path(result.evidence_path) if result.evidence_path else None
    manifest = _load_manifest(run_dir) if run_dir else None
    summary_payload = _load_summary(run_dir) if run_dir else None
    if manifest:
        operator = manifest.get("operator") or {}
        telemetry_stats = operator.get("telemetry_stats") or {}
        sampling_rate = operator.get("sampling_rate_s")
        if telemetry_stats:
            expected = telemetry_stats.get("expected_samples")
            captured = telemetry_stats.get("captured_samples")
            max_gap = telemetry_stats.get("sample_max_gap_s")
            max_gap_excl_first = telemetry_stats.get("sample_max_gap_excluding_first_s")
            avg_delta = telemetry_stats.get("sample_avg_delta_s")
            sampling_duration = telemetry_stats.get("sampling_duration_seconds")
            ratio = None
            if expected and captured is not None:
                try:
                    ratio = float(captured) / float(expected)
                except Exception:
                    ratio = None
            telemetry_lines = []
            if sampling_rate:
                telemetry_lines.append(f"Sampling rate: {sampling_rate}s")
            if sampling_duration is not None:
                try:
                    telemetry_lines.append(f"Sampling window: {float(sampling_duration):.0f}s")
                except Exception:
                    telemetry_lines.append(f"Sampling window: {sampling_duration}s")
            if expected is not None and captured is not None:
                telemetry_lines.append(f"Samples: {captured}/{expected}")
            if ratio is not None:
                telemetry_lines.append(f"Capture ratio: {ratio:.3f}")
            if max_gap is not None:
                telemetry_lines.append(f"Max gap: {max_gap:.2f}s")
            if max_gap_excl_first is not None:
                telemetry_lines.append(f"Max gap (excl first): {max_gap_excl_first:.2f}s")
            if avg_delta is not None:
                telemetry_lines.append(f"Avg delta: {avg_delta:.2f}s")
            if sampling_duration is not None and duration_seconds:
                try:
                    delta = abs(float(duration_seconds) - float(sampling_duration))
                    overhead_line = (
                        f"Elapsed (wall): {int(duration_seconds)}s | "
                        f"Sampling window: {float(sampling_duration):.0f}s | "
                        f"Overhead: {delta:.0f}s"
                    )
                    if delta > 5 and any(token in duration_label.lower() for token in ("guided", "manual")):
                        overhead_line += " (expected in guided/manual runs; includes setup/teardown)"
                    telemetry_lines.append(overhead_line)
                except Exception:
                    pass
            if telemetry_lines:
                _print_simple_list("Telemetry", telemetry_lines)
            if summary_payload:
                telemetry = summary_payload.get("telemetry", {})
                net_quality = telemetry.get("network_signal_quality")
                stats = telemetry.get("stats") or {}
                net_rows = stats.get("netstats_rows")
                net_missing = stats.get("netstats_missing_rows")
                total_in = stats.get("netstats_bytes_in_total")
                total_out = stats.get("netstats_bytes_out_total")
                if net_quality:
                    details = []
                    if total_in is not None or total_out is not None:
                        try:
                            total_bytes = int(total_in or 0) + int(total_out or 0)
                            details.append(f"total_bytes={_format_bytes(total_bytes)}")
                        except Exception:
                            pass
                    if net_rows is not None or net_missing is not None:
                        details.append(
                            f"rows={net_rows if net_rows is not None else '?'} "
                            f"missing={net_missing if net_missing is not None else '?'}"
                        )
                    line = f"Quality: {net_quality}"
                    if details:
                        line += f" ({', '.join(details)})"
                    _print_simple_list("Network QA", [line])

        observers = manifest.get("observers") or []
        if observers:
            observer_lines = []
            failure_lines = []
            for observer in observers:
                observer_id = observer.get("observer_id", "unknown")
                obs_status = observer.get("status", "unknown")
                err = observer.get("error")
                label = f"{observer_id}: {obs_status}"
                if err:
                    label += f" ({err})"
                    if obs_status == "failed":
                        failure_lines.append(f"{observer_id}: {err}")
                observer_lines.append(label)
            _print_simple_list("Observers", observer_lines)
            if failure_lines:
                _print_simple_list("Observer errors", failure_lines)

        artifacts = manifest.get("artifacts") or []
        outputs = manifest.get("outputs") or []
        if artifacts or outputs:
            artifact_summary = [
                f"Artifacts: {len(artifacts)}",
                f"Outputs: {len(outputs)}",
            ]
            _print_simple_list("Artifacts", artifact_summary)

        evidence_lines = []
        if summary_payload:
            capture_info = summary_payload.get("capture") or {}
            pcap_valid = capture_info.get("pcap_valid")
            pcap_size = capture_info.get("pcap_size_bytes")
            capture_mode = capture_info.get("capture_mode")
            if pcap_valid is not None or pcap_size is not None or capture_mode:
                size_label = _format_bytes(int(pcap_size)) if isinstance(pcap_size, int) else "unknown size"
                valid_label = "valid" if pcap_valid is True else "invalid" if pcap_valid is False else "unknown"
                mode_label = capture_mode or "unknown"
                evidence_lines.append(f"PCAPdroid: {mode_label} | {size_label} | {valid_label}")
            if pcap_valid is False:
                size_label = f"{pcap_size}B" if pcap_size is not None else "unknown size"
                min_bytes = capture_info.get("min_pcap_bytes")
                threshold_label = f"{min_bytes}B" if min_bytes is not None else "unknown threshold"
                print(
                    status_messages.status(
                        f"PCAP invalid ({size_label} < {threshold_label}); treated as unavailable for Tier-1.",
                        level="warn",
                    )
                )
            if pcap_valid is None and pcap_size is None:
                if any(
                    isinstance(observer, dict)
                    and str(observer.get("observer_id", "")).startswith("pcapdroid")
                    for observer in (manifest.get("observers") or [])
                ):
                    print(
                        status_messages.status(
                            "PCAP metadata missing; DB fields may be NULL. Run the backfill action if needed.",
                            level="warn",
                        )
                    )
        artifact_types = {a.get("type") for a in artifacts if isinstance(a, dict)}
        if "system_log_capture" in artifact_types:
            evidence_lines.append("System log: yes")
        if evidence_lines:
            _print_simple_list("Evidence", evidence_lines)

        summary_paths = _summary_paths(manifest)
        if summary_paths:
            _print_simple_list("Summary", summary_paths)

        if run_dir:
            events_path = run_dir / "notes" / "run_events.jsonl"
            if events_path.exists():
                _print_simple_list("Logs", [f"Events: {events_path}"])

    if status == "blocked":
        print(status_messages.status("Session blocked by plan validation.", level="warn"))
    elif status != "success":
        print(status_messages.status("Session marked as degraded. Check observer errors above.", level="warn"))


def _load_manifest(run_dir: Path | None) -> dict[str, object] | None:
    if not run_dir:
        return None
    manifest_path = run_dir / "run_manifest.json"
    if not manifest_path.exists():
        return None
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _load_summary(run_dir: Path | None) -> dict[str, object] | None:
    if not run_dir:
        return None
    summary_path = run_dir / "analysis" / "summary.json"
    if not summary_path.exists():
        return None
    try:
        return json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _format_bytes(size: int) -> str:
    if size <= 0:
        return "0B"
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.0f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"


def _summary_paths(manifest: dict[str, object]) -> list[str]:
    outputs = manifest.get("outputs") or []
    summary = {}
    for item in outputs:
        if not isinstance(item, dict):
            continue
        artifact_type = item.get("type")
        path = item.get("relative_path")
        if artifact_type and path:
            summary[artifact_type] = path
    lines = []
    if "analysis_summary_json" in summary:
        lines.append(f"summary.json: {summary['analysis_summary_json']}")
    if "analysis_summary_md" in summary:
        lines.append(f"summary.md: {summary['analysis_summary_md']}")
    return lines


def _print_simple_list(title: str, items: list[str]) -> None:
    if not items:
        return
    lines = [(str(index + 1), value) for index, value in enumerate(items)]
    status_messages.print_strip(title, lines, width=70)


__all__ = ["print_run_summary"]
