"""Dynamic run summary rendering."""

from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.utils.path_utils import resolve_evidence_path
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import load_dataset_tracker
from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages


def print_run_summary(result, duration_label: str) -> None:
    status = result.status or "unknown"
    duration_seconds = result.elapsed_seconds or result.duration_seconds
    run_dir = resolve_evidence_path(result.evidence_path) if result.evidence_path else None
    manifest = _load_manifest(run_dir) if run_dir else None
    print()
    lines = [
        ("Package", result.package_name or "unknown"),
        ("Run ID", result.dynamic_run_id or "unknown"),
        ("Duration", f"{duration_label} ({duration_seconds}s)"),
        ("Status", status),
    ]
    if manifest:
        operator = manifest.get("operator") or {}
        run_profile = operator.get("run_profile")
        run_sequence = operator.get("run_sequence")
        if run_profile:
            seq_label = f"#{run_sequence}" if run_sequence else "—"
            lines.append(("Run profile", f"{run_profile} (run {seq_label})"))
        interaction = operator.get("interaction_level")
        if interaction:
            lines.append(("Interaction", str(interaction)))
    dataset_validity = _dataset_validity_label(result.dynamic_run_id)
    if dataset_validity:
        lines.append(("Dataset validity", dataset_validity))
        if dataset_validity.startswith("❌"):
            reasons = _dataset_validity_reasons(result.dynamic_run_id)
            if reasons:
                lines.append(("Dataset issues", ", ".join(reasons)))
    if result.evidence_path:
        lines.append(("Evidence", result.evidence_path))
    status_messages.print_strip("Session", lines, width=70)

    summary_payload = _load_summary(run_dir) if run_dir else None
    engine_summary = _load_engine_summary(run_dir) if run_dir else None
    if manifest:
        operator = manifest.get("operator") or {}
        telemetry_stats = operator.get("telemetry_stats") or {}
        sampling_rate = operator.get("sampling_rate_s")
        artifacts = manifest.get("artifacts") or []
        outputs = manifest.get("outputs") or []

        telemetry_lines = _build_telemetry_lines(
            telemetry_stats,
            duration_seconds,
            duration_label,
        )
        if telemetry_lines:
            _print_simple_list("Telemetry QA", telemetry_lines)

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
                if (net_rows == 0 or net_rows is None) and (net_missing or 0) > 0:
                    print(
                        status_messages.status(
                            "Netstats missing data recorded; network telemetry may be incomplete.",
                            level="warn",
                        )
                    )

        artifact_summary = [
            f"Artifacts: {len(artifacts)}",
            f"Outputs: {len(outputs)}",
        ]
        _print_simple_list("Artifacts", artifact_summary)

        evidence_lines = _build_evidence_lines(summary_payload, artifacts, manifest)
        if evidence_lines:
            _print_simple_list("Evidence", evidence_lines)

        if engine_summary:
            warnings = engine_summary.get("diagnostics_warnings") or []
            if warnings:
                _print_simple_list("Diagnostics", [str(item) for item in warnings])

        show_details = prompt_utils.prompt_yes_no("Show details?", default=False)
        if show_details:
            if sampling_rate:
                _print_simple_list("Telemetry details", [f"Sampling rate: {sampling_rate}s"])
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

            summary_paths = _summary_paths(manifest)
            if summary_paths:
                _print_simple_list("Summary", summary_paths)

        if run_dir:
            events_path = run_dir / "notes" / "run_events.jsonl"
            if events_path.exists():
                _print_simple_list("Logs", [f"Events: {events_path}"])
            monitor_path = run_dir / "notes" / "run_monitor.jsonl"
            if monitor_path.exists():
                _print_simple_list("Monitor", [f"Runtime: {monitor_path}"])

    if status == "blocked":
        print(status_messages.status("Session blocked by plan validation.", level="warn"))
    elif status != "success":
        print(status_messages.status("Session marked as degraded. Check observer errors above.", level="warn"))
    if result.dynamic_run_id and result.evidence_path:
        print(
            status_messages.status(
                f"Run complete: {result.dynamic_run_id} ({result.evidence_path})",
                level="info",
            )
        )


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


def _load_engine_summary(run_dir: Path | None) -> dict[str, object] | None:
    if not run_dir:
        return None
    summary_path = run_dir / "analysis" / "engine_summary.json"
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


def _dataset_validity_label(dynamic_run_id: str | None) -> str | None:
    if not dynamic_run_id:
        return None
    tracker = load_dataset_tracker()
    apps = tracker.get("apps") if isinstance(tracker, dict) else {}
    if not isinstance(apps, dict):
        return None
    for entry in apps.values():
        if not isinstance(entry, dict):
            continue
        runs = entry.get("runs")
        if not isinstance(runs, list):
            continue
        for run in runs:
            if not isinstance(run, dict):
                continue
            if run.get("run_id") != dynamic_run_id:
                continue
            valid = run.get("valid_dataset_run")
            if valid is True:
                return "✅ valid"
            if valid is False:
                return "❌ invalid"
            return "—"
    return None


def _dataset_validity_reasons(dynamic_run_id: str | None) -> list[str] | None:
    if not dynamic_run_id:
        return None
    tracker = load_dataset_tracker()
    apps = tracker.get("apps") if isinstance(tracker, dict) else {}
    if not isinstance(apps, dict):
        return None
    for entry in apps.values():
        if not isinstance(entry, dict):
            continue
        runs = entry.get("runs")
        if not isinstance(runs, list):
            continue
        for run in runs:
            if not isinstance(run, dict):
                continue
            if run.get("run_id") != dynamic_run_id:
                continue
            reasons = run.get("validity_reasons")
            if isinstance(reasons, list):
                return [str(item) for item in reasons if item]
            return None
    return None


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


def _build_telemetry_lines(
    telemetry_stats: dict[str, object],
    duration_seconds: int | None,
    duration_label: str,
) -> list[str]:
    if not telemetry_stats:
        return []
    expected = telemetry_stats.get("expected_samples")
    captured = telemetry_stats.get("captured_samples")
    max_gap = telemetry_stats.get("sample_max_gap_s")
    max_gap_excl_first = telemetry_stats.get("sample_max_gap_excluding_first_s")
    sampling_duration = telemetry_stats.get("sampling_duration_seconds")

    ratio = None
    if expected and captured is not None:
        try:
            ratio = float(captured) / float(expected)
        except Exception:
            ratio = None

    lines = []
    if expected is not None and captured is not None:
        lines.append(f"Samples: {captured}/{expected}")
    if ratio is not None:
        lines.append(f"Capture ratio: {ratio:.3f}")
    if max_gap is not None:
        lines.append(f"Max gap: {max_gap:.2f}s")
    if max_gap_excl_first is not None:
        lines.append(f"Max gap (excl first): {max_gap_excl_first:.2f}s")
    if sampling_duration is not None:
        try:
            lines.append(f"Sampling window: {float(sampling_duration):.0f}s")
        except Exception:
            pass

    clock_line = _clock_delta_line(sampling_duration, duration_seconds, duration_label)
    if clock_line:
        lines.append(clock_line)
    min_duration = app_config.DYNAMIC_MIN_DURATION_S
    if sampling_duration is not None:
        try:
            if float(sampling_duration) < float(min_duration):
                lines.append(
                    f"Sampling window below minimum ({min_duration}s) — dataset runs require ≥{min_duration}s"
                )
        except Exception:
            pass
    return lines


def _clock_delta_line(
    sampling_duration: object,
    duration_seconds: int | None,
    duration_label: str,
) -> str | None:
    if sampling_duration is None or not duration_seconds:
        return None
    try:
        delta = abs(float(duration_seconds) - float(sampling_duration))
    except Exception:
        return None
    if delta < 30:
        return None
    guided = any(token in duration_label.lower() for token in ("guided", "manual"))
    if guided:
        reason = "guided/manual overhead outside sampling window: setup/teardown, observer start/stop, validation"
    else:
        reason = "overhead outside sampling window: setup/teardown, observer start/stop"
    return f"Clock delta: {delta:.0f}s ({reason})"


def _build_evidence_lines(
    summary_payload: dict[str, object] | None,
    artifacts: list[object],
    manifest: dict[str, object],
) -> list[str]:
    lines = []
    capture_info = (summary_payload or {}).get("capture") or {}
    pcap_valid = capture_info.get("pcap_valid")
    pcap_size = capture_info.get("pcap_size_bytes")
    capture_mode = capture_info.get("capture_mode")
    if pcap_valid is not None or pcap_size is not None or capture_mode:
        size_label = _format_bytes(int(pcap_size)) if isinstance(pcap_size, int) else "unknown size"
        valid_label = "valid" if pcap_valid is True else "invalid" if pcap_valid is False else "unknown"
        mode_label = capture_mode or "unknown"
        lines.append(f"PCAP: {mode_label} | {size_label} | {valid_label}")
    else:
        lines.append("PCAP: unavailable")
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
    artifact_types = {a.get("type") for a in artifacts if isinstance(a, dict)}
    lines.append("System log: yes" if "system_log_capture" in artifact_types else "System log: no")
    return lines


__all__ = ["print_run_summary"]
