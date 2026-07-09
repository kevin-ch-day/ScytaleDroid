"""Dynamic run summary rendering."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import load_dataset_tracker
from scytaledroid.DynamicAnalysis.scenarios.baseline_guidance import (
    baseline_not_idle_next_step as _guidance_baseline_not_idle_next_step,
)
from scytaledroid.DynamicAnalysis.utils.messaging_activity_labels import messaging_activity_label
from scytaledroid.DynamicAnalysis.utils.path_utils import resolve_evidence_path
from scytaledroid.DynamicAnalysis.utils.time_utils import format_seconds
from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages


def print_run_summary(result, duration_label: str) -> None:
    status = result.status or "unknown"
    duration_seconds = result.elapsed_seconds or result.duration_seconds
    run_dir = resolve_evidence_path(result.evidence_path) if result.evidence_path else None
    manifest = _load_manifest(run_dir) if run_dir else None
    dataset_validity: dict[str, object] | None = None
    verdict_line = None  # Always initialize; some branches may not set it.
    print()
    lines = [
        ("Package", result.package_name or "unknown"),
        ("Run ID", result.dynamic_run_id or "unknown"),
        ("Run mode", duration_label),
        ("Session wall-clock", format_seconds(duration_seconds) if duration_seconds is not None else "unknown"),
        ("Status", status),
    ]
    if manifest:
        operator = manifest.get("operator") or {}
        target = manifest.get("target") or {}
        run_profile = operator.get("run_profile")
        interaction = operator.get("interaction_level")
        if interaction:
            lines.append(("Interaction", str(interaction)))
        messaging_activity = operator.get("messaging_activity")
        if messaging_activity:
            lines.append(("Messaging", messaging_activity_label(messaging_activity)))
        _append_call_metadata_lines(lines, operator=operator, messaging_activity=messaging_activity)
        if str(run_profile or "").startswith("interaction_scripted"):
            template_id = operator.get("template_id") or operator.get("scenario_template")
            template_requested = operator.get("template_id_requested")
            template_actual = operator.get("template_id_actual") or template_id
            protocol_version = operator.get("interaction_protocol_version")
            template_hash = operator.get("template_hash") or operator.get("script_hash")
            target_overrun = operator.get("script_target_overrun_s")
            if template_id:
                lines.append(("Template", str(template_id)))
            if template_requested and template_actual and str(template_requested) != str(template_actual):
                lines.append(("Template requested", str(template_requested)))
                lines.append(("Template actual", str(template_actual)))
            if protocol_version is not None:
                lines.append(("Protocol version", str(protocol_version)))
            if template_hash:
                lines.append(("Template hash", f"{str(template_hash)[:12]}..."))
            if operator.get("ai_used") is not None:
                lines.append(("AI used", str(bool(operator.get("ai_used"))).lower()))
            if operator.get("ai_provider"):
                lines.append(("AI provider", str(operator.get("ai_provider"))))
            if operator.get("ai_prompt_id"):
                lines.append(("AI prompt id", str(operator.get("ai_prompt_id"))))
            try:
                if int(target_overrun or 0) > 0:
                    lines.append(("Protocol timing", f"OVERRUN by {int(target_overrun)}s"))
            except Exception:
                pass
        elif str(run_profile or "").startswith("baseline"):
            baseline_protocol_id = operator.get("baseline_protocol_id")
            baseline_protocol_version = operator.get("baseline_protocol_version")
            baseline_protocol_hash = operator.get("baseline_protocol_hash")
            if baseline_protocol_id:
                lines.append(("Baseline protocol", str(baseline_protocol_id)))
            if baseline_protocol_version is not None:
                lines.append(("Baseline protocol version", str(baseline_protocol_version)))
            if baseline_protocol_hash:
                lines.append(("Baseline protocol hash", f"{str(baseline_protocol_hash)[:12]}..."))
        validity = manifest.get("dataset")
        if isinstance(validity, dict):
            dataset_validity = validity
            valid = validity.get("valid_dataset_run")
            reason = validity.get("invalid_reason_code")
            label = "—"
            if valid is True:
                label = "VALID"
            elif valid is False:
                label = f"INVALID: {reason or 'UNKNOWN'}"
            lines.append(("Dataset verdict", label))
            if valid is True and validity.get("baseline_not_idle") is True:
                lines.append(
                    (
                        "App activity tag",
                        "BASELINE_NOT_IDLE (app-generated foreground traffic; not proof of operator interaction)",
                    )
                )
            min_bytes = validity.get("min_pcap_bytes")
            if min_bytes is not None:
                lines.append(("MIN_PCAP_BYTES", str(min_bytes)))
            if validity.get("short_run"):
                lines.append(("Dataset flag", "short_run=1"))
            if validity.get("no_traffic_observed"):
                lines.append(("Dataset flag", "no_traffic_observed=1"))

            # Operator-visible quota tracking (does not block extra runs).
            pkg = (target.get("package_name") if isinstance(target, dict) else None) or result.package_name
            quota = _dataset_quota_label(str(pkg) if pkg else None, result.dynamic_run_id)
            if quota:
                lines.append(("Dataset quota", quota))
                if run_profile:
                    # Do not imply ordering constraints via "slot" language.
                    lines.append(("Run profile", f"{run_profile}"))
                lines.append(("Counts toward quota", _countability_label(validity, run_profile)))
                detail = _countability_detail(str(pkg) if pkg else None, result.dynamic_run_id)
                if detail:
                    lines.append(("Quota detail", detail))
                if (
                    validity.get("valid_dataset_run") is True
                    and validity.get("countable") is True
                    and validity.get("low_signal") is True
                    and str(run_profile or "").strip().lower() == "baseline_connected"
                ):
                    lines.append(
                        (
                            "Messaging note",
                            "Quiet connected-messaging baselines can remain quota-counted when first-party runtime evidence is present; low traffic alone does not mean the baseline failed.",
                        )
                    )
                if _is_low_signal_idle_nonquota(validity, run_profile):
                    lines.append(
                        (
                            "Quota explanation",
                            "This run was valid and retained, but excluded from strict-idle quota because the capture was too quiet for quota evidence.",
                        )
                    )
                    low_signal_reasons = _low_signal_reason_lines(run_dir, validity)
                    if low_signal_reasons:
                        lines.append(("Low-signal reasons", "; ".join(low_signal_reasons)))
                    lines.append(("Retained as", "low-signal idle baseline evidence"))
                    lines.append(("Included in idle ML pool", "yes"))
                if _is_baseline_not_idle_extra(validity, run_profile):
                    non_idle_reasons = _baseline_not_idle_reasons(result.dynamic_run_id, validity)
                    metric_snapshot = _non_idle_metric_snapshot(run_dir)
                    startup_snapshot = _startup_profile_snapshot(run_dir)
                    threshold_crossed = _non_idle_threshold_crossed(result.dynamic_run_id, validity)
                    lines.append(
                        (
                            "Quota explanation",
                            "This run was valid and retained, but excluded from idle-baseline quota because runtime traffic exceeded idle-baseline limits.",
                        )
                    )
                    if non_idle_reasons:
                        lines.append(("Reasons", "; ".join(non_idle_reasons)))
                    lines.append(("Retained as", "non-idle baseline evidence"))
                    lines.append(("Included in idle ML pool", "no"))
                    duration_line = (
                        format_seconds(metric_snapshot.get("duration_s"))
                        if metric_snapshot.get("duration_s") is not None
                        else None
                    )
                    if duration_line:
                        lines.append(("Duration", duration_line))
                    try:
                        total_bytes = int(metric_snapshot.get("total_bytes"))
                    except (TypeError, ValueError):
                        total_bytes = None
                    if total_bytes is not None:
                        lines.append(("Total bytes", _format_bytes(total_bytes)))
                    avg_rate = _fmt_rate(metric_snapshot.get("avg_bytes_per_sec"))
                    if avg_rate:
                        lines.append(("Avg bytes/sec", avg_rate))
                    p95_rate = _fmt_rate(metric_snapshot.get("p95_bytes_per_sec"))
                    if p95_rate:
                        lines.append(("P95 bytes/sec", p95_rate))
                    quic_ratio = _fmt_ratio(metric_snapshot.get("quic_ratio"))
                    if quic_ratio:
                        lines.append(("QUIC ratio", quic_ratio))
                    startup_shape = _startup_shape_label(startup_snapshot)
                    if startup_shape:
                        lines.append(("Traffic shape", startup_shape))
                    startup_share = _fmt_percent_ratio(startup_snapshot.get("startup_byte_share"))
                    if startup_share:
                        lines.append(("Startup byte share", startup_share))
                    post_start_rate = _fmt_rate_per_min(startup_snapshot.get("post_start_median_bytes_per_min"))
                    if post_start_rate:
                        lines.append(("Post-start median", post_start_rate))
                    if _is_x_quiet_tail_pattern(result.dynamic_run_id, pkg, startup_snapshot, validity):
                        lines.append(
                            (
                                "Pattern hint",
                                "X showed a large startup/feed-media burst followed by a quieter tail; this often means the selected screen looked idle after launch, but the opening surface still pulled too much media to count toward strict idle quota.",
                            )
                        )
                    if threshold_crossed:
                        lines.append(("Threshold crossed", threshold_crossed))
                    lines.append(("Next baseline", _baseline_not_idle_next_step(pkg)))
                verdict_line = _three_verdict_label(result.dynamic_run_id)
            elif run_profile:
                # Fallback when tracker isn't available.
                lines.append(("Run profile", f"{run_profile}"))
                verdict_line = _three_verdict_label(result.dynamic_run_id)
            if verdict_line:
                lines.append(("Verdicts", verdict_line))
                reason_line = _paper_reason_line(result.dynamic_run_id)
                if reason_line:
                    lines.append(("Cohort", reason_line))
        else:
            dataset_validity = _dataset_validity_label(result.dynamic_run_id)
            if dataset_validity:
                lines.append(("Dataset verdict", dataset_validity))
                if dataset_validity.startswith("INVALID"):
                    reasons = _dataset_validity_reasons(result.dynamic_run_id)
                    if reasons:
                        lines.append(("Dataset issues", ", ".join(reasons)))
            verdict_line = _three_verdict_label(result.dynamic_run_id)
            if verdict_line:
                lines.append(("Verdicts", verdict_line))
                reason_line = _paper_reason_line(result.dynamic_run_id)
                if reason_line:
                    lines.append(("Cohort", reason_line))

        # DB is a derived index (not authoritative). Make its status explicit so
        # operators can spot schema/persistence problems without reading logs.
        dbp = _load_db_persistence_status(run_dir)
        if isinstance(dbp, dict) and dbp.get("attempted") is True:
            if dbp.get("ok") is True:
                lines.append(("DB persistence", "clean (derived index)"))
            else:
                code = dbp.get("error_code") or "DB_PERSISTENCE_FAILED"
                lines.append(("DB persistence", f"failed: {code} (derived index)"))
    if result.evidence_path:
        lines.append(("Evidence", result.evidence_path))
    status_messages.print_strip("Session", lines, width=70)

    summary_payload = _load_summary(run_dir) if run_dir else None
    engine_summary = _load_engine_summary(run_dir) if run_dir else None
    pcap_report = _load_json(run_dir / "analysis" / "pcap_report.json") if run_dir else None
    pcap_features = _load_json(run_dir / "analysis" / "pcap_features.json") if run_dir else None
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
            dataset_validity,
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

        pcap_qa_lines = _build_pcap_qa_lines(pcap_report, pcap_features)
        if pcap_qa_lines:
            _print_simple_list("PCAP QA", pcap_qa_lines)

        artifact_summary = [
            f"Artifacts: {len(artifacts)}",
            f"Outputs: {len(outputs)}",
        ]
        _print_simple_list("Artifacts", artifact_summary)

        evidence_lines = _build_evidence_lines(
            run_dir,
            summary_payload,
            pcap_report,
            pcap_features,
            artifacts,
            manifest,
        )
        if evidence_lines:
            _print_simple_list("Evidence", evidence_lines)

        indicator_lines = _build_indicator_summary_lines(pcap_report)
        runtime_surface_lines = _build_runtime_surface_summary_lines(summary_payload)
        if indicator_lines:
            _print_simple_list("Indicators (Top)", indicator_lines)
        if runtime_surface_lines:
            _print_simple_list("Runtime surfaces", runtime_surface_lines)

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
        print(status_messages.status(_blocked_status_message(result, run_dir), level="blocked"))
    elif status != "success":
        print(status_messages.status("Session marked as degraded. Check observer errors above.", level="warn"))
    if result.dynamic_run_id and result.evidence_path:
        print(
            status_messages.status(
                f"Run complete: {result.dynamic_run_id} ({result.evidence_path})",
                level="info",
            )
        )

def _append_call_metadata_lines(
    lines: list[tuple[str, str]],
    *,
    operator: dict[str, object],
    messaging_activity: object,
) -> None:
    activity = str(messaging_activity or "").strip().lower()
    call_type = operator.get("call_type")
    if not call_type and activity in {"voice_call", "video_call"}:
        call_type = "video" if activity == "video_call" else "voice"
    has_call_metadata = any(
        operator.get(field) is not None
        for field in (
            "call_attempted",
            "call_connected",
            "call_connect_latency_s",
            "call_connected_duration_s",
            "call_end_reason",
            "call_outcome_reason",
            "call_attempt_count",
            "call_connected_count",
            "call_not_connected_count",
            "call_canceled_count",
            "call_outcome_summary",
            "call_activity_inferred_from_foreground",
        )
    )
    if not call_type and not has_call_metadata:
        return
    if call_type:
        lines.append(("Call type", str(call_type)))
    if operator.get("call_attempted") is not None:
        lines.append(("Call attempted", str(bool(operator.get("call_attempted"))).lower()))
    if operator.get("call_connected") is not None:
        lines.append(("Call connected", str(bool(operator.get("call_connected"))).lower()))
    if operator.get("call_connect_latency_s") is not None:
        lines.append(("Call connect latency", f"{float(operator.get('call_connect_latency_s')):.2f}s"))
    if operator.get("call_connected_duration_s") is not None:
        lines.append(("Call connected duration", f"{float(operator.get('call_connected_duration_s')):.2f}s"))
    if operator.get("call_end_reason"):
        lines.append(("Call end reason", str(operator.get("call_end_reason"))))
    if operator.get("call_outcome_reason"):
        lines.append(("Call outcome", str(operator.get("call_outcome_reason"))))
    if operator.get("call_attempt_count") is not None:
        lines.append(("Call attempts", str(operator.get("call_attempt_count"))))
    if operator.get("call_connected_count") is not None:
        lines.append(("Connected attempts", str(operator.get("call_connected_count"))))
    if operator.get("call_not_connected_count") is not None:
        lines.append(("No-connect/ringing attempts", str(operator.get("call_not_connected_count"))))
    if operator.get("call_canceled_count") is not None:
        lines.append(("Canceled attempts", str(operator.get("call_canceled_count"))))
    if operator.get("call_outcome_summary"):
        lines.append(("Call outcome summary", str(operator.get("call_outcome_summary"))))
    if operator.get("call_activity_inferred_from_foreground") is not None:
        lines.append(
            (
                "Call tag inferred",
                str(bool(operator.get("call_activity_inferred_from_foreground"))).lower(),
            )
        )
    if operator.get("call_activity_original_tag"):
        lines.append(
            (
                "Original messaging tag",
                messaging_activity_label(operator.get("call_activity_original_tag")),
            )
        )
    if operator.get("call_activity_foreground_component"):
        lines.append(
            (
                "Call foreground component",
                str(operator.get("call_activity_foreground_component")),
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


def _load_db_persistence_status(run_dir: Path | None) -> dict[str, object] | None:
    if not run_dir:
        return None
    # Preferred: derived, versioned index artifact (does not mutate the manifest).
    payload = _load_json(run_dir / "analysis" / "index" / "v1" / "db_persistence_status.json")
    if isinstance(payload, dict):
        return payload
    # Backward compatibility: older manifests embedded env.db_persistence.
    manifest = _load_manifest(run_dir)
    if not isinstance(manifest, dict):
        return None
    env = manifest.get("environment")
    if not isinstance(env, dict):
        return None
    dbp = env.get("db_persistence")
    return dbp if isinstance(dbp, dict) else None


def _load_json(path: Path | None) -> dict[str, object] | None:
    if not path:
        return None
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _load_latest_event_details(run_dir: Path | None, *, event_type: str) -> dict[str, object] | None:
    if not run_dir:
        return None
    events_path = run_dir / "notes" / "run_events.jsonl"
    if not events_path.exists():
        return None
    latest: dict[str, object] | None = None
    try:
        for line in events_path.read_text(encoding="utf-8").splitlines():
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


def _blocked_status_message(result, run_dir: Path | None) -> str:
    tools_missing = _blocked_tools_missing_detail(run_dir)
    if tools_missing:
        return f"Session blocked: missing required host tools. {tools_missing}"
    blocked_detail = _blocked_plan_validation_detail(result, run_dir)
    message = "Session blocked by plan validation."
    if blocked_detail:
        message = f"{message} {blocked_detail}"
    return message


def _blocked_tools_missing_detail(run_dir: Path | None) -> str | None:
    event = _load_latest_event_details(run_dir, event_type="preflight.tools_missing")
    if not isinstance(event, dict):
        return None
    tools = _string_list(event.get("missing_tools"))
    if not tools:
        return None
    return f"missing_tools={','.join(tools)}"


def _blocked_plan_validation_detail(result, run_dir: Path | None) -> str | None:
    event = _load_latest_event_details(run_dir, event_type="plan.validation")
    if isinstance(event, dict):
        reasons = _string_list(event.get("reasons"))
        warnings = _string_list(event.get("warnings"))
        summary = event.get("summary") if isinstance(event.get("summary"), dict) else {}
        pieces: list[str] = []
        primary_reason = reasons[0] if reasons else None
        if primary_reason:
            pieces.append(primary_reason)
        mismatch_count = _safe_nonnegative_int(summary.get("mismatch_count"))
        warning_count = _safe_nonnegative_int(summary.get("warning_count"))
        if mismatch_count:
            pieces.append(f"mismatches={mismatch_count}")
        if warning_count:
            pieces.append(f"warnings={warning_count}")
        elif warnings:
            pieces.append(f"warnings={len(warnings)}")
        if pieces:
            return " | ".join(pieces)
    errors = _string_list(getattr(result, "errors", ()))
    if errors:
        return errors[0]
    return None


def _string_list(value: object) -> list[str]:
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes, dict)):
        return []
    out: list[str] = []
    for item in value:
        text = str(item).strip()
        if text:
            out.append(text)
    return out


def _safe_nonnegative_int(value: object) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return parsed if parsed > 0 else 0


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
                return "VALID"
            if valid is False:
                return "INVALID"
            return "—"
    return None


def _tracker_run_row(dynamic_run_id: str | None) -> dict[str, object] | None:
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
            if isinstance(run, dict) and run.get("run_id") == dynamic_run_id:
                return run
    return None


def _three_verdict_label(dynamic_run_id: str | None) -> str | None:
    row = _tracker_run_row(dynamic_run_id)
    if not isinstance(row, dict):
        return None
    technical = str(row.get("technical_validity") or "").strip()
    protocol = str(row.get("protocol_compliance") or "").strip()
    cohort = str(row.get("cohort_eligibility") or "").strip()
    if not (technical and protocol and cohort):
        return None
    return f"Technical={technical} | Protocol={protocol} | Cohort={cohort}"


def _paper_reason_line(dynamic_run_id: str | None) -> str | None:
    row = _tracker_run_row(dynamic_run_id)
    if not isinstance(row, dict):
        return None
    # Only show when the run didn't advance paper cohort.
    if row.get("paper_eligible") is True and bool(row.get("countable")):
        return None
    code = str(row.get("paper_exclusion_primary_reason_code") or "").strip()
    if not code:
        return None
    mapping = {
        "EXCLUDED_MANUAL_NON_COHORT": "Manual runs are exploratory-only in locked cohort mode.",
        "EXCLUDED_EXTRA_RUN": "Quota already satisfied for this app slot; saved as extra evidence.",
        "EXCLUDED_CALL_EXPLORATORY_ONLY": "Call template is exploratory-only by cohort policy.",
        "EXCLUDED_CALL_NOT_CONNECTED": "Call did not connect (not eligible for cohort).",
        "EXCLUDED_LOW_SIGNAL_IDLE_BASELINE": "Low-signal idle baseline (expected for messaging home-idle).",
        "EXCLUDED_SCRIPT_TEMPLATE_MISMATCH": "Observed scripted template did not match expected template policy.",
        "EXCLUDED_SCRIPT_PROTOCOL_SEND": "Messages sent outside allowed scripted-text template policy.",
        "EXCLUDED_IDENTITY_MISMATCH": "Build identity mismatch vs static plan (version/signature drift).",
        "EXCLUDED_WINDOW_COUNT_MISSING": "Window count missing (insufficient capture span or parse failure).",
        "EXCLUDED_DURATION_TOO_SHORT": "Capture duration below minimum sampling contract.",
        "EXCLUDED_INCOMPLETE_ARTIFACT_SET": "Incomplete artifact set (missing/invalid PCAP or parse failure).",
    }
    msg = mapping.get(code, code)
    return f"Reason: {msg} ({code})."


def _dataset_quota_label(package_name: str | None, dynamic_run_id: str | None) -> str | None:
    if not package_name:
        return None
    tracker = load_dataset_tracker()
    apps = tracker.get("apps") if isinstance(tracker, dict) else {}
    if not isinstance(apps, dict):
        return None
    entry = apps.get(str(package_name))
    if not isinstance(entry, dict):
        return None
    valid = int(entry.get("valid_runs") or 0)
    target = int(entry.get("target_runs") or 0)
    if entry.get("quota_met") or entry.get("app_complete"):
        label = f"MET ({valid}/{target})"
    else:
        label = f"{valid}/{target}"
    if dynamic_run_id:
        runs = entry.get("runs")
        if isinstance(runs, list):
            run = next((r for r in runs if isinstance(r, dict) and r.get("run_id") == dynamic_run_id), None)
            if isinstance(run, dict) and run.get("extra_run"):
                label += " (extra_run=1)"
    return label


def _countability_detail(package_name: str | None, dynamic_run_id: str | None) -> str | None:
    if not package_name or not dynamic_run_id:
        return None
    tracker = load_dataset_tracker()
    apps = tracker.get("apps") if isinstance(tracker, dict) else {}
    entry = apps.get(str(package_name)) if isinstance(apps, dict) else None
    runs = entry.get("runs") if isinstance(entry, dict) else None
    if not isinstance(runs, list):
        return None
    run = next((r for r in runs if isinstance(r, dict) and r.get("run_id") == dynamic_run_id), None)
    if not isinstance(run, dict):
        return None
    source = "tracker_quota_marking"
    countable = bool(run.get("countable"))
    reason = str(run.get("paper_exclusion_primary_reason_code") or "").strip()
    # Prefer tracker/finalization truth; only fall back to manifest fields when
    # the tracker row does not carry an explicit value.
    low_signal = (
        True if run.get("low_signal") is True else False if run.get("low_signal") is False else None
    )
    baseline_not_idle = (
        True
        if run.get("baseline_not_idle") is True
        else False
        if run.get("baseline_not_idle") is False
        else None
    )
    run_manifest = _load_manifest(Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic" / str(dynamic_run_id))
    if isinstance(run_manifest, dict):
        ds = run_manifest.get("dataset") if isinstance(run_manifest.get("dataset"), dict) else {}
        if isinstance(ds, dict) and low_signal is None and ds.get("low_signal") is not None:
            low_signal = bool(ds.get("low_signal"))
        if isinstance(ds, dict) and baseline_not_idle is None and ds.get("baseline_not_idle") is not None:
            baseline_not_idle = bool(ds.get("baseline_not_idle"))
    run_profile = str(run.get("run_profile") or "").strip().lower()
    if (
        run.get("valid_dataset_run") is True
        and run_profile == "baseline_idle"
        and low_signal
        and not countable
    ):
        source = "low_signal_policy"
        reason = "LOW_SIGNAL_IDLE"
    elif run.get("valid_dataset_run") is True and not countable and bool(run.get("extra_run")):
        source = "tracker_quota_marking"
        if not reason:
            reason = "EXTRA_RUN"
    parts = [f"source={source}", f"countable={str(countable).lower()}"]
    if reason:
        parts.append(f"reason={reason}")
    return ", ".join(parts)


def _is_baseline_not_idle_extra(validity: dict[str, object], run_profile: str | None) -> bool:
    return False


def _baseline_not_idle_reason_text(code: str) -> str:
    mapping = {
        "BASELINE_BYTES_HIGH": "total bytes crossed the idle-baseline limit",
        "BASELINE_SUSTAINED_DOWNLINK": "sustained average throughput crossed the idle-baseline limit",
        "BASELINE_P95_BURSTY": "burst throughput crossed the idle-baseline limit",
        "BASELINE_QUIC_MEDIA_HEAVY": "QUIC-heavy transport crossed the idle-baseline limit",
    }
    return mapping.get(str(code or "").strip().upper(), str(code or "").strip().upper())


def _baseline_not_idle_reasons(dynamic_run_id: str | None, validity: dict[str, object] | None) -> list[str]:
    reasons = _baseline_not_idle_reason_codes(dynamic_run_id, validity)
    out: list[str] = []
    for reason in reasons:
        label = _baseline_not_idle_reason_text(reason)
        if label and label not in out:
            out.append(label)
    return out


def _non_idle_threshold_crossed(dynamic_run_id: str | None, validity: dict[str, object] | None) -> str | None:
    reasons: list[str] = []
    row = _tracker_run_row(dynamic_run_id)
    if isinstance(row, dict):
        raw = row.get("baseline_not_idle_reasons")
        if isinstance(raw, list):
            reasons.extend(str(item).strip().upper() for item in raw if str(item).strip())
    if not reasons and isinstance(validity, dict):
        raw = validity.get("baseline_not_idle_reasons")
        if isinstance(raw, list):
            reasons.extend(str(item).strip().upper() for item in raw if str(item).strip())
    labels: list[str] = []
    for code in reasons:
        label = {
            "BASELINE_BYTES_HIGH": "total bytes",
            "BASELINE_SUSTAINED_DOWNLINK": "avg bytes/sec",
            "BASELINE_P95_BURSTY": "p95 bytes/sec",
            "BASELINE_QUIC_MEDIA_HEAVY": "QUIC ratio",
        }.get(code)
        if label and label not in labels:
            labels.append(label)
    if not labels:
        return None
    return ", ".join(labels)


def _non_idle_metric_snapshot(run_dir: Path | None) -> dict[str, object]:
    if not run_dir:
        return {}
    report = _load_json(run_dir / "analysis" / "pcap_report.json") or {}
    features = _load_json(run_dir / "analysis" / "pcap_features.json") or {}
    cap = (report.get("capinfos") or {}).get("parsed") or {}
    metrics = features.get("metrics") if isinstance(features.get("metrics"), dict) else {}
    proxies = features.get("proxies") if isinstance(features.get("proxies"), dict) else {}
    return {
        "duration_s": cap.get("capture_duration_s") if isinstance(cap, dict) else None,
        "total_bytes": cap.get("data_size_bytes") if isinstance(cap, dict) else None,
        "avg_bytes_per_sec": (
            metrics.get("bytes_per_second_avg")
            if isinstance(metrics, dict) and metrics.get("bytes_per_second_avg") is not None
            else cap.get("data_byte_rate_bps")
            if isinstance(cap, dict)
            else None
        ),
        "p95_bytes_per_sec": metrics.get("bytes_per_second_p95") if isinstance(metrics, dict) else None,
        "quic_ratio": proxies.get("quic_ratio") if isinstance(proxies, dict) else None,
    }


def _startup_profile_snapshot(run_dir: Path | None) -> dict[str, object]:
    if not run_dir:
        return {}
    summary = _load_summary(run_dir) or {}
    capture = summary.get("capture") if isinstance(summary.get("capture"), dict) else {}
    startup = capture.get("startup_profile") if isinstance(capture.get("startup_profile"), dict) else {}
    if startup:
        return startup
    features = _load_json(run_dir / "analysis" / "pcap_features.json") or {}
    startup_block = features.get("startup_profile") if isinstance(features.get("startup_profile"), dict) else {}
    summary_block = startup_block.get("summary") if isinstance(startup_block.get("summary"), dict) else {}
    return summary_block if summary_block else {}


def _startup_shape_label(startup: dict[str, object]) -> str | None:
    if not isinstance(startup, dict) or not startup:
        return None
    startup_dominant = startup.get("startup_dominant") is True
    post_start = _safe_float(startup.get("post_start_median_bytes_per_min"))
    if startup_dominant and post_start is not None and post_start <= 50_000:
        return "startup-burst then quiet-tail"
    if startup_dominant and post_start is not None and post_start > 50_000:
        return "startup-dominant with elevated tail"
    if post_start is not None and post_start >= 100_000:
        return "sustained active/downlink"
    if post_start is not None:
        return "mixed / periodic refresh"
    if startup_dominant:
        return "startup-dominant"
    return None


def _is_x_quiet_tail_pattern(
    dynamic_run_id: str | None,
    package_name: str | None,
    startup: dict[str, object],
    validity: dict[str, object] | None,
) -> bool:
    if str(package_name or "").strip().lower() != "com.twitter.android":
        return False
    if not isinstance(startup, dict) or not startup:
        return False
    if startup.get("startup_dominant") is not True:
        return False
    share = _safe_float(startup.get("startup_byte_share"))
    post_start = _safe_float(startup.get("post_start_median_bytes_per_min"))
    reasons = set(_baseline_not_idle_reason_codes(dynamic_run_id, validity))
    return (
        share is not None
        and share >= 0.80
        and post_start is not None
        and post_start <= 50_000
        and "BASELINE_BYTES_HIGH" in reasons
    )


def _baseline_not_idle_reason_codes(
    dynamic_run_id: str | None, validity: dict[str, object] | None
) -> list[str]:
    reasons: list[str] = []
    row = _tracker_run_row(dynamic_run_id)
    if isinstance(row, dict):
        raw = row.get("baseline_not_idle_reasons")
        if isinstance(raw, list):
            reasons.extend(str(item).strip().upper() for item in raw if str(item).strip())
    if not reasons and isinstance(validity, dict):
        raw = validity.get("baseline_not_idle_reasons")
        if isinstance(raw, list):
            reasons.extend(str(item).strip().upper() for item in raw if str(item).strip())
    out: list[str] = []
    for reason in reasons:
        if reason and reason not in out:
            out.append(reason)
    return out


def _fmt_rate(value: object) -> str | None:
    try:
        return f"{float(value):,.0f} B/s"
    except (TypeError, ValueError):
        return None


def _fmt_ratio(value: object) -> str | None:
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return None


def _fmt_percent_ratio(value: object) -> str | None:
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return None


def _fmt_rate_per_min(value: object) -> str | None:
    try:
        return f"{float(value):,.0f} B/min"
    except (TypeError, ValueError):
        return None


def _safe_float(value: object) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _dataset_validity_reasons(dynamic_run_id: str | None) -> list[str] | None:
    run = _tracker_run_row(dynamic_run_id)
    if not isinstance(run, dict):
        return None
    code = run.get("invalid_reason_code")
    flags = []
    if run.get("short_run"):
        flags.append("short_run")
    if run.get("no_traffic_observed"):
        flags.append("no_traffic_observed")
    out = []
    if code:
        out.append(str(code))
    out.extend(flags)
    return out or None


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
    print()
    lines = [(str(index + 1), value) for index, value in enumerate(items)]
    status_messages.print_strip(title, lines, width=70)


def _build_telemetry_lines(
    telemetry_stats: dict[str, object],
    duration_seconds: int | None,
    duration_label: str,
    dataset_validity: dict[str, object] | None = None,
) -> list[str]:
    if not telemetry_stats and not dataset_validity:
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
            lines.append(f"Sampling window (telemetry): {float(sampling_duration):.0f}s")
        except Exception:
            pass

    actual_sampling = None
    actual_source = None
    if isinstance(dataset_validity, dict):
        actual_sampling = dataset_validity.get("actual_sampling_seconds")
        actual_source = dataset_validity.get("actual_sampling_seconds_source")
    if actual_sampling is not None:
        try:
            source_label = str(actual_source or "derived")
            lines.append(
                f"Sampling window (authoritative): {float(actual_sampling):.0f}s ({source_label})"
            )
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
    return f"Overhead outside sampling window: {delta:.0f}s ({reason})"


def _baseline_not_idle_next_step(package_name: str | None) -> str:
    return _guidance_baseline_not_idle_next_step(package_name)


def _countability_label(validity: dict[str, object], run_profile: str | None) -> str:
    if validity.get("valid_dataset_run") is False:
        reason = str(validity.get("invalid_reason_code") or "INVALID")
        return f"NO ({reason})"
    if validity.get("countable") is True:
        return f"YES ({run_profile or 'dataset'})"
    # Low-signal is a tag, not a validity failure. Only low-signal *idle* baselines
    # are treated as non-quota (retained as exploratory).
    profile_lc = str(run_profile or "").strip().lower()
    if validity.get("low_signal") is True and profile_lc == "baseline_idle":
        return "NO (LOW_SIGNAL_IDLE)"
    if validity.get("countable") is False:
        exclusion_reason = str(validity.get("paper_exclusion_primary_reason_code") or "").strip().upper()
        cohort_eligibility = str(validity.get("cohort_eligibility") or "").strip().upper()
        if exclusion_reason == "EXCLUDED_MANUAL_NON_COHORT":
            return "NO (manual exploratory)"
        if cohort_eligibility == "EXTRA":
            return "NO (extra run)"
        return "NO (extra run)"
    return "UNKNOWN"


def _is_low_signal_idle_nonquota(validity: dict[str, object], run_profile: str | None) -> bool:
    profile_lc = str(run_profile or "").strip().lower()
    return (
        validity.get("valid_dataset_run") is True
        and validity.get("countable") is not True
        and validity.get("low_signal") is True
        and profile_lc == "baseline_idle"
    )


def _low_signal_reason_lines(
    run_dir: Path | None,
    validity: dict[str, object],
) -> list[str]:
    reasons = validity.get("low_signal_reasons")
    if not isinstance(reasons, list):
        return []
    metrics = _low_signal_metric_snapshot(run_dir, validity)
    labels: list[str] = []
    for raw in reasons:
        code = str(raw or "").strip().upper()
        if not code:
            continue
        if code == "PCAP_BYTES_LOW":
            label = "PCAP bytes low"
            data_size = metrics.get("data_size_bytes")
            threshold = metrics.get("min_data_size_bytes")
            if data_size is not None and threshold is not None:
                label += f" ({_format_bytes(int(data_size))} < {_format_bytes(int(threshold))})"
            labels.append(label)
        elif code == "PCAP_PACKETS_LOW":
            label = "packet count low"
            packet_count = metrics.get("packet_count")
            threshold = metrics.get("min_packet_count")
            if packet_count is not None and threshold is not None:
                label += f" ({int(packet_count)} < {int(threshold)})"
            labels.append(label)
        elif code == "DOMAINS_LOW":
            label = "domain diversity low"
            domain_count = metrics.get("unique_domains_topn")
            threshold = metrics.get("min_unique_domains_topn")
            if domain_count is not None and threshold is not None:
                label += f" ({int(domain_count)} < {int(threshold)})"
            labels.append(label)
        elif code == "PCAP_CAPTURE_TOO_SHORT":
            label = "capture duration low"
            duration = metrics.get("capture_duration_s")
            threshold = metrics.get("min_capture_duration_s")
            if duration is not None and threshold is not None:
                label += f" ({format_seconds(float(duration))} < {format_seconds(float(threshold))})"
            labels.append(label)
        else:
            labels.append(code)
    return labels


def _low_signal_metric_snapshot(
    run_dir: Path | None,
    validity: dict[str, object],
) -> dict[str, object]:
    features = _load_json(run_dir / "analysis" / "pcap_features.json") if run_dir else {}
    report = _load_json(run_dir / "analysis" / "pcap_report.json") if run_dir else {}
    metrics = features.get("metrics") if isinstance(features, dict) and isinstance(features.get("metrics"), dict) else {}
    proxies = features.get("proxies") if isinstance(features, dict) and isinstance(features.get("proxies"), dict) else {}
    cap = (
        (report.get("capinfos") or {}).get("parsed")
        if isinstance(report, dict) and isinstance(report.get("capinfos"), dict)
        else {}
    )
    thresholds = validity.get("low_signal_thresholds")
    thresholds = thresholds if isinstance(thresholds, dict) else {}
    return {
        "capture_duration_s": _first_present(
            metrics.get("capture_duration_s") if isinstance(metrics, dict) else None,
            cap.get("capture_duration_s") if isinstance(cap, dict) else None,
            validity.get("actual_sampling_seconds"),
        ),
        "data_size_bytes": _first_present(
            metrics.get("data_size_bytes") if isinstance(metrics, dict) else None,
            cap.get("data_size_bytes") if isinstance(cap, dict) else None,
            validity.get("pcap_size_bytes"),
        ),
        "packet_count": _first_present(
            metrics.get("packet_count") if isinstance(metrics, dict) else None,
            cap.get("packet_count") if isinstance(cap, dict) else None,
        ),
        "unique_domains_topn": _first_present(
            proxies.get("unique_domains_topn") if isinstance(proxies, dict) else None,
            report.get("service_domain_unique_count") if isinstance(report, dict) else None,
            report.get("dns_unique_count") if isinstance(report, dict) else None,
        ),
        "min_capture_duration_s": thresholds.get("min_capture_duration_s"),
        "min_data_size_bytes": thresholds.get("min_data_size_bytes"),
        "min_packet_count": thresholds.get("min_packet_count"),
        "min_unique_domains_topn": thresholds.get("min_unique_domains_topn"),
    }


def _first_present(*values: object) -> object | None:
    for value in values:
        if value is not None and value != "":
            return value
    return None


def _build_evidence_lines(
    run_dir: Path | None,
    summary_payload: dict[str, object] | None,
    pcap_report: dict[str, object] | None,
    pcap_features: dict[str, object] | None,
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
        if min_bytes is None:
            dataset = manifest.get("dataset") if isinstance(manifest, dict) else {}
            if isinstance(dataset, dict):
                min_bytes = dataset.get("min_pcap_bytes")
        threshold_label = f"{min_bytes}B" if min_bytes is not None else "unknown threshold"
        dataset = manifest.get("dataset") if isinstance(manifest, dict) else {}
        pcap_failure_summary = ""
        if isinstance(dataset, dict):
            pcap_failure_summary = str(dataset.get("pcap_failure_summary") or "").strip()
        if pcap_failure_summary:
            print(status_messages.status(pcap_failure_summary, level="warn"))
        else:
            print(
                status_messages.status(
                    f"PCAP invalid ({size_label} < {threshold_label}); treated as unavailable for Tier-1.",
                    level="warn",
                )
            )
    artifact_types = {a.get("type") for a in artifacts if isinstance(a, dict)}
    lines.append("System log: yes" if "system_log_capture" in artifact_types else "System log: no")

    # Add a compact PCAP QA line when available (keeps operators from guessing).
    # If run_dir exists, show the PCAP report toolchain warning surface (no noise in normal case).
    if run_dir and isinstance(pcap_report, dict):
        missing_tools = pcap_report.get("missing_tools") or []
        if isinstance(missing_tools, list) and missing_tools:
            lines.append("PCAP tools missing: " + ", ".join(str(x) for x in missing_tools))
    return lines


def _build_pcap_qa_lines(
    pcap_report: dict[str, object] | None,
    pcap_features: dict[str, object] | None,
) -> list[str]:
    lines: list[str] = []
    if isinstance(pcap_report, dict):
        cap = (pcap_report.get("capinfos") or {}).get("parsed") or {}
        if isinstance(cap, dict):
            dur = cap.get("capture_duration_s")
            pkts = cap.get("packet_count")
            dbytes = cap.get("data_size_bytes")
            pps = cap.get("avg_packet_rate_pps")
            bps = cap.get("data_byte_rate_bps")
            parts = []
            try:
                if dur is not None:
                    parts.append(f"dur={float(dur):.0f}s")
            except Exception:
                pass
            try:
                if pkts is not None:
                    parts.append(f"pkts={int(pkts)}")
            except Exception:
                pass
            try:
                if dbytes is not None:
                    parts.append(f"data={_format_bytes(int(dbytes))}")
            except Exception:
                pass
            try:
                if pps is not None:
                    parts.append(f"pps={float(pps):.1f}")
            except Exception:
                pass
            try:
                if bps is not None:
                    parts.append(f"byte_rate={_format_bytes(int(float(bps)))}s")
            except Exception:
                pass
            if parts:
                lines.append(" ".join(parts))

    if isinstance(pcap_features, dict):
        proxies = pcap_features.get("proxies") or {}
        if isinstance(proxies, dict):
            # Transport mix proxies (TLS/QUIC/etc)
            tls = proxies.get("tls_ratio")
            quic = proxies.get("quic_ratio")
            tcp = proxies.get("tcp_ratio")
            udp = proxies.get("udp_ratio")
            parts = []
            for k, v in (("tls", tls), ("quic", quic), ("tcp", tcp), ("udp", udp)):
                try:
                    if v is not None:
                        parts.append(f"{k}={float(v):.2f}")
                except Exception:
                    continue
            if parts:
                lines.append("transport: " + " ".join(parts))

            # Diversity proxies
            ud = proxies.get("unique_domains_topn")
            dns_n = proxies.get("unique_dns_topn")
            sni_n = proxies.get("unique_sni_topn")
            segs = []
            if dns_n is not None:
                segs.append(f"dns={dns_n}")
            if sni_n is not None:
                segs.append(f"sni={sni_n}")
            if ud is not None:
                segs.append(f"domains={ud}")
            if segs:
                lines.append("diversity: " + " ".join(segs))
        media_plane = pcap_features.get("media_plane") or {}
        if isinstance(media_plane, dict):
            summary = media_plane.get("summary") or {}
            if isinstance(summary, dict):
                classification = str(summary.get("classification") or "").strip()
                if classification and classification != "not_observed":
                    parts = [classification.replace("_", " ")]
                    rtc_sessions = summary.get("rtc_sustained_session_count")
                    if rtc_sessions is not None:
                        parts.append(f"rtc_sessions={rtc_sessions}")
                    rtc_bytes = summary.get("rtc_total_bytes")
                    try:
                        if rtc_bytes is not None and int(rtc_bytes) > 0:
                            parts.append(f"rtc_bytes={_format_bytes_brief(int(rtc_bytes))}")
                    except (TypeError, ValueError):
                        pass
                    rtc_peers = summary.get("rtc_relay_peer_count")
                    if rtc_peers is not None:
                        parts.append(f"rtc_peers={rtc_peers}")
                    relay_count = summary.get("relay_endpoint_count")
                    if relay_count is not None:
                        parts.append(f"relay_endpoints={relay_count}")
                    try:
                        share = summary.get("dominant_udp_flow", {}).get("share_of_udp_bytes")  # type: ignore[union-attr]
                    except Exception:
                        share = None
                    try:
                        if share is not None:
                            parts.append(f"dominant_udp={float(share):.2f}")
                    except Exception:
                        pass
                    alloc = summary.get("turn_allocate_success_count")
                    if alloc is not None:
                        parts.append(f"turn_alloc={alloc}")
                    lines.append("media: " + " ".join(parts))
    return lines


def _build_indicator_summary_lines(pcap_report: dict[str, object] | None) -> list[str]:
    if not isinstance(pcap_report, dict):
        return []

    def _top(items: object, label: str) -> str | None:
        if not isinstance(items, list) or not items:
            return None
        pairs: list[tuple[str, int]] = []
        for item in items[:3]:
            if not isinstance(item, dict):
                continue
            v = item.get("value")
            c = item.get("count")
            if not isinstance(v, str) or not v.strip():
                continue
            try:
                ci = int(c) if c is not None else 0
            except Exception:
                ci = 0
            pairs.append((v.strip(), ci))
        if not pairs:
            return None
        joined = ", ".join([f"{v} ({c})" if c else v for v, c in pairs])
        return f"{label}: {joined}"

    out: list[str] = []
    dns = _top(pcap_report.get("top_dns"), "dns")
    sni = _top(pcap_report.get("top_sni"), "sni")
    if dns:
        out.append(dns)
    if sni:
        out.append(sni)
    media_plane = pcap_report.get("media_plane") if isinstance(pcap_report.get("media_plane"), dict) else {}
    media_summary = media_plane.get("summary") if isinstance(media_plane.get("summary"), dict) else {}
    dominant_udp = media_summary.get("dominant_udp_flow") if isinstance(media_summary.get("dominant_udp_flow"), dict) else {}
    relay_endpoints = media_summary.get("relay_endpoints") if isinstance(media_summary.get("relay_endpoints"), list) else []
    classification = str(media_summary.get("classification") or "").strip()
    if classification and classification != "not_observed":
        parts = [classification.replace("_", " ")]
        rtc_sessions = media_summary.get("rtc_sustained_session_count")
        if rtc_sessions is not None:
            parts.append(f"rtc_sessions={rtc_sessions}")
        rtc_bytes = media_summary.get("rtc_total_bytes")
        try:
            if rtc_bytes is not None and int(rtc_bytes) > 0:
                parts.append(f"rtc_bytes={_format_bytes_brief(int(rtc_bytes))}")
        except (TypeError, ValueError):
            pass
        rtc_peers = media_summary.get("rtc_relay_peer_count")
        if rtc_peers is not None:
            parts.append(f"rtc_peers={rtc_peers}")
        if relay_endpoints:
            labels = []
            for row in relay_endpoints[:3]:
                if not isinstance(row, dict):
                    continue
                ip = str(row.get("ip") or "").strip()
                port = row.get("port")
                if ip and port is not None:
                    labels.append(f"{ip}:{port}")
            if labels:
                parts.append("relays=" + ", ".join(labels))
        if isinstance(dominant_udp, dict):
            a = str(dominant_udp.get("endpoint_a") or "").strip()
            b = str(dominant_udp.get("endpoint_b") or "").strip()
            if a and b:
                parts.append(f"flow={a} <-> {b}")
        out.append("media: " + " | ".join(parts))
    return out


def _format_bytes_brief(value: int) -> str:
    if value < 1024:
        return f"{value}B"
    if value < 1024 * 1024:
        return f"{value / 1024.0:.1f}KB"
    return f"{value / (1024.0 * 1024.0):.1f}MB"


def _build_runtime_surface_summary_lines(summary_payload: dict[str, object] | None) -> list[str]:
    if not isinstance(summary_payload, dict):
        return []
    indicators = summary_payload.get("indicators")
    if not isinstance(indicators, dict):
        return []
    runtime_surfaces = indicators.get("runtime_surfaces")
    if not isinstance(runtime_surfaces, dict) or not runtime_surfaces:
        return []
    out: list[str] = []
    labels = runtime_surfaces.get("labels")
    if isinstance(labels, list) and labels:
        rendered = [str(item).strip() for item in labels if str(item).strip()]
        if rendered:
            out.append("observed: " + ", ".join(rendered))
    primary_label = str(runtime_surfaces.get("primary_label") or "").strip()
    primary_detail = str(runtime_surfaces.get("primary_detail") or "").strip()
    if primary_label:
        primary_text = primary_label
        if primary_detail:
            primary_text += f" ({primary_detail})"
        out.append("primary: " + primary_text)
    transitions = runtime_surfaces.get("transitions")
    if isinstance(transitions, list) and transitions:
        rendered_steps: list[str] = []
        for row in transitions[:4]:
            if not isinstance(row, dict):
                continue
            label = str(row.get("surface_label") or "").strip()
            if not label:
                continue
            elapsed = row.get("elapsed_s")
            try:
                step = f"{int(elapsed)}s {label}"
            except (TypeError, ValueError):
                step = label
            rendered_steps.append(step)
        if rendered_steps:
            out.append("sequence: " + " -> ".join(rendered_steps))
    return out


__all__ = ["print_run_summary"]
