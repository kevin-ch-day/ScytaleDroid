"""Dynamic run summary rendering."""

from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import load_dataset_tracker
from scytaledroid.DynamicAnalysis.utils.path_utils import resolve_evidence_path
from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages


def print_run_summary(result, duration_label: str) -> None:
    status = result.status or "unknown"
    duration_seconds = result.elapsed_seconds or result.duration_seconds
    run_dir = resolve_evidence_path(result.evidence_path) if result.evidence_path else None
    manifest = _load_manifest(run_dir) if run_dir else None
    dataset_validity: dict[str, object] | None = None
    print()
    lines = [
        ("Package", result.package_name or "unknown"),
        ("Run ID", result.dynamic_run_id or "unknown"),
        ("Session wall-clock", f"{duration_label} ({duration_seconds}s)"),
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
            lines.append(("Messaging", str(messaging_activity)))
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
            call_templates = {
                "messaging_call_basic_v1",
                "messaging_voice_v1",
                "messaging_video_v1",
                "whatsapp_voice_v1",
                "whatsapp_video_v1",
            }
            if str(template_actual or template_id or "") in call_templates:
                lines.append(("Call type", str(operator.get("call_type") or "voice")))
                lines.append(("Call attempted", str(bool(operator.get("call_attempted"))).lower()))
                lines.append(("Call connected", str(bool(operator.get("call_connected"))).lower()))
                if operator.get("call_connect_latency_s") is not None:
                    lines.append(("Call connect latency", f"{float(operator.get('call_connect_latency_s')):.2f}s"))
                if operator.get("call_connected_duration_s") is not None:
                    lines.append(("Call connected duration", f"{float(operator.get('call_connected_duration_s')):.2f}s"))
                if operator.get("call_end_reason"):
                    lines.append(("Call end reason", str(operator.get("call_end_reason"))))
                if operator.get("call_outcome_reason"):
                    lines.append(("Call outcome", str(operator.get("call_outcome_reason"))))
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
                label = "✅ VALID"
            elif valid is False:
                label = f"❌ INVALID: {reason or 'UNKNOWN'}"
            lines.append(("Dataset validity", label))
            if (
                valid is False
                and str(reason or "").strip().upper() == "PCAP_MISSING"
                and str(run_profile or "").strip().lower().startswith("baseline")
            ):
                lines.append(
                    (
                        "Exploratory class",
                        "LOW_SIGNAL_IDLE (retained, not quota-counted)",
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
            elif run_profile:
                # Fallback when tracker isn't available.
                lines.append(("Run profile", f"{run_profile}"))
            verdict_line = _three_verdict_label(result.dynamic_run_id)
            if verdict_line:
                lines.append(("Verdicts", verdict_line))
                reason_line = _paper_reason_line(result.dynamic_run_id)
                if reason_line:
                    lines.append(("Paper", reason_line))
        else:
            dataset_validity = _dataset_validity_label(result.dynamic_run_id)
            if dataset_validity:
                lines.append(("Dataset validity", dataset_validity))
                if dataset_validity.startswith("❌"):
                    reasons = _dataset_validity_reasons(result.dynamic_run_id)
                    if reasons:
                        lines.append(("Dataset issues", ", ".join(reasons)))
            verdict_line = _three_verdict_label(result.dynamic_run_id)
            if verdict_line:
                lines.append(("Verdicts", verdict_line))
                reason_line = _paper_reason_line(result.dynamic_run_id)
                if reason_line:
                    lines.append(("Paper", reason_line))

        # DB is a derived index (not authoritative). Make its status explicit so
        # operators can spot schema/persistence problems without reading logs.
        dbp = _load_db_persistence_status(run_dir)
        if isinstance(dbp, dict) and dbp.get("attempted") is True:
            if dbp.get("ok") is True:
                lines.append(("DB persistence", "OK (derived index)"))
            else:
                code = dbp.get("error_code") or "DB_PERSISTENCE_FAILED"
                lines.append(("DB persistence", f"FAILED: {code} (derived index)"))
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
        if indicator_lines:
            _print_simple_list("Indicators (Top)", indicator_lines)

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
                return "✅ VALID"
            if valid is False:
                return "❌ INVALID"
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
        "EXCLUDED_MANUAL_NON_COHORT": "Manual runs are exploratory-only in Paper Mode.",
        "EXCLUDED_EXTRA_RUN": "Quota already satisfied for this app slot; saved as extra evidence.",
        "EXCLUDED_CALL_EXPLORATORY_ONLY": "Call template is exploratory-only by paper policy.",
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
    # Quota-countability and paper eligibility are separate layers. For baseline
    # low-signal policy exclusions, prefer authoritative manifest dataset flags
    # (not tracker cache) when available.
    low_signal = bool(run.get("low_signal"))
    run_manifest = _load_manifest(Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic" / str(dynamic_run_id))
    if isinstance(run_manifest, dict):
        ds = run_manifest.get("dataset") if isinstance(run_manifest.get("dataset"), dict) else {}
        if isinstance(ds, dict) and ds.get("low_signal") is not None:
            low_signal = bool(ds.get("low_signal"))
    run_profile = str(run.get("run_profile") or "").strip().lower()
    if run.get("valid_dataset_run") is True and run_profile.startswith("baseline") and low_signal:
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


def _countability_label(validity: dict[str, object], run_profile: str | None) -> str:
    if validity.get("valid_dataset_run") is False:
        reason = str(validity.get("invalid_reason_code") or "INVALID")
        return f"NO ({reason})"
    if validity.get("countable") is True:
        return f"YES ({run_profile or 'dataset'})"
    # Low-signal is a tag, not a validity failure. Only low-signal *idle* baselines
    # are treated as non-quota (retained as exploratory).
    if validity.get("low_signal") is True and str(run_profile or "").strip().lower() == "baseline_idle":
        return "NO (LOW_SIGNAL_IDLE)"
    if str(run_profile or "").strip().lower() == "interaction_manual":
        return "NO (manual is exploratory)"
    if validity.get("countable") is False:
        return "NO (extra run)"
    return "UNKNOWN"


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
    return out


__all__ = ["print_run_summary"]
