"""Selected-app review and diagnostics surfaces."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import load_dataset_tracker
from scytaledroid.DynamicAnalysis.services.dynamic_target_state import derive_dynamic_target_state
from scytaledroid.DynamicAnalysis.tracker_scope import default_resolve_tracker_run_identity, scope_tracker_runs_to_active_identity
from scytaledroid.Utils.DisplayUtils.summary_cards import print_summary_card, summary_item


def _dataset_impact_label(latest_recent: Any) -> str:
    valid = getattr(latest_recent, "valid", None)
    if valid is True:
        supplemental_reason = str(getattr(latest_recent, "supplemental_reason", "") or "").strip().upper()
        if supplemental_reason == "LOW_SIGNAL_IDLE":
            return "ML training pool (LOW_SIGNAL_IDLE)"
        if supplemental_reason == "BASELINE_NOT_IDLE":
            return "retained non-idle baseline"
        if supplemental_reason == "MANUAL_EXTRA_RUN":
            return "retained extra (manual extra)"
        if supplemental_reason == "SCRIPTED_EXTRA_RUN":
            return "retained extra (scripted extra)"
        if supplemental_reason == "EXTRA_RUN":
            return "ML training pool (supplemental baseline)"
        if getattr(latest_recent, "countable", None) is True:
            return "quota-counted"
        return "valid retained"
    if valid is False:
        return "excluded from quota/publication"
    return "unknown"


def _next_step_lines(*, valid: bool | None, invalid_reason: str) -> list[str]:
    reason = str(invalid_reason or "").strip().upper()
    if valid is True:
        return [
            "Next step:",
            "This review is display-only; no acceptance action is required here.",
            "Return to the app screen for supplemental baseline, interactive, or manual evidence.",
        ]
    if valid is False:
        if reason == "PCAP_MISSING":
            return [
                "Next step:",
                "This review is display-only; the stored run remains excluded from quota/publication use.",
                "Recollect a current-build run after verifying PCAP capture/export is working.",
            ]
        if reason == "PCAP_TOO_SMALL":
            return [
                "Next step:",
                "This review is display-only; the stored run remains excluded from quota/publication use.",
                "Recollect a longer or higher-signal current-build run before relying on it.",
            ]
        return [
            "Next step:",
            "This review is display-only; the stored run remains excluded from quota/publication use.",
            "Collect a replacement current-build run before relying on this app for publication/archive readiness.",
        ]
    return [
        "Next step:",
        "This review is display-only; no stored QA verdict is available to accept or reject here.",
        "Use run history and diagnostics to decide whether recollection is needed.",
    ]


def _qa_status_label(valid: bool | None) -> str:
    if valid is True:
        return "QA valid"
    if valid is False:
        return "QA invalid"
    return "QA unknown"


def _qa_value_style(valid: bool | None) -> str:
    if valid is True:
        return "success"
    if valid is False:
        return "warning"
    return "muted"


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _latest_run_media_plane_rows(run_id: str) -> list[list[str]]:
    if not run_id:
        return []
    run_dir = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic" / run_id
    report = _load_json(run_dir / "analysis" / "pcap_report.json")
    media_plane = report.get("media_plane") if isinstance(report.get("media_plane"), dict) else {}
    summary = media_plane.get("summary") if isinstance(media_plane.get("summary"), dict) else {}
    classification = str(summary.get("classification") or "").strip()
    if not classification or classification == "not_observed":
        return []
    rows: list[list[str]] = [["Classification", classification.replace("_", " ")]]
    relay_count = summary.get("relay_endpoint_count")
    if relay_count is not None:
        rows.append(["Relay endpoints", str(relay_count)])
    turn_alloc = summary.get("turn_allocate_success_count")
    if turn_alloc is not None:
        rows.append(["TURN alloc success", str(turn_alloc)])
    stun_count = summary.get("stun_frame_count")
    if stun_count is not None:
        rows.append(["STUN frames", str(stun_count)])
    dominant = summary.get("dominant_udp_flow") if isinstance(summary.get("dominant_udp_flow"), dict) else {}
    if dominant:
        a = str(dominant.get("endpoint_a") or "").strip()
        b = str(dominant.get("endpoint_b") or "").strip()
        if a and b:
            rows.append(["Dominant UDP flow", f"{a} <-> {b}"])
        share = dominant.get("share_of_udp_bytes")
        try:
            if share is not None:
                rows.append(["Dominant UDP share", f"{float(share):.2f}"])
        except (TypeError, ValueError):
            pass
    reasons = summary.get("reason_codes")
    if isinstance(reasons, list) and reasons:
        labels = [str(item).strip() for item in reasons if str(item).strip()]
        if labels:
            rows.append(["Reason codes", ", ".join(labels)])
    return rows


def _format_bytes(size: object) -> str:
    try:
        value = int(size)
    except (TypeError, ValueError):
        return "—"
    if value <= 0:
        return "0B"
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return f"{value:.0f}{unit}"
        value /= 1024
    return f"{value:.1f}TB"


def _format_rate(value: object) -> str:
    try:
        return f"{float(value):,.0f} B/s"
    except (TypeError, ValueError):
        return "—"


def _format_ratio(value: object) -> str:
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return "—"


def _format_duration(value: object) -> str:
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return "—"
    if seconds <= 0:
        return "0s"
    if seconds >= 60:
        minutes = int(seconds // 60)
        remain = int(seconds % 60)
        return f"{minutes}m {remain}s"
    return f"{int(seconds)}s"


def _safe_float(value: object) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _format_percent_ratio(value: object) -> str:
    parsed = _safe_float(value)
    if parsed is None:
        return "—"
    return f"{parsed * 100:.1f}%"


def _format_rate_per_min(value: object) -> str:
    parsed = _safe_float(value)
    if parsed is None:
        return "—"
    return f"{parsed:,.0f} B/min"


def _non_idle_reason_labels(row: dict[str, object]) -> str:
    mapping = {
        "BASELINE_BYTES_HIGH": "bytes high",
        "BASELINE_SUSTAINED_DOWNLINK": "avg high",
        "BASELINE_P95_BURSTY": "p95 high",
        "BASELINE_QUIC_MEDIA_HEAVY": "QUIC-heavy",
    }
    raw = row.get("baseline_not_idle_reasons")
    if not isinstance(raw, list):
        return "—"
    labels: list[str] = []
    for item in raw:
        code = str(item or "").strip().upper()
        if not code:
            continue
        label = mapping.get(code, code)
        if label not in labels:
            labels.append(label)
    return ", ".join(labels) if labels else "—"


def _startup_profile_snapshot(report: dict[str, object], features: dict[str, object]) -> dict[str, object]:
    startup = report.get("startup_profile") if isinstance(report.get("startup_profile"), dict) else {}
    if startup:
        return startup
    startup_block = features.get("startup_profile") if isinstance(features.get("startup_profile"), dict) else {}
    summary_block = startup_block.get("summary") if isinstance(startup_block.get("summary"), dict) else {}
    return summary_block if summary_block else {}


def _traffic_shape_label(startup: dict[str, object]) -> str:
    if not isinstance(startup, dict) or not startup:
        return "—"
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
    return "—"


def _active_non_idle_baseline_rows(package_name: str, state: Any) -> list[dict[str, object]]:
    tracker = load_dataset_tracker()
    apps = tracker.get("apps") if isinstance(tracker, dict) else {}
    entry = apps.get(package_name) if isinstance(apps, dict) else None
    runs = entry.get("runs") if isinstance(entry, dict) and isinstance(entry.get("runs"), list) else []
    if not runs:
        return []

    active_version = str(getattr(state, "active_version_code", "") or "").strip() or None
    active_sha = str(getattr(state, "active_base_sha", "") or "").strip().lower() or None
    scoped = scope_tracker_runs_to_active_identity(
        package_name,
        runs,
        resolve_tracker_run_identity_fn=default_resolve_tracker_run_identity,
        active_identity_fn=lambda _pkg: (active_version, active_sha),
    )
    active_runs = [row for row in scoped.get("active_runs", []) if isinstance(row, dict)]
    filtered = [
        row
        for row in active_runs
        if row.get("valid_dataset_run") is True
        and row.get("countable") is False
        and str(row.get("run_profile") or "").strip().lower() == "baseline_idle"
        and row.get("baseline_not_idle") is True
    ]
    filtered.sort(key=lambda row: str(row.get("ended_at") or row.get("started_at") or ""), reverse=True)
    return filtered


def _non_idle_baseline_detail_rows(package_name: str, state: Any) -> list[list[str]]:
    detail_rows: list[list[str]] = []
    for row in _active_non_idle_baseline_rows(package_name, state):
        run_id = str(row.get("run_id") or "").strip()
        if not run_id:
            continue
        run_dir = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic" / run_id
        report = _load_json(run_dir / "analysis" / "pcap_report.json")
        features = _load_json(run_dir / "analysis" / "pcap_features.json")
        cap = (report.get("capinfos") or {}).get("parsed") if isinstance(report.get("capinfos"), dict) else {}
        cap = cap if isinstance(cap, dict) else {}
        metrics = features.get("metrics") if isinstance(features.get("metrics"), dict) else {}
        proxies = features.get("proxies") if isinstance(features.get("proxies"), dict) else {}
        startup = _startup_profile_snapshot(report, features)
        detail_rows.append(
            [
                run_id,
                _format_duration(cap.get("capture_duration_s")),
                _format_bytes(cap.get("data_size_bytes")),
                _format_rate(metrics.get("bytes_per_second_avg") if metrics.get("bytes_per_second_avg") is not None else cap.get("data_byte_rate_bps")),
                _format_rate(metrics.get("bytes_per_second_p95")),
                _format_ratio(proxies.get("quic_ratio")),
                _traffic_shape_label(startup),
                _format_percent_ratio(startup.get("startup_byte_share")),
                _format_rate_per_min(startup.get("post_start_median_bytes_per_min")),
                _non_idle_reason_labels(row),
                "no",
                "no",
            ]
        )
    return detail_rows


def _render_non_idle_baseline_detail(
    *,
    package_name: str,
    state: Any,
    menu_utils: Any,
) -> None:
    rows = _non_idle_baseline_detail_rows(package_name, state)
    if not rows:
        return
    print()
    menu_utils.print_section("Quiescent FG Baselines")
    menu_utils.print_table(
        [
            "Run ID",
            "Dur",
            "Bytes",
            "Avg B/s",
            "P95 B/s",
            "QUIC",
            "Shape",
            "Start%",
            "Tail B/m",
            "Reasons",
            "ML",
            "Quota",
        ],
        rows,
    )


def render_selected_app_review(
    *,
    display_label: str,
    latest_recent: Any,
    print_tier1_qa_result: Callable[[str], None] | None,
    menu_utils: Any,
    status_messages: Any,
    run_profile_label_fn: Callable[[str | None], str],
) -> None:
    print()
    menu_utils.print_header("Stored QA Review", display_label)
    if latest_recent is None:
        print(
            status_messages.status(
                "No stored current-build run is available yet for QA review.",
                level="warn",
            )
        )
        return
    run_id = str(getattr(latest_recent, "run_id", "") or "").strip()
    valid = getattr(latest_recent, "valid", None)
    qa_status = _qa_status_label(valid)
    invalid_reason = str(getattr(latest_recent, "invalid_reason_code", "") or "—").strip()
    pcap_failure_detail = str(getattr(latest_recent, "pcap_failure_detail", "") or "").strip()
    dataset_impact = _dataset_impact_label(latest_recent)
    profile_label = run_profile_label_fn(getattr(latest_recent, "run_profile", None))
    print_summary_card(
        display_label,
        [
            summary_item("QA", qa_status, value_style=_qa_value_style(valid)),
            summary_item("Dataset impact", dataset_impact, value_style="accent"),
            summary_item("Profile", profile_label, value_style="muted"),
            summary_item("Run ID", run_id or "—", value_style="muted"),
            summary_item("Ended", str(getattr(latest_recent, "ended_at", None) or "—"), value_style="muted"),
        ],
        subtitle="Stored QA review",
    )
    print()
    rows = [
        ["Invalid reason", invalid_reason or "—"],
    ]
    if valid is False and pcap_failure_detail:
        rows.append(["PCAP detail", pcap_failure_detail])
    if len(rows) > 0:
        menu_utils.print_table(["Field", "Value"], rows)
    if valid is True:
        print(status_messages.status("Latest current-build run is QA valid.", level="success"))
    elif valid is False:
        print(
            status_messages.status(
                "Latest current-build run is QA invalid and excluded from quota/publication use.",
                level="warn",
            )
        )
    else:
        print(status_messages.status("Latest current-build run has QA unknown status.", level="warn"))
    if print_tier1_qa_result and run_id:
        try:
            print_tier1_qa_result(run_id)
        except Exception as exc:
            print(status_messages.status(f"QA detail rendering failed: {exc}", level="warn"))
    print()
    next_lines = _next_step_lines(valid=valid, invalid_reason=invalid_reason)
    if next_lines:
        print(status_messages.status(next_lines[0], level="info"))
        for line in next_lines[1:]:
            if line.strip():
                print(status_messages.status(line, level="info", show_prefix=False))


def render_selected_app_recent_runs(
    state: Any,
    *,
    menu_utils: Any,
    status_messages: Any,
    run_profile_label_fn: Callable[[str | None], str],
) -> None:
    print()
    menu_utils.print_header("Recent Tracker Runs")
    recent_runs = tuple(getattr(state, "recent_runs", ()) or ())
    if not recent_runs:
        print(status_messages.status("No recent tracker-scoped runs are stored for this app.", level="warn"))
        return
    print(status_messages.status(f"{len(recent_runs)} recent tracker-scoped run(s) on file.", level="info"))
    print()
    rows: list[list[str]] = []
    for index, row in enumerate(recent_runs, start=1):
        if getattr(row, "valid", None) is True:
            qa_label = "QA valid"
        elif getattr(row, "valid", None) is False:
            qa_label = "QA invalid"
        else:
            qa_label = "QA unknown"
        rows.append(
            [
                str(index),
                str(getattr(row, "ended_at", None) or "—"),
                run_profile_label_fn(getattr(row, "run_profile", None)),
                qa_label,
                _dataset_impact_label(row),
                str(getattr(row, "run_id", None) or "—"),
            ]
        )
    menu_utils.print_table(["#", "Ended", "Profile", "QA", "Dataset", "Run ID"], rows)
    _render_non_idle_baseline_detail(
        package_name=str(getattr(state, "package_name", "") or ""),
        state=state,
        menu_utils=menu_utils,
    )
    if int(getattr(state, "baseline_idle_pcap_missing_streak", 0) or 0) > 0:
        print(
            status_messages.status(
                f"Recent baseline PCAP-missing streak: {int(getattr(state, 'baseline_idle_pcap_missing_streak', 0) or 0)}",
                level="warn",
            )
        )
    if int(getattr(state, "baseline_idle_low_signal_streak", 0) or 0) > 0:
        print(
            status_messages.status(
                f"Recent low-signal baseline streak: {int(getattr(state, 'baseline_idle_low_signal_streak', 0) or 0)}",
                level="warn",
            )
        )
    if int(getattr(state, "baseline_connected_insufficient_duration_streak", 0) or 0) > 0:
        print(
            status_messages.status(
                "Recent messaging baseline streak: insufficient duration on connected-idle baselines.",
                level="warn",
            )
        )


def render_selected_app_diagnostics(
    *,
    package_name: str,
    display_label: str,
    state: Any,
    queue_action: str,
    db_active_sessions: int,
    db_historical_sessions: int,
    latest_recent: Any = None,
    has_identity_mismatch: bool = False,
    live_build_drift: bool | None = None,
    menu_utils: Any,
) -> None:
    print()
    target_state = derive_dynamic_target_state(
        package_name=package_name,
        state=state,
        latest_recent=latest_recent,
        db_active_sessions=db_active_sessions,
        db_historical_sessions=db_historical_sessions,
        has_identity_mismatch=has_identity_mismatch,
        live_build_drift=live_build_drift,
        study_identity_available=bool(
            str(getattr(state, "active_version_code", "") or "").strip()
            or str(getattr(state, "active_base_sha", "") or "").strip()
        ),
    )
    study_build = "—"
    if target_state.study_identity.version_code:
        study_build = str(target_state.study_identity.version_code)
    ml_pool_total = int(getattr(state.counts, "baseline_extra_valid", 0) or 0) + int(
        getattr(state.counts, "baseline_low_signal_valid", 0) or 0
    )
    non_idle_baselines = int(getattr(state.counts, "baseline_not_idle_valid", 0) or 0)
    print_summary_card(
        display_label,
        [
            summary_item("Recommended", str(queue_action or "—"), value_style="accent"),
            summary_item("Study", target_state.study_status, value_style="muted"),
            summary_item("Live device", target_state.live_device_status, value_style="muted"),
            summary_item("Capture", target_state.capture_status, value_style="muted"),
            summary_item("Publication", target_state.publication_status, value_style="muted"),
            summary_item("Study build", study_build, value_style="muted"),
            summary_item(
                "Quota baseline",
                f"{int(getattr(state.counts, 'baseline_valid_runs', 0) or 0)} / {int(getattr(state, 'baseline_required', 0) or 0)}",
                value_style="muted",
            ),
            summary_item(
                "Quota interactive",
                f"{int(getattr(state.counts, 'interactive_valid_runs', 0) or 0)} / {int(getattr(state, 'interactive_required', 0) or 0)}",
                value_style="muted",
            ),
            summary_item("ML pool", str(ml_pool_total), value_style="accent" if ml_pool_total > 0 else "muted"),
            summary_item(
                "Quiescent FG",
                str(non_idle_baselines),
                value_style="warning" if non_idle_baselines > 0 else "muted",
            ),
        ],
        subtitle="Diagnostics",
    )
    print()
    rows = [
        ["Package", package_name],
        [
            "Historical evidence",
            f"{int(target_state.historical.valid_runs)} valid run(s) across {int(target_state.historical.build_count)} build(s)",
        ],
        ["Identity mismatch", "yes" if target_state.has_identity_mismatch else "no"],
        ["Tracker-scoped latest-run state", str(getattr(state, "tracker_status", "unknown") or "unknown")],
        ["Evidence lineage state", str(getattr(state, "evidence_status", "unknown") or "unknown")],
        ["Workflow state", str(getattr(state, "state_status", "unknown") or "unknown")],
        ["Local evidence packs", str(int(getattr(state, "local_evidence_dir_count", 0) or 0))],
        [
            "Quota-counted baseline",
            f"{int(getattr(state.counts, 'baseline_valid_runs', 0) or 0)} / {int(getattr(state, 'baseline_required', 0) or 0)}",
        ],
        [
            "Quota-counted interactive",
            f"{int(getattr(state.counts, 'interactive_valid_runs', 0) or 0)} / {int(getattr(state, 'interactive_required', 0) or 0)}",
        ],
        [
            "ML training pool (baseline)",
            (
                f"supplemental={int(getattr(state.counts, 'baseline_extra_valid', 0) or 0)}"
                f" | low-signal={int(getattr(state.counts, 'baseline_low_signal_valid', 0) or 0)}"
                f" | total={int(getattr(state.counts, 'baseline_extra_valid', 0) or 0) + int(getattr(state.counts, 'baseline_low_signal_valid', 0) or 0)}"
            ),
        ],
        [
            "Quiescent FG baseline",
            (
                f"quiescent_fg={int(getattr(state.counts, 'baseline_not_idle_valid', 0) or 0)}"
                " | quota=no | ml_pool=no"
            ),
        ],
        [
            "Retained extra interactive",
            (
                f"extra={int(getattr(state.counts, 'interactive_extra_valid', 0) or 0)}"
                f" | low-signal={int(getattr(state.counts, 'interactive_low_signal_valid', 0) or 0)}"
            ),
        ],
        ["Quota-valid local runs", str(int(getattr(state, "quota_counted_local", 0) or 0))],
        ["Paper-eligible local runs", str(int(getattr(state, "paper_eligible_local", 0) or 0))],
        ["DB current-build evidence", str(int(db_active_sessions))],
        ["DB historical evidence", str(int(db_historical_sessions))],
    ]
    if target_state.latest_invalid_reason:
        rows.append(["Latest invalid reason", target_state.latest_invalid_reason])
    if target_state.latest_pcap_failure_detail:
        rows.append(["Latest PCAP detail", target_state.latest_pcap_failure_detail])
    menu_utils.print_section("Detail")
    menu_utils.print_table(["Field", "Value"], rows)
    latest_run_id = str(getattr(latest_recent, "run_id", "") or "").strip() if latest_recent is not None else ""
    media_rows = _latest_run_media_plane_rows(latest_run_id)
    if media_rows:
        print()
        menu_utils.print_section("Latest Run Media Plane")
        menu_utils.print_table(["Field", "Value"], media_rows)
    _render_non_idle_baseline_detail(
        package_name=package_name,
        state=state,
        menu_utils=menu_utils,
    )
    top = tuple(getattr(state, "exclusion_reason_top", ()) or ())
    if top:
        print()
        menu_utils.print_section("Top Exclusions")
        menu_utils.print_table(
            ["Reason", "Count"],
            [[str(reason), str(int(count))] for reason, count in top],
        )


__all__ = [
    "_next_step_lines",
    "render_selected_app_diagnostics",
    "render_selected_app_recent_runs",
    "render_selected_app_review",
]
