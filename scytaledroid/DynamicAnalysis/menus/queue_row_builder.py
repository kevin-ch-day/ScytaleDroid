"""Row-building helpers for the Dynamic App Queue."""

from __future__ import annotations

from scytaledroid.DynamicAnalysis.controllers.selected_app_state import (
    selected_app_queue_action as _selected_app_queue_action_shared,
)
from scytaledroid.DynamicAnalysis.templates.category_map import resolved_template_for_package


def build_package_selection_row(
    *,
    prepared_row_cls,
    idx: int,
    package: str,
    app_label: str | None,
    collisions: set[str],
    dataset_pkgs: set[str],
    tracker_apps,
    cfg,
    recent_tracker_runs,
    live_build_drift=None,
    db_lineage_context=None,
    truncate_visible_fn,
    bucket_progress_label_fn,
    quota_progress_label_fn,
    static_build_label_fn,
    build_scoped_dataset_counts_fn,
    resolve_tracker_run_identity_fn,
):
    display = ((app_label or package).strip() or package)
    if str(package).strip().lower() == "com.twitter.android" and display.strip().lower() == "x":
        display = "X (Twitter)"
    if display in collisions:
        display = f"{display} ({package})"
    display = truncate_visible_fn(display, 30)

    base_label = "—"
    inter_label = "—"
    need_label = "—"
    next_label = "—"
    build_label = "—"
    total_label = "—"
    legacy_label = "—"
    last_label = "—"
    build_row: list[str] | None = None
    dataset_app_count = 0
    dataset_complete_count = 0
    dataset_valid_runs_count = 0
    historical_valid_runs_count = 0
    historical_build_count = 0
    build_state = "—"
    baseline_countable = 0
    baseline_extra = 0
    baseline_low_signal_supplemental = 0
    interactive_countable = 0
    interactive_extra = 0
    interactive_low_signal_supplemental = 0
    need_baseline = 0
    need_interactive = 0
    prep_label = "—"
    qa_label = "—"
    next_choice_label = "—"
    technical_valid_active = 0
    live_build_drift_flag = False
    live_expected_version_code = ""
    live_expected_version_name = ""
    live_observed_version_code = ""
    live_static_run_id = ""
    lineage_state = ""
    db_active_sessions = 0
    db_historical_sessions = 0
    db_total_sessions = 0

    if package.lower() in dataset_pkgs:
        dataset_app_count = 1
        entry = tracker_apps.get(package) if isinstance(tracker_apps, dict) else None
        runs = entry.get("runs") if isinstance(entry, dict) else []
        scoped = build_scoped_dataset_counts_fn(package, runs if isinstance(runs, list) else [], cfg=cfg)
        base_countable = int(scoped["baseline_countable"])
        base_extra = int(scoped["baseline_extra"])
        base_low_signal = int(scoped.get("baseline_low_signal_supplemental") or 0)
        inter_countable = int(scoped["interactive_countable"])
        inter_extra = int(scoped["interactive_extra"])
        inter_low_signal = int(scoped.get("interactive_low_signal_supplemental") or 0)
        baseline_countable = base_countable
        baseline_extra = base_extra
        baseline_low_signal_supplemental = base_low_signal
        interactive_countable = inter_countable
        interactive_extra = inter_extra
        interactive_low_signal_supplemental = inter_low_signal
        legacy_valid = int(scoped["legacy_valid"])
        legacy_builds = int(scoped["legacy_builds"])
        active_version = str(scoped.get("active_version_code") or "—")
        active_sha = str(scoped.get("active_base_sha") or "")
        active_build = active_version
        if active_sha:
            active_build = f"{active_version} / {active_sha[:10]}"
        elif active_version == "—":
            active_build = "unknown (tracker-only)"
        active_runs = int(scoped.get("technical_valid_active") or 0)

        base_label = bucket_progress_label_fn(
            base_countable,
            int(cfg.baseline_required),
            extra_count=base_extra,
        )
        baseline_complete = base_countable >= int(cfg.baseline_required)
        inter_label = (
            bucket_progress_label_fn(
                inter_countable,
                int(cfg.interactive_required),
                extra_count=inter_extra,
            )
            if baseline_complete
            else "locked"
        )
        need_base = max(0, int(cfg.baseline_required) - base_countable)
        need_inter = max(0, int(cfg.interactive_required) - inter_countable)
        need_baseline = need_base
        need_interactive = need_inter
        if need_base == 0 and need_inter == 0:
            dataset_complete_count = 1
        dataset_valid_runs_count = base_countable + inter_countable
        if need_base or need_inter:
            need_parts = []
            if need_base:
                need_parts.append(f"{need_base}B")
            if need_inter:
                need_parts.append(f"{need_inter}I")
            need_label = " ".join(need_parts)
        else:
            need_label = "0"
        total_required = int(cfg.baseline_required) + int(cfg.interactive_required)
        total_label = quota_progress_label_fn(
            base_countable + inter_countable,
            total_required,
            extra_count=base_extra + inter_extra,
        )
        legacy_label = str(legacy_valid) if legacy_valid > 0 else "0"
        build_label = static_build_label_fn(active_runs, legacy_valid)
        build_state = build_label
        prep_label = build_label
        historical_valid_runs_count = legacy_valid
        historical_build_count = legacy_builds
        technical_valid_active = int(scoped.get("technical_valid_active") or 0)
        if isinstance(db_lineage_context, dict):
            db_active_sessions = int(db_lineage_context.get("db_active_sessions") or 0)
            db_historical_sessions = int(db_lineage_context.get("db_historical_sessions") or 0)
            db_total_sessions = int(db_lineage_context.get("db_total_sessions") or 0)

        latest_valid: bool | None = None
        latest_invalid_reason: str | None = None
        latest_pcap_failure_detail: str | None = None
        recent = recent_tracker_runs(package, limit=1)
        if recent:
            r = recent[0]
            latest_valid = r.valid
            if r.valid is False:
                latest_invalid_reason = str(getattr(r, "invalid_reason_code", "") or "").strip() or None
                latest_pcap_failure_detail = str(getattr(r, "pcap_failure_detail", "") or "").strip() or None
            if r.valid is True:
                last_label = "valid"
            elif r.valid is False:
                last_label = "invalid"
            else:
                last_label = "unknown"
            if (
                last_label == "valid"
                and isinstance(runs, list)
                and (scoped.get("active_version_code") or scoped.get("active_base_sha"))
            ):
                recent_row = next(
                    (
                        item
                        for item in runs
                        if isinstance(item, dict) and str(item.get("run_id") or "") == str(r.run_id or "")
                    ),
                    None,
                )
                if isinstance(recent_row, dict):
                    recent_ident = resolve_tracker_run_identity_fn(package, recent_row)
                    active_ident = (
                        str(scoped.get("active_version_code") or "") or None,
                        str(scoped.get("active_base_sha") or "") or None,
                    )
                    if recent_ident != active_ident:
                        last_label = "valid (id_mismatch)"
        if legacy_valid > 0 and last_label != "—" and not last_label.endswith(" (L)"):
            last_label = f"{last_label} (L)"
        qa_label = last_label

        queue_action, _queue_reason = _selected_app_queue_action_shared(
            live_build_drift=bool(live_build_drift),
            baseline_valid_runs=base_countable,
            interactive_valid_runs=inter_countable,
            baseline_required=int(cfg.baseline_required),
            interactive_required=int(cfg.interactive_required),
            scripted_template_ready=bool(resolved_template_for_package(package)),
            latest_valid=latest_valid,
            latest_invalid_reason=latest_invalid_reason,
            latest_pcap_failure_detail=latest_pcap_failure_detail,
            db_active_sessions=db_active_sessions,
            active_valid_runs=technical_valid_active,
        )
        next_label = queue_action
        next_choice_label = queue_action
        if isinstance(live_build_drift, dict):
            live_build_drift_flag = True
            live_expected_version_code = str(live_build_drift.get("expected_version_code") or "").strip()
            live_expected_version_name = str(live_build_drift.get("expected_version_name") or "").strip()
            live_observed_version_code = str(live_build_drift.get("observed_version_code") or "").strip()
            live_static_run_id = str(live_build_drift.get("static_run_id") or "").strip()
        lineage_state = row_lineage_state(
            active_valid_runs=technical_valid_active,
            legacy_valid_runs=legacy_valid,
            db_active_sessions=db_active_sessions,
            db_historical_sessions=db_historical_sessions,
            live_build_drift=live_build_drift_flag,
        )
        prep_label = prep_label_for_lineage_state(lineage_state, build_label)
        if live_build_drift_flag:
            prep_label = "stale"
            next_choice_label = "refresh static"
        build_row = [display, active_build, str(active_runs), str(legacy_valid), str(legacy_builds)]

    return prepared_row_cls(
        full_row=[
            str(idx),
            display,
            base_label,
            inter_label,
            need_label,
            next_label,
            build_label,
            total_label,
            legacy_label,
            last_label,
        ],
        op_row=[
            str(idx),
            display,
            base_label,
            inter_label,
            total_label,
            build_label,
            last_label,
            next_label,
        ],
        build_row=build_row,
        dataset_app_count=dataset_app_count,
        dataset_complete_count=dataset_complete_count,
        dataset_valid_runs_count=dataset_valid_runs_count,
        historical_valid_runs_count=historical_valid_runs_count,
        historical_build_count=historical_build_count,
        build_state=build_state,
        package_name=package,
        display_name=display,
        baseline_countable=baseline_countable,
        baseline_extra=baseline_extra,
        baseline_low_signal_supplemental=baseline_low_signal_supplemental,
        interactive_countable=interactive_countable,
        interactive_extra=interactive_extra,
        interactive_low_signal_supplemental=interactive_low_signal_supplemental,
        need_baseline=need_baseline,
        need_interactive=need_interactive,
        prep_label=prep_label,
        qa_label=qa_label,
        next_label=next_choice_label,
        technical_valid_active=technical_valid_active,
        live_build_drift=live_build_drift_flag,
        live_expected_version_code=live_expected_version_code,
        live_expected_version_name=live_expected_version_name,
        live_observed_version_code=live_observed_version_code,
        live_static_run_id=live_static_run_id,
        lineage_state=lineage_state,
        db_active_sessions=db_active_sessions,
        db_historical_sessions=db_historical_sessions,
        db_total_sessions=db_total_sessions,
    )


def row_lineage_state(
    *,
    active_valid_runs: int,
    legacy_valid_runs: int,
    db_active_sessions: int,
    db_historical_sessions: int,
    live_build_drift: bool,
) -> str:
    if int(active_valid_runs) > 0:
        return "current_build_observed"
    if int(db_active_sessions) > 0:
        return "current_build_db_only"
    if int(legacy_valid_runs) > 0:
        return "historical_local_only"
    if int(db_historical_sessions) > 0:
        return "historical_db_only"
    return "no_evidence_anywhere"


def prep_label_for_lineage_state(lineage_state: str, default_build_label: str) -> str:
    mapping = {
        "current_build_observed": default_build_label or "current",
        "current_build_db_only": "db-only",
        "historical_local_only": "legacy",
        "historical_db_only": "hist-db",
        "no_evidence_anywhere": "ready",
    }
    return mapping.get(lineage_state, default_build_label or "ready")
