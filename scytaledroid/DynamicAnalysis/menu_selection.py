"""Package selection helpers for the dynamic analysis menu."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.adb import shell as adb_shell
from scytaledroid.DynamicAnalysis.controllers.guided_run_checks import (
    extract_version_code_details_from_dump,
    read_observed_version_code_details,
)
from scytaledroid.DynamicAnalysis.plan_selection import load_plan_candidates
from scytaledroid.DynamicAnalysis.templates.category_map import resolved_template_for_package
from scytaledroid.DynamicAnalysis.tracker_scope import (
    build_scoped_dataset_counts as _build_scoped_dataset_counts_shared,
    resolve_tracker_run_identity as _resolve_tracker_run_identity_shared,
)
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils


@dataclass(frozen=True)
class PreparedPackageSelectionView:
    packages: list[tuple[str, str | None, int | None, str | None]]
    dataset_pkgs: set[str]
    cfg: object
    rows: list[list[str]]
    op_rows: list[list[str]]
    build_rows: list[list[str]]
    dataset_apps_total: int
    dataset_apps_complete: int
    dataset_valid_runs_total: int
    historical_valid_runs_total: int = 0
    historical_build_count_total: int = 0
    mixed_identity_app_count: int = 0
    legacy_only_app_count: int = 0
    expected_runs: int = 0
    evidence_summary: dict[str, int | bool] | None = None
    row_models: list["PreparedPackageSelectionRow"] | None = None


@dataclass(frozen=True)
class PreparedPackageSelectionRow:
    full_row: list[str]
    op_row: list[str]
    build_row: list[str] | None
    dataset_app_count: int
    dataset_complete_count: int
    dataset_valid_runs_count: int
    historical_valid_runs_count: int = 0
    historical_build_count: int = 0
    build_state: str = "—"
    package_name: str = ""
    display_name: str = ""
    baseline_countable: int = 0
    baseline_extra: int = 0
    interactive_countable: int = 0
    interactive_extra: int = 0
    need_baseline: int = 0
    need_interactive: int = 0
    prep_label: str = "—"
    qa_label: str = "—"
    next_label: str = "—"
    technical_valid_active: int = 0
    live_build_drift: bool = False
    live_expected_version_code: str = ""
    live_observed_version_code: str = ""


def prepare_package_selection_view(
    groups,
    *,
    load_dataset_packages,
    list_packages_fn,
    summarize_evidence_quota_fn,
    build_package_selection_row_fn,
    device_serial: str | None = None,
) -> PreparedPackageSelectionView | None:
    packages = list_packages_fn(groups)
    if not packages:
        return None
    dataset_pkgs: set[str] = set()
    try:
        dataset_pkgs = {pkg.lower() for pkg in load_dataset_packages()}
    except Exception:
        dataset_pkgs = set()
    live_build_drift_map = _resolve_live_build_drift_map(
        [package for package, _v, _c, _label in packages],
        device_serial=device_serial,
    )

    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
        DatasetTrackerConfig,
        load_dataset_tracker,
    )
    from scytaledroid.DynamicAnalysis.utils.run_cleanup import recent_tracker_runs

    cfg = DatasetTrackerConfig()
    tracker = load_dataset_tracker()
    tracker_apps = tracker.get("apps") if isinstance(tracker, dict) else {}
    labels = [((app_label or package).strip() or package) for package, _v, _c, app_label in packages]
    collisions = {label for label in labels if labels.count(label) > 1}

    rows = []
    op_rows = []
    build_rows = []
    row_models: list[PreparedPackageSelectionRow] = []
    dataset_apps_total = 0
    dataset_apps_complete = 0
    dataset_valid_runs_total = 0
    historical_valid_runs_total = 0
    historical_build_count_total = 0
    mixed_identity_app_count = 0
    legacy_only_app_count = 0
    evidence_summary: dict[str, int | bool] | None = None
    for idx, (package, _version, _count, app_label) in enumerate(packages, start=1):
        prepared_row = build_package_selection_row_fn(
            idx=idx,
            package=package,
            app_label=app_label,
            collisions=collisions,
            dataset_pkgs=dataset_pkgs,
            tracker_apps=tracker_apps,
            cfg=cfg,
            recent_tracker_runs=recent_tracker_runs,
            live_build_drift=live_build_drift_map.get(str(package or "").strip().lower()),
        )
        dataset_apps_total += prepared_row.dataset_app_count
        dataset_apps_complete += prepared_row.dataset_complete_count
        dataset_valid_runs_total += prepared_row.dataset_valid_runs_count
        historical_valid_runs_total += prepared_row.historical_valid_runs_count
        historical_build_count_total += prepared_row.historical_build_count
        if prepared_row.build_state == "mixed":
            mixed_identity_app_count += 1
        elif prepared_row.build_state == "legacy":
            legacy_only_app_count += 1
        rows.append(prepared_row.full_row)
        op_rows.append(prepared_row.op_row)
        row_models.append(prepared_row)
        if prepared_row.build_row is not None:
            build_rows.append(prepared_row.build_row)

    expected_runs = 0
    if dataset_apps_total > 0:
        evidence_summary = summarize_evidence_quota_fn(dataset_pkgs, cfg)
        expected_runs = dataset_apps_total * (int(cfg.baseline_required) + int(cfg.interactive_required))

    return PreparedPackageSelectionView(
        packages=packages,
        dataset_pkgs=dataset_pkgs,
        cfg=cfg,
        rows=rows,
        op_rows=op_rows,
        build_rows=build_rows,
        dataset_apps_total=dataset_apps_total,
        dataset_apps_complete=dataset_apps_complete,
        dataset_valid_runs_total=dataset_valid_runs_total,
        historical_valid_runs_total=historical_valid_runs_total,
        historical_build_count_total=historical_build_count_total,
        mixed_identity_app_count=mixed_identity_app_count,
        legacy_only_app_count=legacy_only_app_count,
        expected_runs=expected_runs,
        evidence_summary=evidence_summary,
        row_models=row_models,
    )


def build_package_selection_row(
    *,
    idx: int,
    package: str,
    app_label: str | None,
    collisions: set[str],
    dataset_pkgs: set[str],
    tracker_apps,
    cfg,
    recent_tracker_runs,
    live_build_drift=None,
    truncate_visible_fn,
    bucket_progress_label_fn,
    quota_progress_label_fn,
    static_build_label_fn,
    next_action_from_need_fn,
    build_scoped_dataset_counts_fn,
    resolve_tracker_run_identity_fn,
) -> PreparedPackageSelectionRow:
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
    interactive_countable = 0
    interactive_extra = 0
    need_baseline = 0
    need_interactive = 0
    prep_label = "—"
    qa_label = "—"
    next_choice_label = "—"
    technical_valid_active = 0
    live_build_drift_flag = False
    live_expected_version_code = ""
    live_observed_version_code = ""

    if package.lower() in dataset_pkgs:
        dataset_app_count = 1
        entry = tracker_apps.get(package) if isinstance(tracker_apps, dict) else None
        runs = entry.get("runs") if isinstance(entry, dict) else []
        scoped = build_scoped_dataset_counts_fn(package, runs if isinstance(runs, list) else [], cfg=cfg)
        base_countable = int(scoped["baseline_countable"])
        base_extra = int(scoped["baseline_extra"])
        inter_countable = int(scoped["interactive_countable"])
        inter_extra = int(scoped["interactive_extra"])
        baseline_countable = base_countable
        baseline_extra = base_extra
        interactive_countable = inter_countable
        interactive_extra = inter_extra
        legacy_valid = int(scoped["legacy_valid"])
        legacy_builds = int(scoped["legacy_builds"])
        active_version = str(scoped.get("active_version_code") or "—")
        active_sha = str(scoped.get("active_base_sha") or "")
        active_build = active_version
        if active_sha:
            active_build = f"{active_version} / {active_sha[:10]}"
        elif active_version == "—":
            active_build = "unknown (tracker-only)"
        active_runs = base_countable + base_extra + inter_countable + inter_extra

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

        recent = recent_tracker_runs(package, limit=1)
        if recent:
            r = recent[0]
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

        next_label = next_action_from_need_fn(need_base, need_inter)
        if need_label == "0":
            next_label = "—"
        next_choice_label = next_label
        if isinstance(live_build_drift, dict):
            live_build_drift_flag = True
            live_expected_version_code = str(live_build_drift.get("expected_version_code") or "").strip()
            live_observed_version_code = str(live_build_drift.get("observed_version_code") or "").strip()
            prep_label = "stale"
            next_choice_label = "refresh static"
        build_row = [display, active_build, str(active_runs), str(legacy_valid), str(legacy_builds)]

    return PreparedPackageSelectionRow(
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
        interactive_countable=interactive_countable,
        interactive_extra=interactive_extra,
        need_baseline=need_baseline,
        need_interactive=need_interactive,
        prep_label=prep_label,
        qa_label=qa_label,
        next_label=next_choice_label,
        technical_valid_active=technical_valid_active,
        live_build_drift=live_build_drift_flag,
        live_expected_version_code=live_expected_version_code,
        live_observed_version_code=live_observed_version_code,
    )


def run_package_selection_menu(prepared: PreparedPackageSelectionView, *, summarize_evidence_quota_fn) -> str | None:
    evidence_summary = prepared.evidence_summary

    while True:
        if prepared.dataset_apps_total > 0:
            evidence_summary = evidence_summary or summarize_evidence_quota_fn(prepared.dataset_pkgs, prepared.cfg)
            quota = int(evidence_summary.get("quota_runs_counted", 0)) if evidence_summary else 0
            apps_ok = int(evidence_summary.get("apps_satisfied", 0)) if evidence_summary else 0
            freeze_ok = (
                bool(evidence_summary.get("evidence_root_exists"))
                and quota >= int(prepared.expected_runs)
                and apps_ok >= int(prepared.dataset_apps_total)
            ) if evidence_summary else False
            remaining = max(0, int(prepared.expected_runs) - int(quota))
            row_models = list(prepared.row_models or [])
            extra_runs = int(evidence_summary.get("extra_eligible_runs", 0)) if evidence_summary else 0
            progress_parts = [f"{quota}/{prepared.expected_runs} valid", f"{apps_ok}/{prepared.dataset_apps_total} complete", f"{remaining} remaining"]
            if extra_runs > 0:
                progress_parts.append(f"{extra_runs} supplemental")
            print(f"Quota: {' | '.join(progress_parts)}")
            print(f"Archive: {'ready' if freeze_ok else 'blocked'}")
            print()

            next_row = next((row for row in row_models if row.next_label != "—"), None)
            if next_row:
                print(f"Next : {next_row.display_name} — {_display_next_line_action_label(next_row)}")
                print()

            _render_compact_queue_table(
                row_models,
                baseline_required=int(getattr(prepared.cfg, "baseline_required", 3)),
                interactive_required=int(getattr(prepared.cfg, "interactive_required", 2)),
            )
            warnings_line = _compact_warning_line(row_models)
            if warnings_line:
                print()
                print(f"Warnings: {warnings_line}")
            print()
        print()
        print("Select an app by number or name.")
        shortcuts = ["S summary", "Y history", "H help", "D diagnostics", "B back"]
        print(f"Shortcuts         : {' | '.join(shortcuts)}")
        choice = prompt_utils.prompt_text("Choose app # / name", required=False).strip()

        if not choice:
            index = choose_package_selection(prepared)
            if index is None:
                return None
            package_name, _, _, _ = prepared.packages[index]
            return package_name
        choice_lc = choice.lower()
        if choice_lc in {"s", "summary"}:
            from scytaledroid.DynamicAnalysis.menu_reports import render_cohort_status_details

            render_cohort_status_details(
                dataset_apps_total=prepared.dataset_apps_total,
                dataset_apps_complete=prepared.dataset_apps_complete,
                dataset_valid_runs_total=prepared.dataset_valid_runs_total,
                historical_valid_runs_total=prepared.historical_valid_runs_total,
                historical_build_count_total=prepared.historical_build_count_total,
                mixed_identity_app_count=prepared.mixed_identity_app_count,
                legacy_only_app_count=prepared.legacy_only_app_count,
                expected_runs=prepared.expected_runs,
                evidence_summary=evidence_summary,
                row_models=list(prepared.row_models or []),
                baseline_required=int(getattr(prepared.cfg, "baseline_required", 3)),
                interactive_required=int(getattr(prepared.cfg, "interactive_required", 2)),
            )
            continue
        if choice_lc in {"y", "history"}:
            from scytaledroid.DynamicAnalysis.menu_reports import render_cohort_build_history

            render_cohort_build_history(list(prepared.row_models or []), prepared.build_rows)
            continue
        if choice_lc in {"h", "help"}:
            from scytaledroid.DynamicAnalysis.menu_reports import render_cohort_status_help

            render_cohort_status_help()
            continue
        if choice_lc in {"d", "debug", "diagnostics"}:
            from scytaledroid.DynamicAnalysis.menu_reports import render_cohort_status_debug

            render_cohort_status_debug(prepared.rows, list(prepared.row_models or []))
            continue
        if choice_lc in {"0", "b", "back", "cancel"}:
            return None
        index = resolve_package_selection(choice, prepared)
        if index is not None:
            package_name, _, _, _ = prepared.packages[index]
            return package_name
        print(status_messages.status("Invalid choice. Enter an app number/name or use S, Y, H, D, or B.", level="warn"))


def _recommended_reason(row: PreparedPackageSelectionRow) -> str:
    if row.live_build_drift:
        return "installed build differs from newest static plan"
    if row.need_baseline > 0:
        return f"baseline runs needed: {row.need_baseline}"
    if row.need_interactive > 0:
        return f"baseline complete, interactive runs needed: {row.need_interactive}"
    if row.baseline_extra > 0 or row.interactive_extra > 0:
        extra_total = int(row.baseline_extra) + int(row.interactive_extra)
        return f"quota complete, {extra_total} extra run(s) retained"
    return "quota state up to date"


def _compact_warning_line(row_models: list[PreparedPackageSelectionRow]) -> str:
    issues: list[str] = []
    drift_rows = [row.display_name for row in row_models if row.live_build_drift]
    mixed_rows = [row.display_name for row in row_models if row.prep_label == "mixed"]
    invalid_rows = [row.display_name for row in row_models if str(row.qa_label).startswith("invalid")]
    mismatch_rows = [row.display_name for row in row_models if "id_mismatch" in str(row.qa_label)]
    baseline_needed = sum(1 for row in row_models if row.need_baseline > 0)

    if drift_rows:
        label = ", ".join(drift_rows[:2])
        issues.append(f"{label} needs static refresh")
    if mixed_rows:
        label = ", ".join(mixed_rows[:2])
        issues.append(f"{label} mixed current/legacy evidence")
    if invalid_rows:
        label = ", ".join(invalid_rows[:2])
        issues.append(f"{label} QA invalid")
    elif mismatch_rows:
        label = ", ".join(mismatch_rows[:2])
        issues.append(f"{label} identity mismatch")
    if baseline_needed > 0:
        verb = "needs" if baseline_needed == 1 else "need"
        issues.append(f"{baseline_needed} app{'s' if baseline_needed != 1 else ''} {verb} baseline")
    if not issues:
        return ""
    if len(issues) == 1 and invalid_rows:
        return issues[0] + ". Press D for diagnostics."
    if len(issues) <= 2:
        return ". ".join(issues) + "."
    return f"{len(issues)} issues. Press S for summary or D for diagnostics."


def _attention_items(row_models: list[PreparedPackageSelectionRow]) -> list[str]:
    items: list[str] = []
    baseline_needed = sum(1 for row in row_models if row.need_baseline > 0)
    drift_rows = [row for row in row_models if row.live_build_drift]
    invalid_rows = [row for row in row_models if str(row.qa_label).startswith("invalid")]
    mixed_rows = [row for row in row_models if row.prep_label == "mixed"]
    mismatch_rows = [row for row in row_models if "id_mismatch" in str(row.qa_label)]
    for row in drift_rows[:3]:
        items.append(
            f"{row.display_name}: installed build {row.live_observed_version_code or 'unknown'} "
            f"drifted from static plan {row.live_expected_version_code or 'unknown'} — rerun harvest/static"
        )
    for row in invalid_rows[:3]:
        items.append(f"{row.display_name}: QA invalid — review latest run before trusting quota credit")
    for row in mixed_rows[:3]:
        active_runs = int(getattr(row, "technical_valid_active", 0) or 0)
        legacy_runs = int(getattr(row, "historical_valid_runs_count", 0) or 0)
        legacy_builds = int(getattr(row, "historical_build_count", 0) or 0)
        items.append(
            f"{row.display_name}: prep mixed — {active_runs} current-build valid run(s) and "
            f"{legacy_runs} legacy valid run(s) across {legacy_builds} older build(s)"
        )
    for row in mismatch_rows[:3]:
        items.append(f"{row.display_name}: QA identity mismatch — latest valid run does not match active build identity")
    if baseline_needed > 0:
        verb = "needs" if baseline_needed == 1 else "need"
        items.append(f"{baseline_needed} app{'s' if baseline_needed != 1 else ''} still {verb} baseline capture")
    return items


def _render_compact_queue_table(
    rows: list[PreparedPackageSelectionRow],
    *,
    baseline_required: int,
    interactive_required: int,
) -> None:
    headers = ["#", "App", "Status", "Missing", "Quota", "Build/QA", "Template", "Action"]
    total_required = int(baseline_required) + int(interactive_required)
    table_rows = [
        [
            row.full_row[0],
            row.display_name,
            _queue_state_label(row),
            _queue_need_label(row, baseline_required=baseline_required, interactive_required=interactive_required),
            _queue_runs_label(row, total_required=total_required),
            _queue_prep_qa_label(row),
            _queue_template_label(row.package_name),
            _display_action_label(row),
        ]
        for row in rows
    ]
    table_utils.render_table(headers, table_rows, compact=False)


def _queue_state_label(row: PreparedPackageSelectionRow) -> str:
    if row.live_build_drift:
        return "refresh"
    if str(row.qa_label).startswith("invalid"):
        return "review"
    if row.need_baseline > 0:
        return "baseline"
    if row.need_interactive > 0:
        return "manual"
    if row.next_label == "—":
        return "complete"
    if row.prep_label == "mixed":
        return "review"
    return "blocked"


def _queue_need_label(
    row: PreparedPackageSelectionRow,
    *,
    baseline_required: int,
    interactive_required: int,
) -> str:
    state = _queue_state_label(row)
    if row.live_build_drift:
        return "static refresh"
    if state == "review":
        return "review QA"
    if state == "baseline":
        return f"base {row.baseline_countable}/{int(baseline_required)}"
    if state == "manual":
        return f"manual {row.interactive_countable}/{int(interactive_required)}"
    return "—"


def _queue_runs_label(row: PreparedPackageSelectionRow, *, total_required: int) -> str:
    countable = int(row.baseline_countable) + int(row.interactive_countable)
    extra = int(row.baseline_extra) + int(row.interactive_extra)
    missing = int(row.need_baseline) + int(row.need_interactive)
    if missing <= 0:
        if extra > 0:
            return f"{countable}/{int(total_required)} +{extra}"
        return f"{countable}/{int(total_required)}"
    return f"{countable}/{int(total_required)} n{missing}"


def _queue_prep_qa_label(row: PreparedPackageSelectionRow) -> str:
    prep = str(row.prep_label or "—").strip() or "—"
    qa = _queue_qa_badge(row.qa_label)
    return f"{prep}/{qa}"


def _queue_qa_badge(value: str) -> str:
    text = str(value or "").strip()
    if text in {"", "—"}:
        return "—"
    if text == "valid":
        return "✓"
    if text == "valid (L)":
        return "+L"
    if text == "valid (id_mismatch)":
        return "+id"
    if text == "valid (id_mismatch) (L)":
        return "+id+L"
    if text.startswith("invalid"):
        return "invalid"
    return text


def _queue_template_label(package_name: str) -> str:
    template_id = str(resolved_template_for_package(package_name) or "").strip()
    if not template_id:
        return "none"
    if template_id == "news_reader_basic_v1":
        return "news"
    if template_id in {
        "social_feed_basic_v2",
        "facebook_basic_v2",
        "snapchat_basic_v1",
        "x_twitter_full_session_v1",
        "social_messaging_basic_v1",
        "messaging_idle_v1",
        "messaging_text_v1",
        "messaging_voice_v1",
        "messaging_video_v1",
        "messaging_call_basic_v1",
        "whatsapp_idle_v1",
        "whatsapp_text_v1",
        "whatsapp_voice_v1",
        "whatsapp_video_v1",
        "tiktok_basic_v1",
        "tiktok_basic_v2",
    }:
        return "acct"
    return "generic"


def _display_action_label(row: PreparedPackageSelectionRow) -> str:
    if row.live_build_drift:
        return "refresh"
    action = _main_action_label(row.next_label)
    if action != "manual":
        return action
    template = _queue_template_label(row.package_name)
    if row.need_interactive > 0 and row.need_baseline <= 0 and template in {"news", "generic"}:
        return "scripted"
    return action


def _display_next_line_action_label(row: PreparedPackageSelectionRow) -> str:
    action = _display_action_label(row)
    if action == "scripted":
        return "scripted interaction"
    if action == "manual":
        return "manual interaction"
    return action


def _group_queue_sections(
    row_models: list[PreparedPackageSelectionRow],
) -> list[tuple[str, list[PreparedPackageSelectionRow]]]:
    needs_refresh: list[PreparedPackageSelectionRow] = []
    ready_manual: list[PreparedPackageSelectionRow] = []
    needs_baseline: list[PreparedPackageSelectionRow] = []
    complete_or_extra: list[PreparedPackageSelectionRow] = []
    other_blocked: list[PreparedPackageSelectionRow] = []
    for row in row_models:
        if row.live_build_drift:
            needs_refresh.append(row)
        elif row.need_baseline > 0:
            needs_baseline.append(row)
        elif row.need_interactive > 0 and row.next_label == "manual interaction":
            ready_manual.append(row)
        elif row.next_label == "—":
            complete_or_extra.append(row)
        else:
            other_blocked.append(row)
    sections: list[tuple[str, list[PreparedPackageSelectionRow]]] = []
    sections.append(("Needs static refresh", needs_refresh))
    sections.append(("Ready for manual interaction", ready_manual))
    sections.append(("Needs baseline capture", needs_baseline))
    sections.append(("Complete / over-quota", complete_or_extra))
    if other_blocked:
        sections.append(("Other / blocked", other_blocked))
    return sections


def _render_queue_section_table(
    rows: list[PreparedPackageSelectionRow],
    *,
    baseline_required: int,
    interactive_required: int,
    show_all: bool = False,
) -> None:
    headers = ["#", "App", "Baseline", "Manual", "Quota", "Prep", "QA", "Action"]
    total_required = int(baseline_required) + int(interactive_required)
    table_rows = [
        [
            row.full_row[0],
            row.display_name,
            _main_progress_label(row.baseline_countable, row.baseline_extra, required=baseline_required),
            _manual_progress_label(row, interactive_required=interactive_required),
            _main_progress_label(
                row.baseline_countable + row.interactive_countable,
                row.baseline_extra + row.interactive_extra,
                required=total_required,
                missing=row.need_baseline + row.need_interactive,
            ),
            row.prep_label or "—",
            _compact_qa_label(row.qa_label),
            _main_action_label(row.next_label),
        ]
        for row in rows
    ]
    max_rows = None if show_all else 15
    table_utils.render_table(headers, table_rows, compact=False, max_rows=max_rows, padding=3)


def _main_progress_label(
    countable: int,
    extra: int,
    *,
    required: int,
    missing: int | None = None,
) -> str:
    count_i = max(0, int(countable))
    extra_i = max(0, int(extra))
    required_i = max(0, int(required))
    missing_i = max(0, int(missing if missing is not None else max(required_i - count_i, 0)))
    if missing_i == 0:
        if extra_i > 0:
            suffix = " extra" if extra_i == 1 else " extras"
            return f"{count_i}/{required_i} +{extra_i}{suffix}"
        return f"{count_i}/{required_i} complete"
    return f"{count_i}/{required_i} need {missing_i}"


def _manual_progress_label(row: PreparedPackageSelectionRow, *, interactive_required: int) -> str:
    if row.need_baseline > 0:
        return "locked"
    return _main_progress_label(
        row.interactive_countable,
        row.interactive_extra,
        required=interactive_required,
        missing=row.need_interactive,
    )


def _main_action_label(value: str) -> str:
    text = str(value or "").strip()
    if text == "manual interaction":
        return "manual"
    if text == "refresh static":
        return "refresh"
    return text or "—"


def render_package_table(
    rows,
    *,
    headers: list[str] | None = None,
    max_preview: int = 15,
    show_all: bool = False,
) -> bool:
    headers = list(headers) if headers else ["#", "App"]
    selection_headers = ["#", "App", "Baseline", "Manual", "Quota", "Static prep", "Last QA", "Next action"]
    # Avoid a pointless "show full list" branch when only a single row would be hidden.
    effective_preview = max_preview + 1 if len(rows) == (max_preview + 1) else max_preview
    truncated = len(rows) > effective_preview and not show_all
    rendered_rows = rows if show_all or len(rows) <= effective_preview else rows[:effective_preview]
    if headers == selection_headers:
        compact_headers = ["#", "App", "Base", "Manual", "Quota", "Prep", "QA", "Next"]
        table_utils.render_table(compact_headers, _compact_selection_rows(rendered_rows), compact=False)
    else:
        table_utils.render_table(headers, rendered_rows, compact=False)
    if truncated:
        print(f"Showing first {effective_preview} of {len(rows)} apps.")
    return truncated


def _compact_selection_rows(rows: list[list[str]]) -> list[list[str]]:
    return [
        [
            row[0],
            row[1],
            _compact_progress_label(row[2]),
            _compact_progress_label(row[3]),
            _compact_progress_label(row[4]),
            _compact_prep_label(row[5]),
            _compact_qa_label(row[6]),
            _compact_next_action(row[7]),
        ]
        for row in rows
    ]


def _compact_progress_label(value: str) -> str:
    text = str(value or "").strip()
    if not text or text == "—":
        return text or "—"
    if text == "locked":
        return "locked"
    complete_match = re.fullmatch(r"(\d+)/(\d+)\s+complete(?:\s+\(\+(\d+)\s+extra\))?", text)
    if complete_match:
        count = int(complete_match.group(1))
        required = int(complete_match.group(2))
        extra = int(complete_match.group(3) or 0)
        if extra > 0:
            return f"{count + extra}/{required}"
        return f"{count}/{required}"
    need_match = re.fullmatch(r"(\d+)/(\d+)\s+need\s+(\d+)(?:\s+\(\+(\d+)\s+extra\))?", text)
    if need_match:
        count = int(need_match.group(1))
        required = int(need_match.group(2))
        missing = int(need_match.group(3))
        return f"{count}/{required} n{missing}"
    return text


def _compact_next_action(value: str) -> str:
    text = str(value or "").strip().lower()
    if text == "manual interaction":
        return "manual"
    return str(value or "").strip() or "—"


def _compact_prep_label(value: str) -> str:
    text = str(value or "").strip().lower()
    mapping = {
        "current": "current",
        "mixed": "mixed",
        "legacy": "legacy",
        "ready": "ready",
        "stale": "stale",
    }
    return mapping.get(text, str(value or "").strip() or "—")


def _compact_qa_label(value: str) -> str:
    text = str(value or "").strip()
    if text == "valid (L)":
        return "valid+L"
    if text == "valid (id_mismatch) (L)":
        return "valid+id+L"
    if text == "valid (id_mismatch)":
        return "valid+id"
    return text or "—"


def _resolve_live_build_drift_map(
    packages: list[str],
    *,
    device_serial: str | None,
) -> dict[str, dict[str, str]]:
    if not str(device_serial or "").strip():
        return {}
    out: dict[str, dict[str, str]] = {}
    for package_name in packages:
        pkg = str(package_name or "").strip()
        if not pkg:
            continue
        try:
            candidates, _note = load_plan_candidates(pkg)
        except Exception:
            continue
        if not candidates:
            continue
        newest = sorted(candidates, key=lambda row: row.get("generated_at") or "", reverse=True)[0]
        identity = newest.get("identity") if isinstance(newest.get("identity"), dict) else {}
        expected_vc = str(identity.get("version_code") or newest.get("version_code") or "").strip()
        if not expected_vc:
            continue
        try:
            observed = read_observed_version_code_details(
                str(device_serial).strip(),
                pkg,
                run_shell_fn=lambda serial, command: adb_shell.run_shell(serial, list(command)),
                extract_details_fn=extract_version_code_details_from_dump,
            )
        except Exception:
            continue
        observed_vc = str(observed.get("version_code") or "").strip()
        if not observed_vc or observed_vc == expected_vc:
            continue
        out[pkg.lower()] = {
            "expected_version_code": expected_vc,
            "observed_version_code": observed_vc,
        }
    return out


def build_scoped_dataset_counts(
    package_name: str,
    runs: list[dict],
    *,
    cfg: object | None = None,
    resolve_tracker_run_identity_fn,
) -> dict[str, int | str]:
    return _build_scoped_dataset_counts_shared(
        package_name,
        runs,
        cfg=cfg,
        resolve_tracker_run_identity_fn=resolve_tracker_run_identity_fn,
    )


def resolve_tracker_run_identity(
    package_name: str,
    run: dict,
    *,
    run_identity_cache: dict[str, tuple[str | None, str | None]],
    output_dir: str,
) -> tuple[str | None, str | None]:
    return _resolve_tracker_run_identity_shared(
        package_name,
        run,
        run_identity_cache=run_identity_cache,
        output_dir=output_dir,
    )


def choose_package_selection(prepared: PreparedPackageSelectionView) -> int | None:
    total = len(prepared.packages)
    if total <= 0:
        return None
    while True:
        raw = prompt_utils.prompt_text(
            "Select app number or app name",
            required=False,
        ).strip()
        if not raw:
            return 0
        if raw.lower() in {"0", "b", "back", "cancel"}:
            return None
        resolved = resolve_package_selection(raw, prepared)
        if resolved is not None:
            return resolved
        print(
            status_messages.status(
                f"No matching app found. Enter a number from 1-{total} or an app name like Facebook.",
                level="warn",
            )
        )


def resolve_package_selection(raw: str, prepared: PreparedPackageSelectionView) -> int | None:
    total = len(prepared.packages)
    if total <= 0:
        return None
    lookup: dict[str, int] = {}
    for idx, (package_name, app_label, _static_run_id, _plan_path) in enumerate(prepared.packages):
        lookup[str(idx + 1)] = idx
        pkg_lc = str(package_name or "").strip().lower()
        if pkg_lc:
            lookup[pkg_lc] = idx
        label_lc = str(app_label or "").strip().lower()
        if label_lc:
            lookup[label_lc] = idx
        if idx < len(prepared.op_rows) and len(prepared.op_rows[idx]) > 1:
            display_lc = str(prepared.op_rows[idx][1] or "").strip().lower()
            if display_lc:
                lookup[display_lc] = idx

    choice = raw.strip().lower()
    if choice in lookup:
        return lookup[choice]
    matches = [idx for key, idx in lookup.items() if choice and choice in key and not key.isdigit()]
    matches = sorted(set(matches))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print(status_messages.status(f"Multiple apps matched \"{raw}\". Please enter the app number.", level="warn"))
    return None
