"""Package selection helpers for the dynamic analysis menu."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.Config import app_config
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


def prepare_package_selection_view(
    groups,
    *,
    load_dataset_packages,
    list_packages_fn,
    summarize_evidence_quota_fn,
    build_package_selection_row_fn,
) -> PreparedPackageSelectionView | None:
    packages = list_packages_fn(groups)
    if not packages:
        return None
    dataset_pkgs: set[str] = set()
    try:
        dataset_pkgs = {pkg.lower() for pkg in load_dataset_packages()}
    except Exception:
        dataset_pkgs = set()

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

    if package.lower() in dataset_pkgs:
        dataset_app_count = 1
        entry = tracker_apps.get(package) if isinstance(tracker_apps, dict) else None
        runs = entry.get("runs") if isinstance(entry, dict) else []
        scoped = build_scoped_dataset_counts_fn(package, runs if isinstance(runs, list) else [], cfg=cfg)
        base_countable = int(scoped["baseline_countable"])
        base_extra = int(scoped["baseline_extra"])
        inter_countable = int(scoped["interactive_countable"])
        inter_extra = int(scoped["interactive_extra"])
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
        historical_valid_runs_count = legacy_valid
        historical_build_count = legacy_builds

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

        next_label = next_action_from_need_fn(need_base, need_inter)
        if need_label == "0":
            next_label = "—"
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
    )


def run_package_selection_menu(prepared: PreparedPackageSelectionView, *, summarize_evidence_quota_fn) -> str | None:
    evidence_summary = prepared.evidence_summary
    show_all = False

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
            print(f"Runs complete     : {quota} / {prepared.expected_runs}")
            print(f"Apps complete     : {apps_ok} / {prepared.dataset_apps_total}")
            if freeze_ok:
                print("Archive readiness : ready")
            else:
                print(f"Archive readiness : blocked — {remaining} runs remaining")
            extra_runs = int(evidence_summary.get("extra_eligible_runs", 0)) if evidence_summary else 0
            if extra_runs > 0:
                print(f"Supplemental runs : {extra_runs} extra valid run(s) retained outside quota")
            next_row = next((row for row in prepared.op_rows if len(row) >= 8 and row[7] != "—"), None)
            if next_row:
                print(f"Recommended next  : {next_row[1]} — {next_row[7]}")
            print()

        truncated = render_package_table(
            prepared.op_rows,
            headers=[
                "#",
                "App",
                "Baseline",
                "Manual",
                "Quota",
                "Static prep",
                "Last QA",
                "Next action",
            ],
            show_all=show_all,
        )
        print()
        print("Select an app by number or name.")
        shortcuts = ["S summary", "Y history", "H help", "D diagnostics", "B back"]
        if truncated and not show_all:
            shortcuts.insert(0, "L full list")
        print(f"Shortcuts         : {' | '.join(shortcuts)}")
        choice = prompt_utils.prompt_text("Choose app # / name", required=False).strip()

        if not choice:
            index = choose_package_selection(prepared)
            if index is None:
                return None
            package_name, _, _, _ = prepared.packages[index]
            return package_name
        choice_lc = choice.lower()
        if choice_lc in {"l", "list", "full"} and truncated and not show_all:
            show_all = True
            print()
            continue
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
            )
            continue
        if choice_lc in {"y", "history"}:
            from scytaledroid.DynamicAnalysis.menu_reports import render_cohort_build_history

            render_cohort_build_history(prepared.build_rows)
            continue
        if choice_lc in {"h", "help"}:
            from scytaledroid.DynamicAnalysis.menu_reports import render_cohort_status_help

            render_cohort_status_help()
            continue
        if choice_lc in {"d", "debug", "diagnostics"}:
            from scytaledroid.DynamicAnalysis.menu_reports import render_cohort_status_debug

            render_cohort_status_debug(prepared.rows)
            continue
        if choice_lc in {"0", "b", "back", "cancel"}:
            return None
        index = resolve_package_selection(choice, prepared)
        if index is not None:
            package_name, _, _, _ = prepared.packages[index]
            return package_name
        print(status_messages.status("Invalid choice. Enter an app number/name or use S, Y, H, D, or B.", level="warn"))


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
