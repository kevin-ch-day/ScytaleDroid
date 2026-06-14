"""Package selection helpers for the dynamic analysis menu."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils
from scytaledroid.Utils.DisplayUtils.terminal import get_terminal_width


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
    expected_runs: int
    evidence_summary: dict[str, int | bool] | None


@dataclass(frozen=True)
class PreparedPackageSelectionRow:
    full_row: list[str]
    op_row: list[str]
    build_row: list[str] | None
    dataset_app_count: int
    dataset_complete_count: int
    dataset_valid_runs_count: int


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

    if package.lower() in dataset_pkgs:
        dataset_app_count = 1
        entry = tracker_apps.get(package) if isinstance(tracker_apps, dict) else None
        runs = entry.get("runs") if isinstance(entry, dict) else []
        scoped = build_scoped_dataset_counts_fn(package, runs if isinstance(runs, list) else [], cfg=cfg)
        base_countable = int(scoped["baseline_countable"])
        base_extra = int(scoped["baseline_extra"])
        inter_countable = int(scoped["interactive_countable"])
        inter_extra = int(scoped["interactive_extra"])
        scripted_countable = int(scoped.get("interactive_scripted_countable") or 0)
        scripted_extra = int(scoped.get("interactive_scripted_extra") or 0)
        manual_countable = int(scoped.get("interactive_manual_countable") or 0)
        manual_extra = int(scoped.get("interactive_manual_extra") or 0)
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

        base_label = quota_progress_label_fn(base_countable, int(cfg.baseline_required))
        baseline_complete = base_countable >= int(cfg.baseline_required)
        inter_label = (
            quota_progress_label_fn(inter_countable, int(cfg.interactive_required))
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
        total_label = f"{base_countable + inter_countable}/{total_required}"
        legacy_label = str(legacy_valid) if legacy_valid > 0 else "0"
        build_label = static_build_label_fn(active_runs, legacy_valid)

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
    )


def run_package_selection_menu(prepared: PreparedPackageSelectionView, *, summarize_evidence_quota_fn) -> str | None:
    evidence_summary = prepared.evidence_summary
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
        print(f"Progress: {quota} / {prepared.expected_runs} required runs complete")
        print(f"Apps complete: {apps_ok} / {prepared.dataset_apps_total}")
        if freeze_ok:
            print("Freeze/export: ready")
        else:
            print(f"Freeze/export: blocked — {remaining} runs remaining")
        next_row = next((row for row in prepared.op_rows if len(row) >= 8 and row[7] != "—"), None)
        if next_row:
            print(f"Next recommended run: {next_row[1]} — {next_row[7]}")
        print()

    render_package_table(
        prepared.op_rows,
        headers=[
            "#",
            "App",
            "Baseline",
            "Interactive",
            "Total",
            "Static",
            "QA",
            "Next run",
        ],
    )

    while True:
        print()
        menu_utils.print_header("Options")
        print("1) Run App")
        print("2) View Details")
        print("3) Build history")
        print("4) Help")
        print("5) Debug")
        print("0) Return to Dynamic Analysis")
        choice = prompt_utils.prompt_text("Select", required=False).strip()

        if choice in {"", "1"}:
            index = choose_package_selection(prepared)
            if index is None:
                return None
            package_name, _, _, _ = prepared.packages[index]
            return package_name
        if choice == "2":
            from scytaledroid.DynamicAnalysis.menu_reports import render_cohort_status_details

            render_cohort_status_details(
                dataset_apps_total=prepared.dataset_apps_total,
                dataset_apps_complete=prepared.dataset_apps_complete,
                dataset_valid_runs_total=prepared.dataset_valid_runs_total,
                expected_runs=prepared.expected_runs,
                evidence_summary=evidence_summary,
            )
            continue
        if choice == "3":
            from scytaledroid.DynamicAnalysis.menu_reports import render_cohort_build_history

            render_cohort_build_history(prepared.build_rows)
            continue
        if choice == "4":
            from scytaledroid.DynamicAnalysis.menu_reports import render_cohort_status_help

            render_cohort_status_help()
            continue
        if choice == "5":
            from scytaledroid.DynamicAnalysis.menu_reports import render_cohort_status_debug

            render_cohort_status_debug(prepared.rows)
            continue
        if choice == "0":
            return None
        print(status_messages.status("Invalid option. Choose 0-5.", level="warn"))


def render_package_table(rows, *, headers: list[str] | None = None, max_preview: int = 15) -> None:
    headers = list(headers) if headers else ["#", "App"]
    selection_headers = ["#", "App", "Baseline", "Interactive", "Total", "Static", "QA", "Next run"]
    if headers == selection_headers and get_terminal_width() < 96:
        rendered = rows if len(rows) <= max_preview else rows[:max_preview]
        for row in rendered:
            print(
                f"{row[0]}) {row[1]} | Baseline: {row[2]} | Interactive: {row[3]} | "
                f"Total: {row[4]} | Static: {row[5]} | QA: {row[6]}"
            )
            print(f"   Next run: {row[7]}")
        if len(rows) > max_preview:
            response = prompt_utils.prompt_text("[L] List all | [Enter] Continue", required=False)
            if response.strip().lower() == "l":
                for row in rows:
                    print(
                        f"{row[0]}) {row[1]} | Baseline: {row[2]} | Interactive: {row[3]} | "
                        f"Total: {row[4]} | Static: {row[5]} | QA: {row[6]}"
                    )
                    print(f"   Next run: {row[7]}")
        return
    if len(rows) <= max_preview:
        table_utils.render_table(headers, rows, compact=False)
        return
    preview = rows[:max_preview]
    table_utils.render_table(headers, preview, compact=False)
    response = prompt_utils.prompt_text("[L] List all | [Enter] Continue", required=False)
    if response.strip().lower() == "l":
        table_utils.render_table(headers, rows, compact=False)


def build_scoped_dataset_counts(
    package_name: str,
    runs: list[dict],
    *,
    cfg: object | None = None,
    resolve_tracker_run_identity_fn,
) -> dict[str, int | str]:
    valid_runs: list[dict] = []
    for r in runs:
        if not isinstance(r, dict):
            continue
        if r.get("valid_dataset_run") is not True:
            continue
        valid_runs.append(r)

    active_identity: tuple[str | None, str | None] | None = None
    for r in sorted(valid_runs, key=lambda row: str(row.get("ended_at") or row.get("started_at") or ""), reverse=True):
        ident = resolve_tracker_run_identity_fn(package_name, r)
        if ident[0] or ident[1]:
            active_identity = ident
            break

    out = {
        "baseline_countable": 0,
        "baseline_extra": 0,
        "interactive_countable": 0,
        "interactive_extra": 0,
        "interactive_scripted_countable": 0,
        "interactive_scripted_extra": 0,
        "interactive_manual_countable": 0,
        "interactive_manual_extra": 0,
        "interactive_other_countable": 0,
        "interactive_other_extra": 0,
        "legacy_valid": 0,
        "legacy_builds": 0,
        "technical_valid_total": 0,
        "technical_valid_active": 0,
        "active_version_code": "",
        "active_base_sha": "",
    }
    legacy_identity_seen: set[tuple[str, str]] = set()
    if active_identity is not None:
        out["active_version_code"] = active_identity[0] or ""
        out["active_base_sha"] = active_identity[1] or ""
    active_runs: list[dict] = []
    for r in valid_runs:
        ident = resolve_tracker_run_identity_fn(package_name, r)
        ident_key = (ident[0] or "", ident[1] or "")
        if active_identity is not None and ident != active_identity:
            out["legacy_valid"] += 1
            if ident_key != ("", ""):
                legacy_identity_seen.add(ident_key)
            continue
        active_runs.append(r)
    out["technical_valid_total"] = len(valid_runs)
    out["technical_valid_active"] = len(active_runs)

    baseline_needed = max(0, int(getattr(cfg, "baseline_required", 1)))
    interactive_needed = max(0, int(getattr(cfg, "interactive_required", 2)))
    baseline_seen = 0
    interactive_seen = 0
    indexed: list[tuple[int, dict]] = [(i, r) for i, r in enumerate(active_runs)]
    indexed.sort(
        key=lambda item: (
            str(item[1].get("ended_at") or item[1].get("started_at") or ""),
            item[0],
        )
    )
    for _, r in indexed:
        prof = str(r.get("run_profile") or "").strip().lower()
        paper_eligible = r.get("paper_eligible")
        if paper_eligible is False:
            continue
        is_baseline = prof.startswith("baseline") or ("baseline" in prof) or ("idle" in prof)
        is_interactive = ("interaction" in prof) or ("interactive" in prof)
        if is_baseline:
            if baseline_seen < baseline_needed:
                baseline_seen += 1
                out["baseline_countable"] += 1
            else:
                out["baseline_extra"] += 1
            continue
        if is_interactive:
            kind = "other"
            if "interaction_manual" in prof or prof.endswith("_manual") or "manual" in prof:
                kind = "manual"
            elif "interaction_scripted" in prof or "scripted" in prof or "script" in prof:
                kind = "scripted"
            if interactive_seen < interactive_needed:
                interactive_seen += 1
                out["interactive_countable"] += 1
                out[f"interactive_{kind}_countable"] += 1
            else:
                out["interactive_extra"] += 1
                out[f"interactive_{kind}_extra"] += 1
            continue
    out["legacy_builds"] = len(legacy_identity_seen)
    return out


def resolve_tracker_run_identity(
    package_name: str,
    run: dict,
    *,
    run_identity_cache: dict[str, tuple[str | None, str | None]],
    output_dir: str,
) -> tuple[str | None, str | None]:
    version_code = str(
        run.get("version_code")
        or run.get("observed_version_code")
        or ""
    ).strip() or None
    base_sha = str(
        run.get("base_apk_sha256")
        or ""
    ).strip().lower() or None
    if version_code or base_sha:
        return (version_code, base_sha)

    run_id = str(run.get("run_id") or "").strip()
    if not run_id:
        return (None, None)
    cached = run_identity_cache.get(run_id)
    if cached is not None:
        return cached

    manifest_path = Path(output_dir) / "evidence" / "dynamic" / run_id / "run_manifest.json"
    if not manifest_path.exists():
        run_identity_cache[run_id] = (None, None)
        return (None, None)
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        run_identity_cache[run_id] = (None, None)
        return (None, None)

    target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
    ident = target.get("run_identity") if isinstance(target.get("run_identity"), dict) else {}
    pkg = str(target.get("package_name") or package_name or "").strip().lower()
    if pkg and pkg != package_name.strip().lower():
        run_identity_cache[run_id] = (None, None)
        return (None, None)

    version_code = str(
        ident.get("version_code")
        or target.get("version_code")
        or ""
    ).strip() or None
    base_sha = str(
        ident.get("base_apk_sha256")
        or ""
    ).strip().lower() or None
    resolved = (version_code, base_sha)
    run_identity_cache[run_id] = resolved
    return resolved


def choose_package_selection(prepared: PreparedPackageSelectionView) -> int | None:
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

    while True:
        raw = prompt_utils.prompt_text(
            "Select app number or app name",
            required=False,
        ).strip()
        if not raw:
            return 0
        choice = raw.lower()
        if choice in {"0", "b", "back", "cancel"}:
            return None
        if choice in lookup:
            return lookup[choice]
        matches = [idx for key, idx in lookup.items() if choice and choice in key and not key.isdigit()]
        matches = sorted(set(matches))
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            print(status_messages.status(f"Multiple apps matched \"{raw}\". Please enter the app number.", level="warn"))
            continue
        print(
            status_messages.status(
                f"No matching app found. Enter a number from 1-{total} or an app name like Facebook.",
                level="warn",
            )
        )
