"""Workspace maintenance & cleanup menu."""

from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.services import artifact_store
from scytaledroid.Utils.DisplayUtils import (
    display_settings,
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
    text_blocks,
)


def _dir_size_bytes(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for entry in path.rglob("*"):
        if entry.is_file():
            try:
                total += entry.stat().st_size
            except OSError:
                continue
    return total


def _humanize_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    for unit in units:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"

def _count_files(path: Path, *, pattern: str = "**/*") -> int:
    if not path.exists():
        return 0
    n = 0
    for entry in path.glob(pattern):
        if entry.is_file():
            n += 1
    return n


def _count_dirs(path: Path) -> int:
    if not path.exists():
        return 0
    try:
        return sum(1 for p in path.iterdir() if p.is_dir())
    except OSError:
        return 0


def _show_summary() -> None:
    data_dir = Path("data")
    apks_dir = artifact_store.analysis_apk_root()
    receipts_dir = artifact_store.receipts_root()
    logs_dir = Path("logs")
    output_dir = Path(app_config.OUTPUT_DIR)
    cache_dirs = [data_dir / "static_analysis" / "cache", output_dir / "cache"]
    apk_files = list(apks_dir.rglob("*.apk")) if apks_dir.exists() else []

    apks_size = _dir_size_bytes(apks_dir)
    logs_size = _dir_size_bytes(logs_dir)
    cache_size = sum(_dir_size_bytes(p) for p in cache_dirs)

    print()
    print(text_blocks.headline("Workspace Disk Usage", width=display_settings.default_width(80)))

    table_kwargs = display_settings.apply_table_defaults({"compact": True, "accent_first_column": True})

    # Storage: high-level footprint.
    menu_utils.print_section("Storage")
    storage_rows: list[list[str]] = [
        ["APK storage", str(apks_dir)],
        ["APK files", f"{len(apk_files)}"],
        ["APK size", _humanize_bytes(apks_size)],
        ["Receipts dir", str(receipts_dir)],
        ["Receipts size", _humanize_bytes(_dir_size_bytes(receipts_dir))],
        ["Logs dir", str(logs_dir)],
        ["Logs size", _humanize_bytes(logs_size)],
        ["Output dir", str(output_dir)],
        ["Output size", _humanize_bytes(_dir_size_bytes(output_dir))],
    ]
    table_utils.render_table(["Item", "Value"], storage_rows, **table_kwargs)

    # Evidence: dataset-critical growth areas.
    dyn_evidence = output_dir / "evidence" / "dynamic"
    static_runs_output = output_dir / "evidence" / "static_runs"
    static_runs_legacy = Path("evidence") / "static_runs"
    static_runs = static_runs_output if static_runs_output.exists() else static_runs_legacy
    batches_dir = output_dir / "batches"

    menu_utils.print_section("Evidence")
    evidence_rows: list[list[str]] = [
        ["Dynamic evidence packs", f"{_count_dirs(dyn_evidence)} run(s)"],
        ["Dynamic evidence size", _humanize_bytes(_dir_size_bytes(dyn_evidence))],
        ["Static evidence root", str(static_runs)],
        ["Static runs (evidence)", f"{_count_dirs(static_runs)} run(s)"],
        ["Static evidence size", _humanize_bytes(_dir_size_bytes(static_runs))],
        ["Batch JSON outputs", f"{_count_files(batches_dir, pattern='**/*.json')}"],
        ["Batch output size", _humanize_bytes(_dir_size_bytes(batches_dir))],
    ]
    if static_runs_output.exists() and static_runs_legacy.exists() and static_runs_output != static_runs_legacy:
        evidence_rows.append(["Static runs (output)", f"{_count_dirs(static_runs_output)} run(s)"])
        evidence_rows.append(["Static runs (legacy)", f"{_count_dirs(static_runs_legacy)} run(s)"])
    table_utils.render_table(["Item", "Value"], evidence_rows, **table_kwargs)

    # Inventory: should be bounded by retention (Phase A).
    menu_utils.print_section("Inventory")
    state_dir = Path(app_config.DATA_DIR) / "state"
    inv_dir: Path | None = None
    try:
        serial_dirs = sorted([p for p in state_dir.iterdir() if p.is_dir()])
        if serial_dirs:
            inv_dir = serial_dirs[0] / "inventory"
    except OSError:
        inv_dir = None
    inv_rows: list[list[str]] = []
    if inv_dir and inv_dir.exists():
        inv_snapshots = [
            p
            for p in inv_dir.glob("inventory_*.json")
            if p.is_file() and not p.name.endswith(".meta.json")
        ]
        inv_meta = [p for p in inv_dir.glob("inventory_*.meta.json") if p.is_file()]
        latest_ptr = inv_dir / "latest.json"
        latest_meta = inv_dir / "latest.meta.json"
        inv_rows.extend(
            [
                ["Inventory snapshots (fs)", f"{len(inv_snapshots)} (policy N=5)"],
                ["Inventory snapshot meta", f"{len(inv_meta)}"],
                ["Inventory latest pointer", "yes" if latest_ptr.exists() else "no"],
                ["Inventory latest meta", "yes" if latest_meta.exists() else "no"],
                ["Inventory dir", str(inv_dir)],
            ]
        )
    else:
        inv_rows.append(["Inventory", "—"])
    table_utils.render_table(["Item", "Value"], inv_rows, **table_kwargs)

    # Caches: rarely needed for dataset collection, but useful for disk pressure.
    menu_utils.print_section("Caches")
    cache_rows: list[list[str]] = []
    for p in cache_dirs:
        cache_rows.append([str(p), _humanize_bytes(_dir_size_bytes(p))])
    cache_rows.append(["Total", _humanize_bytes(cache_size)])
    table_utils.render_table(["Cache", "Size"], cache_rows, **table_kwargs)

    print()
    print(text_blocks.headline("Cleanup hints", width=display_settings.default_width(80)))
    hints: list[str] = []
    dyn_size = _dir_size_bytes(dyn_evidence)
    if dyn_size > 5 * 1024 * 1024 * 1024:
        hints.append(
            "Dynamic evidence is large: consider cleanup of invalid/ghost runs (Evidence & Workspace -> Cleanup dynamic evidence workspace)."
        )
    if cache_size > 1024 * 1024 * 1024:
        hints.append("Caches exceed 1GB: clear output cache if disk space is tight.")
    if static_runs_legacy.exists() and not static_runs_output.exists():
        hints.append("Static evidence is stored under legacy path evidence/static_runs (this is OK).")
    if inv_dir and inv_dir.exists():
        inv_snapshots = [
            p
            for p in inv_dir.glob("inventory_*.json")
            if p.is_file() and not p.name.endswith(".meta.json")
        ]
        if len(inv_snapshots) > 5:
            hints.append("Inventory snapshots exceed expected retention: verify retention is running on sync.")
    if not hints:
        hints.append("No cleanup actions suggested.")
    for line in hints:
        print(status_messages.status(line, level="info"))
    prompt_utils.press_enter_to_continue()


def _show_dashboard() -> None:
    """Print a compact, operator-facing dashboard for dataset collection."""

    output_dir = Path(app_config.OUTPUT_DIR)
    dyn_root = output_dir / "evidence" / "dynamic"
    packs = _count_dirs(dyn_root)
    dyn_size = _dir_size_bytes(dyn_root)

    # Dataset app coverage: which apps have >=1 run on disk.
    dataset_pkgs: list[str] = []
    try:
        from scytaledroid.DynamicAnalysis.profile_loader import load_profile_packages

        dataset_pkgs = [p for p in load_profile_packages("RESEARCH_DATASET_ALPHA") if str(p).strip()]
    except Exception:
        dataset_pkgs = []
    dataset_set = {p.strip() for p in dataset_pkgs}

    # Best-effort DB label enrichment (optional).
    labels: dict[str, str] = {}
    if dataset_set:
        try:
            from scytaledroid.Database.db_core import run_sql

            placeholders = ",".join(["%s"] * len(dataset_set))
            sql = f"SELECT package_name, display_name FROM apps WHERE package_name IN ({placeholders})"
            rows = run_sql(sql, tuple(sorted(dataset_set)), fetch="all", dictionary=True)
            for row in rows or []:
                pkg = str(row.get("package_name") or "").strip()
                name = str(row.get("display_name") or "").strip()
                if pkg and name:
                    labels[pkg] = name
        except Exception:
            labels = {}

    # Scan manifests to compute collection progress (DB-free).
    per_app: dict[str, dict[str, int]] = {}
    if dyn_root.exists():
        for mf in dyn_root.glob("*/run_manifest.json"):
            try:
                payload = json.loads(mf.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue
            target = payload.get("target") or {}
            pkg = target.get("package_name") if isinstance(target, dict) else None
            if not isinstance(pkg, str) or not pkg.strip():
                continue
            pkg = pkg.strip()
            if dataset_set and pkg not in dataset_set:
                continue
            ds = payload.get("dataset") if isinstance(payload.get("dataset"), dict) else {}
            op = payload.get("operator") if isinstance(payload.get("operator"), dict) else {}
            countable = ds.get("countable")
            if countable is False:
                continue
            valid = ds.get("valid_dataset_run")
            prof = str(op.get("run_profile") or "").lower()

            rec = per_app.setdefault(
                pkg,
                {
                    "runs": 0,
                    "valid": 0,
                    "baseline": 0,
                    "interactive": 0,
                },
            )
            rec["runs"] += 1
            if valid is True:
                rec["valid"] += 1
                if "baseline" in prof or "idle" in prof:
                    rec["baseline"] += 1
                elif "interactive" in prof:
                    rec["interactive"] += 1

    baseline_required = 1
    interactive_required = 2
    valid_required = 3
    try:
        from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig

        cfg = DatasetTrackerConfig()
        baseline_required = int(cfg.baseline_required)
        interactive_required = int(cfg.interactive_required)
        valid_required = baseline_required + interactive_required
    except Exception:
        pass

    apps_total = len(dataset_set) if dataset_set else len(per_app)
    apps_with_runs = len(per_app)
    complete = [
        pkg
        for pkg, stats in per_app.items()
        if stats.get("valid", 0) >= valid_required
    ]
    need_base = [
        pkg
        for pkg, stats in per_app.items()
        if stats.get("baseline", 0) < baseline_required
    ]
    need_inter = [
        pkg
        for pkg, stats in per_app.items()
        if stats.get("baseline", 0) >= baseline_required
        and stats.get("interactive", 0) < interactive_required
    ]

    def _fmt_pkg_list(pkgs: list[str], limit: int = 6) -> str:
        if not pkgs:
            return "—"
        out = [labels.get(p, p) for p in pkgs[:limit]]
        suffix = " ..." if len(pkgs) > limit else ""
        return ", ".join(out) + suffix

    print()
    print(text_blocks.headline("Collection Dashboard", width=display_settings.default_width(80)))
    print(f"Dynamic evidence: {packs} pack(s), {_humanize_bytes(dyn_size)}")
    if apps_total:
        print(f"Dataset apps with runs: {apps_with_runs}/{apps_total}")
        print(f"Complete (>= {valid_required} valid): {len(complete)}/{apps_total}")
        total_valid = sum(int(stats.get("valid", 0) or 0) for stats in per_app.values())
        target_valid = int(apps_total) * int(valid_required)
        remaining = max(0, target_valid - total_valid)
        print(f"Valid runs collected: {total_valid}/{target_valid} (remaining {remaining})")
    if need_base:
        print("baseline needed -> " + _fmt_pkg_list(sorted(need_base)))
    if need_inter:
        print("interactive needed -> " + _fmt_pkg_list(sorted(need_inter)))


def workspace_menu() -> None:
    """Render the workspace maintenance menu."""

    shown_dashboard = False
    while True:
        print()
        if not shown_dashboard:
            _show_dashboard()
            shown_dashboard = True
        print()
        menu_utils.print_header("Evidence & Workspace")
        menu_utils.print_hint(
            "Verify evidence packs, inspect app run coverage, and maintain derived indexes without changing authoritative artifacts."
        )
        menu_utils.print_section("Actions")
        items = [
            menu_utils.MenuOption("1", "Show workspace usage"),
            menu_utils.MenuOption("2", "Verify evidence packs (overview)"),
            menu_utils.MenuOption("3", "Quick health check (packs/missing/bad + PCAP sizes)"),
            menu_utils.MenuOption("4", "View app runs (details)"),
            menu_utils.MenuOption("5", "Recompute dataset tracker (from evidence packs)"),
            menu_utils.MenuOption("6", "Rebuild DB index from evidence packs (derived)"),
            menu_utils.MenuOption("7", "Network audit report (trends)"),
            menu_utils.MenuOption("8", "Cleanup dynamic evidence workspace (safe)"),
            menu_utils.MenuOption("9", "Deep checks (DB vs manifest + transport + indicator quality)"),
            menu_utils.MenuOption("10", "Prune derived dynamic DB orphans (safe)"),
            menu_utils.MenuOption("11", "Clear dangling dynamic/static DB links (safe)"),
            menu_utils.MenuOption("12", "Prune orphan artifact registry rows (safe)"),
        ]
        spec_kwargs = display_settings.apply_menu_defaults(
            {"items": items, "exit_label": "Back", "show_exit": True}
        )
        menu_utils.render_menu(menu_utils.MenuSpec(**spec_kwargs))
        choice = prompt_utils.get_choice(
            menu_utils.selectable_keys(items, include_exit=True),
            default="1",
            disabled=[opt.key for opt in items if opt.disabled],
        )

        if choice == "0":
            break
        if choice == "1":
            _show_summary()
        elif choice == "2":
            from scytaledroid.DynamicAnalysis.tools.evidence.menu import evidence_verify_overview

            evidence_verify_overview(pause=True)
        elif choice == "3":
            from scytaledroid.DynamicAnalysis.tools.evidence.menu import evidence_quick_health_check

            evidence_quick_health_check(pause=True)
        elif choice == "4":
            from scytaledroid.DynamicAnalysis.tools.evidence.menu import evidence_view_app_runs

            evidence_view_app_runs(pause=True)
        elif choice == "5":
            from scytaledroid.DynamicAnalysis.tools.evidence.menu import (
                evidence_recompute_dataset_tracker,
            )

            evidence_recompute_dataset_tracker(pause=True)
        elif choice == "6":
            from scytaledroid.DynamicAnalysis.storage.index_from_evidence import (
                index_dynamic_evidence_packs_to_db,
            )

            root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
            print()
            menu_utils.print_header("Rebuild DB Index From Evidence Packs")
            print(status_messages.status("DB is a derived index. Evidence packs remain authoritative.", level="info"))
            if not prompt_utils.prompt_yes_no("Rebuild DB index now?", default=True):
                prompt_utils.press_enter_to_continue()
                continue
            res = index_dynamic_evidence_packs_to_db(root)
            print(status_messages.status(f"Scanned={res.get('scanned')} ok={res.get('ok')}", level="success"))
            if res.get("errors"):
                print(status_messages.status(f"Errors (sample): {', '.join(res.get('errors') or [])}", level="warn"))
            prompt_utils.press_enter_to_continue()
        elif choice == "7":
            from scytaledroid.DynamicAnalysis.tools.evidence.menu import (
                evidence_network_audit_report,
            )

            evidence_network_audit_report(pause=True)
        elif choice == "8":
            from scytaledroid.DynamicAnalysis.tools.evidence.menu import evidence_cleanup_workspace

            evidence_cleanup_workspace(pause=True)
        elif choice == "9":
            from scytaledroid.DynamicAnalysis.tools.evidence.menu import evidence_deep_checks

            evidence_deep_checks(pause=True)
        elif choice == "10":
            _prune_dynamic_db_orphans()
        elif choice == "11":
            _clear_dangling_dynamic_static_links()
        elif choice == "12":
            _prune_artifact_registry_orphans()
        else:
            print(status_messages.status("Option not available yet.", level="warn"))
            prompt_utils.press_enter_to_continue()


def _prune_dynamic_db_orphans() -> None:
    """Delete dynamic_sessions rows whose evidence_path no longer exists locally."""
    from pathlib import Path

    from scytaledroid.DynamicAnalysis.storage.db_maintenance import (
        delete_dynamic_sessions_by_id,
        find_dynamic_db_orphans,
    )

    print()
    menu_utils.print_header("Prune Derived Dynamic DB Orphans")
    print(status_messages.status("DB is a derived index. Evidence packs remain authoritative.", level="info"))
    repo_root = Path.cwd()
    orphans = find_dynamic_db_orphans(repo_root=repo_root)
    if not orphans:
        print(status_messages.status("No DB orphans found.", level="success"))
        prompt_utils.press_enter_to_continue()
        return
    print(status_messages.status(f"Orphans found: {len(orphans)}", level="warn"))
    # Show a compact sample for operator confidence.
    for o in orphans[:10]:
        rid = str(o.get("dynamic_run_id") or "")[:8]
        pkg = str(o.get("package_name") or "")
        reason = str(o.get("reason") or "")
        path = str(o.get("evidence_path") or "")
        print(status_messages.status(f"- {rid} {pkg} ({reason}) path={path}", level="warn"))
    if len(orphans) > 10:
        print(status_messages.status(f"... and {len(orphans) - 10} more", level="info"))

    if not prompt_utils.prompt_yes_no("Delete these orphan DB rows now? (cascades to derived tables)", default=False):
        print(status_messages.status("Cancelled.", level="info"))
        prompt_utils.press_enter_to_continue()
        return
    ids = [str(o.get("dynamic_run_id") or "") for o in orphans if str(o.get("dynamic_run_id") or "").strip()]
    deleted = delete_dynamic_sessions_by_id(ids)
    print(status_messages.status(f"Deleted {deleted} dynamic_sessions row(s).", level="success"))
    prompt_utils.press_enter_to_continue()


def _clear_dangling_dynamic_static_links() -> None:
    """Null dynamic-session static_run_id values that no longer resolve."""

    from scytaledroid.DynamicAnalysis.storage.db_maintenance import (
        clear_dangling_dynamic_static_links,
        find_dangling_dynamic_static_links,
    )

    print()
    menu_utils.print_header("Clear Dangling Dynamic/Static Links")
    print(status_messages.status("DB is a derived index. Evidence packs remain authoritative.", level="info"))
    rows = find_dangling_dynamic_static_links()
    if not rows:
        print(status_messages.status("No dangling dynamic/static links found.", level="success"))
        prompt_utils.press_enter_to_continue()
        return

    print(status_messages.status(f"Dangling links found: {len(rows)}", level="warn"))
    sample_rows = [
        [
            str(row.get("dynamic_run_id") or "")[:8],
            str(row.get("package_name") or ""),
            str(row.get("static_run_id") or "—"),
            "Y" if row.get("static_handoff_hash") else "N",
        ]
        for row in rows[:10]
    ]
    table_utils.render_table(
        ["dynamic_run_id", "package_name", "static_run_id", "handoff_hash"],
        sample_rows,
        compact=True,
    )
    if len(rows) > 10:
        print(status_messages.status(f"... and {len(rows) - 10} more", level="info"))

    if not prompt_utils.prompt_yes_no("Null these dangling static_run_id links now?", default=False):
        print(status_messages.status("Cancelled.", level="info"))
        prompt_utils.press_enter_to_continue()
        return

    repaired = clear_dangling_dynamic_static_links(
        [str(row.get("dynamic_run_id") or "") for row in rows if str(row.get("dynamic_run_id") or "").strip()]
    )
    print(status_messages.status(f"Cleared dangling static_run_id on {repaired} dynamic run(s).", level="success"))
    prompt_utils.press_enter_to_continue()


def _prune_artifact_registry_orphans() -> None:
    """Delete artifact_registry rows whose linked run no longer resolves."""

    from scytaledroid.DynamicAnalysis.storage.db_maintenance import (
        delete_artifact_registry_rows,
        find_artifact_registry_orphans,
    )

    print()
    menu_utils.print_header("Prune Orphan Artifact Registry Rows")
    print(status_messages.status("DB is a derived index. Evidence packs remain authoritative.", level="info"))
    rows = find_artifact_registry_orphans()
    if not rows:
        print(status_messages.status("No orphan artifact_registry rows found.", level="success"))
        prompt_utils.press_enter_to_continue()
        return

    dynamic_rows = [row for row in rows if str(row.get("run_type") or "") == "dynamic"]
    static_rows = [row for row in rows if str(row.get("run_type") or "") == "static"]
    print(
        status_messages.status(
            f"Orphan artifact rows found: total={len(rows)} dynamic={len(dynamic_rows)} static={len(static_rows)}",
            level="warn",
        )
    )
    sample_rows = [
        [
            str(row.get("artifact_id") or "—"),
            str(row.get("run_type") or "—"),
            str(row.get("artifact_type") or "—"),
            str(row.get("link_state") or "—"),
            str(row.get("run_id") or "—")[:12],
        ]
        for row in rows[:10]
    ]
    table_utils.render_table(
        ["artifact_id", "run_type", "artifact_type", "link_state", "run_id"],
        sample_rows,
        compact=True,
    )
    if len(rows) > 10:
        print(status_messages.status(f"... and {len(rows) - 10} more", level="info"))

    if not prompt_utils.prompt_yes_no("Delete these orphan artifact_registry rows now?", default=False):
        print(status_messages.status("Cancelled.", level="info"))
        prompt_utils.press_enter_to_continue()
        return

    artifact_ids = [int(row["artifact_id"]) for row in rows if row.get("artifact_id") is not None]
    deleted = delete_artifact_registry_rows(artifact_ids)
    print(status_messages.status(f"Deleted {deleted} artifact_registry row(s).", level="success"))
    prompt_utils.press_enter_to_continue()


__all__ = ["workspace_menu"]
