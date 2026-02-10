"""Workspace maintenance & cleanup menu."""

from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Config import app_config
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
    apks_dir = data_dir / "device_apks"
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
            "Dynamic evidence is large: consider cleanup of invalid/ghost runs (Workspace & Evidence -> Cleanup dynamic evidence workspace)."
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
        menu_utils.print_header("Workspace & Evidence Options")
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
            menu_utils.MenuOption("11", "Prune legacy ML artifacts on disk (safe)"),
        ]
        spec_kwargs = display_settings.apply_menu_defaults(
            {"items": items, "exit_label": "Back", "show_exit": True}
        )
        menu_utils.render_menu(menu_utils.MenuSpec(**spec_kwargs))
        choice = prompt_utils.get_choice([opt.key for opt in items] + ["0"], default="1")

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
            _prune_legacy_ml_artifacts()
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


def _prune_legacy_ml_artifacts() -> None:
    """Remove legacy ML outputs that are redundant with canonical `analysis/ml/v1` artifacts.

    Safe deletion rules:
    - Remove `analysis/ml_provisional/...` only when `analysis/ml/v1/ml_summary.json` exists.
    - Remove legacy score CSV filenames under `analysis/ml/v1/` only when canonical files exist.
    """
    import shutil

    print()
    menu_utils.print_header("Prune Legacy ML Artifacts")
    print(status_messages.status("This deletes redundant legacy files on disk; it does not recompute ML.", level="info"))

    root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    if not root.exists():
        print(status_messages.status(f"No dynamic evidence root: {root}", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    dirs_to_delete: list[Path] = []
    files_to_delete: list[Path] = []

    # Canonical v1 marker.
    def _has_canonical_v1(run_dir: Path) -> bool:
        return (run_dir / "analysis" / "ml" / "v1" / "ml_summary.json").exists()

    for run_dir in sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name):
        if not _has_canonical_v1(run_dir):
            continue

        legacy_dir = run_dir / "analysis" / "ml_provisional"
        if legacy_dir.exists():
            dirs_to_delete.append(legacy_dir)

        v1_dir = run_dir / "analysis" / "ml" / "v1"
        if not v1_dir.exists():
            continue

        # Legacy filenames kept for back-compat; safe to remove when canonical exists.
        canon_if = v1_dir / "anomaly_scores_iforest.csv"
        canon_oc = v1_dir / "anomaly_scores_ocsvm.csv"
        if canon_if.exists():
            legacy_if = v1_dir / "anomaly_scores_isolation_forest.csv"
            if legacy_if.exists():
                files_to_delete.append(legacy_if)
        if canon_oc.exists():
            legacy_oc = v1_dir / "anomaly_scores_one_class_svm.csv"
            if legacy_oc.exists():
                files_to_delete.append(legacy_oc)

    if not dirs_to_delete and not files_to_delete:
        print(status_messages.status("No legacy ML artifacts found to prune.", level="success"))
        prompt_utils.press_enter_to_continue()
        return

    bytes_dirs = sum(_dir_size_bytes(p) for p in dirs_to_delete if p.exists())
    bytes_files = sum(p.stat().st_size for p in files_to_delete if p.exists())
    print(
        status_messages.status(
            f"Will delete: {len(dirs_to_delete)} legacy dir(s), {len(files_to_delete)} legacy file(s) "
            f"({ _humanize_bytes(int(bytes_dirs + bytes_files)) } total).",
            level="warn",
        )
    )
    if dirs_to_delete:
        print(status_messages.status(f"- dirs: {len(dirs_to_delete)} (e.g., {dirs_to_delete[0]})", level="info"))
    if files_to_delete:
        print(status_messages.status(f"- files: {len(files_to_delete)} (e.g., {files_to_delete[0]})", level="info"))

    if not prompt_utils.prompt_yes_no("Delete these legacy ML artifacts now?", default=False):
        print(status_messages.status("Cancelled.", level="info"))
        prompt_utils.press_enter_to_continue()
        return

    deleted_dirs = 0
    deleted_files = 0
    for p in files_to_delete:
        try:
            if p.exists():
                p.unlink()
                deleted_files += 1
        except OSError:
            continue
    for p in dirs_to_delete:
        try:
            if p.exists():
                shutil.rmtree(p)
                deleted_dirs += 1
        except OSError:
            continue

    print(status_messages.status(f"Deleted legacy ML: dirs={deleted_dirs} files={deleted_files}", level="success"))
    prompt_utils.press_enter_to_continue()


__all__ = ["workspace_menu"]
