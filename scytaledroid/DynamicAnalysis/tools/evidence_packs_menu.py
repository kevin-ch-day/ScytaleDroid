"""Operator menu for managing dynamic evidence packs.

This is primarily used during dataset collection to:
- Verify evidence packs are complete and ML-ready.
- Repair legacy manifests.
- Clean up local invalid runs to keep the workspace tidy.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def _dynamic_evidence_root() -> Path:
    return Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"


def _safe_rmtree(path: Path, *, root: Path) -> bool:
    try:
        resolved = path.resolve()
        root_resolved = root.resolve()
        if root_resolved not in resolved.parents:
            return False
        shutil.rmtree(resolved)
        return True
    except Exception:
        return False


def _read_json(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _load_app_labels(packages: set[str]) -> dict[str, str]:
    if not packages:
        return {}
    try:
        from scytaledroid.Database.db_core import run_sql
    except Exception:
        return {}
    try:
        placeholders = ",".join(["%s"] * len(packages))
        sql = f"SELECT package_name, display_name FROM apps WHERE package_name IN ({placeholders})"
        rows = run_sql(sql, tuple(sorted(packages)), fetch="all", dictionary=True)
    except Exception:
        return {}
    mapping: dict[str, str] = {}
    for row in rows or []:
        pkg = str(row.get("package_name") or "").strip()
        name = str(row.get("display_name") or "").strip()
        if pkg and name:
            mapping[pkg] = name
    return mapping


def _list_run_manifests(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(root.glob("*/run_manifest.json"))


def _runs_for_package(root: Path, package_name: str) -> list[dict]:
    runs: list[dict] = []
    for mf in _list_run_manifests(root):
        m = _read_json(mf) or {}
        target = m.get("target") or {}
        pkg = target.get("package_name") if isinstance(target, dict) else None
        if str(pkg or "").strip() != package_name:
            continue
        ds = m.get("dataset") if isinstance(m.get("dataset"), dict) else {}
        op = m.get("operator") if isinstance(m.get("operator"), dict) else {}
        rid = str(m.get("dynamic_run_id") or mf.parent.name)
        runs.append(
            {
                "run_id": rid,
                "ended_at": str(m.get("ended_at") or ""),
                "run_profile": str(op.get("run_profile") or ""),
                "interaction_level": str(op.get("interaction_level") or ""),
                "messaging_activity": str(op.get("messaging_activity") or ""),
                "valid": ds.get("valid_dataset_run"),
                "reason": ds.get("invalid_reason_code"),
                "countable": ds.get("countable"),
                "sampling_s": ds.get("sampling_duration_seconds"),
                "pcap_size_bytes": ds.get("pcap_size_bytes") or None,
            }
        )
    # ended_at is iso, sort descending when possible; fallback by run_id
    return sorted(runs, key=lambda r: (r.get("ended_at") or "", r.get("run_id") or ""), reverse=True)


def _render_app_runs(root: Path, display_name: str, package_name: str, runs: list[dict]) -> None:
    print()
    menu_utils.print_header(f"{display_name}", subtitle=package_name)
    if not runs:
        print(status_messages.status("No runs found.", level="info"))
        return
    # Compact table with reasons (this is the drilldown view).
    headers = ["#", "Run", "Ended", "Profile", "Interact", "Msg", "Valid", "Reason"]
    rows = []
    for idx, r in enumerate(runs, start=1):
        valid = r.get("valid")
        valid_label = "VALID" if valid is True else ("INVALID" if valid is False else "—")
        reason = r.get("reason") or "—"
        rows.append(
            [
                str(idx),
                str(r.get("run_id") or "")[:8],
                str(r.get("ended_at") or "")[:19] or "—",
                str(r.get("run_profile") or "") or "—",
                str(r.get("interaction_level") or "") or "—",
                str(r.get("messaging_activity") or "") or "—",
                valid_label,
                reason,
            ]
        )
    # Use the shared table renderer for consistent formatting.
    from scytaledroid.Utils.DisplayUtils import table_utils, display_settings

    table_kwargs = display_settings.apply_table_defaults({"compact": True, "accent_first_column": True})
    table_utils.render_table(headers, rows, **table_kwargs)


def evidence_packs_menu() -> None:
    while True:
        print()
        menu_utils.print_header("Dynamic Evidence Packs")
        items = [
            menu_utils.MenuOption("1", "Verify evidence packs (recommended)"),
            menu_utils.MenuOption("2", "View app runs (details)"),
            menu_utils.MenuOption("3", "Delete INVALID dataset runs (local only)"),
            menu_utils.MenuOption("4", "Repair legacy manifests (dataset block)"),
            menu_utils.MenuOption("5", "Recompute dataset tracker (from evidence packs)"),
        ]
        menu_utils.render_menu(menu_utils.MenuSpec(items=items, exit_label="Back", show_exit=True))
        choice = prompt_utils.get_choice([opt.key for opt in items] + ["0"], default="1")
        if choice == "0":
            break

        if choice == "1":
            from scytaledroid.DynamicAnalysis.tools.evidence_verify_cli import run_dynamic_evidence_verify

            print()
            # Main view stays compact; drilldown shows reason codes.
            run_dynamic_evidence_verify(enrich_db_labels=True, show_reason_column=False)
            prompt_utils.press_enter_to_continue()
            continue

        if choice == "2":
            root = _dynamic_evidence_root()
            manifests = _list_run_manifests(root)
            packages = set()
            for mf in manifests:
                m = _read_json(mf) or {}
                target = m.get("target") or {}
                pkg = target.get("package_name") if isinstance(target, dict) else None
                if isinstance(pkg, str) and pkg.strip():
                    packages.add(pkg.strip())
            if not packages:
                print(status_messages.status("No runs available.", level="warn"))
                prompt_utils.press_enter_to_continue()
                continue
            labels = _load_app_labels(packages)
            app_list = sorted([(labels.get(p, p), p) for p in packages], key=lambda x: x[0].lower())

            print()
            menu_utils.print_header("Select App", "View runs and reasons")
            from scytaledroid.Utils.DisplayUtils import table_utils, display_settings

            rows = [[str(i + 1), name] for i, (name, _pkg) in enumerate(app_list)]
            table_kwargs = display_settings.apply_table_defaults({"compact": True, "accent_first_column": True})
            table_utils.render_table(["#", "App"], rows, **table_kwargs)

            options = [str(i) for i in range(1, len(app_list) + 1)]
            sel = prompt_utils.get_choice(options + ["0"], default="1", prompt="Select app # ")
            if sel == "0":
                continue
            idx = int(sel) - 1
            display_name, pkg = app_list[idx]
            runs = _runs_for_package(root, pkg)
            _render_app_runs(root, display_name, pkg, runs)

            print()
            items2 = [
                menu_utils.MenuOption("D", "Delete a run (local)"),
                menu_utils.MenuOption("X", "Delete INVALID runs for this app (local)"),
            ]
            menu_utils.render_menu(menu_utils.MenuSpec(items=items2, exit_label="Back", show_exit=True))
            action = prompt_utils.get_choice([opt.key for opt in items2] + ["0"], default="0")
            if action == "0":
                continue
            if action == "D":
                choice_run = prompt_utils.prompt_text("Run # to delete", required=False).strip()
                try:
                    ri = int(choice_run)
                except Exception:
                    continue
                if ri < 1 or ri > len(runs):
                    continue
                run_id = str(runs[ri - 1].get("run_id") or "")
                if not run_id:
                    continue
                confirm = prompt_utils.prompt_text("Type DELETE to confirm", required=False).strip()
                if confirm != "DELETE":
                    continue
                ok = _safe_rmtree(root / run_id, root=root)
                print(status_messages.status("Deleted." if ok else "Delete failed.", level="success" if ok else "error"))
            elif action == "X":
                invalid = [r for r in runs if r.get("valid") is False]
                if not invalid:
                    print(status_messages.status("No INVALID runs for this app.", level="info"))
                    prompt_utils.press_enter_to_continue()
                    continue
                confirm = prompt_utils.prompt_text("Type DELETE to confirm", required=False).strip()
                if confirm != "DELETE":
                    continue
                deleted = 0
                for r in invalid:
                    run_id = str(r.get("run_id") or "")
                    if run_id and _safe_rmtree(root / run_id, root=root):
                        deleted += 1
                print(status_messages.status(f"Deleted {deleted} INVALID run(s).", level="success"))

            from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import recompute_dataset_tracker

            recompute_dataset_tracker()
            prompt_utils.press_enter_to_continue()
            continue

        if choice == "3":
            root = _dynamic_evidence_root()
            from scytaledroid.DynamicAnalysis.tools.evidence_verify_cli import run_dynamic_evidence_verify

            # Generate a report payload without writing a new JSON file just for deletion.
            report = run_dynamic_evidence_verify(write_json=False, enrich_db_labels=True, show_reason_column=True)
            invalid = [
                r
                for r in (report.get("packs") or [])
                if isinstance(r, dict)
                and r.get("valid_dataset_run") is False
                and (r.get("countable") is not False)
            ]
            if not invalid:
                print(status_messages.status("No INVALID dataset runs found to delete.", level="info"))
                prompt_utils.press_enter_to_continue()
                continue

            print()
            print(status_messages.status(f"INVALID runs to delete: {len(invalid)}", level="warn"))
            for row in invalid:
                rid = str(row.get("run_id") or "")[:8]
                name = str(row.get("display_name") or row.get("package_name") or "_unknown")
                reason = str(row.get("invalid_reason_code") or "UNKNOWN")
                print(status_messages.status(f"{rid} {name} INVALID:{reason}", level="warn"))

            confirm = prompt_utils.prompt_text(
                "Type DELETE to confirm deletion of these local evidence packs",
                required=False,
            ).strip()
            if confirm != "DELETE":
                print(status_messages.status("Cancelled.", level="info"))
                prompt_utils.press_enter_to_continue()
                continue

            deleted = 0
            failed = 0
            for row in invalid:
                run_id = str(row.get("run_id") or "")
                if not run_id:
                    continue
                ok = _safe_rmtree(root / run_id, root=root)
                if ok:
                    deleted += 1
                else:
                    failed += 1
            print(status_messages.status(f"Deleted {deleted} run(s). Failed {failed}.", level="success"))

            # Keep the derived tracker in sync.
            from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import recompute_dataset_tracker

            recompute_dataset_tracker()
            prompt_utils.press_enter_to_continue()
            continue

        if choice == "4":
            from scytaledroid.DynamicAnalysis.tools.manifest_repair import backfill_dataset_block

            root = _dynamic_evidence_root()
            print()
            print(status_messages.status("Repair will update run_manifest.json files in-place.", level="warn"))
            proceed = prompt_utils.confirm("Proceed?", default=False)
            if not proceed:
                continue
            result = backfill_dataset_block(root, dry_run=False)
            print(
                status_messages.status(
                    f"Repair complete: scanned={result.scanned} repaired={result.repaired} skipped={result.skipped} errors={result.errors}",
                    level="success",
                )
            )
            prompt_utils.press_enter_to_continue()
            continue

        if choice == "5":
            from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import recompute_dataset_tracker

            path = recompute_dataset_tracker()
            if path:
                print(status_messages.status(f"Tracker rebuilt: {path}", level="success"))
            else:
                print(status_messages.status("No tracker written (no evidence packs found).", level="warn"))
            prompt_utils.press_enter_to_continue()
            continue


__all__ = ["evidence_packs_menu"]
