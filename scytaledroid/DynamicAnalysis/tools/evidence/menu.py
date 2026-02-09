"""Operator menu for managing dynamic evidence packs.

This is primarily used during dataset collection to:
- Verify evidence packs are complete and ML-ready.
- Clean up local invalid runs to keep the workspace tidy.
"""

from __future__ import annotations

import os
import json
import shutil
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def _dynamic_evidence_root() -> Path:
    return Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"

def _canonical_paper2_freeze_anchor_path() -> Path:
    # Paper #2 citation anchor (PM/reviewer locked).
    return Path(app_config.DATA_DIR) / "archive" / "dataset_freeze-20260208T201527Z.json"


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

def _load_freeze_included_ids(*, freeze_path: Path) -> set[str] | None:
    payload = _read_json(freeze_path)
    if not isinstance(payload, dict):
        return None
    ids = payload.get("included_run_ids")
    checksums = payload.get("included_run_checksums")
    if not isinstance(ids, list) or not isinstance(checksums, dict) or not checksums:
        return None
    out: set[str] = set()
    for rid in ids:
        if isinstance(rid, str) and rid.strip():
            out.add(rid.strip())
    return out or None


def _cleanup_dynamic_workspace(
    *,
    evidence_root: Path,
    freeze_included: set[str] | None,
    delete_ghost_dirs: bool,
    delete_invalid_runs: bool,
    delete_out_of_dataset_valid_runs: bool,
    purge_dynamic_batch_outputs: bool,
) -> dict[str, object]:
    """Delete local-only workspace artifacts without touching the frozen dataset."""
    deleted = {"ghost_dirs": 0, "invalid_runs": 0, "extra_valid_runs": 0, "batch_reports": 0}
    kept = {"frozen": 0, "valid_in_dataset": 0, "valid_out_of_dataset": 0}
    errors: list[str] = []

    # Evidence dirs
    if evidence_root.exists():
        for run_dir in sorted([p for p in evidence_root.iterdir() if p.is_dir()]):
            mf = run_dir / "run_manifest.json"
            if not mf.exists():
                if delete_ghost_dirs:
                    if _safe_rmtree(run_dir, root=evidence_root):
                        deleted["ghost_dirs"] += 1
                    else:
                        errors.append(f"failed_delete_ghost:{run_dir.name}")
                continue

            m = _read_json(mf) or {}
            rid = str(m.get("dynamic_run_id") or run_dir.name)
            ds = m.get("dataset") if isinstance(m.get("dataset"), dict) else {}
            tier = str(ds.get("tier") or "").lower()
            valid = ds.get("valid_dataset_run")

            if freeze_included and rid in freeze_included:
                kept["frozen"] += 1
                kept["valid_in_dataset"] += 1 if valid is True else 0
                continue

            if delete_invalid_runs and tier == "dataset" and valid is False:
                if _safe_rmtree(run_dir, root=evidence_root):
                    deleted["invalid_runs"] += 1
                else:
                    errors.append(f"failed_delete_invalid:{rid}")
                continue

            if delete_out_of_dataset_valid_runs and tier == "dataset" and valid is True:
                if _safe_rmtree(run_dir, root=evidence_root):
                    deleted["extra_valid_runs"] += 1
                else:
                    errors.append(f"failed_delete_extra_valid:{rid}")
                continue

            if tier == "dataset" and valid is True:
                kept["valid_out_of_dataset"] += 1

    # Batch outputs (purely derived)
    if purge_dynamic_batch_outputs:
        dyn_batches = Path(app_config.OUTPUT_DIR) / "batches" / "dynamic"
        if dyn_batches.exists():
            for p in sorted(dyn_batches.iterdir()):
                if p.is_file():
                    try:
                        p.unlink()
                        deleted["batch_reports"] += 1
                    except Exception:
                        errors.append(f"failed_unlink:{p}")
                elif p.is_dir():
                    # Derived outputs only; safe to remove.
                    try:
                        shutil.rmtree(p, ignore_errors=True)
                        deleted["batch_reports"] += 1
                    except Exception:
                        errors.append(f"failed_rmtree:{p}")

    return {"deleted": deleted, "kept": kept, "errors": errors}


def evidence_cleanup_workspace(*, pause: bool = True) -> None:
    """Operator-facing cleanup for dynamic evidence workspace (safe)."""
    root = _dynamic_evidence_root()
    freeze_path = _canonical_paper2_freeze_anchor_path()
    freeze_ids = _load_freeze_included_ids(freeze_path=freeze_path) if freeze_path.exists() else None

    print()
    menu_utils.print_header("Workspace Cleanup (Dynamic Evidence)", "Safe cleanup (does not touch frozen dataset)")
    if not freeze_ids:
        print(status_messages.status(f"Canonical freeze anchor missing/invalid: {freeze_path}", level="warn"))
        print(status_messages.status("Cleanup of out-of-dataset VALID runs is blocked (need freeze included_run_ids).", level="info"))

    items = [
        menu_utils.MenuOption("1", "Delete ghost dirs", description="dirs under output/evidence/dynamic without run_manifest.json"),
        menu_utils.MenuOption("2", "Delete INVALID dataset runs", description="valid_dataset_run=false (never in frozen dataset)"),
        menu_utils.MenuOption("3", "Delete out-of-dataset VALID runs", description="valid_dataset_run=true but not in freeze included_run_ids"),
        menu_utils.MenuOption("4", "Purge old dynamic batch reports", description="delete output/batches/dynamic/* (derived)"),
    ]
    menu_utils.render_menu(
        menu_utils.MenuSpec(items=items, exit_label="Back", show_exit=True, show_descriptions=True, compact=True)
    )
    choice = prompt_utils.get_choice([opt.key for opt in items] + ["0"], default="0", prompt="Select cleanup option (or 0): ")
    if choice == "0":
        if pause:
            prompt_utils.press_enter_to_continue()
        return

    delete_ghost = choice in ("1",)
    delete_invalid = choice in ("2",)
    delete_extra_valid = choice in ("3",)
    purge_batches = choice in ("4",)

    if delete_extra_valid and not freeze_ids:
        print(status_messages.status("Blocked: freeze anchor not available; cannot safely identify out-of-dataset runs.", level="error"))
        if pause:
            prompt_utils.press_enter_to_continue()
        return

    confirm_msg = {
        "1": "Delete ghost dirs now?",
        "2": "Delete INVALID dataset runs now?",
        "3": "Delete out-of-dataset VALID dataset runs now?",
        "4": "Purge old dynamic batch reports now?",
    }.get(choice, "Proceed?")
    if not prompt_utils.prompt_yes_no(confirm_msg, default=False):
        print(status_messages.status("Cancelled.", level="info"))
        if pause:
            prompt_utils.press_enter_to_continue()
        return

    res = _cleanup_dynamic_workspace(
        evidence_root=root,
        freeze_included=freeze_ids,
        delete_ghost_dirs=delete_ghost,
        delete_invalid_runs=delete_invalid,
        delete_out_of_dataset_valid_runs=delete_extra_valid,
        purge_dynamic_batch_outputs=purge_batches,
    )
    d = res.get("deleted") if isinstance(res, dict) else {}
    e = res.get("errors") if isinstance(res, dict) else []
    print(status_messages.status(f"Deleted: {d}", level="success"))
    if e:
        print(status_messages.status(f"Errors (sample): {', '.join(str(x) for x in e[:5])}", level="warn"))
    if pause:
        prompt_utils.press_enter_to_continue()


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


def evidence_verify_overview(*, pause: bool = True) -> None:
    from scytaledroid.DynamicAnalysis.tools.evidence.verify_cli import run_dynamic_evidence_verify

    print()
    run_dynamic_evidence_verify(enrich_db_labels=True, show_reason_column=False)
    if pause:
        prompt_utils.press_enter_to_continue()


def evidence_quick_health_check(*, pause: bool = True) -> None:
    from scytaledroid.DynamicAnalysis.tools.evidence.verify_cli import run_dynamic_evidence_quick_check

    run_dynamic_evidence_quick_check(enrich_db_labels=True)
    if pause:
        prompt_utils.press_enter_to_continue()


def evidence_deep_checks(*, pause: bool = True) -> None:
    from scytaledroid.DynamicAnalysis.tools.evidence.verify_cli import run_dynamic_evidence_deep_checks

    run_dynamic_evidence_deep_checks(enrich_db_labels=True, write_outputs=True)
    if pause:
        prompt_utils.press_enter_to_continue()


def evidence_recompute_pcap_artifacts(*, pause: bool = True) -> None:
    """Recompute pcap_report.json + pcap_features.json for existing packs (pre-freeze)."""
    root = _dynamic_evidence_root()
    if not root.exists():
        print(status_messages.status("No evidence packs found.", level="warn"))
        if pause:
            prompt_utils.press_enter_to_continue()
        return

    # Paper #2 (PM-locked): once the canonical checksummed freeze anchor exists,
    # we must not mutate evidence packs in-place. Any recomputation must be
    # versioned (new dataset or versioned derived outputs), not overwriting.
    from scytaledroid.DynamicAnalysis.ml.ml_parameters_paper2 import FREEZE_CANONICAL_FILENAME

    freeze_anchor = Path(app_config.DATA_DIR) / "archive" / FREEZE_CANONICAL_FILENAME
    if freeze_anchor.exists():
        print()
        menu_utils.print_header("Recompute PCAP Artifacts")
        print(
            status_messages.status(
                f"Dataset is frozen (canonical freeze anchor exists: {freeze_anchor}). Recomputing would mutate evidence packs.",
                level="warn",
            )
        )
        print(
            status_messages.status(
                "Blocked by design. For Paper #2, do not overwrite frozen inputs. If a bug is discovered, version outputs or version the dataset.",
                level="info",
            )
        )
        if pause:
            prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_header("Recompute PCAP Artifacts", "Re-run pcap_report + pcap_features (pre-freeze only)")
    print(status_messages.status("This overwrites analysis artifacts inside evidence packs.", level="warn"))
    confirm = prompt_utils.prompt_text("Type RECOMPUTE to continue", required=False).strip()
    if confirm != "RECOMPUTE":
        print(status_messages.status("Cancelled.", level="info"))
        if pause:
            prompt_utils.press_enter_to_continue()
        return

    from scytaledroid.DynamicAnalysis.tools.evidence.pcap_recompute import recompute_pcap_artifacts

    res = recompute_pcap_artifacts(root, dry_run=False)
    print(status_messages.status(f"Scanned={res.scanned} updated={res.updated} skipped={res.skipped} errors={res.errors}", level="info"))
    if pause:
        prompt_utils.press_enter_to_continue()


def evidence_view_app_runs(*, pause: bool = True) -> None:
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
        if pause:
            prompt_utils.press_enter_to_continue()
        return
    labels = _load_app_labels(packages)
    app_list = sorted([(labels.get(p, p), p) for p in packages], key=lambda x: x[0].lower())

    print()
    menu_utils.print_header("Select App", "View runs and reasons")
    from scytaledroid.Utils.DisplayUtils import table_utils, display_settings

    try:
        from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig

        cfg = DatasetTrackerConfig()
        baseline_required = int(cfg.baseline_required)
        interactive_required = int(cfg.interactive_required)
    except Exception:
        baseline_required = 1
        interactive_required = 2

    rows = []
    for i, (name, pkg) in enumerate(app_list):
        runs = _runs_for_package(root, pkg)
        valid = sum(1 for r in runs if r.get("valid") is True and r.get("countable") is not False)
        invalid = sum(1 for r in runs if r.get("valid") is False and r.get("countable") is not False)
        base_valid = sum(
            1
            for r in runs
            if r.get("valid") is True
            and r.get("countable") is not False
            and "baseline" in str(r.get("run_profile") or "").lower()
        )
        inter_valid = sum(
            1
            for r in runs
            if r.get("valid") is True
            and r.get("countable") is not False
            and "interactive" in str(r.get("run_profile") or "").lower()
        )
        rows.append(
            [
                str(i + 1),
                name,
                str(len(runs)),
                str(valid),
                str(invalid),
                f"{base_valid}/{baseline_required}",
                f"{inter_valid}/{interactive_required}",
            ]
        )
    table_kwargs = display_settings.apply_table_defaults({"compact": True, "accent_first_column": True})
    table_utils.render_table(["#", "App", "Runs", "Valid", "Invalid", "Base", "Int"], rows, **table_kwargs)
    print(status_messages.status("0 = Back", level="info"))

    options = [str(i) for i in range(1, len(app_list) + 1)]
    sel = prompt_utils.get_choice(options + ["0"], default="1", prompt="Select app # ")
    if sel == "0":
        return
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
        return
    if action == "D":
        choice_run = prompt_utils.prompt_text("Run # to delete", required=False).strip()
        try:
            ri = int(choice_run)
        except Exception:
            return
        if ri < 1 or ri > len(runs):
            return
        run_id = str(runs[ri - 1].get("run_id") or "")
        if not run_id:
            return
        if not prompt_utils.prompt_yes_no(f"Delete run {run_id[:8]} locally?", default=False):
            return
        ok = _safe_rmtree(root / run_id, root=root)
        print(status_messages.status("Deleted." if ok else "Delete failed.", level="success" if ok else "error"))
    elif action == "X":
        invalid = [r for r in runs if r.get("valid") is False]
        if not invalid:
            print(status_messages.status("No INVALID runs for this app.", level="info"))
            if pause:
                prompt_utils.press_enter_to_continue()
            return
        if not prompt_utils.prompt_yes_no(f"Delete {len(invalid)} INVALID run(s) for this app locally?", default=False):
            return
        deleted = 0
        for r in invalid:
            run_id = str(r.get("run_id") or "")
            if run_id and _safe_rmtree(root / run_id, root=root):
                deleted += 1
        print(status_messages.status(f"Deleted {deleted} INVALID run(s).", level="success"))

    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import recompute_dataset_tracker

    recompute_dataset_tracker()
    if pause:
        prompt_utils.press_enter_to_continue()


def evidence_delete_invalid_dataset_runs(*, pause: bool = True) -> None:
    root = _dynamic_evidence_root()
    from scytaledroid.DynamicAnalysis.tools.evidence.verify_cli import run_dynamic_evidence_verify

    report = run_dynamic_evidence_verify(write_json=False, enrich_db_labels=True, show_reason_column=True)
    ghost_dirs = [g for g in (report.get("ghost_dirs") or []) if isinstance(g, str) and g.strip()]
    invalid = [
        r
        for r in (report.get("packs") or [])
        # Delete INVALID runs regardless of whether they're countable/extras. Invalid
        # evidence packs are never part of the frozen dataset and keeping them tends
        # to confuse operators and inflate workspace size.
        if isinstance(r, dict) and r.get("valid_dataset_run") is False
    ]
    if not invalid and not ghost_dirs:
        print(status_messages.status("No INVALID runs or ghost dirs found to delete.", level="info"))
        if pause:
            prompt_utils.press_enter_to_continue()
        return

    print()
    if ghost_dirs:
        print(status_messages.status(f"Ghost dirs to delete: {len(ghost_dirs)}", level="warn"))
        print(status_messages.status(", ".join(ghost_dirs), level="warn"))
        print()
    if invalid:
        print(status_messages.status(f"INVALID runs to delete: {len(invalid)}", level="warn"))
        for row in invalid:
            rid = str(row.get("run_id") or "")[:8]
            name = str(row.get("display_name") or row.get("package_name") or "_unknown")
            reason = str(row.get("invalid_reason_code") or "UNKNOWN")
            print(status_messages.status(f"{rid} {name} INVALID:{reason}", level="warn"))

    total = len(invalid) + len(ghost_dirs)
    if not prompt_utils.prompt_yes_no(f"Delete these {total} item(s) locally?", default=False):
        return

    deleted = 0
    for row in invalid:
        run_id = str(row.get("run_id") or "")
        if run_id and _safe_rmtree(root / run_id, root=root):
            deleted += 1
    for gid in ghost_dirs:
        if _safe_rmtree(root / gid, root=root):
            deleted += 1
    print(status_messages.status(f"Deleted {deleted} item(s).", level="success"))

    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import recompute_dataset_tracker

    recompute_dataset_tracker()
    if pause:
        prompt_utils.press_enter_to_continue()


def evidence_write_dataset_freeze_manifest(*, pause: bool = True) -> None:
    root = _dynamic_evidence_root()
    if not root.exists():
        print(status_messages.status("No evidence packs found.", level="warn"))
        if pause:
            prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_header("Dataset Freeze Manifest", "Paper #2 dataset anchor (does not mutate packs)")
    out_dir = Path(app_config.DATA_DIR) / "archive"
    canonical = out_dir / "dataset_freeze.json"
    if canonical.exists():
        print(status_messages.status(f"Canonical freeze file already exists: {canonical}", level="warn"))
        if not prompt_utils.prompt_yes_no("Write an additional timestamped freeze manifest?", default=False):
            print(status_messages.status("Cancelled.", level="info"))
            if pause:
                prompt_utils.press_enter_to_continue()
            return

    from scytaledroid.DynamicAnalysis.tools.evidence.freeze_manifest import write_dataset_freeze_manifest

    try:
        path = write_dataset_freeze_manifest(evidence_root=root, out_dir=out_dir, also_write_canonical=not canonical.exists())
    except Exception as exc:  # noqa: BLE001
        print(status_messages.status(f"Freeze manifest failed: {exc}", level="error"))
        if pause:
            prompt_utils.press_enter_to_continue()
        return

    print(status_messages.status(f"Freeze manifest written: {path}", level="success"))
    if not canonical.exists():
        print(status_messages.status(f"Canonical freeze written: {out_dir / 'dataset_freeze.json'}", level="success"))
    if pause:
        prompt_utils.press_enter_to_continue()


def evidence_verify_freeze_immutability(*, pause: bool = True) -> None:
    """Verify the frozen inputs for included runs have not changed since freeze."""
    out_dir = Path(app_config.DATA_DIR) / "archive"
    # Paper #2 (PM-locked): always prefer the canonical checksummed freeze anchor
    # used by Phase E. Only fall back to other freeze files if that anchor is absent.
    from scytaledroid.DynamicAnalysis.ml.ml_parameters_paper2 import FREEZE_CANONICAL_FILENAME

    freeze_path = out_dir / FREEZE_CANONICAL_FILENAME
    if not freeze_path.exists():
        # Fallback: pick the newest timestamped freeze file that contains checksums.
        candidates = sorted(out_dir.glob("dataset_freeze-*.json"))
        selected = None
        for p in reversed(candidates):
            payload = _read_json(p) or {}
            if isinstance(payload.get("included_run_checksums"), dict) and payload.get("included_run_checksums"):
                selected = p
                break
        freeze_path = selected or (out_dir / "dataset_freeze.json")

    if not freeze_path.exists():
        print(status_messages.status(f"Freeze file not found: {freeze_path}", level="warn"))
        if pause:
            prompt_utils.press_enter_to_continue()
        return

    root = _dynamic_evidence_root()
    if not root.exists():
        print(status_messages.status("No evidence packs found.", level="warn"))
        if pause:
            prompt_utils.press_enter_to_continue()
        return

    from scytaledroid.DynamicAnalysis.tools.evidence.freeze_verify import verify_dataset_freeze_immutability

    print()
    menu_utils.print_header("Freeze Immutability Check", "Hash-based verification (does not mutate packs)")
    try:
        # Quick structural check before doing any expensive hashing.
        payload = _read_json(freeze_path) or {}
        if not isinstance(payload.get("included_run_checksums"), dict) or not payload.get("included_run_checksums"):
            print(
                status_messages.status(
                    f"No freeze file with checksums found (selected is legacy): {freeze_path}",
                    level="warn",
                )
            )
            print(
                status_messages.status(
                    "Action: generate a checksummed freeze manifest (Paper mode), then rerun this check.",
                    level="info",
                )
            )
            if pause:
                prompt_utils.press_enter_to_continue()
            return
        res = verify_dataset_freeze_immutability(
            freeze_path=freeze_path, evidence_root=root, write_outputs=True
        )
    except Exception as exc:  # noqa: BLE001
        print(status_messages.status(f"Freeze immutability check failed: {exc}", level="error"))
        if pause:
            prompt_utils.press_enter_to_continue()
        return
    if res.mismatches or res.missing:
        print(status_messages.status(f"FAILED: mismatches={res.mismatches} missing={res.missing}", level="warn"))
        for issue in res.issues[:10]:
            rid = str(issue.get("run_id") or "")
            path = str(issue.get("path") or "")
            kind = str(issue.get("issue") or "")
            msg = f"- {rid} {kind}"
            if path:
                msg += f" path={path}"
            print(status_messages.status(msg, level="warn"))
        if len(res.issues) > 10:
            print(status_messages.status(f"... and {len(res.issues) - 10} more", level="info"))
    else:
        print(status_messages.status(f"OK: scanned={res.scanned} mismatches=0 missing=0", level="success"))
    if pause:
        prompt_utils.press_enter_to_continue()


def evidence_recompute_dataset_tracker(*, pause: bool = True) -> None:
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import recompute_dataset_tracker

    recompute_dataset_tracker()
    print(status_messages.status("Tracker recomputed from evidence packs.", level="success"))
    if pause:
        prompt_utils.press_enter_to_continue()


def evidence_network_audit_report(*, pause: bool = True) -> None:
    from scytaledroid.DynamicAnalysis.tools.evidence.audit_report import run_dynamic_evidence_network_audit

    print()
    report = run_dynamic_evidence_network_audit(enrich_db_labels=True, write_outputs=True)
    paths = report.get("report_paths") if isinstance(report.get("report_paths"), dict) else {}
    json_path = str(paths.get("json") or "")
    md_path = str(paths.get("md") or "")
    if json_path:
        print(status_messages.status(f"Report written: {json_path}", level="success"))
    if md_path:
        print(status_messages.status(f"Report written: {md_path}", level="success"))
    if pause:
        prompt_utils.press_enter_to_continue()


def evidence_packs_menu() -> None:
    while True:
        print()
        menu_utils.print_header("Dynamic Evidence Packs")
        items = [
            menu_utils.MenuOption("1", "Verify evidence packs (overview)"),
            menu_utils.MenuOption("2", "Quick health check (packs/missing/bad + PCAP sizes)"),
            menu_utils.MenuOption("3", "View app runs (details)"),
            menu_utils.MenuOption("4", "Delete INVALID dataset runs (local only)"),
            menu_utils.MenuOption("5", "Recompute dataset tracker (from evidence packs)"),
            menu_utils.MenuOption("6", "Network audit report (trends)"),
            menu_utils.MenuOption("9", "Deep checks (DB vs manifest + transport + indicator quality)"),
            menu_utils.MenuOption("R", "Recompute PCAP artifacts (pcap_report + pcap_features)"),
        ]
        menu_utils.render_menu(menu_utils.MenuSpec(items=items, exit_label="Back", show_exit=True))
        choice = prompt_utils.get_choice([opt.key for opt in items] + ["0"], default="1")
        if choice == "0":
            break

        if choice == "1":
            evidence_verify_overview(pause=True)
            continue

        if choice == "2":
            evidence_quick_health_check(pause=True)
            continue

        if choice == "3":
            evidence_view_app_runs(pause=True)
            continue

        if choice == "4":
            evidence_delete_invalid_dataset_runs(pause=True)
            continue

        if choice == "5":
            evidence_recompute_dataset_tracker(pause=True)
            continue

        if choice == "6":
            evidence_network_audit_report(pause=True)
            continue
        if choice == "9":
            evidence_deep_checks(pause=True)
            continue
        if choice == "R":
            evidence_recompute_pcap_artifacts(pause=True)
            continue


__all__ = [
    "evidence_delete_invalid_dataset_runs",
    "evidence_cleanup_workspace",
    "evidence_deep_checks",
    "evidence_recompute_pcap_artifacts",
    "evidence_network_audit_report",
    "evidence_packs_menu",
    "evidence_quick_health_check",
    "evidence_recompute_dataset_tracker",
    "evidence_verify_overview",
    "evidence_verify_freeze_immutability",
    "evidence_view_app_runs",
    "evidence_write_dataset_freeze_manifest",
]
