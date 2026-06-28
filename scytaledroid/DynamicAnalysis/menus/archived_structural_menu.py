"""Archived profile-v3 structural cohort menu helpers."""

from __future__ import annotations

import os
from pathlib import Path

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils


def print_profile_v3_capture_runbook() -> None:
    """Print a concise operator runbook for the archived structural cohort flow."""

    print()
    menu_utils.print_header("Structural Cohort Capture Runbook", "archived scripted flow")
    try:
        from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config
        from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import MIN_WINDOWS_PER_RUN

        min_windows = int(MIN_WINDOWS_PER_RUN)
        min_pcap_idle = int(getattr(profile_config, "MIN_PCAP_BYTES_V3_IDLE", 0))
        min_pcap_scripted = int(
            getattr(profile_config, "MIN_PCAP_BYTES_V3_SCRIPTED", getattr(profile_config, "MIN_PCAP_BYTES", 50_000))
        )
    except Exception:
        min_windows = 20
        min_pcap_idle = 0
        min_pcap_scripted = 40_000
    lines = [
        "Goal: collect archive-grade dynamic evidence for the structural cohort.",
        "",
        "Hard locks:",
        "- interaction is scripted-only for the structural manifest flow.",
        "- cohort is catalog-defined (profiles/profile_v3_app_catalog.json).",
        "",
        "Required per app (minimum):",
        f"- baseline_idle: windows>={min_windows}, pcap_bytes>={min_pcap_idle}",
        f"- interaction_scripted: windows>={min_windows}, pcap_bytes>={min_pcap_scripted}",
        "",
        "Recommended order:",
        "1. Device Analysis: Refresh Inventory; Execute Harvest -> app profile (full refresh).",
        "2. Static Analysis: Run Static Pipeline (Full) -> Profile.",
        "3. Reporting: Run structural archive integrity gates (freshness + scripted coverage).",
        "4. Dynamic Analysis: capture missing scripted runs (baseline_idle + interaction_scripted).",
        "5. Dynamic Analysis: Build v3 manifest (included runs).",
        "6. Reporting: Strict v3 export + strict lint -> ready.",
        "",
        "Notes:",
        "- If v3 exporter fails with included_run_ids=0, you have not built the manifest yet.",
        "- If scripted coverage gate FAILs, recapture scripted interaction for the listed apps.",
    ]
    for line in lines:
        print(status_messages.status(line, level="info") if line else "")
    prompt_utils.press_enter_to_continue()


def run_profile_v3_guided_phase2_capture(*, load_dynamic_ui_defaults_fn) -> None:
    """Guided capture helper for the archived structural cohort flow."""

    import io
    from contextlib import redirect_stdout

    from scytaledroid.DynamicAnalysis.services.profile_v3_capture_status_service import (
        main as capture_status_main,
    )

    print()
    if "SCYTALEDROID_V3_ACCEPT_MANUAL_INTERACTIVE" not in os.environ:
        strict_env = str(os.environ.get("SCYTALEDROID_PAPER_STRICT") or "").strip().lower() in {"1", "true", "yes", "on"}
        if strict_env:
            os.environ["SCYTALEDROID_V3_ACCEPT_MANUAL_INTERACTIVE"] = "1"
    accept_manual = str(os.environ.get("SCYTALEDROID_V3_ACCEPT_MANUAL_INTERACTIVE") or "").strip().lower() in {"1", "true", "yes", "on"}
    subtitle = "Archive burn-down (idle + interactive)"
    subtitle += " (scripted|manual)" if accept_manual else " (scripted)"
    menu_utils.print_header("Structural Cohort Guided Capture", subtitle)

    repo_root = Path(__file__).resolve().parents[2]
    audit_dir = repo_root / "output" / "audit" / "profile_v3"
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            capture_status_main(["--write-audit"])
    except SystemExit:
        pass
    finally:
        try:
            out = buf.getvalue().splitlines()
        except Exception:
            out = []
        copy_lines = [ln for ln in out if ln.startswith("[COPY] ")]
        main = next((ln for ln in copy_lines if ln.startswith("[COPY] v3_capture_status ")), None)
        if main:
            print(main)
        csv_ln = next((ln for ln in copy_lines if ln.startswith("[COPY] v3_capture_status_csv ")), None)
        rec_ln = next((ln for ln in copy_lines if ln.startswith("[COPY] v3_capture_status_receipt ")), None)
        plan_ln = next((ln for ln in copy_lines if ln.startswith("[COPY] v3_recapture_plan_csv ")), None)
        parts = []
        if csv_ln:
            parts.append("csv=" + (csv_ln.split("path=", 1)[-1].strip() if "path=" in csv_ln else "").strip())
        if rec_ln:
            parts.append("receipt=" + (rec_ln.split("path=", 1)[-1].strip() if "path=" in rec_ln else "").strip())
        if plan_ln:
            parts.append("plan=" + (plan_ln.split("path=", 1)[-1].strip() if "path=" in plan_ln else "").strip())
        if parts:
            print("[COPY] v3_capture_receipts " + " ".join(parts))

    status_csvs = sorted(audit_dir.glob("capture_status_*.csv"))
    if not status_csvs:
        print(status_messages.status("No v3 capture_status CSV found. Run the dashboard first.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return
    status_csv = status_csvs[-1]

    import csv

    rows: list[dict[str, str]] = []
    try:
        with status_csv.open("r", encoding="utf-8", newline="") as f:
            r = csv.DictReader(f)
            for row in r:
                if not isinstance(row, dict):
                    continue
                rows.append({k: (row.get(k) or "").strip() for k in (r.fieldnames or [])})
    except Exception as exc:
        print(status_messages.status(f"Failed to read capture status CSV: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    pass_n = sum(1 for r in rows if (r.get("status") or "").strip().upper() == "PASS")
    block_n = sum(1 for r in rows if (r.get("status") or "").strip().upper() != "PASS")
    strict = os.environ.get("SCYTALEDROID_PAPER_STRICT", "0").strip() or "0"
    postrun = os.environ.get("SCYTALEDROID_V3_POSTRUN_CHECK", "0").strip() or "0"
    min_windows = (rows[0].get("min_windows_required") if rows else "") or "?"
    min_pcap_idle = (rows[0].get("min_pcap_bytes_required_idle") if rows else "") or "?"
    min_pcap_scripted = (rows[0].get("min_pcap_bytes_required_scripted") if rows else "") or "?"
    idle_target = (rows[0].get("idle_runs_eligible_target") if rows else "") or "1"
    scripted_target = (rows[0].get("scripted_runs_eligible_target") if rows else "") or "1"
    status_bits = [f"PASS={pass_n}", f"BLOCKERS={block_n}", f"strict={strict}", f"postrun={postrun}", f"accept_manual={int(accept_manual)}"]
    minima_bits = [f"W>={min_windows}", f"idle>={min_pcap_idle}", f"scripted>={min_pcap_scripted}"]
    if str(idle_target).strip() not in {"", "1"}:
        minima_bits.append(f"idle_runs>={idle_target}")
    if str(scripted_target).strip() not in {"", "1"}:
        minima_bits.append(f"scripted_runs>={scripted_target}")
    print(status_messages.status("Status: " + " | ".join(status_bits) + " | minima: " + " ".join(minima_bits), level="info"))

    if not accept_manual:
        try:
            import json as _json

            from scytaledroid.DynamicAnalysis.run_profile_norm import normalize_run_profile as _nrp
            from scytaledroid.DynamicAnalysis.run_profile_norm import (
                resolve_run_profile_from_manifest as _rrp,
            )

            evidence_root = repo_root / "output" / "evidence" / "dynamic"
            manual_seen = 0
            for mf in evidence_root.glob("*/run_manifest.json"):
                try:
                    m = _json.loads(mf.read_text(encoding="utf-8"))
                except Exception:
                    continue
                try:
                    rp = _rrp(m, strict_conflict=False).normalized
                except Exception:
                    rp = ""
                if _nrp(rp) == "interaction_manual":
                    manual_seen += 1
                    if manual_seen >= 1:
                        break
            if manual_seen:
                print(
                    status_messages.status(
                        "Note: manual interaction runs exist, but SCYTALEDROID_V3_ACCEPT_MANUAL_INTERACTIVE=0 so they do not count toward Interactive eligible.",
                        level="warn",
                    )
                )
                print(
                    status_messages.status(
                        "Set: export SCYTALEDROID_V3_ACCEPT_MANUAL_INTERACTIVE=1 (archive flow only).",
                        level="warn",
                    )
                )
        except Exception:
            pass

    need_both = 0
    need_idle = 0
    need_scripted = 0
    need_idle_redundancy = 0
    need_scripted_redundancy = 0
    for r in rows:
        reasons = r.get("reasons") or ""
        miss_idle = "missing_required_phase_idle" in reasons
        miss_scripted = "missing_required_phase_scripted" in reasons
        if miss_idle and miss_scripted:
            need_both += 1
        elif miss_idle:
            need_idle += 1
        elif miss_scripted:
            need_scripted += 1
        else:
            try:
                if (r.get("status") or "").strip().upper() == "PASS" and int(r.get("idle_runs_eligible_gap") or "0") > 0:
                    need_idle_redundancy += 1
                if (r.get("status") or "").strip().upper() == "PASS" and int(r.get("scripted_runs_eligible_gap") or "0") > 0:
                    need_scripted_redundancy += 1
            except Exception:
                pass
    if block_n:
        print(status_messages.status(f"Next actions: both={need_both} idle={need_idle} scripted={need_scripted}", level="warn"))
    if need_idle_redundancy:
        print(status_messages.status(f"Quality target: apps needing extra idle runs={need_idle_redundancy}", level="warn"))
    if need_scripted_redundancy:
        print(status_messages.status(f"Quality target: apps needing extra scripted runs={need_scripted_redundancy}", level="warn"))

    def _need_label(r: dict[str, str]) -> str:
        reasons = r.get("reasons") or ""
        status = (r.get("status") or "").strip().upper()
        mixed = (r.get("mixed_versions") or "").strip() == "1" or "MIXED_VERSIONS" in reasons
        if "missing_required_phase_idle" in reasons and "missing_required_phase_scripted" in reasons:
            return "CAPTURE_BOTH"
        if "missing_required_phase_idle" in reasons:
            return "CAPTURE_IDLE"
        if "missing_required_phase_scripted" in reasons:
            return "CAPTURE_INTERACTIVE" if accept_manual else "CAPTURE_SCRIPTED"
        if status == "PASS":
            if mixed:
                return "WARN_MIXED_VERSIONS"
            try:
                if str(idle_target).strip() not in {"", "1"} and int(r.get("idle_runs_eligible_gap") or "0") > 0:
                    return "CAPTURE_IDLE_REDUNDANCY"
                if str(scripted_target).strip() not in {"", "1"} and int(r.get("scripted_runs_eligible_gap") or "0") > 0:
                    return "CAPTURE_INTERACTIVE_REDUNDANCY" if accept_manual else "CAPTURE_SCRIPTED_REDUNDANCY"
            except Exception:
                pass
            return "PASS"
        return status or "BLOCK"

    def _sort_key(r: dict[str, str]) -> tuple[str, str]:
        app = str(r.get("app") or r.get("package") or "").strip().casefold()
        pkg = str(r.get("package") or "").strip().casefold()
        return (app, pkg)

    view_rows = sorted(list(rows), key=_sort_key)

    def _need_short(need: str) -> str:
        mapping = {
            "CAPTURE_BOTH": "BOTH",
            "CAPTURE_IDLE": "IDLE",
            "CAPTURE_SCRIPTED": "SCR",
            "CAPTURE_INTERACTIVE": "INT",
            "CAPTURE_IDLE_REDUNDANCY": "IDLE+",
            "CAPTURE_SCRIPTED_REDUNDANCY": "SCR+",
            "CAPTURE_INTERACTIVE_REDUNDANCY": "INT+",
            "WARN_MIXED_VERSIONS": "WARN_VER",
            "PASS": "PASS",
            "BLOCK": "BLOCK",
        }
        n = str(need or "").strip().upper()
        return mapping.get(n, n[:12] or "?")

    table_rows: list[list[str]] = []
    for idx, r in enumerate(view_rows, start=1):
        app = r.get("app") or r.get("package") or ""
        pkg = r.get("package") or ""
        pkg_disp = pkg if len(pkg) <= 40 else pkg[:18] + "..." + pkg[-18:]
        idle_ok = r.get("idle_runs_eligible") or "0"
        idle_disp = str(idle_ok)
        if str(idle_target).strip() not in {"", "1"}:
            try:
                n = int(idle_ok)
                t = int(idle_target)
                idle_disp = f"{min(n, t)}/{t}"
            except Exception:
                idle_disp = f"{idle_ok}/{idle_target}"
        scr_ok = r.get("scripted_runs_eligible") or "0"
        scr_disp = str(scr_ok)
        if str(scripted_target).strip() not in {"", "1"}:
            try:
                n = int(scr_ok)
                t = int(scripted_target)
                scr_disp = f"{min(n, t)}/{t}"
            except Exception:
                scr_disp = f"{scr_ok}/{scripted_target}"
        table_rows.append([str(idx), app, pkg_disp, idle_disp, scr_disp, _need_short(_need_label(r))])
    scr_label = "Int" if accept_manual else "Scr"
    table_utils.render_table(["#", "App", "Package", "Idle", scr_label, "Need"], table_rows, padding=1)

    print()
    print("Need legend: BOTH=idle+interactive, IDLE=need idle, INT=need interactive, IDLE+/INT+=redundancy target, WARN_VER=mixed versions")

    from scytaledroid.DynamicAnalysis.controllers.profile_v3_phase2_capture import (
        run_profile_v3_capture_menu,
    )

    print()
    print("Select App To Run:")
    selectable = [str(i) for i in range(1, len(view_rows) + 1)]
    idx = prompt_utils.get_choice(selectable + ["0"], default="1")
    if idx == "0":
        return
    try:
        i = int(idx) - 1
    except Exception:
        return
    if i < 0 or i >= len(view_rows):
        return
    r = view_rows[i]
    pkg = (r.get("package") or "").strip()
    need = _need_label(r)
    if need == "CAPTURE_BOTH":
        need_short = "IDLE+SCRIPTED"
    elif need == "CAPTURE_IDLE":
        need_short = "IDLE"
    elif need in {"CAPTURE_SCRIPTED", "CAPTURE_INTERACTIVE"}:
        need_short = "INTERACTIVE" if accept_manual else "SCRIPTED"
    else:
        need_short = ""
    run_profile_v3_capture_menu(
        package_name=pkg,
        need=need_short or need,
        ui_prompt_observers=load_dynamic_ui_defaults_fn().observer_prompts_enabled,
    )


def run_profile_v3_manifest_build() -> None:
    from scytaledroid.DynamicAnalysis.services.profile_v3_manifest_build_service import (
        main as manifest_build_main,
    )

    print()
    menu_utils.print_header("Structural Cohort Manifest Build")
    try:
        manifest_build_main([])
    except SystemExit as exc:
        if int(getattr(exc, "code", 1) or 0) != 0:
            print(status_messages.status(f"Manifest build failed: exit={exc.code}", level="error"))
            prompt_utils.press_enter_to_continue()
            return
    print(status_messages.status("Manifest build completed.", level="success"))
    prompt_utils.press_enter_to_continue()


def run_profile_v3_capture_status_dashboard() -> None:
    from scytaledroid.DynamicAnalysis.services.profile_v3_capture_status_service import (
        main as capture_status_main,
    )

    print()
    menu_utils.print_header("Structural Cohort Capture Status")
    try:
        capture_status_main([])
    except SystemExit as exc:
        code = int(getattr(exc, "code", 1) or 0)
        if code != 0:
            print(status_messages.status(f"Dashboard reported blockers (exit={code}).", level="warn"))
    prompt_utils.press_enter_to_continue()


def run_profile_v3_recapture_plan_view() -> None:
    import csv

    print()
    menu_utils.print_header("Structural Cohort Recapture Plan", "Ordered actions to reach blockers=0")
    repo_root = Path(__file__).resolve().parents[2]
    audit_dir = repo_root / "output" / "audit" / "profile_v3"
    recapture_plans = sorted(audit_dir.glob("recapture_plan_*.csv"))
    recapture_csv = recapture_plans[-1] if recapture_plans else None
    if not recapture_csv or not recapture_csv.exists():
        print(status_messages.status("No recapture_plan CSV found. Run the v3 dashboard first.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return
    print(status_messages.status(f"Source: {recapture_csv.relative_to(repo_root)}", level="info"))
    try:
        with recapture_csv.open("r", encoding="utf-8", newline="") as f:
            r = csv.DictReader(f)
            plan_rows = [row for row in r if isinstance(row, dict)]
    except Exception as exc:
        print(status_messages.status(f"Failed to read recapture plan: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return
    for row in plan_rows[:40]:
        pkg = (row.get("package") or "").strip()
        action = (row.get("action") or "").strip()
        reasons = (row.get("reasons") or "").strip()
        print(f"- {action:14} {pkg}  ({reasons})")
    if len(plan_rows) > 40:
        print(f"- ... ({len(plan_rows) - 40} more)")
    prompt_utils.press_enter_to_continue()
