"""Dynamic analysis menu scaffolding."""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config  # noqa: F401 - re-exported for tests
from scytaledroid.Database.db_core import run_sql
from scytaledroid.DeviceAnalysis.adb import shell as adb_shell
from scytaledroid.DeviceAnalysis.adb import status as adb_status
from scytaledroid.DynamicAnalysis import plan_selection as _plan_selection
from scytaledroid.DynamicAnalysis.controllers.guided_run import run_guided_dataset_run
from scytaledroid.DynamicAnalysis.datasets.research_dataset_alpha import (
    PROFILE_KEY as _DATASET_PROFILE_KEY,
)
from scytaledroid.DynamicAnalysis.datasets.research_dataset_alpha import (
    load_dataset_packages as _load_dataset_packages,
)
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config
from scytaledroid.DynamicAnalysis.menu_views import (
    build_dynamic_menu_sections,
    render_dynamic_menu_overview,
)
from scytaledroid.DynamicAnalysis.freeze_eligibility import derive_freeze_eligibility
from scytaledroid.DynamicAnalysis.profile_loader import load_db_profiles, load_profile_packages
from scytaledroid.DynamicAnalysis.services.observer_service import (
    select_observers as _service_select_observers,
)
from scytaledroid.StaticAnalysis.core.repository import (
    group_artifacts,
    list_categories,
    list_packages,
    load_profile_map,
)
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption, MenuSpec

_DEVICE_STATUS_CACHE: dict[str, dict[str, str]] = {}
_RUN_IDENTITY_CACHE: dict[str, tuple[str | None, str | None]] = {}

_MENU_STARTED_AT_MONOTONIC = time.monotonic()


def _sha256_file(path: Path) -> str:
    try:
        data = path.read_bytes()
    except Exception:
        return ""
    return hashlib.sha256(data).hexdigest()


def _code_signature() -> dict[str, str]:
    # If operators update code while the menu is running, the already-loaded Python
    # modules won't reflect it. This signature lets us warn about "stale process"
    # issues that otherwise look like protocol/template bugs.
    root = Path(__file__).resolve().parents[0]
    files = {
        "menu.py": Path(__file__).resolve(),
        "guided_run.py": (root / "controllers" / "guided_run.py").resolve(),
        "manual.py": (root / "scenarios" / "manual.py").resolve(),
        "manual_templates.py": (root / "scenarios" / "manual_templates.py").resolve(),
        "paper_eligibility.py": (root / "paper_eligibility.py").resolve(),
    }
    return {name: _sha256_file(path) for name, path in files.items()}


_MENU_CODE_SIGNATURE_AT_START = _code_signature()


def _warn_if_code_changed() -> None:
    current = _code_signature()
    changed = [name for name, sig in current.items() if sig and sig != _MENU_CODE_SIGNATURE_AT_START.get(name, sig)]
    if not changed:
        return
    # Keep it extremely obvious: stale process == stale templates.
    changed_list = ", ".join(changed[:5]) + (" ..." if len(changed) > 5 else "")
    status_messages.print_status(
        f"Code changed on disk since this Dynamic Analysis menu started ({changed_list}).",
        level="warn",
    )
    status_messages.print_status(
        "Exit ScytaleDroid completely (Main Menu -> 0) and restart to apply the new templates/logic.",
        level="warn",
    )


def _read_json(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _min_windows_per_run() -> int:
    try:
        from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import MIN_WINDOWS_PER_RUN

        return int(MIN_WINDOWS_PER_RUN)
    except Exception:
        return 20


def _run_profile_bucket(run_profile: str) -> str:
    prof = (run_profile or "").strip().lower()
    if "baseline" in prof or "idle" in prof:
        return "baseline"
    if "interaction" in prof or "interactive" in prof or "script" in prof or "manual" in prof:
        return "interactive"
    return "unknown"


def _summarize_evidence_quota(dataset_pkgs: set[str], cfg) -> dict[str, int | bool]:
    root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    out: dict[str, int | bool] = {
        "evidence_root_exists": root.exists(),
        "total_runs": 0,
        "technical_valid_runs": 0,
        "paper_eligible_runs": 0,
        "quota_runs_counted": 0,
        "apps_satisfied": 0,
        "excluded_runs": 0,
        "extra_eligible_runs": 0,
        "protocol_fit_poor_runs": 0,
        "low_signal_exploratory_runs": 0,
    }
    if not root.exists():
        return out

    per_pkg: dict[str, dict[str, int]] = {}
    for run_dir in sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name):
        manifest_path = run_dir / "run_manifest.json"
        if not manifest_path.exists():
            continue
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        out["total_runs"] = int(out["total_runs"]) + 1
        dataset = payload.get("dataset") if isinstance(payload.get("dataset"), dict) else {}
        if dataset.get("valid_dataset_run") is True:
            out["technical_valid_runs"] = int(out["technical_valid_runs"]) + 1
        operator = payload.get("operator") if isinstance(payload.get("operator"), dict) else {}
        target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
        package = str(target.get("package_name") or "").strip().lower()
        if package not in dataset_pkgs:
            continue
        plan = _read_json(run_dir / "inputs" / "static_dynamic_plan.json") or {}
        eligibility = derive_freeze_eligibility(
            manifest=payload,
            plan=plan,
            min_windows=_min_windows_per_run(),
            required_capture_policy_version=int(profile_config.PAPER_CONTRACT_VERSION),
        )
        if not eligibility.paper_eligible:
            out["excluded_runs"] = int(out["excluded_runs"]) + 1
            continue
        out["paper_eligible_runs"] = int(out["paper_eligible_runs"]) + 1
        bucket = _run_profile_bucket(
            str(dataset.get("run_profile") or operator.get("run_profile") or "")
        )
        if bucket == "unknown":
            continue
        # PM lock: low-signal *idle* baselines are retained but exploratory-only.
        # baseline_connected remains quota-eligible (low_signal is a tag, not an invalidation).
        prof_lc = str(dataset.get("run_profile") or operator.get("run_profile") or "").strip().lower()
        if bucket == "baseline" and prof_lc == "baseline_idle" and bool(dataset.get("low_signal")):
            out["low_signal_exploratory_runs"] = int(out["low_signal_exploratory_runs"]) + 1
            out["extra_eligible_runs"] = int(out["extra_eligible_runs"]) + 1
            continue
        pkg_counts = per_pkg.setdefault(package, {"baseline": 0, "interactive": 0})
        # Protocol-fit feedback is an operational flag only; it must not prevent
        # an otherwise paper-eligible run from satisfying quota.
        if bucket == "interactive" and str(operator.get("protocol_fit") or "").strip().lower() == "poor":
            out["protocol_fit_poor_runs"] = int(out["protocol_fit_poor_runs"]) + 1
        needed = int(cfg.baseline_required if bucket == "baseline" else cfg.interactive_required)
        if int(pkg_counts.get(bucket, 0)) < needed:
            pkg_counts[bucket] = int(pkg_counts.get(bucket, 0)) + 1
            out["quota_runs_counted"] = int(out["quota_runs_counted"]) + 1
        else:
            out["extra_eligible_runs"] = int(out["extra_eligible_runs"]) + 1
    out["apps_satisfied"] = sum(
        1
        for counts in per_pkg.values()
        if int(counts.get("baseline", 0)) >= int(cfg.baseline_required)
        and int(counts.get("interactive", 0)) >= int(cfg.interactive_required)
    )
    return out

@dataclass(frozen=True)
class _DynamicUiDefaults:
    observer_prompts_enabled: bool
    pcapdroid_api_key: str | None


@dataclass(frozen=True)
class _PreparedPackageSelectionView:
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


def _load_dynamic_ui_defaults() -> _DynamicUiDefaults:
    # UI-layer defaults only. Execution semantics must rely on the frozen config
    # carried in DynamicSessionConfig/RunContext and recorded in run_manifest.json.
    return _DynamicUiDefaults(
        observer_prompts_enabled=(os.environ.get("SCYTALEDROID_OBSERVER_PROMPTS") == "1"),
        pcapdroid_api_key=os.environ.get("SCYTALEDROID_PCAPDROID_API_KEY"),
    )

def _print_profile_v3_capture_runbook() -> None:
    """Print a concise operator runbook for the archived structural cohort flow."""

    print()
    menu_utils.print_header("Structural Cohort Capture Runbook", "archived scripted flow")
    # Keep the runbook aligned with strict-manifest enforcement.
    try:
        from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import MIN_WINDOWS_PER_RUN
        from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config

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


def _run_profile_v3_guided_phase2_capture() -> None:
    """Guided capture helper for the archived structural cohort flow.

    This is intentionally lightweight: it surfaces the dashboard as a cohort table plus a
    recapture plan, so operators can burn down blockers without copy/pasting between screens.
    """

    import csv
    import io
    import runpy
    import sys
    from contextlib import redirect_stdout
    from datetime import UTC, datetime

    print()
    # Phase 2 is often time-constrained. If the operator did not explicitly configure this
    # (env var unset), default to counting manual interaction runs as "interactive" in the
    # guided burn-down UI. Explicitly setting it to 0 keeps scripted-only behavior.
    if "SCYTALEDROID_V3_ACCEPT_MANUAL_INTERACTIVE" not in os.environ:
        strict_env = str(os.environ.get("SCYTALEDROID_PAPER_STRICT") or "").strip().lower() in {"1", "true", "yes", "on"}
        if strict_env:
            os.environ["SCYTALEDROID_V3_ACCEPT_MANUAL_INTERACTIVE"] = "1"
    accept_manual = str(os.environ.get("SCYTALEDROID_V3_ACCEPT_MANUAL_INTERACTIVE") or "").strip().lower() in {"1", "true", "yes", "on"}
    subtitle = "Archive burn-down (idle + interactive)"
    if accept_manual:
        subtitle += " (scripted|manual)"
    else:
        subtitle += " (scripted)"
    menu_utils.print_header("Structural Cohort Guided Capture", subtitle)

    repo_root = Path(__file__).resolve().parents[2]
    audit_dir = repo_root / "output" / "audit" / "profile_v3"
    script = repo_root / "scripts" / "profile_tools" / "profile_v3_capture_status.py"
    if script.exists():
        # Refresh the dashboard artifacts so the guided view is current.
        #
        # The dashboard script prints a verbose blockers list; for this guided screen we keep
        # output tight and replay only its stable [COPY] lines (PM/audit-friendly).
        # It may exit non-zero (blockers present); that's expected, so swallow SystemExit.
        argv_saved = list(sys.argv)
        try:
            sys.argv = [str(script), "--write-audit"]
            try:
                buf = io.StringIO()
                with redirect_stdout(buf):
                    runpy.run_path(str(script), run_name="__main__")
            except SystemExit:
                pass
            finally:
                # Replay only a compact subset of [COPY] lines:
                # - the main cohort status line
                # - a single receipts line with the latest CSV/JSON paths
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
        finally:
            sys.argv = argv_saved

    status_csvs = sorted(audit_dir.glob("capture_status_*.csv"))
    if not status_csvs:
        print(status_messages.status("No v3 capture_status CSV found. Run the dashboard first.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return
    status_csv = status_csvs[-1]

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
    # Compact one-liner status (PM/operator friendly).
    status_bits = [f"PASS={pass_n}", f"BLOCKERS={block_n}", f"strict={strict}", f"postrun={postrun}", f"accept_manual={int(accept_manual)}"]
    minima_bits = [f"W>={min_windows}", f"idle>={min_pcap_idle}", f"scripted>={min_pcap_scripted}"]
    if str(idle_target).strip() not in {"", "1"}:
        minima_bits.append(f"idle_runs>={idle_target}")
    if str(scripted_target).strip() not in {"", "1"}:
        minima_bits.append(f"scripted_runs>={scripted_target}")
    print(status_messages.status("Status: " + " | ".join(status_bits) + " | minima: " + " ".join(minima_bits), level="info"))

    # Operator footgun: manual interaction runs won't count unless accept_manual is enabled.
    if not accept_manual:
        try:
            import json as _json
            from scytaledroid.DynamicAnalysis.run_profile_norm import normalize_run_profile as _nrp, resolve_run_profile_from_manifest as _rrp

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

    # Operator summary: how many need which action (derived from reasons, not from UI labels).
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
            # Quality target only: PASS rows can still need more idle runs for redundancy.
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

    accept_manual = str(os.environ.get("SCYTALEDROID_V3_ACCEPT_MANUAL_INTERACTIVE") or "").strip().lower() in {"1", "true", "yes", "on"}

    # Show all apps (21) with stable ordering.
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
        # Operators requested stable ordering: keep app rows sorted by name so the numeric
        # indices do not shift between runs (easy to track burn-down).
        app = str(r.get("app") or r.get("package") or "").strip().casefold()
        pkg = str(r.get("package") or "").strip().casefold()
        return (app, pkg)

    view_rows = sorted(list(rows), key=_sort_key)

    table_rows: list[list[str]] = []
    def _need_short(need: str) -> str:
        n = str(need or "").strip().upper()
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
        return mapping.get(n, n[:12] or "?")

    for idx, r in enumerate(view_rows, start=1):
        app = r.get("app") or r.get("package") or ""
        pkg = r.get("package") or ""
        # Package names can be very long; shorten for the table view to keep columns readable.
        # Selection is by row number, so we can safely abbreviate here.
        pkg_disp = pkg
        if len(pkg_disp) > 40:
            pkg_disp = pkg_disp[:18] + "..." + pkg_disp[-18:]
        idle_ok = r.get("idle_runs_eligible") or "0"
        idle_gap = r.get("idle_runs_eligible_gap") or "0"
        idle_disp = str(idle_ok)
        if str(idle_target).strip() not in {"", "1"}:
            try:
                # Display as N/T but cap N at T (avoid confusing 4/3 style output).
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
        need = _need_label(r)
        table_rows.append([str(idx), app, pkg_disp, idle_disp, scr_disp, _need_short(need)])
    scr_label = "Int" if accept_manual else "Scr"
    table_utils.render_table(["#", "App", "Package", "Idle", scr_label, "Need"], table_rows, padding=1)

    # Legend for compact Need codes (avoid truncation in narrow terminals).
    print()
    print("Need legend: BOTH=idle+interactive, IDLE=need idle, INT=need interactive, IDLE+/INT+=redundancy target, WARN_VER=mixed versions")

    # Only remaining action here: select an app row number to capture.
    # Re-use the table above (avoid duplicating the list).
    from scytaledroid.DynamicAnalysis.controllers.profile_v3_phase2_capture import run_profile_v3_capture_menu

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
    # Translate UI need label into the per-app intent menu default.
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
        ui_prompt_observers=_load_dynamic_ui_defaults().observer_prompts_enabled,
    )
    return


def _run_profile_v3_manifest_build() -> None:
    """Build/update the structural cohort manifest from existing evidence packs."""

    print()
    menu_utils.print_header("Structural Cohort Manifest Build")
    script = Path(__file__).resolve().parents[2] / "scripts" / "profile_tools" / "profile_v3_manifest_build.py"
    if not script.exists():
        print(status_messages.status(f"Missing script: {script}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    import runpy

    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as exc:
        if int(getattr(exc, "code", 1) or 0) != 0:
            print(status_messages.status(f"Manifest build failed: exit={exc.code}", level="error"))
            prompt_utils.press_enter_to_continue()
            return
    print(status_messages.status("Manifest build completed.", level="success"))
    prompt_utils.press_enter_to_continue()


def _run_profile_v3_capture_status_dashboard() -> None:
    """Show per-app structural cohort capture readiness."""

    print()
    menu_utils.print_header("Structural Cohort Capture Status")
    script = Path(__file__).resolve().parents[2] / "scripts" / "profile_tools" / "profile_v3_capture_status.py"
    if not script.exists():
        print(status_messages.status(f"Missing script: {script}", level="error"))
        prompt_utils.press_enter_to_continue()
        return
    import runpy

    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as exc:
        # The dashboard may return non-zero in strict mode; do not treat that as a crash.
        code = int(getattr(exc, "code", 1) or 0)
        if code != 0:
            print(status_messages.status(f"Dashboard reported blockers (exit={code}).", level="warn"))
    prompt_utils.press_enter_to_continue()


def _run_profile_v3_recapture_plan_view() -> None:
    """Show the latest structural cohort recapture plan."""

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


def _legacy_structural_archive_menu(*, pause_if_verbose) -> None:
    options = [
        MenuOption("1", "Guided capture"),
        MenuOption("2", "Runbook"),
        MenuOption("3", "Recapture plan"),
        MenuOption("4", "Status dashboard"),
        MenuOption("5", "Integrity gates"),
        MenuOption("6", "Manifest build"),
    ]

    while True:
        print()
        menu_utils.print_header("Archived Structural Cohort")
        menu_utils.print_menu(options, show_exit=True, exit_label="Back", show_descriptions=False, compact=True)
        choice = prompt_utils.get_choice(menu_utils.selectable_keys(options, include_exit=True), default="0")
        if choice == "0":
            return
        if choice == "1":
            _run_profile_v3_guided_phase2_capture()
            pause_if_verbose()
            continue
        if choice == "2":
            _print_profile_v3_capture_runbook()
            pause_if_verbose()
            continue
        if choice == "3":
            _run_profile_v3_recapture_plan_view()
            pause_if_verbose()
            continue
        if choice == "4":
            _run_profile_v3_capture_status_dashboard()
            pause_if_verbose()
            continue
        if choice == "5":
            try:
                from scytaledroid.Reporting.menu_actions import handle_profile_v3_integrity_gates

                handle_profile_v3_integrity_gates()
            except Exception:
                print(status_messages.status("Failed to open structural archive integrity gates (Reporting).", level="error"))
                prompt_utils.press_enter_to_continue()
            pause_if_verbose()
            continue
        if choice == "6":
            _run_profile_v3_manifest_build()
            pause_if_verbose()
            continue


def dynamic_analysis_menu() -> None:
    from scytaledroid.Database.db_utils import schema_gate
    ok, message, detail = schema_gate.dynamic_schema_gate()
    if not ok:
        # Freeze/profile contract: evidence packs are authoritative; DB is a derived index.
        # Do not block capture/collection on DB readiness. Surface a warning and
        # allow DB-free workflows to proceed.
        status_messages.print_status(message, level="warn")
        if detail:
            status_messages.print_status(detail, level="warn")
        status_messages.print_status(
            "Note: DB-backed features may be unavailable. Dynamic capture and evidence-pack workflows remain enabled.",
            level="warn",
        )

    sections = build_dynamic_menu_sections()
    options = sections.all_options

    ui_defaults = _load_dynamic_ui_defaults()

    def _pause_if_verbose() -> None:
        # Operator default: do not force extra Enter presses between actions.
        # Details/debug users tend to want time to read the full tables.
        level = str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower()
        if level in {"details", "debug"}:
            prompt_utils.press_enter_to_continue()

    while True:
        print()
        menu_utils.print_header("Dynamic Analysis")
        _warn_if_code_changed()
        render_dynamic_menu_overview()
        print()
        menu_utils.print_section("Primary Actions")
        menu_utils.print_menu(sections.primary_actions, show_exit=False, show_descriptions=False, compact=True)
        menu_utils.print_section("Evidence & Integrity")
        menu_utils.print_menu(sections.evidence_integrity, show_exit=False, show_descriptions=False, compact=True)
        menu_utils.print_section("Exports")
        menu_utils.print_menu(sections.exports, show_exit=False, show_descriptions=False, compact=True)
        menu_utils.print_section("System")
        menu_utils.print_menu(
            sections.system,
            show_exit=False,
            show_descriptions=False,
            compact=True,
        )
        menu_utils.print_section("Legacy / Archive")
        menu_utils.print_menu(
            sections.legacy_archive,
            show_exit=True,
            exit_label="Back",
            show_descriptions=False,
            compact=True,
        )
        choice = prompt_utils.get_choice(
            menu_utils.selectable_keys(options, include_exit=True),
            disabled=[option.key for option in options if option.disabled],
        )

        if choice == "0":
            break

        if choice == "1":
            _warn_if_code_changed()
            _run_guided_dataset_run(ui_defaults)
            _pause_if_verbose()
            continue

        if choice == "2":
            _render_dataset_status()
            _pause_if_verbose()
            continue

        if choice == "3":
            _legacy_structural_archive_menu(pause_if_verbose=_pause_if_verbose)
            continue

        if choice == "4":
            _run_freeze_readiness_audit()
            _pause_if_verbose()
            continue

        if choice == "5":
            _repair_reindex_tracker()
            _pause_if_verbose()
            continue

        if choice == "6":
            _prune_incomplete_dynamic_evidence_dirs()
            _pause_if_verbose()
            continue

        if choice == "7":
            # Single canonical frozen-cohort export surface lives in Reporting.
            try:
                from scytaledroid.Reporting.menu_actions import handle_export_freeze_anchored_csvs

                handle_export_freeze_anchored_csvs()
            except Exception:
                print(status_messages.status("Failed to open export helper (Reporting).", level="error"))
            _pause_if_verbose()
            continue

        if choice == "8":
            _verify_host_pcap_tools()
            _pause_if_verbose()
            continue

        if choice == "9":
            _run_state_summary()
            _pause_if_verbose()
            continue


    return


def _prune_incomplete_dynamic_evidence_dirs() -> None:
    from scytaledroid.DynamicAnalysis.utils.run_cleanup import (
        find_incomplete_dynamic_run_dirs,
        prune_incomplete_dynamic_run_dirs,
    )

    print()
    menu_utils.print_header("Prune Incomplete Dynamic Evidence")
    incomplete = find_incomplete_dynamic_run_dirs()
    if not incomplete:
        print(status_messages.status("No incomplete evidence dirs found.", level="success"))
        print(status_messages.status("Next: run option 10 (State summary) before collection.", level="info"))
        return

    print(
        status_messages.status(
            f"Found {len(incomplete)} incomplete dir(s) missing run_manifest.json.",
            level="warn",
        )
    )
    preview = [p.name for p in incomplete[:10]]
    if preview:
        print(status_messages.status("Examples: " + ", ".join(preview), level="info"))
    confirmed = prompt_utils.prompt_yes_no("Delete these incomplete dirs now? (safe)", default=False)
    if not confirmed:
        print(status_messages.status("Prune canceled.", level="info"))
        return
    deleted = prune_incomplete_dynamic_run_dirs()
    remaining = len(find_incomplete_dynamic_run_dirs())
    print(
        status_messages.status(
            f"Deleted incomplete dirs: {deleted}. Remaining incomplete dirs: {remaining}.",
            level="success" if remaining == 0 else "warn",
        )
    )
    if remaining == 0:
        print(status_messages.status("Next: run option 10 (State summary) to verify CAN_FREEZE and blockers.", level="info"))
        if prompt_utils.prompt_yes_no("Run state summary now?", default=True):
            _run_state_summary()
    else:
        print(status_messages.status("Still blocked: cleanup remaining incomplete dirs before freeze/export.", level="warn"))


def _repair_reindex_tracker() -> None:
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
        DatasetTrackerConfig,
        load_dataset_tracker,
        recompute_dataset_tracker,
    )

    print()
    menu_utils.print_header("Repair/Reindex Tracker")
    cfg = DatasetTrackerConfig()
    tracker_before = load_dataset_tracker()
    before_apps = tracker_before.get("apps") if isinstance(tracker_before, dict) else {}
    before_runs = sum(
        len(v.get("runs", []))
        for v in before_apps.values()
        if isinstance(v, dict) and isinstance(v.get("runs"), list)
    ) if isinstance(before_apps, dict) else 0

    if before_runs > 0:
        print(
            status_messages.status(
                "Reindex rebuilds tracker from local evidence packs only and drops tracker-only historical rows.",
                level="warn",
            )
        )
        confirmed = prompt_utils.prompt_yes_no(
            f"Proceed with reindex? current tracker runs={before_runs}",
            default=False,
        )
        if not confirmed:
            print(status_messages.status("Reindex canceled.", level="info"))
            return

    out = recompute_dataset_tracker(config=cfg)
    if out is None:
        print(
            status_messages.status(
                "No dynamic evidence root found; cannot reindex tracker. Ensure output/evidence/dynamic exists.",
                level="error",
            )
        )
        return

    tracker_after = load_dataset_tracker()
    apps = tracker_after.get("apps") if isinstance(tracker_after, dict) else {}
    app_count = len(apps) if isinstance(apps, dict) else 0
    run_count = 0
    valid_count = 0
    missing_window_count = 0
    missing_paper_identity_count = 0
    for entry in (apps.values() if isinstance(apps, dict) else []):
        if not isinstance(entry, dict):
            continue
        runs = entry.get("runs")
        if not isinstance(runs, list):
            continue
        for r in runs:
            if not isinstance(r, dict):
                continue
            run_count += 1
            if r.get("valid_dataset_run") is not True:
                continue
            valid_count += 1
            if r.get("window_count") in (None, ""):
                missing_window_count += 1
            run_id = str(r.get("run_id") or "").strip()
            if not run_id:
                missing_paper_identity_count += 1
                continue
            manifest = _read_json(Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic" / run_id / "run_manifest.json") or {}
            plan = _read_json(Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic" / run_id / "inputs" / "static_dynamic_plan.json") or {}
            eligibility = derive_freeze_eligibility(
                manifest=manifest,
                plan=plan,
                min_windows=_min_windows_per_run(),
                required_capture_policy_version=int(profile_config.PAPER_CONTRACT_VERSION),
            )
            if not eligibility.paper_eligible and eligibility.reason_code == "EXCLUDED_MISSING_REQUIRED_IDENTITY_FIELD":
                missing_paper_identity_count += 1

    evidence_summary = _summarize_evidence_quota(
        {pkg.lower() for pkg in _load_dataset_packages()},
        cfg,
    )
    expected_runs = len(_load_dataset_packages()) * (int(cfg.baseline_required) + int(cfg.interactive_required))
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    report_path = Path(app_config.OUTPUT_DIR) / "audit" / "dynamic" / f"tracker_reindex_{stamp}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_payload = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "tracker_path": str(out),
        "tracker_before_runs": int(before_runs),
        "tracker_after_runs": int(run_count),
        "tracker_after_apps": int(app_count),
        "valid_runs": int(valid_count),
        "missing_window_count_in_valid_runs": int(missing_window_count),
        "missing_paper_identity_in_valid_runs": int(missing_paper_identity_count),
        "evidence_root_exists": bool(evidence_summary.get("evidence_root_exists")),
        "evidence_quota_runs_counted": int(evidence_summary.get("quota_runs_counted", 0)),
        "evidence_paper_eligible_runs": int(evidence_summary.get("paper_eligible_runs", 0)),
        "expected_runs": int(expected_runs),
    }
    report_path.write_text(json.dumps(report_payload, indent=2, sort_keys=True), encoding="utf-8")

    rows = [
        ("Tracker runs (before)", str(before_runs)),
        ("Tracker runs (after)", str(run_count)),
        ("Tracker apps (after)", str(app_count)),
        ("Valid runs (after)", str(valid_count)),
        ("Valid runs missing window_count", str(missing_window_count)),
        ("Valid runs missing required identity fields", str(missing_paper_identity_count)),
        ("Evidence quota counted", f"{int(evidence_summary.get('quota_runs_counted', 0))}/{expected_runs}"),
        ("Evidence eligible", str(int(evidence_summary.get("paper_eligible_runs", 0)))),
    ]
    ui_level = str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower()
    verbose = ui_level in {"details", "debug"}
    if verbose:
        table_utils.render_table(["Metric", "Count"], rows, compact=False)
    else:
        quota_line = next((v for k, v in rows if k == "Evidence quota counted"), "")
        print(
            status_messages.status(
                f"Reindex complete | runs={run_count} apps={app_count} valid={valid_count} | quota={quota_line}",
                level="success",
            )
        )
    print(status_messages.status(f"Tracker reindexed from evidence: {out}", level="success"))
    print(status_messages.status(f"Report: {report_path}", level="info"))


def _run_freeze_readiness_audit() -> None:
    from scytaledroid.DynamicAnalysis.menu_reports import run_freeze_readiness_audit_report

    run_freeze_readiness_audit_report()


def _run_state_summary() -> None:
    from scytaledroid.DynamicAnalysis.tools.evidence.freeze_readiness_audit import (
        run_freeze_readiness_audit,
    )
    from scytaledroid.DynamicAnalysis.menu_reports import run_state_summary_report
    from scytaledroid.DynamicAnalysis.tools.evidence.state_summary import build_state_summary

    summary = run_freeze_readiness_audit()
    payload = _read_json(Path(summary.report_path)) or {}
    state_payload = build_state_summary()
    delta_rows = _compute_tracker_vs_evidence_deltas()
    priorities = _build_collection_priorities(delta_rows)
    run_state_summary_report(
        summary=summary,
        payload=payload,
        state_payload=state_payload,
        delta_rows=delta_rows,
        priorities=priorities,
    )


def _compute_tracker_vs_evidence_deltas() -> list[dict[str, object]]:
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
        DatasetTrackerConfig,
        load_dataset_tracker,
    )

    cfg = DatasetTrackerConfig()
    tracker = load_dataset_tracker()
    tracker_apps = tracker.get("apps") if isinstance(tracker.get("apps"), dict) else {}
    dataset_pkgs = {str(pkg).strip().lower() for pkg in _load_dataset_packages() if str(pkg).strip()}
    root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    per_pkg: dict[str, dict[str, int]] = {}
    for pkg in dataset_pkgs:
        per_pkg[pkg] = {"base_eligible": 0, "inter_eligible": 0, "excluded": 0}
    if root.exists():
        for run_dir in sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name):
            manifest = _read_json(run_dir / "run_manifest.json")
            if not isinstance(manifest, dict):
                continue
            target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
            pkg = str(target.get("package_name") or "").strip().lower()
            if pkg not in dataset_pkgs:
                continue
            plan = _read_json(run_dir / "inputs" / "static_dynamic_plan.json") or {}
            eligibility = derive_freeze_eligibility(
                manifest=manifest,
                plan=plan,
                min_windows=_min_windows_per_run(),
                required_capture_policy_version=int(profile_config.PAPER_CONTRACT_VERSION),
            )
            if not eligibility.paper_eligible:
                per_pkg[pkg]["excluded"] += 1
                continue
            operator = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
            dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), dict) else {}
            bucket = _run_profile_bucket(str(operator.get("run_profile") or dataset.get("run_profile") or ""))
            if bucket == "baseline":
                per_pkg[pkg]["base_eligible"] += 1
            elif bucket == "interactive":
                per_pkg[pkg]["inter_eligible"] += 1
            else:
                per_pkg[pkg]["excluded"] += 1

    rows: list[dict[str, object]] = []
    for pkg in sorted(dataset_pkgs):
        entry = tracker_apps.get(pkg) if isinstance(tracker_apps, dict) else None
        tracker_base = int(entry.get("baseline_valid_runs") or 0) if isinstance(entry, dict) else 0
        tracker_inter = int(entry.get("interactive_valid_runs") or 0) if isinstance(entry, dict) else 0
        tracker_countable = tracker_base + tracker_inter
        base_eligible = int(per_pkg.get(pkg, {}).get("base_eligible", 0))
        inter_eligible = int(per_pkg.get(pkg, {}).get("inter_eligible", 0))
        evidence_countable = min(base_eligible, int(cfg.baseline_required)) + min(inter_eligible, int(cfg.interactive_required))
        need_baseline = max(0, int(cfg.baseline_required) - min(base_eligible, int(cfg.baseline_required)))
        need_interactive = max(0, int(cfg.interactive_required) - min(inter_eligible, int(cfg.interactive_required)))
        extras = max(0, base_eligible - int(cfg.baseline_required)) + max(0, inter_eligible - int(cfg.interactive_required))
        excluded = int(per_pkg.get(pkg, {}).get("excluded", 0))
        rows.append(
            {
                "Package": pkg,
                "Tracker countable": tracker_countable,
                "Evidence eligible countable": evidence_countable,
                "Need baseline": need_baseline,
                "Need interactive": need_interactive,
                "Extras": extras,
                "Excluded": excluded,
            }
        )
    return rows


def _build_collection_priorities(delta_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for row in delta_rows:
        need_b = int(row.get("Need baseline") or 0)
        need_i = int(row.get("Need interactive") or 0)
        total = need_b + need_i
        if total <= 0:
            continue
        next_action = _next_action_from_need(need_b, need_i)
        out.append(
            {
                "Package": row.get("Package"),
                "Need baseline": need_b,
                "Need interactive": need_i,
                "Total needed": total,
                "Suggested next": next_action,
            }
        )
    out.sort(key=lambda r: (-int(r["Total needed"]), str(r["Package"])))
    return out


def _next_action_from_need(need_baseline: int, need_interactive: int) -> str:
    nb = max(0, int(need_baseline))
    ni = max(0, int(need_interactive))
    if nb > 0:
        return "baseline"
    if ni > 0:
        return "scripted"
    # Quota satisfied: avoid implying additional action is required.
    return "—"


def _render_dataset_status() -> None:
    from scytaledroid.DynamicAnalysis.menu_reports import render_dataset_status

    render_dataset_status()


def _export_pcap_features_csv() -> None:
    from scytaledroid.DynamicAnalysis.pcap.aggregate import export_pcap_features_csv

    print()
    menu_utils.print_header("PCAP Features Export")
    freeze_path = Path(app_config.DATA_DIR) / "archive" / "dataset_freeze.json"
    try:
        output_path = export_pcap_features_csv(freeze_path=freeze_path, require_freeze=True)
    except RuntimeError as exc:
        print(status_messages.status(str(exc), level="error"))
        return
    if output_path is None:
        print(status_messages.status("No pcap_features.json files found.", level="warn"))
        return
    count = _count_csv_rows(output_path)
    msg = f"Exported CSV: {output_path} [frozen-archive]"
    if count is not None:
        msg += f" ({count} row(s))"
    print(status_messages.status(msg, level="success"))
    return

def _export_dynamic_run_summary_csv() -> None:
    from scytaledroid.DynamicAnalysis.pcap.aggregate import export_dynamic_run_summary_csv

    print()
    menu_utils.print_header("Run Summary Export")
    freeze_path = Path(app_config.DATA_DIR) / "archive" / "dataset_freeze.json"
    try:
        output_path = export_dynamic_run_summary_csv(freeze_path=freeze_path, require_freeze=True)
    except RuntimeError as exc:
        print(status_messages.status(str(exc), level="error"))
        return
    if output_path is None:
        print(status_messages.status("No dynamic run summaries found.", level="warn"))
        return
    count = _count_csv_rows(output_path)
    msg = f"Exported CSV: {output_path} [frozen-archive]"
    if count is not None:
        msg += f" ({count} row(s))"
    print(status_messages.status(msg, level="success"))


def _export_protocol_ledger_csv() -> None:
    from scytaledroid.DynamicAnalysis.pcap.aggregate import export_protocol_ledger_csv

    print()
    menu_utils.print_header("Protocol Ledger Export")
    freeze_path = Path(app_config.DATA_DIR) / "archive" / "dataset_freeze.json"
    try:
        output_path = export_protocol_ledger_csv(freeze_path=freeze_path, require_freeze=True)
    except RuntimeError as exc:
        print(status_messages.status(str(exc), level="error"))
        return
    if output_path is None:
        print(status_messages.status("No protocol ledger rows found.", level="warn"))
        return
    count = _count_csv_rows(output_path)
    msg = f"Exported CSV: {output_path} [frozen-archive]"
    if count is not None:
        msg += f" ({count} row(s))"
    print(status_messages.status(msg, level="success"))


def _count_csv_rows(path: Path) -> int | None:
    """Return data row count for a CSV (excluding header)."""
    try:
        with path.open("r", encoding="utf-8") as f:
            # cheap line count; subtract 1 for header
            n = sum(1 for _ in f)
        return max(0, n - 1)
    except Exception:
        return None


def _verify_host_pcap_tools() -> None:
    """Verify host toolchain required for dataset-tier PCAP post-analysis."""
    from scytaledroid.DynamicAnalysis.menu_reports import render_host_pcap_tools

    render_host_pcap_tools()


def _select_dynamic_target() -> tuple[str, str] | None:
    print()
    menu_utils.print_header("Dynamic Run Target")
    target_options = [
        MenuOption("1", "App (select from available artifacts)"),
        MenuOption("2", "Profile (select app from profile)"),
        MenuOption("3", "Custom package name"),
    ]
    target_spec = MenuSpec(items=target_options, exit_label="Cancel", show_exit=True)
    menu_utils.render_menu(target_spec)
    choice = prompt_utils.get_choice(
        menu_utils.selectable_keys(target_options, include_exit=True),
        default="1",
        disabled=[option.key for option in target_options if option.disabled],
    )
    if choice == "0":
        return None

    groups = group_artifacts()
    dataset_pkgs: set[str] = set()
    try:
        dataset_pkgs = {pkg.lower() for pkg in _load_dataset_packages()}
    except Exception:
        dataset_pkgs = set()

    if choice == "1":
        package_name = _select_package_from_groups(groups, title="App selection")
        if package_name:
            if package_name.lower() in dataset_pkgs:
                run_as_dataset = prompt_utils.prompt_yes_no(
                    "This app is in Research Dataset Alpha. Run as dataset tier?",
                    default=True,
                )
                return (package_name, "dataset" if run_as_dataset else "exploration")
            return (package_name, "exploration")
        package_name = _prompt_custom_package()
        if package_name:
            return _resolve_custom_tier(package_name, dataset_pkgs)
        return None

    if choice == "2":
        profile_selection = _select_profile_package(groups)
        if profile_selection:
            package_name, profile_key = profile_selection
            tier = "dataset" if profile_key == _DATASET_PROFILE_KEY else "exploration"
            return (package_name, tier)
        package_name = _prompt_custom_package()
        if package_name:
            return _resolve_custom_tier(package_name, dataset_pkgs)
        return None

    package_name = _prompt_custom_package()
    if package_name:
        return _resolve_custom_tier(package_name, dataset_pkgs)
    return None


def _resolve_plan_selection(package_name: str) -> dict[str, object] | None:
    candidates, note = _plan_selection._load_plan_candidates(package_name)
    if not candidates:
        return _prompt_missing_baseline(package_name, note)

    grouped: dict[str, list[dict[str, object]]] = {}
    for candidate in candidates:
        key = candidate["identity_key"]
        grouped.setdefault(key, []).append(candidate)

    if len(grouped) == 1:
        only_key = next(iter(grouped))
        selection = _plan_selection._pick_newest_candidate(grouped[only_key])
        return _plan_selection._build_selection(selection)

    return _prompt_baseline_selection(package_name, candidates)


def _run_guided_dataset_run(ui_defaults: _DynamicUiDefaults) -> None:
    run_guided_dataset_run(
        select_package_from_groups=_select_package_from_groups,
        select_observers=lambda device_serial, mode: _service_select_observers(
            device_serial,
            mode=mode,
            prompt_enabled=bool(ui_defaults.observer_prompts_enabled),
        ),
        print_device_badge=_print_device_badge,
        print_tier1_qa_result=_print_tier1_qa_result,
        observer_prompts_enabled=bool(ui_defaults.observer_prompts_enabled),
        pcapdroid_api_key=ui_defaults.pcapdroid_api_key,
    )


def _print_tier1_qa_result(dynamic_run_id: str) -> None:
    try:
        row = run_sql(
            """
            SELECT
              ds.dynamic_run_id,
              ds.status,
              ds.tier,
              ds.sampling_rate_s,
              ds.expected_samples,
              ds.captured_samples,
              ds.sample_max_gap_s,
              MAX(CASE WHEN i.issue_code = 'telemetry_partial_samples' THEN 1 ELSE 0 END) AS telemetry_partial
            FROM dynamic_sessions ds
            LEFT JOIN dynamic_session_issues i
              ON i.dynamic_run_id = ds.dynamic_run_id
            WHERE ds.dynamic_run_id = %s
            GROUP BY ds.dynamic_run_id, ds.status, ds.tier, ds.sampling_rate_s,
                     ds.expected_samples, ds.captured_samples, ds.sample_max_gap_s
            """,
            (dynamic_run_id,),
            fetch="one",
            dictionary=True,
        )
    except Exception as exc:  # noqa: BLE001
        print(
            status_messages.status(
                f"Tier-1 QA unavailable (DB error: {exc}).",
                level="warn",
            )
        )
        return
    if not row:
        print(status_messages.status("Tier-1 QA gate: NOT ENFORCED (dynamic).", level="info"))
        return

    failures = []
    if row.get("tier") != "dataset":
        failures.append("tier_not_dataset")
    if row.get("status") != "success":
        failures.append("status_not_success")
    ratio = _safe_ratio(row.get("captured_samples"), row.get("expected_samples"))
    if ratio is None:
        failures.append("missing_capture_ratio")
    elif ratio < 0.90:
        failures.append("low_capture_ratio")
    try:
        sampling_rate = float(row.get("sampling_rate_s"))
        max_gap = float(row.get("sample_max_gap_s"))
        if max_gap > (sampling_rate * 2):
            failures.append("max_gap_exceeded")
    except (TypeError, ValueError):
        failures.append("missing_gap_stats")
    if row.get("telemetry_partial"):
        failures.append("telemetry_partial_samples")

    if failures:
        print(
            status_messages.status(
                f"Tier-1 QA: FAIL ({', '.join(failures)}) [quality gate; does not override technical dataset validity]",
                level="warn",
            )
        )
    else:
        print(status_messages.status("Tier-1 QA: PASS", level="success"))


def _safe_ratio(captured: object, expected: object) -> float | None:
    try:
        cap = float(captured)
        exp = float(expected)
    except (TypeError, ValueError):
        return None
    if exp == 0:
        return None
    return cap / exp


def _resolve_custom_tier(package_name: str, dataset_pkgs: set[str]) -> tuple[str, str]:
    if package_name.lower() in dataset_pkgs:
        run_as_dataset = prompt_utils.prompt_yes_no(
            "This app is in Research Dataset Alpha. Run as dataset tier?",
            default=True,
        )
        return (package_name, "dataset" if run_as_dataset else "exploration")
    run_as_dataset = prompt_utils.prompt_yes_no(
        "Run this custom package as dataset tier?",
        default=False,
    )
    return (package_name, "dataset" if run_as_dataset else "exploration")


def _select_profile_package(groups) -> tuple[str, str | None] | None:
    categories = list_categories(groups)
    db_profiles = load_db_profiles()
    if not categories and not db_profiles:
        print(status_messages.status("No profile data available for selection.", level="warn"))
        return None
    print()
    print("Dynamic Run Scope (Profile)")
    print("-" * 86)
    available_counts = {label: count for label, count in categories}
    profile_rows = []
    for profile in db_profiles:
        profile_rows.append(
            {
                "label": profile["display_name"],
                "key": profile["profile_key"],
                "db_count": profile["app_count"],
                "available_count": available_counts.get(profile["display_name"], 0),
            }
        )
    for label, count in categories:
        if any(row["label"] == label for row in profile_rows):
            continue
        profile_rows.append(
            {
                "label": label,
                "key": None,
                "db_count": count,
                "available_count": count,
            }
        )
    profile_rows.sort(
        key=lambda row: (
            0 if row.get("key") == "RESEARCH_DATASET_ALPHA" else 1,
            row["label"].lower(),
        )
    )
    rows = [
        [str(idx), row["label"], str(row["db_count"]), str(row["available_count"])]
        for idx, row in enumerate(profile_rows, start=1)
    ]
    table_utils.render_table(["#", "Profile", "Apps (db)", "Available"], rows, compact=True)
    index = _choose_index("Select profile #", len(profile_rows))
    if index is None:
        return None
    selected = profile_rows[index]
    profile_key = selected.get("key")
    if profile_key:
        if profile_key == "RESEARCH_DATASET_ALPHA":
            try:
                from scytaledroid.Database.db_utils.menu_actions import ensure_dynamic_tier_column

                ensure_dynamic_tier_column(prompt_user=True)
            except Exception:
                print(
                    status_messages.status(
                        "Unable to verify dynamic_sessions.tier column; dataset tagging may be unavailable.",
                        level="warn",
                    )
                )
        packages = load_profile_packages(profile_key)
        if not packages:
            print(status_messages.status("No apps found for that profile.", level="warn"))
            return None
        available = {group.package_name.lower() for group in groups if group.package_name}
        scoped_groups = tuple(group for group in groups if group.package_name.lower() in available.intersection(packages))
        if not scoped_groups:
            print(
                status_messages.status(
                    "No APK artifacts available yet for that profile. Execute Harvest or use Custom package name.",
                    level="warn",
                )
            )
            return None
        package_name = _select_package_from_groups(scoped_groups, title=f"{selected['label']} apps")
        if not package_name:
            return None
        return (package_name, profile_key)
    category_name = selected["label"]
    profile_map = load_profile_map(groups)
    scoped_groups = tuple(
        group
        for group in groups
        if (
            profile_map.get(group.package_name.lower())
            or group.category
            or "Uncategorized"
        )
        == category_name
    )
    if not scoped_groups:
        print(status_messages.status("No apps found for that profile.", level="warn"))
        return None
    package_name = _select_package_from_groups(scoped_groups, title=f"{category_name} apps")
    if not package_name:
        return None
    return (package_name, None)


def _select_package_from_groups(groups, *, title: str) -> str | None:
    prepared = _prepare_package_selection_view(groups)
    if prepared is None:
        print(status_messages.status("No apps available for selection.", level="warn"))
        return None
    print()
    menu_utils.print_header(title)
    return _run_package_selection_menu(prepared)


def _prepare_package_selection_view(groups) -> _PreparedPackageSelectionView | None:
    packages = list_packages(groups)
    if not packages:
        return None
    dataset_pkgs: set[str] = set()
    try:
        dataset_pkgs = {pkg.lower() for pkg in _load_dataset_packages()}
    except Exception:
        dataset_pkgs = set()

    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
        DatasetTrackerConfig,
        load_dataset_tracker,
    )
    from scytaledroid.DynamicAnalysis.utils.run_cleanup import recent_tracker_runs
    from scytaledroid.Utils.DisplayUtils import text_blocks

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
        display = ((app_label or package).strip() or package)
        if str(package).strip().lower() == "com.twitter.android" and display.strip().lower() == "x":
            display = "X (Twitter)"
        if display in collisions:
            display = f"{display} ({package})"
        display = text_blocks.truncate_visible(display, 30)

        base_label = "—"
        inter_label = "—"
        scripted_label = "—"
        manual_label = "—"
        need_label = "—"
        next_label = "—"
        build_label = "—"
        total_label = "—"
        legacy_label = "—"
        last_label = "—"
        if package.lower() in dataset_pkgs:
            dataset_apps_total += 1
            entry = tracker_apps.get(package) if isinstance(tracker_apps, dict) else None
            runs = entry.get("runs") if isinstance(entry, dict) else []
            scoped = _build_scoped_dataset_counts(package, runs if isinstance(runs, list) else [], cfg=cfg)
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
            total_valid_runs = active_runs + legacy_valid

            base_label = str(base_countable) if base_extra <= 0 else f"{base_countable} (+{base_extra})"
            inter_label = str(inter_countable) if inter_extra <= 0 else f"{inter_countable} (+{inter_extra})"
            scripted_label = (
                str(scripted_countable) if scripted_extra <= 0 else f"{scripted_countable} (+{scripted_extra})"
            )
            manual_label = str(manual_countable) if manual_extra <= 0 else f"{manual_countable} (+{manual_extra})"
            need_base = max(0, int(cfg.baseline_required) - base_countable)
            need_inter = max(0, int(cfg.interactive_required) - inter_countable)
            if need_base == 0 and need_inter == 0:
                dataset_apps_complete += 1
            dataset_valid_runs_total += base_countable + inter_countable
            if need_base or need_inter:
                need_parts = []
                if need_base:
                    need_parts.append(f"{need_base}B")
                if need_inter:
                    need_parts.append(f"{need_inter}I")
                need_label = " ".join(need_parts)
            else:
                need_label = "0"
            technical_total = int(scoped.get("technical_valid_total") or total_valid_runs)
            total_label = str(technical_total)
            legacy_label = str(legacy_valid) if legacy_valid > 0 else "0"
            if active_runs > 0 and legacy_valid > 0:
                build_label = "MIX"
            elif active_runs > 0:
                build_label = "CUR"
            elif legacy_valid > 0:
                build_label = "OLD"
            else:
                build_label = "—"

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
                        recent_ident = _resolve_tracker_run_identity(package, recent_row)
                        active_ident = (
                            str(scoped.get("active_version_code") or "") or None,
                            str(scoped.get("active_base_sha") or "") or None,
                        )
                        if recent_ident != active_ident:
                            last_label = "valid (id_mismatch)"
            if legacy_valid > 0 and last_label != "—" and not last_label.endswith(" (L)"):
                last_label = f"{last_label} (L)"

            next_label = _next_action_from_need(need_base, need_inter)
            if need_label == "0":
                next_label = "—"
            build_rows.append([display, active_build, str(active_runs), str(legacy_valid), str(legacy_builds)])

        rows.append(
            [
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
            ]
        )
        op_rows.append(
            [
                str(idx),
                display,
                base_label,
                scripted_label,
                manual_label,
                need_label,
                next_label,
                build_label,
                total_label,
                last_label,
            ]
        )

    expected_runs = 0
    if dataset_apps_total > 0:
        evidence_summary = _summarize_evidence_quota(dataset_pkgs, cfg)
        expected_runs = dataset_apps_total * (int(cfg.baseline_required) + int(cfg.interactive_required))

    return _PreparedPackageSelectionView(
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


def _run_package_selection_menu(prepared: _PreparedPackageSelectionView) -> str | None:
    evidence_summary = prepared.evidence_summary
    if prepared.dataset_apps_total > 0:
        evidence_summary = evidence_summary or _summarize_evidence_quota(prepared.dataset_pkgs, prepared.cfg)
        quota = int(evidence_summary.get("quota_runs_counted", 0)) if evidence_summary else 0
        apps_ok = int(evidence_summary.get("apps_satisfied", 0)) if evidence_summary else 0
        freeze_ok = (
            bool(evidence_summary.get("evidence_root_exists"))
            and quota >= int(prepared.expected_runs)
            and apps_ok >= int(prepared.dataset_apps_total)
        ) if evidence_summary else False
        line = f"Evidence quota: {quota}/{prepared.expected_runs} | Apps satisfied: {apps_ok}/{prepared.dataset_apps_total}"
        if freeze_ok:
            line += " | Freeze: enabled"
        else:
            line += f" | Freeze: blocked ({max(0, int(prepared.expected_runs) - int(quota))} run(s) missing)"
        print(line)
        print()

    _render_package_table(
        prepared.op_rows,
        headers=["#", "App", "Baseline", "Scripted", "Manual", "Need", "Next", "Build", "Total", "QA"],
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
            index = _choose_index("Select app #", len(prepared.packages))
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


def _render_package_table(rows, *, headers: list[str] | None = None, max_preview: int = 15) -> None:
    headers = list(headers) if headers else ["#", "App"]
    if len(rows) <= max_preview:
        table_utils.render_table(headers, rows, compact=False)
        return
    preview = rows[:max_preview]
    table_utils.render_table(headers, preview, compact=False)
    response = prompt_utils.prompt_text("[L] List all | [Enter] Continue", required=False)
    if response.strip().lower() == "l":
        table_utils.render_table(headers, rows, compact=False)


def _build_scoped_dataset_counts(package_name: str, runs: list[dict], *, cfg: object | None = None) -> dict[str, int | str]:
    valid_runs: list[dict] = []
    for r in runs:
        if not isinstance(r, dict):
            continue
        if r.get("valid_dataset_run") is not True:
            continue
        valid_runs.append(r)

    # Determine active build identity from the most recent valid run that has identity fields.
    active_identity: tuple[str | None, str | None] | None = None
    for r in sorted(valid_runs, key=lambda row: str(row.get("ended_at") or row.get("started_at") or ""), reverse=True):
        ident = _resolve_tracker_run_identity(package_name, r)
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
        # Evidence-derived technical capture totals (informational lane).
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
        ident = _resolve_tracker_run_identity(package_name, r)
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
        # Quota-style tracker display should mirror paper-mode semantics: only
        # technically valid + paper-eligible runs participate in countable/extra
        # bucket math. Legacy rows may miss paper_eligible; treat missing as
        # backward-compatible "eligible unless explicitly false".
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


def _resolve_tracker_run_identity(package_name: str, run: dict) -> tuple[str | None, str | None]:
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
    cached = _RUN_IDENTITY_CACHE.get(run_id)
    if cached is not None:
        return cached

    manifest_path = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic" / run_id / "run_manifest.json"
    if not manifest_path.exists():
        _RUN_IDENTITY_CACHE[run_id] = (None, None)
        return (None, None)
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        _RUN_IDENTITY_CACHE[run_id] = (None, None)
        return (None, None)

    target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
    ident = target.get("run_identity") if isinstance(target.get("run_identity"), dict) else {}
    pkg = str(target.get("package_name") or package_name or "").strip().lower()
    if pkg and pkg != package_name.strip().lower():
        _RUN_IDENTITY_CACHE[run_id] = (None, None)
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
    _RUN_IDENTITY_CACHE[run_id] = resolved
    return resolved


def _choose_index(prompt: str, total: int) -> int | None:
    if total <= 0:
        return None
    options = [str(idx) for idx in range(1, total + 1)]
    choice = prompt_utils.get_choice(options + ["0"], default="1", prompt=f"{prompt} ")
    if choice == "0":
        return None
    return int(choice) - 1


def _prompt_custom_package() -> str:
    return prompt_utils.prompt_text(
        "Package name",
        required=True,
        error_message="Please provide a package name.",
    )


def _prompt_baseline_selection(
    package_name: str,
    candidates: list[dict[str, object]],
) -> dict[str, object] | None:
    return _plan_selection._prompt_baseline_selection(package_name, candidates)


def _prompt_missing_baseline(package_name: str, note: str | None) -> dict[str, object] | None:
    return _plan_selection._prompt_missing_baseline(package_name, note)

def _select_observers(device_serial: str, *, mode: str) -> list[str]:
    # Back-compat helper (used by older call sites/tests). Prefer passing a
    # closure from the menu with frozen UI defaults.
    return _service_select_observers(device_serial, mode=mode, prompt_enabled=False)


def _print_device_badge(device_serial: str, device_label: str) -> None:
    stats = adb_status.get_device_stats(device_serial)
    root_state = (stats.get("is_rooted") or "Unknown").strip().upper()
    if root_state == "YES":
        root_label = "yes"
    elif root_state == "NO":
        root_label = "no"
    else:
        root_label = "unknown"

    net_label = "unknown"
    try:
        status = adb_shell.run_shell(device_serial, ["dumpsys", "connectivity"]).lower()
        if "not connected" in status:
            net_label = "not_connected"
        elif "not_vpn" in status or "not vpn" in status:
            net_label = "not_vpn"
        elif "validated" in status:
            net_label = "validated"
    except Exception:
        net_label = "unknown"

    badge = f"Device: {device_label} | root: {root_label} | net: {net_label}"
    cached = _DEVICE_STATUS_CACHE.get(device_serial, {})
    if cached.get("badge") != badge:
        print(status_messages.status(badge, level="info"))
        cached["badge"] = badge
        _DEVICE_STATUS_CACHE[device_serial] = cached


def _print_root_status(device_serial: str, *, force: bool = False) -> bool:
    stats = adb_status.get_device_stats(device_serial)
    root_state = (stats.get("is_rooted") or "Unknown").strip().upper()
    if root_state == "YES":
        message = "Device root: YES (advanced capture available)."
        level = "success"
        is_rooted = True
    elif root_state == "NO":
        message = "Device root: NO (non-root mode)."
        level = "info"
        is_rooted = False
    else:
        message = "Device root: Unknown."
        level = "warn"
        is_rooted = False
    cached = _DEVICE_STATUS_CACHE.get(device_serial, {})
    if force or cached.get("root") != message:
        print(status_messages.status(message, level=level))
        cached["root"] = message
        _DEVICE_STATUS_CACHE[device_serial] = cached
    return is_rooted


def _print_network_status(device_serial: str, *, force: bool = False) -> None:
    details = []
    try:
        status = adb_shell.run_shell(device_serial, ["dumpsys", "connectivity"]).lower()
    except Exception:
        print(status_messages.status("Network status: unable to read connectivity state.", level="warn"))
        return
    if "validated" in status:
        details.append("validated")
    if "not_vpn" in status or "not vpn" in status:
        details.append("not_vpn")
    if "not connected" in status:
        print(status_messages.status("Network status: not connected.", level="warn"))
        return
    label = "Network status: " + (", ".join(details) if details else "unknown")
    cached = _DEVICE_STATUS_CACHE.get(device_serial, {})
    if force or cached.get("network") != label:
        print(status_messages.status(label, level="info"))
        cached["network"] = label
        _DEVICE_STATUS_CACHE[device_serial] = cached
