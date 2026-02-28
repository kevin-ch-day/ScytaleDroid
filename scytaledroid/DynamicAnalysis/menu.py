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
from scytaledroid.DynamicAnalysis.paper_eligibility import derive_paper_eligibility
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
        f"[WARN] Code changed on disk since this Dynamic Analysis menu started ({changed_list}).",
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
        eligibility = derive_paper_eligibility(
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


def _load_dynamic_ui_defaults() -> _DynamicUiDefaults:
    # UI-layer defaults only. Execution semantics must rely on the frozen config
    # carried in DynamicSessionConfig/RunContext and recorded in run_manifest.json.
    return _DynamicUiDefaults(
        observer_prompts_enabled=(os.environ.get("SCYTALEDROID_OBSERVER_PROMPTS") == "1"),
        pcapdroid_api_key=os.environ.get("SCYTALEDROID_PCAPDROID_API_KEY"),
    )

def _print_profile_v3_capture_runbook() -> None:
    """Print a concise operator runbook for Paper #3 dynamic capture."""

    print()
    menu_utils.print_header("Profile v3 Capture Runbook", "Paper #3 (scripted-only)")
    lines = [
        "Goal: collect paper-grade dynamic evidence for the v3 catalog cohort.",
        "",
        "Hard locks:",
        "- interaction is scripted-only for Paper #3 (no manual runs in the v3 manifest).",
        "- cohort is catalog-defined (profiles/profile_v3_app_catalog.json).",
        "",
        "Required per app (minimum):",
        "- baseline_idle run that passes min_windows/min_bytes gates",
        "- interaction_scripted run that passes min_windows/min_bytes gates",
        "",
        "Recommended order:",
        "1. Device Analysis: Sync inventory; Pull APKs -> Paper #3 Dataset (full refresh).",
        "2. Static Analysis: Run Profile v3 Structural Cohort (batch).",
        "3. Reporting: Run v3 integrity gates (freshness + scripted coverage).",
        "4. Dynamic Analysis: capture missing scripted runs (baseline_idle + interaction_scripted).",
        "5. Dynamic Analysis: Build v3 manifest (included runs).",
        "6. Reporting: Strict v3 export + strict lint -> READY.",
        "",
        "Notes:",
        "- If v3 exporter fails with included_run_ids=0, you have not built the manifest yet.",
        "- If scripted coverage gate FAILs, recapture scripted interaction for the listed apps.",
    ]
    for line in lines:
        print(status_messages.status(line, level="info") if line else "")
    prompt_utils.press_enter_to_continue()


def _run_profile_v3_manifest_build() -> None:
    """Build/update the v3 manifest (included runs list) from existing evidence packs."""

    print()
    menu_utils.print_header("Profile v3 Manifest Build")
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


def dynamic_analysis_menu() -> None:
    from scytaledroid.Database.db_utils import schema_gate
    ok, message, detail = schema_gate.dynamic_schema_gate()
    if not ok:
        # Freeze/profile contract: evidence packs are authoritative; DB is a derived index.
        # Do not block capture/collection on DB readiness. Surface a warning and
        # allow DB-free workflows to proceed.
        status_messages.print_status(f"[WARN] {message}", level="warn")
        if detail:
            status_messages.print_status(detail, level="warn")
        status_messages.print_status(
            "Note: DB-backed features may be unavailable. Dynamic capture and evidence-pack workflows remain enabled.",
            level="warn",
        )

    # Publication exports are consolidated under Reporting (single canonical surface).
    # Keep menu numbering sequential to avoid operator mistakes under time pressure.
    v2_options = [
        MenuOption("1", "Guided cohort run (Research Dataset Alpha)"),
        MenuOption("2", "Cohort status overview"),
    ]
    # Paper #3 uses the same capture engine but a different cohort contract and reporting outputs.
    # Keep the operator surface explicit so v2/v3 runs are not confused during demos.
    v3_options = [
        MenuOption("3", "Capture runbook (scripted-only)"),
        MenuOption("4", "Run integrity gates (Reporting)"),
        MenuOption("5", "Build v3 manifest (included runs)"),
    ]
    integrity_options = [
        MenuOption("6", "Freeze readiness audit (evidence packs)"),
        MenuOption("7", "Reindex/repair tracker from evidence packs"),
        MenuOption("8", "Prune incomplete dynamic evidence dirs"),
    ]
    reporting_options = [
        MenuOption("9", "Export freeze-anchored CSVs (Reporting)"),
    ]
    system_options = [
        MenuOption("10", "Verify host PCAP tools (tshark + capinfos)"),
        MenuOption("11", "State summary (freeze/evidence/tracker deltas)"),
    ]
    options = [
        *v2_options,
        *v3_options,
        *integrity_options,
        *reporting_options,
        *system_options,
    ]

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
        menu_utils.print_section("Profile v2 (Paper #2)")
        menu_utils.print_menu(v2_options, show_exit=False, show_descriptions=False, compact=True)
        menu_utils.print_section("Profile v3 (Paper #3)")
        menu_utils.print_menu(v3_options, show_exit=False, show_descriptions=False, compact=True)
        menu_utils.print_section("Integrity & Audit")
        menu_utils.print_menu(integrity_options, show_exit=False, show_descriptions=False, compact=True)
        menu_utils.print_section("Reporting")
        menu_utils.print_menu(reporting_options, show_exit=False, show_descriptions=False, compact=True)
        menu_utils.print_section("System")
        menu_utils.print_menu(
            system_options,
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
            _print_profile_v3_capture_runbook()
            _pause_if_verbose()
            continue

        if choice == "4":
            try:
                from scytaledroid.Reporting.menu_actions import handle_profile_v3_integrity_gates

                handle_profile_v3_integrity_gates()
            except Exception:
                print(status_messages.status("Failed to open v3 integrity gates (Reporting).", level="error"))
                prompt_utils.press_enter_to_continue()
            _pause_if_verbose()
            continue

        if choice == "5":
            _run_profile_v3_manifest_build()
            _pause_if_verbose()
            continue

        if choice == "6":
            _run_paper_readiness_audit()
            _pause_if_verbose()
            continue

        if choice == "7":
            _repair_reindex_tracker()
            _pause_if_verbose()
            continue

        if choice == "8":
            _prune_incomplete_dynamic_evidence_dirs()
            _pause_if_verbose()
            continue

        if choice == "9":
            # Single canonical paper-facing export surface lives in Reporting.
            try:
                from scytaledroid.Reporting.menu_actions import handle_export_freeze_anchored_csvs

                handle_export_freeze_anchored_csvs()
            except Exception:
                print(status_messages.status("Failed to open export helper (Reporting).", level="error"))
            _pause_if_verbose()
            continue

        if choice == "10":
            _verify_host_pcap_tools()
            _pause_if_verbose()
            continue

        if choice == "11":
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
            eligibility = derive_paper_eligibility(
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


def _run_paper_readiness_audit() -> None:
    from scytaledroid.DynamicAnalysis.tools.evidence.freeze_readiness_audit import (
        run_freeze_readiness_audit,
    )

    summary = run_freeze_readiness_audit()
    print()
    menu_utils.print_header("Freeze Readiness Audit")
    ui_level = str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower()
    verbose = ui_level in {"details", "debug"}
    if not verbose:
        verdict = "GO" if summary.result == "GO" else "NO-GO"
        can_freeze = "YES" if summary.can_freeze else "NO"
        msg = (
            f"Audit={verdict} | CAN_FREEZE={can_freeze} | "
            f"VALID={summary.valid_runs} | eligible={summary.paper_eligible_runs} | "
            f"missing_window_count={summary.missing_window_count} | identity_mismatch={summary.identity_mismatch}"
        )
        level = "success" if summary.result == "GO" else "error"
        print(status_messages.status(msg, level=level))
        if summary.first_failing_reason:
            print(status_messages.status(f"First failing reason: {summary.first_failing_reason}", level="warn"))
        if summary.report_path:
            print(status_messages.status(f"Report: {summary.report_path}", level="info"))
        return
    rows = [
        ("Total runs", str(summary.total_runs)),
        ("VALID runs", str(summary.valid_runs)),
        ("Cohort-eligible runs", str(summary.paper_eligible_runs)),
        ("CAN_FREEZE", "YES" if summary.can_freeze else "NO"),
        ("First failing reason", str(summary.first_failing_reason or "—")),
        ("Incomplete dirs (no manifest)", str(summary.missing_run_manifest_dirs)),
        ("Expected valid runs", str(summary.expected_valid_runs)),
        ("Expected total runs", str(summary.expected_total_runs)),
        ("Missing capture_policy_version", str(summary.missing_capture_policy_version)),
        ("capture_policy_version mismatch", str(summary.capture_policy_version_mismatch)),
        ("Missing signer_set_hash", str(summary.missing_signer_set_hash)),
        ("Identity mismatch", str(summary.identity_mismatch)),
        ("Missing window_count", str(summary.missing_window_count)),
        ("window_count < min", str(summary.window_count_below_min)),
        ("Canonical freeze role", str(summary.canonical_freeze_role)),
        ("Canonical freeze hash present", str(summary.canonical_freeze_contract_hash_present).lower()),
        ("Canonical freeze run IDs present", f"{summary.freeze_run_ids_present}/{summary.freeze_run_ids_total}"),
        ("Tracker runs (hint)", str(summary.tracker_runs_hint)),
        ("Static runs (hint)", str(summary.static_runs_hint)),
    ]
    table_utils.render_table(["Metric", "Count"], rows, compact=False)
    if summary.result != "GO":
        print(status_messages.status("Audit result: NO-GO (freeze readiness checks failed).", level="error"))
    else:
        print(status_messages.status("Audit result: GO (freeze readiness checks passed).", level="success"))
    if summary.reasons:
        reason_text = ", ".join(summary.reasons)
        print(status_messages.status(f"Reasons: {reason_text}", level="warn"))
    if "NO_EVIDENCE_PACKS_FOUND" in summary.reasons and summary.tracker_runs_hint > 0:
        print(
            status_messages.status(
                "Tracker contains historical runs but local evidence packs are missing. Recollect runs or repoint evidence root before freeze.",
                level="warn",
            )
        )
    if summary.missing_run_manifest_dirs > 0:
        print(
            status_messages.status(
                "Incomplete dynamic evidence directories detected (missing run_manifest.json). "
                "Clean up orphan run folders before freeze.",
                level="warn",
            )
        )
    if "NO_EVIDENCE_PACKS_FOUND" in summary.reasons and summary.static_runs_hint > 0:
        print(
            status_messages.status(
                "Static evidence packs were found in this workspace, but dynamic evidence packs were not. Run dynamic collection on this host or copy dynamic evidence packs before freeze.",
                level="warn",
            )
        )
    if summary.canonical_freeze_demoted_to_legacy:
        print(
            status_messages.status(
                f"Renamed stale dataset_freeze.json -> {summary.canonical_freeze_demoted_to_legacy} (blocked from export).",
                level="warn",
            )
        )
    print(status_messages.status(f"Evidence root: {summary.evidence_root}", level="info"))
    print(status_messages.status(f"Evidence root exists: {str(summary.evidence_root_exists).lower()}", level="info"))
    print(status_messages.status(f"Runs discovered from: {summary.runs_discovered_from}", level="info"))
    print(status_messages.status(f"Report: {summary.report_path}", level="info"))


def _run_state_summary() -> None:
    from scytaledroid.DynamicAnalysis.tools.evidence.freeze_readiness_audit import (
        run_freeze_readiness_audit,
    )
    from scytaledroid.DynamicAnalysis.tools.evidence.state_summary import build_state_summary

    summary = run_freeze_readiness_audit()
    payload = _read_json(Path(summary.report_path)) or {}
    state_payload = build_state_summary()
    print()
    menu_utils.print_header("State Summary")
    ui_level = str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower()
    verbose = ui_level in {"details", "debug"}
    if not verbose:
        line = (
            f"CAN_FREEZE={'YES' if summary.can_freeze else 'NO'}"
            f" | total_runs={summary.total_runs}"
            f" | eligible_runs={summary.paper_eligible_runs}"
        )
        if summary.first_failing_reason:
            line += f" | first_fail={summary.first_failing_reason}"
        print(status_messages.status(line, level="success" if summary.can_freeze else "warn"))
        print(status_messages.status(f"Audit report: {summary.report_path}", level="info"))
        return
    rows = [
        ("CAN_FREEZE", "YES" if summary.can_freeze else "NO"),
        ("First failing reason", str(summary.first_failing_reason or "—")),
        ("Canonical freeze role", str(summary.canonical_freeze_role)),
        ("Canonical freeze hash present", str(summary.canonical_freeze_contract_hash_present).lower()),
        ("Freeze run IDs present", f"{summary.freeze_run_ids_present}/{summary.freeze_run_ids_total}"),
        ("Evidence root", str(summary.evidence_root)),
        ("Total runs", str(summary.total_runs)),
        ("Cohort-eligible runs", str(summary.paper_eligible_runs)),
    ]
    table_utils.render_table(["Metric", "Value"], rows, compact=False)

    canonical = payload.get("canonical_freeze") if isinstance(payload.get("canonical_freeze"), dict) else {}
    presence = (
        canonical.get("run_id_presence_classification")
        if isinstance(canonical.get("run_id_presence_classification"), dict)
        else {}
    )
    if presence:
        print()
        menu_utils.print_header("Freeze Run-ID Presence")
        prow = [
            ("Total IDs", str(int(presence.get("total_run_ids") or 0))),
            ("Present run dirs", str(int(presence.get("present_run_dirs") or 0))),
            ("Missing run dirs", str(int(presence.get("missing_run_dirs") or 0))),
            ("Found but incomplete", str(int(presence.get("found_but_incomplete") or 0))),
            ("Missing required files", str(int(presence.get("found_but_missing_required_files") or 0))),
            ("Found but identity mismatch", str(int(presence.get("found_but_identity_mismatch") or 0))),
        ]
        table_utils.render_table(["Category", "Count"], prow, compact=False)

    exclusion_counts = payload.get("exclusion_reason_counts") if isinstance(payload.get("exclusion_reason_counts"), dict) else {}
    if exclusion_counts:
        print()
        menu_utils.print_header("Exclusion Reasons")
        erows = [[k, str(int(v))] for k, v in sorted(exclusion_counts.items(), key=lambda kv: (-int(kv[1]), str(kv[0])))]
        table_utils.render_table(["Reason", "Count"], erows, compact=False)

    baseline_signal = (
        state_payload.get("baseline_signal_summary")
        if isinstance(state_payload.get("baseline_signal_summary"), dict)
        else {}
    )
    if baseline_signal:
        print()
        menu_utils.print_header("Baseline Signal")
        by_cat = (
            baseline_signal.get("baseline_idle_failures_by_category")
            if isinstance(baseline_signal.get("baseline_idle_failures_by_category"), dict)
            else {}
        )
        brows = [[f"baseline_idle failures ({k})", str(int(v))] for k, v in sorted(by_cat.items())]
        brows.append(
            [
                "baseline_connected successes",
                str(int(baseline_signal.get("baseline_connected_successes") or 0)),
            ]
        )
        table_utils.render_table(["Metric", "Count"], brows, compact=False)

    delta_rows = _compute_tracker_vs_evidence_deltas()
    if delta_rows:
        print()
        menu_utils.print_header("Tracker vs Evidence (Per App)")
        table_utils.print_table(
            delta_rows,
            headers=[
                "Package",
                "Tracker countable",
                "Evidence eligible countable",
                "Extras",
                "Excluded",
            ],
        )
        priorities = _build_collection_priorities(delta_rows)
        if priorities:
            print()
            menu_utils.print_header("Next Collection Priorities")
            table_utils.print_table(
                priorities,
                headers=[
                    "Package",
                    "Need baseline",
                    "Need interactive",
                    "Total needed",
                    "Suggested next",
                ],
            )
    print(status_messages.status(f"Audit report: {summary.report_path}", level="info"))


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
            eligibility = derive_paper_eligibility(
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
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import load_dataset_tracker

    print()
    menu_utils.print_header("Dataset Run Status")
    payload = load_dataset_tracker()
    apps = payload.get("apps", {})
    rows = []
    for package, entry in sorted(apps.items()):
        runs = int(entry.get("run_count") or 0)
        valid = int(entry.get("valid_runs") or 0)
        target = int(entry.get("target_runs") or 0)
        base = int(entry.get("baseline_valid_runs") or 0)
        inter = int(entry.get("interactive_valid_runs") or 0)
        extra = int(entry.get("extra_valid_runs") or 0)
        quota_met_at = entry.get("quota_met_at") or ""
        status = "DONE" if entry.get("app_complete") else "IN_PROGRESS"
        rows.append(
            {
                "Package": package,
                "Valid": valid,
                "Base": base,
                "Inter": inter,
                "Runs": runs,
                "Target": target,
                "Extra": extra,
                "Quota met at": str(quota_met_at),
                "Status": status,
            }
        )
    if not rows:
        print(status_messages.status("No dataset runs recorded yet.", level="info"))
        return
    table_utils.print_table(
        rows,
        headers=["Package", "Valid", "Base", "Inter", "Runs", "Target", "Extra", "Quota met at", "Status"],
    )


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
    msg = f"Exported CSV: {output_path} [freeze-anchored]"
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
    msg = f"Exported CSV: {output_path} [freeze-anchored]"
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
    msg = f"Exported CSV: {output_path} [freeze-anchored]"
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
    from pathlib import Path

    from scytaledroid.DynamicAnalysis.pcap.tools import collect_host_tools, missing_required_tools

    print()
    menu_utils.print_header("Host PCAP Tools")
    tools = collect_host_tools()
    missing = missing_required_tools(tier="dataset")
    ui_level = str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower()
    verbose = ui_level in {"details", "debug"}
    if not verbose and not missing:
        tshark_path = ((tools.get("tshark") or {}) if isinstance(tools, dict) else {}).get("path")
        capinfos_path = ((tools.get("capinfos") or {}) if isinstance(tools, dict) else {}).get("path")
        tshark_ok = "OK" if tshark_path else "MISSING"
        capinfos_ok = "OK" if capinfos_path else "MISSING"
        print(status_messages.status(f"tshark={tshark_ok} | capinfos={capinfos_ok}", level="success"))
        print(status_messages.status("Host toolchain is dataset-ready.", level="success"))
        return
    for name in ("tshark", "capinfos"):
        meta = tools.get(name) if isinstance(tools, dict) else None
        path = meta.get("path") if isinstance(meta, dict) else None
        version = meta.get("version") if isinstance(meta, dict) else None
        if path:
            print(status_messages.status(f"{name}: OK ({path})", level="success"))
            if verbose and version:
                print(status_messages.status(f"{name}: {version}", level="info"))
        else:
            print(status_messages.status(f"{name}: MISSING", level="warn"))

    script = Path("scripts/install_wireshark_cli.sh")
    if missing:
        if script.exists():
            print(
                status_messages.status(
                    "Fix: install required tools with: sudo scripts/install_wireshark_cli.sh",
                    level="warn",
                )
            )
        else:
            print(
                status_messages.status(
                    "Fix: install wireshark-cli (tshark + capinfos) using your OS package manager.",
                    level="warn",
                )
            )
    else:
        print(status_messages.status("Host toolchain is dataset-ready.", level="success"))


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
                    "No APK artifacts available yet for that profile. Pull APKs or use Custom package name.",
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
    packages = list_packages(groups)
    if not packages:
        print(status_messages.status("No apps available for selection.", level="warn"))
        return None
    print()
    menu_utils.print_header(title)
    # Dataset progress columns (valid runs + suggested next profile) help operators
    # track collection without opening the tracker view.
    dataset_pkgs: set[str] = set()
    try:
        dataset_pkgs = {pkg.lower() for pkg in _load_dataset_packages()}
    except Exception:
        dataset_pkgs = set()

    # Lazy imports avoid unnecessary module work for non-dataset menus.
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
        DatasetTrackerConfig,
        load_dataset_tracker,
    )
    from scytaledroid.DynamicAnalysis.utils.run_cleanup import recent_tracker_runs
    from scytaledroid.Utils.DisplayUtils import text_blocks

    cfg = DatasetTrackerConfig()
    tracker = load_dataset_tracker()
    tracker_apps = tracker.get("apps") if isinstance(tracker, dict) else {}

    # Prefer human-friendly app labels in the table. If labels collide, append the
    # package name so operators can disambiguate.
    labels = [((app_label or package).strip() or package) for package, _v, _c, app_label in packages]
    collisions = {label for label in labels if labels.count(label) > 1}

    rows = []  # full table (debug/details)
    op_rows = []  # operator-default table
    build_rows = []
    dataset_apps_total = 0
    dataset_apps_complete = 0
    dataset_valid_runs_total = 0
    dataset_window_count_total = 0
    dataset_window_count_missing = 0
    evidence_summary: dict[str, int | bool] | None = None
    for idx, (package, _version, _count, app_label) in enumerate(packages, start=1):
        display = ((app_label or package).strip() or package)
        if str(package).strip().lower() == "com.twitter.android" and display.strip().lower() == "x":
            display = "X (Twitter)"
        if display in collisions:
            display = f"{display} ({package})"
        # Keep app labels readable without overloading the main run-selection view.
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
            # Important: the dataset tracker deterministically counts only the
            # first N valid runs per bucket (baseline/interactive). Operators can
            # still collect extra valid runs for exploration. To avoid confusion,
            # show "countable(+extra)" here rather than a quota-style "x/y".
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
            # Total should reflect technical capture volume, not just paper-eligible quota math.
            # Baseline/Interactive show countable(+extra) for the active build cohort.
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
                    last_label = "VALID"
                elif r.valid is False:
                    last_label = "INVALID"
                else:
                    last_label = "UNKNOWN"
                if (
                    last_label == "VALID"
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
                            last_label = "VALID (ID_MISMATCH)"
            if legacy_valid > 0 and last_label != "—":
                if not last_label.endswith(" (L)"):
                    last_label = f"{last_label} (L)"

            # Keep "Next Action" deterministic from displayed need to avoid
            # confusion when tracker recommendation and scoped display diverge.
            next_label = _next_action_from_need(need_base, need_inter)
            # When quota is satisfied, avoid showing an action label in the table.
            if need_label == "0":
                next_label = "—"
            build_rows.append(
                [
                    display,
                    active_build,
                    str(active_runs),
                    str(legacy_valid),
                    str(legacy_builds),
                ]
            )
            if isinstance(runs, list):
                for run in runs:
                    if not isinstance(run, dict):
                        continue
                    if run.get("valid_dataset_run") is not True:
                        continue
                    wc_raw = run.get("window_count")
                    if wc_raw in (None, ""):
                        dataset_window_count_missing += 1
                        continue
                    try:
                        wc = int(wc_raw)
                    except Exception:
                        dataset_window_count_missing += 1
                        continue
                    dataset_window_count_total += max(0, wc)

        full_row = [
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
        rows.append(full_row)
        # Operator view: include a few high-signal columns without dumping the full debug table.
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

    if dataset_apps_total > 0:
        evidence_summary = _summarize_evidence_quota(dataset_pkgs, cfg)
        expected_runs = dataset_apps_total * (int(cfg.baseline_required) + int(cfg.interactive_required))
        quota = int(evidence_summary.get("quota_runs_counted", 0))
        apps_ok = int(evidence_summary.get("apps_satisfied", 0))
        freeze_ok = bool(evidence_summary.get("evidence_root_exists")) and quota >= int(expected_runs) and apps_ok >= int(dataset_apps_total)
        paper_line = f"Evidence quota: {quota}/{expected_runs} | Apps satisfied: {apps_ok}/{dataset_apps_total}"
        if freeze_ok:
            paper_line += " | Freeze: Allowed"
        else:
            paper_line += f" | Freeze: BLOCKED ({max(0, int(expected_runs) - int(quota))} run(s) missing)"
        print(paper_line)
        print()

    _render_package_table(op_rows, headers=["#", "App", "Baseline", "Scripted", "Manual", "Need", "Next", "Build", "Total", "QA"])

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
            index = _choose_index("Select app #", len(packages))
            if index is None:
                return None
            package_name, _, _, _ = packages[index]
            return package_name
        if choice == "2":
            print()
            menu_utils.print_header("Details", "Tracker vs evidence (compact)")
            if dataset_apps_total > 0:
                evidence_summary = evidence_summary or _summarize_evidence_quota(dataset_pkgs, cfg)
                expected_runs = dataset_apps_total * (int(cfg.baseline_required) + int(cfg.interactive_required))
                print("Tracker (informational)")
                print(f"  Apps satisfied  : {dataset_apps_complete} / {dataset_apps_total}")
                print(f"  Valid runs      : {dataset_valid_runs_total} / {expected_runs}")
                print("Evidence (authoritative)")
                print(f"  Apps satisfied  : {int(evidence_summary.get('apps_satisfied', 0))} / {dataset_apps_total}")
                print(f"  Eligible counted: {int(evidence_summary.get('quota_runs_counted', 0))} / {expected_runs}")
                print(f"  Eligible found  : {int(evidence_summary.get('paper_eligible_runs', 0))}")
                print(f"  Extras          : {int(evidence_summary.get('extra_eligible_runs', 0))}")
                print(f"  Excluded        : {int(evidence_summary.get('excluded_runs', 0))}")
                if int(evidence_summary.get("protocol_fit_poor_runs", 0)) > 0:
                    print(f"  Protocol fit poor: {int(evidence_summary.get('protocol_fit_poor_runs', 0))} (flagged)")
                if int(evidence_summary.get("low_signal_exploratory_runs", 0)) > 0:
                    print(f"  Low-signal (exploratory): {int(evidence_summary.get('low_signal_exploratory_runs', 0))}")
            prompt_utils.press_enter_to_continue()
            continue
        if choice == "3":
            print()
            menu_utils.print_header("Build History Details")
            table_utils.render_table(
                ["App", "Identity (vc/base)", "Active Runs", "Legacy Runs", "Legacy Builds"],
                build_rows,
                compact=True,
            )
            prompt_utils.press_enter_to_continue()
            continue
        if choice == "4":
            print()
            menu_utils.print_header("Help", "Legend (short)")
            print("Baseline / Interactive = countable valid runs for active build")
            print("Scripted / Manual      = interactive run breakdown (countable(+extra))")
            print("(+N)                   = extra valid runs (not quota-counted)")
            print("Need                   = remaining quota slots for this package")
            print("Next                   = deterministic suggestion from Need")
            print("Build                  = CUR(current build) | OLD(legacy only) | MIX(both)")
            print("Total                  = technically VALID evidence packs found (includes excluded/exploratory)")
            print("QA                     = latest tracker QA status (may include identity mismatch note)")
            prompt_utils.press_enter_to_continue()
            continue
        if choice == "5":
            print()
            menu_utils.print_header("Debug", "Full table + legacy/QA fields")
            _render_package_table(
                rows,
                headers=["#", "App", "Baseline", "Interactive", "Need", "Next Action", "Build", "Total", "Legacy", "Last QA"],
            )
            prompt_utils.press_enter_to_continue()
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
