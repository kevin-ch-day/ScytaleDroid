"""Dynamic analysis menu scaffolding."""

from __future__ import annotations

import os
import json
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
from scytaledroid.DynamicAnalysis.ml import ml_parameters_paper2 as paper2_config
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
        "paper_eligible_runs": 0,
        "quota_runs_counted": 0,
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
            required_capture_policy_version=int(paper2_config.PAPER_CONTRACT_VERSION),
        )
        if not eligibility.paper_eligible:
            continue
        out["paper_eligible_runs"] = int(out["paper_eligible_runs"]) + 1
        bucket = _run_profile_bucket(
            str(dataset.get("run_profile") or operator.get("run_profile") or "")
        )
        if bucket == "unknown":
            continue
        pkg_counts = per_pkg.setdefault(package, {"baseline": 0, "interactive": 0})
        needed = int(cfg.baseline_required if bucket == "baseline" else cfg.interactive_required)
        if int(pkg_counts.get(bucket, 0)) < needed:
            pkg_counts[bucket] = int(pkg_counts.get(bucket, 0)) + 1
            out["quota_runs_counted"] = int(out["quota_runs_counted"]) + 1
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


def dynamic_analysis_menu() -> None:
    from scytaledroid.Database.db_utils import schema_gate
    ok, message, detail = schema_gate.dynamic_schema_gate()
    if not ok:
        # Paper #2 contract: evidence packs are authoritative; DB is a derived index.
        # Do not block capture/collection on DB readiness. Surface a warning and
        # allow DB-free workflows to proceed.
        status_messages.print_status(f"[WARN] {message}", level="warn")
        if detail:
            status_messages.print_status(detail, level="warn")
        status_messages.print_status(
            "Note: DB-backed features may be unavailable. Dynamic capture and evidence-pack workflows remain enabled.",
            level="warn",
        )

    options = [
        MenuOption("1", "Run Research Dataset Alpha (guided)"),
        MenuOption("2", "Dataset run status"),
        MenuOption("3", "Export run summary CSV"),
        MenuOption("4", "Export PCAP features CSV"),
        MenuOption("5", "Verify host PCAP tools (tshark + capinfos)"),
        MenuOption("6", "Paper readiness audit (evidence packs)"),
        MenuOption("7", "Repair/reindex tracker from evidence packs"),
    ]

    ui_defaults = _load_dynamic_ui_defaults()

    while True:
        print()
        menu_utils.print_header("Dynamic Analysis")
        spec = MenuSpec(items=options, exit_label="Back", show_exit=True)
        menu_utils.render_menu(spec)
        choice = prompt_utils.get_choice(
            menu_utils.selectable_keys(options, include_exit=True),
            disabled=[option.key for option in options if option.disabled],
        )

        if choice == "0":
            break

        if choice == "1":
            _run_guided_dataset_run(ui_defaults)
            prompt_utils.press_enter_to_continue()
            continue

        if choice == "2":
            _render_dataset_status()
            prompt_utils.press_enter_to_continue()
            continue

        if choice == "3":
            _export_dynamic_run_summary_csv()
            prompt_utils.press_enter_to_continue()
            continue

        if choice == "4":
            _export_pcap_features_csv()
            prompt_utils.press_enter_to_continue()
            continue

        if choice == "5":
            _verify_host_pcap_tools()
            prompt_utils.press_enter_to_continue()
            continue
        if choice == "6":
            _run_paper_readiness_audit()
            prompt_utils.press_enter_to_continue()
            continue
        if choice == "7":
            _repair_reindex_tracker()
            prompt_utils.press_enter_to_continue()
            continue


    return


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
                required_capture_policy_version=int(paper2_config.PAPER_CONTRACT_VERSION),
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
        ("Valid runs missing paper identity/link", str(missing_paper_identity_count)),
        ("Evidence quota counted", f"{int(evidence_summary.get('quota_runs_counted', 0))}/{expected_runs}"),
        ("Evidence paper-eligible", str(int(evidence_summary.get("paper_eligible_runs", 0)))),
    ]
    table_utils.render_table(["Metric", "Count"], rows, compact=False)
    print(status_messages.status(f"Tracker reindexed from evidence: {out}", level="success"))
    print(status_messages.status(f"Report: {report_path}", level="info"))


def _run_paper_readiness_audit() -> None:
    from scytaledroid.DynamicAnalysis.tools.evidence.paper_readiness_audit import (
        run_paper_readiness_audit,
    )

    summary = run_paper_readiness_audit()
    print()
    menu_utils.print_header("Paper Readiness Audit")
    rows = [
        ("Total runs", str(summary.total_runs)),
        ("VALID runs", str(summary.valid_runs)),
        ("Expected valid runs", str(summary.expected_valid_runs)),
        ("Expected total runs", str(summary.expected_total_runs)),
        ("Missing capture_policy_version", str(summary.missing_capture_policy_version)),
        ("capture_policy_version mismatch", str(summary.capture_policy_version_mismatch)),
        ("Missing signer_set_hash", str(summary.missing_signer_set_hash)),
        ("Missing window_count", str(summary.missing_window_count)),
        ("window_count < min", str(summary.window_count_below_min)),
        ("Tracker runs (hint)", str(summary.tracker_runs_hint)),
        ("Static runs (hint)", str(summary.static_runs_hint)),
    ]
    table_utils.render_table(["Metric", "Count"], rows, compact=False)
    if summary.result != "GO":
        print(status_messages.status("Audit result: NO-GO (paper-readiness checks failed).", level="error"))
    else:
        print(status_messages.status("Audit result: GO (paper-readiness checks passed).", level="success"))
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
    if "NO_EVIDENCE_PACKS_FOUND" in summary.reasons and summary.static_runs_hint > 0:
        print(
            status_messages.status(
                "Static evidence packs were found in this workspace, but dynamic evidence packs were not. Run dynamic collection on this host or copy dynamic evidence packs before freeze.",
                level="warn",
            )
        )
    print(status_messages.status(f"Evidence root: {summary.evidence_root}", level="info"))
    print(status_messages.status(f"Evidence root exists: {str(summary.evidence_root_exists).lower()}", level="info"))
    print(status_messages.status(f"Runs discovered from: {summary.runs_discovered_from}", level="info"))
    print(status_messages.status(f"Report: {summary.report_path}", level="info"))


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
    output_path = export_pcap_features_csv()
    if output_path is None:
        print(status_messages.status("No pcap_features.json files found.", level="warn"))
        return
    count = _count_csv_rows(output_path)
    msg = f"Exported CSV: {output_path}"
    if count is not None:
        msg += f" ({count} row(s))"
    print(status_messages.status(msg, level="success"))
    return

def _export_dynamic_run_summary_csv() -> None:
    from scytaledroid.DynamicAnalysis.pcap.aggregate import export_dynamic_run_summary_csv

    print()
    menu_utils.print_header("Run Summary Export")
    output_path = export_dynamic_run_summary_csv()
    if output_path is None:
        print(status_messages.status("No dynamic run summaries found.", level="warn"))
        return
    count = _count_csv_rows(output_path)
    msg = f"Exported CSV: {output_path}"
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
    for name in ("tshark", "capinfos"):
        meta = tools.get(name) if isinstance(tools, dict) else None
        path = meta.get("path") if isinstance(meta, dict) else None
        version = meta.get("version") if isinstance(meta, dict) else None
        if path:
            print(status_messages.status(f"{name}: OK ({path})", level="success"))
            if version:
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
                f"Tier-1 QA: FAIL ({', '.join(failures)})",
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
    menu_utils.print_header(title, "Select a package to run")
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
        peek_next_run_protocol,
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

    rows = []
    build_rows = []
    dataset_apps_total = 0
    dataset_apps_complete = 0
    dataset_valid_runs_total = 0
    dataset_window_count_total = 0
    dataset_window_count_missing = 0
    evidence_summary: dict[str, int | bool] | None = None
    for idx, (package, _version, _count, app_label) in enumerate(packages, start=1):
        display = ((app_label or package).strip() or package)
        if display in collisions:
            display = f"{display} ({package})"
        # Keep dataset selection tables readable on narrower terminals. We bias
        # the width budget toward progress columns ("Base/Int/Next") so they
        # don't get truncated into "interact…".
        display = text_blocks.truncate_visible(display, 26)

        base_label = "—"
        inter_label = "—"
        need_label = "—"
        runs_label = "—"
        hist_label = "—"
        last_label = "—"
        next_label = "—"
        if package.lower() in dataset_pkgs:
            dataset_apps_total += 1
            # Important: the dataset tracker deterministically counts only the
            # first N valid runs per bucket (baseline/interactive). Operators can
            # still collect extra valid runs for exploration. To avoid confusion,
            # show "countable(+extra)" here rather than a quota-style "x/y".
            entry = tracker_apps.get(package) if isinstance(tracker_apps, dict) else None
            runs = entry.get("runs") if isinstance(entry, dict) else []
            total_runs = len(runs) if isinstance(runs, list) else 0
            scoped = _build_scoped_dataset_counts(package, runs if isinstance(runs, list) else [])
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

            base_label = str(base_countable) if base_extra <= 0 else f"{base_countable}(+{base_extra})"
            inter_label = str(inter_countable) if inter_extra <= 0 else f"{inter_countable}(+{inter_extra})"
            need_base = max(0, int(cfg.baseline_required) - base_countable)
            need_inter = max(0, int(cfg.interactive_required) - inter_countable)
            if need_base == 0 and need_inter == 0:
                dataset_apps_complete += 1
            dataset_valid_runs_total += base_countable + inter_countable
            if need_base or need_inter:
                need_parts = []
                if need_base:
                    need_parts.append(f"B{need_base}")
                if need_inter:
                    need_parts.append(f"I{need_inter}")
                need_label = " ".join(need_parts)
            else:
                need_label = "0"
            runs_label = str(total_runs)
            hist_label = str(legacy_valid) if legacy_valid > 0 else "0"
            recent = recent_tracker_runs(package, limit=1)
            if recent:
                r = recent[0]
                if r.valid is True:
                    last_label = "VALID"
                elif r.valid is False:
                    # Keep the selection table compact; detailed reason codes are
                    # visible in Recent Runs and per-run summaries.
                    last_label = "INVALID"
                else:
                    last_label = "UNKNOWN"
            if legacy_valid > 0 and last_label != "—":
                last_label = f"{last_label}*"
            proto = peek_next_run_protocol(package, tier="dataset") or {}
            prof = (proto.get("run_profile") or "").lower()
            if "baseline" in prof or "idle" in prof:
                next_label = "base"
            elif "scripted" in prof:
                next_label = "script"
            elif "manual" in prof:
                next_label = "manual"
            elif prof:
                next_label = "inter"
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

        # Columns are intentionally minimal for dataset collection.
        # Column order is chosen to avoid "Next" being truncated on narrow terminals.
        rows.append([str(idx), display, base_label, inter_label, need_label, next_label, runs_label, hist_label, last_label])
    _render_package_table(rows)
    if any(r[2] != "—" for r in rows):
        print(
            status_messages.status(
                "Note: Baseline/Interactive show countable valid runs; '(+N)' indicates extra valid runs (kept, out-of-dataset).",
                level="info",
            )
        )
        print(
            status_messages.status(
                "Build-scoped view: counts are computed for the latest app build identity; '*' in Last QA indicates legacy valid runs from older builds exist.",
                level="info",
            )
        )
        print(
            "Legacy column shows valid older-build runs retained for cross-version pattern analysis (not counted toward current-build quota)."
        )
        print(
            "Last QA is derived from post-run integrity checks (PCAP threshold, capinfos/tshark parse, feature extraction, minimum window count)."
        )
        if dataset_apps_total > 0:
            evidence_summary = _summarize_evidence_quota(dataset_pkgs, cfg)
            expected_runs = dataset_apps_total * (int(cfg.baseline_required) + int(cfg.interactive_required))
            if dataset_window_count_missing > 0:
                tracker_windows_label = f"? (missing window_count in {dataset_window_count_missing} run(s))"
            else:
                tracker_windows_label = str(dataset_window_count_total)
            print(
                f"Tracker quota (informational): {dataset_apps_complete}/{dataset_apps_total} apps satisfied | valid runs={dataset_valid_runs_total}/{expected_runs} | total windows={tracker_windows_label}"
            )
            print(
                f"Evidence quota (authoritative): valid runs={int(evidence_summary['quota_runs_counted'])}/{expected_runs} | paper-eligible runs discovered={int(evidence_summary['paper_eligible_runs'])}"
            )
            if not bool(evidence_summary.get("evidence_root_exists")):
                print(
                    status_messages.status(
                        "Evidence root missing; paper-mode freeze is blocked until dynamic evidence packs are available.",
                        level="warn",
                    )
                )
        data_rows = [r for r in rows if r[2] != "—"]
        evidence_ready = False
        if dataset_apps_total > 0 and evidence_summary is not None:
            expected_runs = dataset_apps_total * (int(cfg.baseline_required) + int(cfg.interactive_required))
            evidence_ready = bool(evidence_summary.get("evidence_root_exists")) and int(evidence_summary.get("quota_runs_counted", 0)) >= expected_runs
        if data_rows and all(str(r[4]).strip() == "0" for r in data_rows) and evidence_ready:
            print(status_messages.status("Dataset status: QUOTA SATISFIED. Freeze recommended.", level="success"))
        elif data_rows and all(str(r[4]).strip() == "0" for r in data_rows):
            print(
                status_messages.status(
                    "Tracker quota is satisfied, but paper freeze is blocked until evidence-derived quota is satisfied and paper audit is GO.",
                    level="warn",
                )
            )
        detail_choice = prompt_utils.prompt_text("Press D for build history details, or Enter to continue", required=False)
        if detail_choice.strip().lower() == "d":
            print()
            menu_utils.print_header("Build History Details")
            table_utils.render_table(
                ["App", "Identity (vc/base)", "Active Runs", "Legacy Runs", "Legacy Builds"],
                build_rows,
                compact=True,
            )
    index = _choose_index("Select app #", len(packages))
    if index is None:
        return None
    package_name, _, _, _ = packages[index]
    return package_name


def _render_package_table(rows, *, max_preview: int = 15) -> None:
    headers = ["#", "App"]
    if rows and len(rows[0]) >= 9:
        # Put "Next" before the trailing status columns so it is less likely to
        # get truncated when the terminal is narrow (table shrink truncates from
        # the rightmost columns first).
        headers = ["#", "App", "Baseline", "Interactive", "Need", "Next", "Runs(All)", "Legacy", "Last QA"]
    if len(rows) <= max_preview:
        table_utils.render_table(headers, rows, compact=False)
        return
    preview = rows[:max_preview]
    table_utils.render_table(headers, preview, compact=False)
    response = prompt_utils.prompt_text("Press L to list all, or Enter to continue", required=False)
    if response.strip().lower() == "l":
        table_utils.render_table(headers, rows, compact=False)


def _build_scoped_dataset_counts(package_name: str, runs: list[dict]) -> dict[str, int | str]:
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
        "legacy_valid": 0,
        "legacy_builds": 0,
        "active_version_code": "",
        "active_base_sha": "",
    }
    legacy_identity_seen: set[tuple[str, str]] = set()
    if active_identity is not None:
        out["active_version_code"] = active_identity[0] or ""
        out["active_base_sha"] = active_identity[1] or ""
    for r in valid_runs:
        ident = _resolve_tracker_run_identity(package_name, r)
        ident_key = (ident[0] or "", ident[1] or "")
        if active_identity is not None and ident != active_identity:
            out["legacy_valid"] += 1
            if ident_key != ("", ""):
                legacy_identity_seen.add(ident_key)
            continue
        prof = str(r.get("run_profile") or "").lower()
        countable = bool(r.get("countable", r.get("counts_toward_quota", True)))
        is_baseline = ("baseline" in prof) or ("idle" in prof)
        if is_baseline:
            if countable:
                out["baseline_countable"] += 1
            else:
                out["baseline_extra"] += 1
        else:
            if countable:
                out["interactive_countable"] += 1
            else:
                out["interactive_extra"] += 1
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
