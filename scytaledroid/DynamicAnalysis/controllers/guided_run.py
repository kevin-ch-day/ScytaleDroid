"""Guided cohort run controller."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.adb import shell as adb_shell
from scytaledroid.DynamicAnalysis.controllers.device_select import select_device
from scytaledroid.DynamicAnalysis.controllers.guided_run_checks import (
    device_preflight_checks as _device_preflight_checks_impl,
    extract_version_code_details_from_dump as _extract_version_code_details_from_dump_impl,
    post_run_integrity_check as _post_run_integrity_check_impl,
    pre_run_scientific_checks as _pre_run_scientific_checks_impl,
    read_observed_signer_set_hash as _read_observed_signer_set_hash_impl,
    read_observed_version_code_details as _read_observed_version_code_details_impl,
)
from scytaledroid.DynamicAnalysis.core.run_specs import build_dynamic_run_spec
from scytaledroid.DynamicAnalysis.core.target_manager import extract_version_code_from_dump
from scytaledroid.DynamicAnalysis.datasets.research_dataset_alpha import (
    MESSAGING_PACKAGES,
)
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config
from scytaledroid.DynamicAnalysis.pcap.tools import collect_host_tools, missing_required_tools
from scytaledroid.DynamicAnalysis.plan_selection import (
    ensure_plan_or_error,
    print_plan_selection_banner,
)
from scytaledroid.DynamicAnalysis.research_cohort_runtime import (
    active_research_cohort_label,
    active_research_cohort_packages,
)
from scytaledroid.DynamicAnalysis.run_dynamic_analysis import execute_dynamic_run_spec
from scytaledroid.DynamicAnalysis.run_summary import print_run_summary
from scytaledroid.DynamicAnalysis.scenarios.manual import preview_script_template_for_package
from scytaledroid.DynamicAnalysis.services.dataset_run_state import load_dataset_run_state
from scytaledroid.DynamicAnalysis.templates.category_map import (
    category_for_package,
    resolved_template_for_package,
)
from scytaledroid.DynamicAnalysis.utils.path_utils import resolve_evidence_path
from scytaledroid.DynamicAnalysis.utils.run_cleanup import (
    delete_dynamic_evidence_packs,
    find_dynamic_run_dirs,
    reset_package_dataset_tracker,
)
from scytaledroid.StaticAnalysis.core.repository import group_artifacts
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

_BATTERY_WARN_PCT = 30
_BATTERY_BLOCK_PCT = 20
_STORAGE_BLOCK_GB = 1.5
_CLOCK_WARN_S = 5
_CLOCK_BLOCK_S = 30
_STABILIZATION_WAIT_S = 15
_META_FAMILY_PACKAGES = {
    "com.facebook.katana",
    "com.facebook.orca",
    "com.instagram.android",
    "com.whatsapp",
}


def _is_messaging_package_or_category(package_name: str) -> bool:
    pkg_lc = str(package_name or "").strip().lower()
    if not pkg_lc:
        return False
    category = str(category_for_package(pkg_lc) or "").strip().lower()
    if category == "messaging":
        return True
    # Backstop for legacy mappings while category maps are evolving.
    return pkg_lc in {p.lower() for p in MESSAGING_PACKAGES}


def _canonical_baseline_profile_for_package(package_name: str) -> str:
    if _is_messaging_package_or_category(package_name):
        return "baseline_connected"
    return "baseline_idle"


def _is_messaging_connected_baseline(
    *,
    package_name: str,
    run_profile: str,
    messaging_activity: str | None,
) -> bool:
    return (
        _is_messaging_package_or_category(package_name)
        and str(run_profile or "").strip().lower() == "baseline_connected"
        and str(messaging_activity or "").strip().lower() in {"", "connected_idle"}
    )


def _messaging_baseline_connected_insufficient_duration_streak(
    recent_runs: list[Any],
    *,
    package_name: str,
) -> int:
    if not _is_messaging_package_or_category(package_name):
        return 0
    streak = 0
    for r in recent_runs:
        prof = str(getattr(r, "run_profile", "") or "").strip().lower()
        reason = str(getattr(r, "invalid_reason_code", "") or "").strip().upper()
        if prof == "baseline_connected" and getattr(r, "valid", None) is False and reason == "INSUFFICIENT_DURATION":
            streak += 1
            continue
        break
    return streak


def _intent_counts_toward_quota(
    *,
    run_profile: str,
    baseline_valid_runs: int,
    interactive_valid_runs: int,
    cfg: Any,
) -> bool:
    profile = str(run_profile or "").strip().lower()
    if profile.startswith("baseline"):
        return int(baseline_valid_runs) < int(cfg.baseline_required)
    if profile.startswith("interaction_") or "interactive" in profile:
        return (
            int(baseline_valid_runs) >= int(cfg.baseline_required)
            and int(interactive_valid_runs) < int(cfg.interactive_required)
        )
    return False


def _is_interactive_profile(profile: str) -> bool:
    p = str(profile or "").strip().lower()
    return ("interaction" in p) or ("interactive" in p) or ("script" in p)


def _apply_messaging_baseline_countability_policy(
    *,
    package_name: str,
    run_profile: str,
    messaging_activity: str | None,
    counts_toward_completion: bool,
) -> tuple[bool, str | None]:
    """Messaging baseline policy: baseline is baseline_connected by default."""
    if not counts_toward_completion:
        return counts_toward_completion, None
    if not _is_messaging_package_or_category(package_name):
        return counts_toward_completion, None
    if not str(run_profile or "").strip().lower().startswith("baseline"):
        return counts_toward_completion, None
    activity = str(messaging_activity or "").strip().lower()
    if activity in {"", "none"}:
        return False, "MESSAGING_BASELINE_NONE_EXPLORATORY"
    return counts_toward_completion, None


def _print_paper_mode_constants() -> None:
    try:
        import numpy as _np

        numpy_version = str(getattr(_np, "__version__", "unknown"))
    except Exception:
        numpy_version = "unknown"
    try:
        import sklearn as _sk

        sklearn_version = str(getattr(_sk, "__version__", "unknown"))
    except Exception:
        sklearn_version = "unknown"

    # Default operator UX: keep this compact. Full parameter tables are available
    # on demand to avoid drowning operators in static boilerplate.
    menu_utils.print_section("ML Parameters (Locked)")
    rows = [
        ("Window size", f"{int(profile_config.WINDOW_SIZE_S)}s"),
        ("Stride", f"{int(profile_config.WINDOW_STRIDE_S)}s"),
        ("Min sampling time", f"{int(getattr(profile_config, 'MIN_SAMPLING_SECONDS', 180))}s"),
        ("Recommended time", f"{int(getattr(profile_config, 'RECOMMENDED_SAMPLING_SECONDS', 240))}s"),
        ("Percentile threshold", f"{int(profile_config.THRESHOLD_PERCENTILE)}"),
        ("Percentile method", str(getattr(profile_config, "NP_PERCENTILE_METHOD", "linear"))),
        ("Min PCAP bytes", f"{int(profile_config.MIN_PCAP_BYTES)}"),
        ("Models", "Isolation Forest + OC-SVM"),
        ("Baseline-only training", "YES"),
        ("NumPy version", numpy_version),
        ("scikit-learn version", sklearn_version),
    ]
    compact = (
        str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower() not in {"debug", "details"}
    )
    if compact:
        line = (
            f"Window={int(profile_config.WINDOW_SIZE_S)}s/{int(profile_config.WINDOW_STRIDE_S)}s | "
            f"Min={int(getattr(profile_config, 'MIN_SAMPLING_SECONDS', 180))}s | "
            f"Rec={int(getattr(profile_config, 'RECOMMENDED_SAMPLING_SECONDS', 240))}s | "
            f"MinPCAP={int(profile_config.MIN_PCAP_BYTES)} | "
            f"Models=IF+OCSVM | Baseline-only=YES"
        )
        print(status_messages.status(line, level="info"))
        # Keep guided collection fast: no extra prompt here. Operators can switch to
        # SCYTALEDROID_UI_LEVEL=details/debug for full tables.
        return
    menu_utils.print_table(["Parameter", "Value"], rows)


def _load_plan_identity(plan_path: str) -> dict[str, str]:
    payload = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    run_identity = (
        payload.get("run_identity")
        if isinstance(payload, dict) and isinstance(payload.get("run_identity"), dict)
        else {}
    )
    return {
        "package_name_lc": str(
            run_identity.get("package_name_lc") or payload.get("package_name") or ""
        ).strip().lower(),
        "version_code": str(
            run_identity.get("version_code") or payload.get("version_code") or ""
        ).strip(),
        "base_apk_sha256": str(run_identity.get("base_apk_sha256") or "").strip().lower(),
        "artifact_set_hash": str(run_identity.get("artifact_set_hash") or "").strip().lower(),
        "signer_set_hash": str(
            run_identity.get("signer_set_hash") or run_identity.get("signer_digest") or ""
        ).strip().lower(),
    }


def _known_signer_hash(value: object) -> str:
    text = str(value or "").strip().lower()
    if text in {"", "unknown", "none", "null"}:
        return ""
    return text


def _progress_label(count: int, required: int, *, noun: str = "needed") -> str:
    count_i = max(0, int(count))
    required_i = max(0, int(required))
    missing = max(0, required_i - count_i)
    if missing == 0:
        return f"{count_i}/{required_i} complete"
    return f"{count_i}/{required_i} need {missing}"


def _run_profile_label(run_profile: str | None) -> str:
    profile = str(run_profile or "").strip().lower()
    if profile == "baseline_idle" or "baseline" in profile or "idle" in profile:
        return "baseline"
    if profile == "interaction_scripted":
        return "scripted interaction"
    if profile == "interaction_manual":
        return "manual interaction"
    return str(run_profile or "interaction").strip() or "interaction"


def _interactive_phase_label(cfg: Any) -> str:
    profile = str(getattr(cfg, "interactive_profile", "") or "").strip().lower()
    if profile == "interaction_manual":
        return "Manual runs"
    return "Interactive runs"


def _scripted_template_available(package_name: str) -> bool:
    return bool(resolved_template_for_package(package_name))


def _suggested_menu_key(run_profile: str | None) -> str:
    profile = str(run_profile or "").strip().lower()
    if profile.startswith("baseline"):
        return "1"
    if profile == "interaction_scripted":
        return "2"
    if profile == "interaction_manual":
        return "3"
    return "1"


def _read_battery_level(device_serial: str) -> int | None:
    out = adb_shell.run_shell(device_serial, ["dumpsys", "battery"])
    m = re.search(r"level:\s*(\d+)", out)
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def _read_storage_free_gb(device_serial: str) -> float | None:
    out = adb_shell.run_shell(device_serial, ["df", "-k", "/data"])
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    if len(lines) < 2:
        return None
    parts = lines[-1].split()
    if len(parts) < 4:
        return None
    try:
        avail_kb = int(parts[3])
        return round(avail_kb / (1024 * 1024), 2)
    except Exception:
        return None


def _read_clock_drift_seconds(device_serial: str) -> float | None:
    out = adb_shell.run_shell(device_serial, ["date", "+%s"]).strip()
    try:
        device_epoch = int(out)
    except Exception:
        return None
    host_epoch = int(datetime.now(UTC).timestamp())
    return float(abs(host_epoch - device_epoch))


def _read_vpn_state(device_serial: str) -> str:
    out = adb_shell.run_shell(device_serial, ["dumpsys", "connectivity"]).lower()
    if "not_vpn" in out or "not vpn" in out:
        return "not_vpn"
    if "vpn" in out:
        return "vpn"
    return "unknown"


def _extract_route_interface(route_output: str) -> str | None:
    for line in route_output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Common forms:
        # - default via 192.168.1.1 dev wlan0
        # - 10.0.0.0/8 dev rmnet_data0 scope link
        if " dev " not in line:
            continue
        m = re.search(r"\bdev\s+(\S+)", line)
        if not m:
            continue
        iface = m.group(1).strip()
        if iface and iface not in {"lo"}:
            return iface
    return None


def _read_capture_interface(device_serial: str) -> str | None:
    # 1) Route-based detection (preferred).
    for cmd in (
        ["ip", "route"],
        ["ip", "-o", "route", "show"],
        ["ip", "route", "show", "table", "all"],
        ["/system/bin/ip", "route"],
    ):
        try:
            out = adb_shell.run_shell(device_serial, cmd)
        except Exception:
            out = ""
        iface = _extract_route_interface(out or "")
        if iface:
            return iface

    # 2) Connectivity service fallback.
    try:
        conn = adb_shell.run_shell(device_serial, ["dumpsys", "connectivity"])
    except Exception:
        conn = ""
    for pattern in (
        r"\binterfaceName[:=]\s*([a-zA-Z0-9_.:-]+)",
        r"\bIface[:=]\s*([a-zA-Z0-9_.:-]+)",
    ):
        m = re.search(pattern, conn or "", flags=re.IGNORECASE)
        if m:
            iface = m.group(1).strip()
            if iface and iface != "lo":
                return iface

    # 3) Property fallback for OEM/network stacks.
    for prop in ("wifi.interface", "vendor.wifi.interface", "persist.vendor.wifi.interface"):
        try:
            val = adb_shell.run_shell(device_serial, ["getprop", prop]).strip()
        except Exception:
            val = ""
        if val and val != "[]":
            return val
    return None


def _read_observed_version_code(device_serial: str, package_name: str) -> str | None:
    details = _read_observed_version_code_details(device_serial, package_name)
    return details.get("version_code")


def _read_observed_version_code_details(device_serial: str, package_name: str) -> dict[str, str]:
    return _read_observed_version_code_details_impl(
        device_serial,
        package_name,
        run_shell_fn=adb_shell.run_shell,
        extract_details_fn=_extract_version_code_details_from_dump,
    )


def _extract_version_code_from_dump(dump: str, package_name: str) -> str | None:
    return extract_version_code_from_dump(dump, package_name)


def _extract_version_code_details_from_dump(dump: str, package_name: str) -> dict[str, str]:
    return _extract_version_code_details_from_dump_impl(dump, package_name)


def _read_observed_signer_set_hash(device_serial: str, package_name: str) -> str | None:
    return _read_observed_signer_set_hash_impl(
        device_serial,
        package_name,
        run_shell_fn=adb_shell.run_shell,
    )


def _pre_run_scientific_checks(
    *,
    device_serial: str,
    package_name: str,
    plan_path: str,
    observer_ids: list[str],
) -> bool:
    return _pre_run_scientific_checks_impl(
        device_serial=device_serial,
        package_name=package_name,
        plan_path=plan_path,
        observer_ids=observer_ids,
        data_dir=app_config.DATA_DIR,
        battery_block_pct=_BATTERY_BLOCK_PCT,
        battery_warn_pct=_BATTERY_WARN_PCT,
        storage_block_gb=_STORAGE_BLOCK_GB,
        clock_block_s=_CLOCK_BLOCK_S,
        clock_warn_s=_CLOCK_WARN_S,
        missing_required_tools_fn=missing_required_tools,
        read_capture_interface_fn=_read_capture_interface,
        read_vpn_state_fn=_read_vpn_state,
        read_battery_level_fn=_read_battery_level,
        read_storage_free_gb_fn=_read_storage_free_gb,
        read_clock_drift_seconds_fn=_read_clock_drift_seconds,
        load_plan_identity_fn=_load_plan_identity,
        read_observed_version_code_details_fn=_read_observed_version_code_details,
        known_signer_hash_fn=_known_signer_hash,
        read_observed_signer_set_hash_fn=_read_observed_signer_set_hash,
    )


def _device_preflight_checks(device_serial: str) -> bool:
    return _device_preflight_checks_impl(
        device_serial,
        data_dir=app_config.DATA_DIR,
        battery_block_pct=_BATTERY_BLOCK_PCT,
        battery_warn_pct=_BATTERY_WARN_PCT,
        storage_block_gb=_STORAGE_BLOCK_GB,
        clock_block_s=_CLOCK_BLOCK_S,
        clock_warn_s=_CLOCK_WARN_S,
        ui_level=str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower(),
        missing_required_tools_fn=missing_required_tools,
        read_capture_interface_fn=_read_capture_interface,
        read_vpn_state_fn=_read_vpn_state,
        read_battery_level_fn=_read_battery_level,
        read_storage_free_gb_fn=_read_storage_free_gb,
        read_clock_drift_seconds_fn=_read_clock_drift_seconds,
    )


def _post_run_integrity_check(result) -> None:
    _post_run_integrity_check_impl(
        result,
        min_pcap_bytes=int(profile_config.MIN_PCAP_BYTES),
        min_windows=int(getattr(profile_config, "MIN_WINDOWS_PER_RUN", 20)),
        ui_level=str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower(),
    )


def _auto_run_static_for_package(package_name: str) -> bool:
    """Dataset-mode helper: run static analysis quietly to produce a dynamic plan.

    This is non-interactive and intended only to unblock dataset collection.
    """

    from scytaledroid.DeviceAnalysis.services import artifact_store
    from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
    from scytaledroid.StaticAnalysis.cli.core.run_specs import build_static_run_spec
    from scytaledroid.StaticAnalysis.cli.flows.run_dispatch import execute_run_spec
    from scytaledroid.StaticAnalysis.session import make_session_stamp, normalize_session_stamp

    groups = group_artifacts()
    group = next((g for g in groups if (g.package_name or "").lower() == package_name.lower()), None)
    if not group:
        print(status_messages.status("No APK artifacts found locally for this package.", level="error"))
        return False

    session_stamp = normalize_session_stamp(f"{make_session_stamp()}-{group.package_name}")
    selection = ScopeSelection(scope="app", label=group.package_name, groups=(group,))
    params = RunParameters(
        profile="full",
        scope=selection.scope,
        scope_label=selection.label,
        session_stamp=session_stamp,
        show_split_summaries=False,
        # Noninteractive run: never prompt on collisions.
        canonical_action="append",
    )
    buffer_out = io.StringIO()
    buffer_err = io.StringIO()
    with contextlib.redirect_stdout(buffer_out), contextlib.redirect_stderr(buffer_err):
        spec = build_static_run_spec(
            selection=selection,
            params=params,
            base_dir=artifact_store.analysis_apk_root(),
            run_mode="batch",
            quiet=True,
            noninteractive=True,
        )
        execute_run_spec(spec)
    return True


def run_guided_dataset_run(
    *,
    select_package_from_groups: Callable[[object, str], str | None],
    select_observers: Callable[[str, str], list[str]],
    print_device_badge: Callable[[str, str], None],
    print_tier1_qa_result: Callable[[str], None] | None = None,
    observer_prompts_enabled: bool = False,
    pcapdroid_api_key: str | None = None,
) -> None:
    print()
    cohort_label = active_research_cohort_label()
    menu_utils.print_header("Dynamic Cohort Run", cohort_label)
    _print_paper_mode_constants()
    selected = select_device()
    if not selected:
        return
    device_serial, device_label = selected
    print_device_badge(device_serial, device_label)
    if not _device_preflight_checks(device_serial):
        prompt_utils.press_enter_to_continue()
        return

    while True:
        keep_running = _run_guided_dataset_iteration(
            cohort_label=cohort_label,
            device_serial=device_serial,
            device_label=device_label,
            select_package_from_groups=select_package_from_groups,
            select_observers=select_observers,
            print_tier1_qa_result=print_tier1_qa_result,
            observer_prompts_enabled=observer_prompts_enabled,
            pcapdroid_api_key=pcapdroid_api_key,
        )
        if not keep_running:
            return


def _run_guided_dataset_iteration(
    *,
    cohort_label: str,
    device_serial: str,
    device_label: str,
    select_package_from_groups: Callable[[object, str], str | None],
    select_observers: Callable[[str, str], list[str]],
    print_tier1_qa_result: Callable[[str], None] | None = None,
    observer_prompts_enabled: bool = False,
    pcapdroid_api_key: str | None = None,
) -> bool:
    scenario_id = "basic_usage"
    duration_seconds = 0
    label = "Cohort"

    groups = group_artifacts()
    dataset_pkgs = {pkg.lower() for pkg in active_research_cohort_packages()}
    if not dataset_pkgs:
        print(status_messages.status(f"{cohort_label} has no apps.", level="warn"))
        return False

    available = {group.package_name.lower() for group in groups if group.package_name}
    scoped_groups = tuple(
        group
        for group in groups
        if group.package_name
        and group.package_name.lower() in available.intersection(dataset_pkgs)
    )
    if not scoped_groups:
        print(
            status_messages.status(
                f"No APK artifacts available for {cohort_label}. Execute Harvest or use Custom package name.",
                level="warn",
            )
        )
        return False

    package_name = select_package_from_groups(
        scoped_groups,
        title="App Queue",
        subtitle=f"{cohort_label} · {device_label}",
    )
    if not package_name:
        return False
    pkg_lc = str(package_name or "").strip().lower()
    display_label = package_name
    try:
        display_map = {
            str(g.package_name or "").strip().lower(): (g.display_name or g.package_name)
            for g in groups
            if getattr(g, "package_name", None)
        }
        display_label = display_map.get(pkg_lc) or package_name
    except Exception:
        display_label = package_name
    print(
        status_messages.status(
            f"Selected app: {display_label}",
            level="info",
        )
    )
    if display_label != package_name:
        print(status_messages.status(f"Package: {package_name}", level="info"))
    meta_family_note = bool(pkg_lc in _META_FAMILY_PACKAGES)

    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig

    cfg = DatasetTrackerConfig()
    state = load_dataset_run_state(package_name, config=cfg)
    total_required = int(state.total_required)
    counts = state.counts
    scripted_template_ready = _scripted_template_available(package_name)
    suggested_profile = (
        state.effective_suggested_profile
        or str(getattr(cfg, "interactive_profile", "") or "interaction_manual")
    ).strip()
    suggested_slot = state.suggested_slot
    paper_eligible_local = int(state.paper_eligible_local)
    quota_counted_local = int(state.quota_counted_local)
    extra_valid_local = int(counts.extra_valid_runs)
    historical_valid_local = int(state.historical_valid_runs)
    historical_build_count = int(state.historical_build_count)
    interactive_label = _interactive_phase_label(cfg)
    if int(counts.baseline_valid_runs) < int(cfg.baseline_required):
        suggested_profile = _canonical_baseline_profile_for_package(package_name)
        suggested_slot = max(1, min(int(counts.baseline_valid_runs) + 1, int(cfg.baseline_required)))
    baseline_complete = int(counts.baseline_valid_runs) >= int(cfg.baseline_required)
    if counts.quota_met:
        suggested_slot = None

    suggested_is_interactive = _is_interactive_profile(suggested_profile)
    suggested_default_key = _suggested_menu_key(suggested_profile)

    def _badge_for(key: str) -> str | None:
        if not suggested_slot:
            return None
        return "suggested" if key == suggested_default_key else None

    can_reset = bool(state.reset_available)
    protocol_options = [
        menu_utils.MenuOption(
            "1",
            "Baseline",
            description=(
                (
                    "Purpose: baseline-only training. run_profile="
                    if int(counts.baseline_valid_runs) < int(cfg.baseline_required)
                    else "Purpose: supplemental baseline evidence. run_profile="
                )
                + _canonical_baseline_profile_for_package(package_name)
                + " | "
                + (
                    "Counts toward quota: YES (baseline requirement not yet met)"
                    if int(counts.baseline_valid_runs) < int(cfg.baseline_required)
                    else "Counts toward quota: NO (baseline requirement already met). Saved as supplemental baseline evidence."
                )
            ),
            badge=_badge_for("1"),
        ),
        menu_utils.MenuOption(
            "2",
            "Scripted Interaction",
            description=(
                (
                    "Purpose: optional template-backed repeatable stimulus. run_profile=interaction_scripted | "
                    + (
                        "Counts toward quota: YES (if VALID)"
                        if baseline_complete and int(counts.interactive_valid_runs) < int(cfg.interactive_required)
                        else (
                            "Counts toward quota: NO (baseline requirement not complete)"
                            if not baseline_complete
                            else "Counts toward quota: NO (interactive quota met; saved as supplemental evidence)"
                        )
                    )
                )
                if scripted_template_ready
                else "Unavailable for this app: no scripted interaction template is defined. Use Manual Interaction for dynamic stimulus."
            ),
            badge=_badge_for("2"),
            disabled=(not scripted_template_ready),
        ),
        menu_utils.MenuOption(
            "3",
            "Manual Interaction",
            description=(
                (
                    "Purpose: operator-driven dynamic stimulus. Standard cohort interaction path for paper #3. "
                    if str(getattr(cfg, "interactive_profile", "") or "").strip().lower() == "interaction_manual"
                    else (
                        "Purpose: operator-driven dynamic stimulus. Recommended when no scripted template exists. "
                        if not scripted_template_ready
                        else "Purpose: operator-driven dynamic stimulus. "
                    )
                )
                + "run_profile=interaction_manual | "
                + (
                    "Counts toward quota: YES (if VALID)"
                    if baseline_complete and int(counts.interactive_valid_runs) < int(cfg.interactive_required)
                    else (
                        "Counts toward quota: NO (baseline requirement not complete)"
                        if not baseline_complete
                        else "Counts toward quota: NO (interactive quota met; saved as supplemental evidence)"
                    )
                )
            ),
            badge=_badge_for("3"),
        ),
        menu_utils.MenuOption("4", "Test app (Dry Run/No Saving)", description="no capture; checks plan + tools", badge=None),
        menu_utils.MenuOption(
            "D",
            "Reset app (dangerous)",
            description=(
                "delete local evidence packs + reset tracker for this app"
                if can_reset
                else "disabled: no local evidence packs in this workspace"
            ),
            badge=None,
            disabled=(not can_reset),
        ),
    ]

    menu_utils.print_header("Select Run Intent")
    if meta_family_note:
        print(
            status_messages.status(
                "Meta-family app: Facebook, Messenger, Instagram, and WhatsApp are tracked as separate apps.",
                level="info",
            )
        )
    if historical_valid_local > 0:
        build_text = (
            f" across {historical_build_count} older build(s)"
            if historical_build_count > 0
            else ""
        )
        print(
            status_messages.status(
                f"Historical context: {historical_valid_local} legacy valid run(s){build_text} retained for comparison; not counted toward current quota.",
                level="info",
            )
        )
    if extra_valid_local > 0:
        print(
            status_messages.status(
                f"Supplemental current-build evidence: {extra_valid_local} extra valid run(s) retained outside quota.",
                level="info",
            )
        )
    menu_utils.render_menu(
        menu_utils.MenuSpec(
            items=protocol_options,
            default=suggested_default_key if suggested_is_interactive else "1",
            exit_label="Exit",
            show_exit=True,
            show_descriptions=True,
            compact=True,
        )
    )
    selected_protocol = prompt_utils.get_choice(
        menu_utils.selectable_keys(protocol_options, include_exit=True),
        default=suggested_default_key if suggested_is_interactive else "1",
        casefold=True,
        invalid_message="Choose 0-4 or D.",
        disabled=[option.key for option in protocol_options if option.disabled],
    )
    selected_protocol = selected_protocol.upper()
    if selected_protocol == "0":
        return True
    if selected_protocol == "D":
        local = find_dynamic_run_dirs(package_name)
        print(
            status_messages.status(
                f"Local dynamic runs for {package_name}: {len(local)} evidence pack(s).",
                level="warn",
            )
        )
        if not local:
            print(
                status_messages.status(
                    "Delete is blocked: local evidence packs are missing in this workspace. Resetting tracker-only state is unsafe in freeze/profile mode.",
                    level="error",
                )
            )
            prompt_utils.press_enter_to_continue()
            return True
        confirmed = prompt_utils.prompt_yes_no(
            f"Delete local evidence packs AND reset dataset tracker entry for {package_name}?",
            default=False,
        )
        if not confirmed:
            return True
        deleted = delete_dynamic_evidence_packs(package_name)
        reset_package_dataset_tracker(package_name)
        remaining = len(find_dynamic_run_dirs(package_name))
        print(
            status_messages.status(
                f"Deleted {deleted} evidence pack(s). Remaining={remaining}. Tracker entry reset.",
                level="info",
            )
        )
        prompt_utils.press_enter_to_continue()
        return True
    if selected_protocol == "4":
        # Preflight-only test: do not capture or write evidence packs.
        missing = missing_required_tools(tier="dataset")
        tools = collect_host_tools()
        if missing:
            print(
                status_messages.status(
                    f"Preflight FAIL: missing host tools: {', '.join(missing)}",
                    level="error",
                )
            )
        else:
            print(status_messages.status("Preflight OK: host tools present.", level="success"))
        print(status_messages.status(f"Host tools: {tools}", level="info"))
        # Also ensure a plan exists (offer to run static once, as normal).
        plan_selection = ensure_plan_or_error(
            package_name,
            prompt_run_static=True,
            deterministic=True,
            run_static_callback=_auto_run_static_for_package,
        )
        if plan_selection:
            print(status_messages.status(f"Plan OK: {plan_selection['plan_path']}", level="success"))
        mapped = resolved_template_for_package(package_name)
        if mapped:
            try:
                template_id, steps = preview_script_template_for_package(package_name=package_name)
                print()
                menu_utils.print_section("Dry Run Script Preview")
                print(status_messages.status(f"Template: {template_id}", level="info"))
                rows = [[str(i), sid, str(sexp)] for i, (sid, _sdesc, sexp) in enumerate(steps, start=1)]
                menu_utils.print_table(["#", "Step ID", "Expected (s)"], rows)
                print(status_messages.status("Dry run validates plan/tools only; no capture or saving is performed.", level="info"))
            except Exception as exc:
                print(status_messages.status(f"Template preview unavailable: {exc}", level="warn"))
        prompt_utils.press_enter_to_continue()
        return True

    # Show recent history before starting capture so operator can sanity-check state.
    recent = state.recent_runs
    if recent:
        rows = []
        for r in recent:
            rows.append(
                [
                    (r.ended_at or "—")[:19],
                    (r.run_profile or "—"),
                    (r.interaction_level or "—"),
                    (r.messaging_activity or "—"),
                    r.status_label,
                    (r.run_id or "—")[:8],
                ]
            )
        print()
        menu_utils.print_section("Recent Tracker Runs (informational)")
        menu_utils.print_table(
            ["Ended", "Profile", "Interaction", "Msg", "Status", "Run ID"],
            rows,
        )
        # Operator guidance: repeated baseline PCAP_MISSING usually indicates
        # low-signal app-idle behavior; suggest a warm baseline or scripted run.
        if state.baseline_idle_pcap_missing_streak >= 2:
            print(
                status_messages.status(
                    "Recent baseline_idle runs repeatedly failed with PCAP_MISSING. "
                    "If idle traffic stays low, try a minimal warm baseline (open chats list briefly) "
                    "before collecting interaction.",
                    level="warn",
                )
            )
        if state.baseline_idle_low_signal_streak >= 2:
            print(
                status_messages.status(
                    "Recent baseline_idle runs were VALID but LOW_SIGNAL_IDLE. "
                    "For messaging/chat-like apps, collect manual interaction next to avoid non-countable baselines.",
                    level="warn",
                )
            )
        if state.baseline_connected_insufficient_duration_streak >= 2:
            print(
                status_messages.status(
                    "Recent baseline_connected runs failed with INSUFFICIENT_DURATION. "
                    "Baseline quota remains the recommended next step until it is complete.",
                    level="warn",
                )
            )

    # Capture modes.
    tier = "dataset"
    if selected_protocol == "1":
        run_profile = _canonical_baseline_profile_for_package(package_name)
        interaction_level = "minimal"
    elif selected_protocol == "2":
        run_profile = "interaction_scripted"
        interaction_level = "scripted"
    else:
        run_profile = "interaction_manual"
        interaction_level = "manual"
    if (
        selected_protocol in {"2", "3"}
        and int(counts.baseline_valid_runs) < int(cfg.baseline_required)
    ):
        print(
            status_messages.status(
                "Baseline requirement is not complete: "
                f"{counts.baseline_valid_runs}/{cfg.baseline_required} valid baseline runs.",
                level="warn",
            )
        )
        print(status_messages.status("Recommended next run is baseline.", level="warn"))
        if not prompt_utils.prompt_yes_no("Proceed with interaction anyway?", default=False):
            return True
    counts_toward_completion = _intent_counts_toward_quota(
        run_profile=run_profile,
        baseline_valid_runs=int(counts.baseline_valid_runs),
        interactive_valid_runs=int(counts.interactive_valid_runs),
        cfg=cfg,
    )
    suggested_key = suggested_default_key if suggested_is_interactive else "1"
    if selected_protocol in {"1", "2", "3"} and selected_protocol != suggested_key and not counts_toward_completion:
        print(
            status_messages.status(
                "Selected intent is not quota-suggested and will be saved as supplemental evidence (not quota-counted).",
                level="warn",
            )
        )
        proceed = prompt_utils.prompt_yes_no("Proceed with supplemental run anyway?", default=False)
        if not proceed:
            print(status_messages.status("Run canceled. Choose the suggested intent to fill quota.", level="info"))
            return True

    # Manual runs can be quota-counted (by policy), so do not gate behind an
    # "EXPLORATORY" confirmation.
    messaging_activity: str | None = None
    if _is_messaging_package_or_category(package_name):
        # PM lock: messaging activity is a tag describing what happened. In manual mode, it
        # must never affect countability. In scripted mode, it selects a deterministic
        # template (template policy then determines cohort eligibility).
        if str(run_profile or "").strip().lower().startswith("baseline"):
            # Keep baseline deterministic: messaging baselines are baseline_connected and the
            # activity is "connected_idle" by definition. Do not offer a menu that can
            # accidentally select known-low-signal "home idle" baselines.
            messaging_activity = "connected_idle"
            print()
            print(status_messages.status("Messaging Activity tag: Idle (baseline_connected).", level="info"))
        else:
            print()
            menu_utils.print_header("Messaging Activity (Tag)")
            messaging_options = [
                menu_utils.MenuOption("1", "Idle", description="browse thread/list surfaces; no sending/calls/media"),
                menu_utils.MenuOption(
                    "2",
                    "Text",
                    description="send 2 fixed text messages (no media). Use Meta AI/Saved/Note-to-self if needed.",
                ),
                menu_utils.MenuOption("3", "Voice Call", description="start call; if connected hold ~90s; end call"),
                menu_utils.MenuOption("4", "Video Call", description="start video call; if connected hold ~90s; end call"),
                menu_utils.MenuOption("5", "Mixed", description="text + call (exploratory-only; non-cohort)"),
            ]
            menu_utils.render_menu(
                menu_utils.MenuSpec(
                    items=messaging_options,
                    default="2" if str(run_profile or "").strip().lower() == "interaction_scripted" else "1",
                    exit_label=None,
                    show_exit=False,
                    show_descriptions=True,
                    compact=True,
                )
            )
            valid_choices = menu_utils.selectable_keys(messaging_options, include_exit=False)
            choice = prompt_utils.get_choice(
                valid_choices,
                default="2" if str(run_profile or "").strip().lower() == "interaction_scripted" else "1",
                invalid_message=f"Choose {valid_choices[0]}-{valid_choices[-1]}.",
                disabled=[option.key for option in messaging_options if option.disabled],
            )
            messaging_activity = {
                "1": "idle",
                "2": "text_only",
                "3": "voice_call",
                "4": "video_call",
                "5": "mixed",
            }[choice]
    else:
        # Non-messaging apps: leave unset so downstream can distinguish "not applicable" vs "none".
        messaging_activity = None

    counts_toward_completion, policy_reason = _apply_messaging_baseline_countability_policy(
        package_name=package_name,
        run_profile=run_profile,
        messaging_activity=messaging_activity,
        counts_toward_completion=counts_toward_completion,
    )
    if policy_reason == "MESSAGING_BASELINE_NONE_EXPLORATORY":
        print(
            status_messages.status(
                "Messaging baseline with 'none/home idle' is exploratory. "
                "Use 'Connected idle' (open thread, no send/call) for countable messaging baseline.",
                level="warn",
            )
        )
        if prompt_utils.prompt_yes_no("Switch to connected-idle baseline now?", default=True):
            messaging_activity = "connected_idle"
            run_profile = "baseline_connected"
            counts_toward_completion = _intent_counts_toward_quota(
                run_profile=run_profile,
                baseline_valid_runs=int(counts.baseline_valid_runs),
                interactive_valid_runs=int(counts.interactive_valid_runs),
                cfg=cfg,
            )
            print(status_messages.status("Using messaging baseline_connected behavior.", level="info"))

    if _is_messaging_connected_baseline(
        package_name=package_name,
        run_profile=run_profile,
        messaging_activity=messaging_activity,
    ):
        can_open_thread = prompt_utils.prompt_yes_no(
            "Can you open an existing conversation thread now? (required for baseline_connected)",
            default=True,
        )
        if not can_open_thread:
            print(
                status_messages.status(
                    "Without an existing thread, messaging baseline is likely low-signal and may be excluded.",
                    level="warn",
                )
            )
            fallback_interaction = "interaction_manual"
            fallback_label = "manual interaction"
            if prompt_utils.prompt_yes_no(f"Switch to {fallback_label} now?", default=True):
                run_profile = fallback_interaction
                interaction_level = "manual"
                messaging_activity = "none"
                counts_toward_completion = _intent_counts_toward_quota(
                    run_profile=run_profile,
                    baseline_valid_runs=int(counts.baseline_valid_runs),
                    interactive_valid_runs=int(counts.interactive_valid_runs),
                    cfg=cfg,
                )
                print(status_messages.status(f"Switched to {fallback_label}.", level="info"))
            else:
                print(
                    status_messages.status(
                        "Run canceled to avoid low-signal baseline. Start again when a thread is available.",
                        level="info",
                    )
                )
                return True

    # Template policy determines scripted countability (messaging activity is only a tag).
    if _is_messaging_package_or_category(package_name) and str(run_profile or "").strip().lower() == "interaction_scripted":
        try:
            tmpl_id, _steps = preview_script_template_for_package(
                package_name=str(package_name or "").strip().lower(),
                messaging_activity=str(messaging_activity or "").strip().lower(),
            )
            print(status_messages.status(f"Script template selected: {tmpl_id}", level="info"))
            if str(tmpl_id) == "messaging_call_basic_v1":
                print(
                    status_messages.status(
                        "Template policy: Mixed/call template is exploratory-only (will NOT count toward paper quota).",
                        level="warn",
                    )
                )
                counts_toward_completion = False
        except Exception:
            # If preview fails, keep behavior unchanged; capture can still proceed and will
            # be evaluated evidence-first post-run.
            pass

    # Operator-facing paper quota impact label (avoid generic "countable" wording).
    prof_lc = str(run_profile or "").strip().lower()
    if counts_toward_completion:
        paper_impact_label = "Cohort quota impact: YES (if VALID)"
    else:
        paper_impact_label = "Cohort quota impact: NO (supplemental evidence / policy)"

    print(
        paper_impact_label
    )

    print()
    menu_utils.print_header("Dynamic Run Observers")
    observer_ids = select_observers(device_serial, mode="guided")

    if not observer_ids:
        print(status_messages.status("Select at least one observer.", level="error"))
        return True

    # Dataset mode is deterministic about plan choice, but interactive about gating:
    # if no plan exists yet, offer a single prompt to run static now.
    plan_selection = ensure_plan_or_error(
        package_name,
        prompt_run_static=True,
        deterministic=True,
        run_static_callback=_auto_run_static_for_package,
    )
    if not plan_selection:
        return True
    plan_path = plan_selection["plan_path"]
    static_run_id = plan_selection["static_run_id"]
    print_plan_selection_banner(plan_selection)
    if not _pre_run_scientific_checks(
        device_serial=device_serial,
        package_name=package_name,
        plan_path=plan_path,
        observer_ids=observer_ids,
    ):
        prompt_utils.press_enter_to_continue()
        return True
    print(status_messages.status(f"Stabilizing environment ({_STABILIZATION_WAIT_S}s)...", level="info"))
    time.sleep(_STABILIZATION_WAIT_S)
    clear_logcat = prompt_utils.prompt_yes_no("Clear logcat at run start?", default=True)
    if run_profile == "interaction_scripted":
        mapped = resolved_template_for_package(package_name)
        if not mapped:
            print(
                status_messages.status(
                    f"BLOCKED_UNKNOWN_CATEGORY: no scripted template mapping for {package_name} in freeze/profile mode.",
                    level="error",
                )
            )
            prompt_utils.press_enter_to_continue()
            return True

    spec = build_dynamic_run_spec(
        package_name=package_name,
        device_serial=device_serial,
        observer_ids=tuple(observer_ids),
        scenario_id=scenario_id,
        tier=tier,
        duration_seconds=duration_seconds,
        plan_path=plan_path,
        static_run_id=static_run_id,
        clear_logcat=clear_logcat,
        interactive=True,
        # Dataset tier is strict; exploratory runs are allowed to proceed with best-effort
        # schema/persistence while still producing an evidence pack.
        require_dynamic_schema=(tier == "dataset"),
        observer_prompts_enabled=bool(observer_prompts_enabled),
        pcapdroid_api_key=pcapdroid_api_key,
        run_profile=run_profile,
        interaction_level=interaction_level,
        messaging_activity=messaging_activity,
        counts_toward_completion=counts_toward_completion,
    )
    result = execute_dynamic_run_spec(spec)
    print_run_summary(result, label)
    _post_run_integrity_check(result)
    if result.dynamic_run_id and print_tier1_qa_result:
        print_tier1_qa_result(result.dynamic_run_id)
    _capture_protocol_fit_feedback(result=result, run_profile=run_profile, package_name=package_name)
    return True


def _capture_protocol_fit_feedback(*, result, run_profile: str, package_name: str | None) -> None:
    if run_profile != "interaction_scripted":
        return
    if not result or str(getattr(result, "status", "")).lower() != "success":
        return
    run_id = str(getattr(result, "dynamic_run_id", "") or "").strip()
    if not run_id:
        return
    print()
    menu_utils.print_header("Protocol Fit (Optional)")
    fit_options = [
        menu_utils.MenuOption("1", "Great", description="Steps matched app flow well."),
        menu_utils.MenuOption("2", "Okay", description="Mostly good; minor mismatch."),
        menu_utils.MenuOption("3", "Poor", description="Steps did not fit app well."),
    ]
    menu_utils.render_menu(
        menu_utils.MenuSpec(
            items=fit_options,
            default="2",
            show_exit=False,
            show_descriptions=True,
            compact=True,
        )
    )
    fit_choice = prompt_utils.get_choice(["1", "2", "3"], default="2", invalid_message="Choose 1-3.")
    fit_label = {"1": "great", "2": "okay", "3": "poor"}.get(fit_choice, "okay")

    step_ref = ""
    replacement_note = ""
    if fit_label == "poor":
        step_ref = prompt_utils.prompt_text(
            "Which step number felt wrong? (optional, e.g., 2)",
            required=False,
        ).strip()
        replacement_note = prompt_utils.prompt_text(
            "Suggested replacement step (optional one-line note)",
            required=False,
        ).strip()
        print(
            status_messages.status(
                "Rerun recommended with the correct template/protocol before counting this app for paper cohort.",
                level="warn",
            )
        )

    # Messaging templates may legitimately send messages (text-mode templates). Only flag
    # "send" as a protocol violation when it was not expected by the selected template.
    send_detected = False

    event = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "event": "protocol_fit_feedback",
        "run_id": run_id,
        "run_profile": run_profile,
        "fit": fit_label,
        "step_ref": step_ref or None,
        "replacement_note": replacement_note or None,
        "script_protocol_send": bool(send_detected),
    }
    run_dir = resolve_evidence_path(getattr(result, "evidence_path", None)) if getattr(result, "evidence_path", None) else None
    if not run_dir:
        return
    manifest_path = Path(run_dir) / "run_manifest.json"
    events_path = Path(run_dir) / "notes" / "run_events.jsonl"
    try:
        events_path.parent.mkdir(parents=True, exist_ok=True)
        with events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
    except Exception:
        return
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            operator_existing = payload.get("operator") if isinstance(payload.get("operator"), dict) else {}
            observed_template = str(operator_existing.get("template_id_actual") or operator_existing.get("template_id") or "").strip()
            is_text_template = observed_template.endswith("_text_v1") or observed_template in {"messaging_text_v1", "whatsapp_text_v1"}
            if _is_messaging_package_or_category(str(package_name or "").strip().lower()) and not is_text_template:
                send_detected = prompt_utils.prompt_yes_no(
                    "Did this scripted run send messages outside of the template steps? (protocol violation)",
                    default=False,
                )
            operator = payload.get("operator") if isinstance(payload.get("operator"), dict) else {}
            operator["protocol_fit"] = fit_label
            operator["protocol_fit_step_ref"] = step_ref or None
            operator["protocol_fit_replacement_note"] = replacement_note or None
            operator["script_protocol_send"] = bool(send_detected)
            payload["operator"] = operator
            manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    except Exception:
        pass
    print(status_messages.status("Protocol fit feedback saved.", level="info"))


__all__ = ["run_guided_dataset_run"]
