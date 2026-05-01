"""Profile v3 (Paper #3) guided Phase 2 capture helpers.

Goal: provide a v2-like "Run App" operator workflow for v3 without mixing cohorts.
This is an operator convenience layer; cohort validity is enforced later by:
- v3 capture status dashboard
- strict v3 manifest builder
- strict exports/lint
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.DynamicAnalysis.controllers.device_select import select_device
from scytaledroid.DynamicAnalysis.core.run_specs import build_dynamic_run_spec
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config
from scytaledroid.DynamicAnalysis.plan_selection import ensure_plan_or_error, print_plan_selection_banner
from scytaledroid.DynamicAnalysis.run_dynamic_analysis import execute_dynamic_run_spec
from scytaledroid.DynamicAnalysis.run_summary import print_run_summary
from scytaledroid.DynamicAnalysis.services.observer_service import select_observers
from scytaledroid.DynamicAnalysis.templates.category_map import resolved_template_for_package
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


_STABILIZATION_WAIT_S = 10


@dataclass(frozen=True)
class V3CaptureDefaults:
    duration_s: int
    scenario_id: str
    require_dynamic_schema: bool


def _defaults() -> V3CaptureDefaults:
    # v3 paper capture wants predictable window counts; prefer recommended sampling seconds.
    dur = int(float(getattr(profile_config, "RECOMMENDED_SAMPLING_SECONDS", 240.0)))
    if dur <= 0:
        dur = 240
    return V3CaptureDefaults(
        duration_s=dur,
        scenario_id="paper3_profile_v3",
        # v3 pipeline is filesystem-first; do not block capture on DB schema readiness.
        require_dynamic_schema=False,
    )


def run_profile_v3_capture_for_package(*, package_name: str, run_profile: str, ui_prompt_observers: bool) -> None:
    """Run a single v3 capture for a package with the given run_profile."""

    # Ensure scripted template resolution uses the Profile v3 catalog mapping.
    os.environ.setdefault("SCYTALEDROID_TEMPLATE_MAP_PROFILE", "v3")

    selected = select_device()
    if not selected:
        return
    device_serial, device_label = selected
    print(status_messages.status(f"Device: {device_label} ({device_serial})", level="info"))

    # Observer selection (defaults are fine; prompts are opt-in).
    observer_ids = select_observers(device_serial, mode="profile_v3", prompt_enabled=bool(ui_prompt_observers))
    if not observer_ids:
        print(status_messages.status("Select at least one observer.", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    # Scripted runs must have a template mapping.
    if str(run_profile or "").strip().lower() == "interaction_scripted":
        mapped = resolved_template_for_package(package_name)
        if not mapped:
            print(
                status_messages.status(
                    f"BLOCKED_UNKNOWN_CATEGORY: no scripted template mapping for {package_name}.",
                    level="error",
                )
            )
            prompt_utils.press_enter_to_continue()
            return

    # Resolve static plan + static_run_id (dynamic engine requires static_run_id).
    plan_selection = ensure_plan_or_error(
        package_name,
        prompt_run_static=True,
        deterministic=True,
        run_static_callback=None,
    )
    if not plan_selection:
        return
    plan_path = plan_selection["plan_path"]
    static_run_id = plan_selection["static_run_id"]
    # v3 capture operators asked to reduce noise: the full static plan banner is useful
    # for forensic review, but slows Phase 2 burn-down. Keep a compact one-line summary
    # by default, and allow opt-in to the full banner.
    show_full_banner = str(os.environ.get("SCYTALEDROID_V3_SHOW_STATIC_PLAN_BANNER") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if show_full_banner:
        print_plan_selection_banner(plan_selection)
    else:
        # Prefer stable identifiers: package + version_code + artifact sha (short) + static_run_id.
        ver_code = str(plan_selection.get("version_code") or plan_selection.get("observed_version_code") or "").strip()
        artifact_sha = str(plan_selection.get("artifact_sha256") or "").strip()
        artifact_short = (artifact_sha[:8] + "…") if artifact_sha else ""
        ver_disp = f" version_code={ver_code}" if ver_code else ""
        art_disp = f" artifact={artifact_short}" if artifact_short else ""
        print(
            status_messages.status(
                f"Static plan: package={package_name}{ver_disp}{art_disp} static_run={static_run_id}",
                level="info",
            )
        )

    defaults = _defaults()
    print(status_messages.status(f"Stabilizing environment ({_STABILIZATION_WAIT_S}s)...", level="info"))
    time.sleep(_STABILIZATION_WAIT_S)

    clear_logcat = prompt_utils.prompt_yes_no("Clear logcat at run start?", default=True)

    spec = build_dynamic_run_spec(
        package_name=package_name,
        device_serial=device_serial,
        observer_ids=tuple(observer_ids),
        scenario_id=defaults.scenario_id,
        tier="exploration",
        duration_seconds=defaults.duration_s,
        plan_path=plan_path,
        static_run_id=static_run_id,
        clear_logcat=bool(clear_logcat),
        interactive=True,
        require_dynamic_schema=bool(defaults.require_dynamic_schema),
        run_profile=str(run_profile or "").strip(),
        counts_toward_completion=True,
        observer_prompts_enabled=bool(ui_prompt_observers),
        pcapdroid_api_key=os.environ.get("SCYTALEDROID_PCAPDROID_API_KEY"),
    )

    result = execute_dynamic_run_spec(spec)
    # print_run_summary expects a short wall-clock label (kept for back-compat across flows).
    try:
        print_run_summary(result, f"Profile v3 ({run_profile})")
    except Exception as exc:  # noqa: BLE001
        # Capture already succeeded; don't crash the operator flow on summary rendering bugs.
        print(status_messages.status(f"Run summary rendering failed (non-blocking): {type(exc).__name__}: {exc}", level="warn"))
    prompt_utils.press_enter_to_continue()


def run_profile_v3_capture_menu(*, package_name: str, need: str, ui_prompt_observers: bool) -> None:
    """Small per-app run intent menu (baseline/scripted/both) based on need."""

    need = str(need or "").strip().upper()
    accept_manual = str(os.environ.get("SCYTALEDROID_V3_ACCEPT_MANUAL_INTERACTIVE") or "").strip().lower() in {"1", "true", "yes", "on"}
    if accept_manual and need in {"SCRIPTED", "IDLE+SCRIPTED", "INTERACTIVE", "IDLE+INTERACTIVE"}:
        # Time-constrained Phase 2 mode: default to manual interactive when allowed.
        suggested = "4"
    else:
        suggested = "2" if need in {"SCRIPTED", "IDLE+SCRIPTED", "INTERACTIVE", "IDLE+INTERACTIVE"} else "1"
    items = [
        menu_utils.MenuOption("1", "Baseline (idle)", description="run_profile=baseline_idle (phase=idle)", badge=None),
        menu_utils.MenuOption("2", "Interactive (scripted)", description="run_profile=interaction_scripted (phase=interactive)", badge=None),
        menu_utils.MenuOption("3", "Both (idle then scripted)", description="runs two captures back-to-back", badge=None),
        menu_utils.MenuOption("4", "Interactive (manual, fast)", description="run_profile=interaction_manual (phase=interactive)", badge=None),
        menu_utils.MenuOption("5", "Both (idle then manual)", description="runs two captures back-to-back", badge=None),
    ]
    menu_utils.render_menu(
        menu_utils.MenuSpec(items=items, default=suggested, show_exit=True, exit_label="Back", show_descriptions=True, compact=True)
    )
    choice = prompt_utils.get_choice(menu_utils.selectable_keys(items, include_exit=True), default=suggested, casefold=True)
    if choice == "0":
        return
    if choice == "1":
        run_profile_v3_capture_for_package(package_name=package_name, run_profile="baseline_idle", ui_prompt_observers=ui_prompt_observers)
        return
    if choice == "2":
        run_profile_v3_capture_for_package(package_name=package_name, run_profile="interaction_scripted", ui_prompt_observers=ui_prompt_observers)
        return
    if choice == "3":
        run_profile_v3_capture_for_package(package_name=package_name, run_profile="baseline_idle", ui_prompt_observers=ui_prompt_observers)
        run_profile_v3_capture_for_package(package_name=package_name, run_profile="interaction_scripted", ui_prompt_observers=ui_prompt_observers)
        return
    if choice == "4":
        # Manual interaction is allowed for Phase 2 burn-down when time-constrained.
        # Strict manifest/paper policies may still exclude manual runs by default.
        run_profile_v3_capture_for_package(package_name=package_name, run_profile="interaction_manual", ui_prompt_observers=ui_prompt_observers)
        return
    if choice == "5":
        run_profile_v3_capture_for_package(package_name=package_name, run_profile="baseline_idle", ui_prompt_observers=ui_prompt_observers)
        run_profile_v3_capture_for_package(package_name=package_name, run_profile="interaction_manual", ui_prompt_observers=ui_prompt_observers)
        return


__all__ = ["run_profile_v3_capture_menu"]
