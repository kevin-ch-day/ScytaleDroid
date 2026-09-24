"""Capture-first controller; the existing engine owns evidence and persistence."""

from __future__ import annotations

from functools import partial

from scytaledroid.DynamicAnalysis.controllers.device_select import select_device
from scytaledroid.DynamicAnalysis.menus.capture_summary import (
    exact_build_history,
    print_capture_summary,
)
from scytaledroid.DynamicAnalysis.services.application_resolution import (
    find_applications,
    load_applications,
)
from scytaledroid.DynamicAnalysis.services.capture_target import (
    TargetUnavailable,
    read_installed_build,
    select_exact_plan,
    verification_record,
)
from scytaledroid.Utils.DisplayUtils import prompt_utils


def choose_application(applications):
    while True:
        query = prompt_utils.prompt_text(
            "App name or package (blank to go back)", required=False
        ).strip()
        if not query:
            return None
        matches = find_applications(query, applications)
        if not matches.applications:
            print(
                "No recognized application. Check spelling, install it, or refresh inventory/harvest."
            )
            continue
        print(
            "Closest matches — confirm your selection:"
            if matches.fuzzy
            else "Matching applications:"
        )
        for i, app in enumerate(matches.applications, 1):
            installed = "unknown" if app.installed is None else "yes" if app.installed else "no"
            print(
                f"  {i}) {app.label} | {app.package} | installed: {installed} | harvested: {'yes' if app.harvested else 'no'}"
            )
        if len(matches.applications) == 1:
            app = matches.applications[0]
            if not matches.fuzzy or prompt_utils.prompt_yes_no("Use this app?", default=False):
                return app
            continue
        choice = prompt_utils.prompt_text(
            "Choose app # (blank to search again)", required=False
        ).strip()
        if choice.isdecimal() and 1 <= int(choice) <= len(matches.applications):
            app = matches.applications[int(choice) - 1]
            if not matches.fuzzy or prompt_utils.prompt_yes_no("Use this app?", default=False):
                return app


def _prerequisite_error(exc):
    if isinstance(exc, TargetUnavailable):
        return str(exc)
    return f"Device or static evidence check failed ({type(exc).__name__}). Open Environment diagnostics; capture was not started."


def _choose_behavior():
    print("\nWhat do you want to capture?")
    print(
        "  1) Interactive — use the app normally [default]\n  2) Idle — quiet baseline intent\n  3) Quiescent foreground — foregrounded, untouched\n  4) Guided collection — open the research queue\n  5) Advanced — legacy scenario and observer controls\n  0) Back"
    )
    return prompt_utils.get_choice(["0", "1", "2", "3", "4", "5"], default="1")


def _final_metadata(serial, build, selection, behavior, proof, _manifest):
    record = dict(proof)
    try:
        end = read_installed_build(serial, build.package)
        record["end_matches_start"] = end == build
        record["end"] = verification_record(end, selection)
        if end != build:
            record["end"]["artifact_set_hash"] = None
            record["end"]["artifact_set_hash_version"] = None
    except Exception:
        record["end_matches_start"] = None
        record["end_error"] = "installed-byte verification unavailable"
    return {"capture_behavior_intent": behavior, "capture_build_verification": record}


def run_capture_app(
    *,
    select_observers,
    guided_collection,
    advanced_capture,
    research_qualification,
    observer_prompts_enabled=False,
    pcapdroid_api_key=None,
):
    selected = select_device()
    if not selected:
        return
    serial, device_label = selected
    applications, notes = load_applications(serial)
    for note in notes:
        print(note)
    while True:
        app = choose_application(applications)
        if app is None:
            return
        next_mode = None
        while True:
            try:
                print("Checking installed APK bytes and exact-build static evidence…")
                build = read_installed_build(serial, app.package)
                selection = select_exact_plan(build)
            except Exception as exc:
                print(f"Capture prerequisite unavailable: {_prerequisite_error(exc)}")
                break
            history = exact_build_history(app.package, selection)
            print(
                f"\n{app.label}\n  {app.package}\n  Installed version: {build.version_name or 'unknown'} ({build.version_code})\n  Base APK SHA-256: {build.base_sha256}\n  APK set: base + {len(build.members) - 1} splits\n  Install-set identity: {selection['artifact_set_hash_version']} / {selection['artifact_set_hash']}\n  Static evidence: ready (run {selection['static_run_id']})\n  Local history: {history['total']} run records; {history['current']} for this exact build\n  Device: {device_label}\n  Capture environment: device/build checked; observers checked at start"
            )
            if not prompt_utils.prompt_yes_no("Use this installed build?", default=True):
                break
            mode = next_mode or _choose_behavior()
            next_mode = None
            if mode == "0":
                break
            if mode == "4":
                guided_collection()
                return
            if mode == "5":
                advanced_capture()
                return
            behavior = {"1": "interactive", "2": "idle", "3": "quiescent_foreground"}[mode]
            if mode != "1":
                print(
                    "Leave the app foregrounded and untouched. This records intent; strict-idle/QFG research qualification requires measured checks."
                )
            observers = select_observers(serial, mode="capture")
            if not observers:
                print("No capture observers available. Open Environment diagnostics.")
                break
            duration_text = (
                prompt_utils.prompt_text(
                    "Capture seconds [240; 0 for manual stop]", required=False
                ).strip()
                or "240"
            )
            if not duration_text.isdecimal() or not 0 <= int(duration_text) <= 86400:
                print("Duration must be 0–86400 seconds.")
                continue
            if not prompt_utils.prompt_yes_no("Start capture?", default=True):
                break
            try:
                if read_installed_build(serial, app.package) != build:
                    raise TargetUnavailable(
                        "Installed build changed after confirmation; select it again."
                    )
            except Exception as exc:
                print(f"Capture not started: {_prerequisite_error(exc)}")
                break
            from scytaledroid.DynamicAnalysis.run_dynamic_analysis import run_dynamic_analysis

            result = run_dynamic_analysis(
                app.package,
                duration_seconds=int(duration_text),
                device_serial=serial,
                scenario_id="basic_usage",
                observer_ids=tuple(observers),
                interactive=True,
                plan_path=selection["plan_path"],
                static_run_id=selection["static_run_id"],
                tier="exploration",
                run_profile="interaction_manual" if mode == "1" else "baseline_idle",
                interaction_level="manual" if mode == "1" else "minimal",
                counts_toward_completion=False,
                require_dynamic_schema=False,
                clear_logcat=False,
                observer_prompts_enabled=observer_prompts_enabled,
                pcapdroid_api_key=pcapdroid_api_key,
                final_operator_metadata_collector=partial(
                    _final_metadata,
                    serial,
                    build,
                    selection,
                    behavior,
                    verification_record(build, selection),
                ),
            )
            print_capture_summary(result, app.label, behavior, selection)
            while True:
                print(
                    "\n1) Run again  2) Capture idle  3) View evidence  4) Another app  5) Research qualification  0) Done"
                )
                action = prompt_utils.get_choice(["0", "1", "2", "3", "4", "5"], default="0")
                if action == "0":
                    return
                if action == "3":
                    from scytaledroid.DynamicAnalysis.run_summary import print_run_summary

                    print_run_summary(result, behavior)
                    continue
                if action == "5":
                    print(
                        "This reviews the active research cohort. This capture remains not evaluated; no evidence is rewritten."
                    )
                    research_qualification()
                    continue
                if action in {"1", "2"}:
                    next_mode = mode if action == "1" else "2"
                break
            if action == "4":
                break
