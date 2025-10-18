"""Interactive menu for APK static analysis workflows."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

from ..core.repository import group_artifacts
from .masvs_menu import render_masvs_summary_menu, render_scoring_explainer_menu
from .models import RunParameters
from .profiles import run_modules_for_profile
from .prompts import prompt_tuning
from .runner import launch_scan_flow
from .scope import select_scope, format_scope_target


MENU_OPTIONS = [
    ("1", "Full static analysis (all detectors; writes to DB)", "Run all detectors and persist summaries", "full"),
    ("2", "Baseline static analysis (paper-aligned; writes to DB)", "Faster path; key detectors only", "lightweight"),
    ("3", "App Metadata (hashes, manifest flags)", "No DB writes; summary only", "metadata"),
    ("4", "Permission Analysis (writes to DB)", "Persist detected permissions and audit", "permissions"),
    ("5", "String analysis (DEX + resources; writes to DB)", "Persist string summary and samples", "strings"),
    ("6", "Split-APK composition (base + splits)", "Analyze split grouping and consistency", "split"),
    ("7", "WebView posture (read-only)", "Check JS/mixed-content/JS bridge flags", "webview"),
    ("8", "Network Security Config (read-only)", "Parse NSC cleartext/pins/user certs", "nsc"),
    ("9", "IPC & PendingIntent safety (read-only)", "Exported receivers/permissions; PI flags", "ipc"),
    ("10", "Crypto/TLS quick scan (read-only)", "Weak hashes/TLS refs in strings", "crypto"),
    ("11", "SDK fingerprints (read-only)", "Known analytics/ads SDK presence", "sdk"),
]


def static_analysis_menu() -> None:
    base_dir = Path(app_config.DATA_DIR) / "apks"
    groups = tuple(group_artifacts(base_dir))
    if not groups:
        print(status_messages.status("No harvested APK groups found. Run Device Analysis → 7 to pull artifacts.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    while True:
        print()
        menu_utils.print_header("Android APK Static Analysis")
        menu_utils.print_menu([(opt, name, desc) for opt, name, desc, _ in MENU_OPTIONS] + [
            ("12", "MASVS summary (read-only)", "Summarise MASVS pass/fail by area from last baseline"),
            ("13", "Risk scoring explainer (read-only)", "Explain weights, breadth bonus and grade thresholds"),
        ], is_main=False)
        choice = prompt_utils.get_choice([opt for opt, *_ in MENU_OPTIONS] + ["12", "13", "0"], default="0")

        if choice == "0":
            break
        if choice == "12":
            render_masvs_summary_menu()
            continue
        if choice == "13":
            render_scoring_explainer_menu()
            continue

        profile = next((profile for opt, *_rest, profile in MENU_OPTIONS if opt == choice), None)
        if profile is None:
            print(status_messages.status("Unsupported option selected.", level="warn"))
            continue

        selection = select_scope(groups)
        params = RunParameters(profile=profile, scope=selection.scope, scope_label=selection.label)
        params = prompt_tuning(params)

        modules = params.selected_tests if params.profile == "custom" and params.selected_tests else run_modules_for_profile(params.profile)
        print()
        menu_utils.print_section("Run Overview")
        for module in modules:
            print(f"  - {module}")

        launch_scan_flow(selection, params, base_dir)


__all__ = ["static_analysis_menu"]
