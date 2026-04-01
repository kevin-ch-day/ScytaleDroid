"""CLI UI helpers for APK pull workflows."""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence

from scytaledroid.DeviceAnalysis import harvest, inventory
from scytaledroid.DeviceAnalysis.apk.models import PlanResolution
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.utils import (
    coerce_float,
    humanize_seconds,
)
from scytaledroid.Utils.DisplayUtils import error_panels, menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def is_harvest_simple_mode() -> bool:
    return os.getenv("SCYTALEDROID_HARVEST_SIMPLE", "1").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def make_progress_callback(action_label: str) -> Callable[[dict[str, object]], bool]:
    last_reported = 0.0

    def _callback(event: dict[str, object]) -> bool:
        nonlocal last_reported

        phase = event.get("phase")
        if phase == "start":
            total = event.get("total")
            if isinstance(total, int) and total > 0:
                message = f"{action_label}: {total} packages"
            else:
                message = f"{action_label}..."
            print(status_messages.status(message, level="info"))
            return True

        if phase == "progress":
            percentage = event.get("percentage")
            eta_seconds = coerce_float(event.get("eta_seconds"))
            percent_value = None
            if isinstance(percentage, (int, float)):
                percent_value = float(percentage)
            else:
                processed = event.get("processed")
                total = event.get("total")
                if isinstance(processed, int) and isinstance(total, int) and total:
                    percent_value = (processed / total) * 100

            if percent_value is not None:
                if percent_value >= 100 or percent_value - last_reported >= 5:
                    last_reported = percent_value
                    if eta_seconds is not None and eta_seconds > 0:
                        eta_text = humanize_seconds(eta_seconds)
                        message = f"{action_label} progress: {percent_value:.1f}% (ETA {eta_text})"
                    else:
                        message = f"{action_label} progress: {percent_value:.1f}%"
                    print(status_messages.status(message, level="info"))
            elif eta_seconds is not None and eta_seconds > 0:
                eta_text = humanize_seconds(eta_seconds)
                print(
                    status_messages.status(
                        f"{action_label} progress (ETA {eta_text})",
                        level="info",
                    )
                )

            return True

        if phase == "complete":
            elapsed = coerce_float(event.get("elapsed_seconds"))
            if elapsed is not None and elapsed >= 0:
                message = f"{action_label} completed in {humanize_seconds(elapsed)}."
            else:
                message = f"{action_label} completed."
            print(status_messages.status(message, level="success"))
            return True

        return True

    return _callback


def run_scope_refresh(serial: str, packages: Sequence[object]) -> bool:
    if not packages:
        print(status_messages.status("No packages provided for scoped refresh.", level="warn"))
        return False

    progress = make_progress_callback("Refreshing scoped inventory")
    try:
        snapshot_path = inventory.sync_subset(
            packages,
            serial=serial,
            progress_callback=progress,
        )
    except inventory.InventorySyncAborted:
        print(status_messages.status("Scoped refresh cancelled.", level="warn"))
        return False
    except Exception as exc:  # pragma: no cover - defensive logging
        log.warning(f"Scoped inventory refresh failed: {exc}", category="device")
        print(status_messages.status("Scoped refresh failed.", level="error"))
        return False

    if not snapshot_path:
        print(status_messages.status("Scoped refresh produced no snapshot.", level="warn"))
        return False

    print(status_messages.status(f"Scoped inventory saved to {str(snapshot_path)}", level="success"))
    return True


def render_plan_overview(resolution: PlanResolution) -> None:
    selection = resolution.selection
    stats = resolution.stats
    print()
    delta_line = None
    if selection.metadata.get("delta_filter_applied"):
        delta_total = selection.metadata.get("delta_filter_total")
        delta_matched = selection.metadata.get("delta_filter_matched")
        if delta_total is not None or delta_matched is not None:
            parts: list[str] = []
            if delta_total is not None:
                parts.append(f"changed={delta_total}")
            if delta_matched is not None:
                parts.append(f"matched_in_scope={delta_matched}")
            delta_line = f"Delta: applied ({', '.join(parts)})"
        else:
            delta_line = "Delta: applied"

    candidate_count = selection.metadata.get("candidate_count")
    selected_count = selection.metadata.get("selected_count")
    if not candidate_count:
        candidate_count = len(selection.packages)
    if selected_count is None:
        selected_count = len(selection.packages)

    scheduled_packages = int(stats["scheduled_packages"])
    blocked_packages = int(stats["blocked_packages"])
    scheduled_files = int(stats["scheduled_files"])
    policy_blocked = int(stats["policy_blocked"])
    policy = str(stats["policy"])
    eligible_policy = max(scheduled_packages + policy_blocked, 0)
    blocked_scope = max(blocked_packages - policy_blocked, 0)
    if is_harvest_simple_mode():
        return

    print("APK Harvest Plan")
    print("-" * 86)
    print(
        f"Scope={selection.label} | candidates={candidate_count} | selected={selected_count} | "
        f"policy_eligible={eligible_policy} | scheduled_in_scope={scheduled_packages} | "
        f"blocked_by_policy={policy_blocked} | blocked_by_scope={blocked_scope} | "
        f"blocked_total={blocked_packages} | files≈{scheduled_files} | policy={policy}"
    )
    if delta_line:
        print(delta_line)
    focus = selection.metadata.get("sample_names") or []
    total = selection.metadata.get("selected_count") or len(selection.packages)
    if focus:
        extra = f" (+{int(total) - len(focus)} more)" if total and int(total) > len(focus) else ""
        print(f"Focus: {', '.join(focus)}{extra}")
    print("-" * 86)


def prompt_plan_action(resolution: PlanResolution) -> str:
    print("1) Pull APKs (default)   - download APK splits + metadata")
    print("2) Preview plan          - dry run (list only)")
    print("0) Cancel")
    choice = prompt_utils.get_choice(["1", "2", "0"], default="1", prompt="Select: ")
    if choice == "1":
        return "pull_snapshot"
    if choice == "2":
        return "dry-run"
    return "cancel"


def prompt_delta_filter_mode(summary: Mapping[str, object]) -> bool:
    """Return True to apply delta filtering, False to disable it for this pull session."""

    total_changed = summary.get("total_changed")
    total_text = f"{int(total_changed)}" if isinstance(total_changed, int) else "some"
    print()
    print("Harvest Mode")
    print("────────────")
    print(
        status_messages.status(
            f"Recent package changes detected ({total_text}).",
            level="info",
        )
    )
    print("1) Pull changed packages only (default)  - faster, avoids re-downloading unchanged APKs")
    print("2) Pull all packages in selected scope   - forces a full refresh on disk")
    choice = prompt_utils.get_choice(["1", "2"], default="1", prompt="Select: ")
    return choice == "1"


def maybe_save_watchlist(selection: harvest.ScopeSelection) -> None:
    if selection.kind not in {"profile_subset", "profiles"}:
        return

    packages = [row.package_name for row in selection.packages]
    if len(packages) < 2:
        return
    if not prompt_utils.prompt_yes_no("Save this scope as a watchlist?", default=False):
        return

    default_name = selection.metadata.get("watchlist", selection.label)
    default_name = str(default_name).replace("Watchlist:", "").strip() or "New Watchlist"

    while True:
        name = prompt_utils.prompt_text("Watchlist name", default=default_name)
        try:
            path = harvest.save_watchlist(name, packages, overwrite=False)
        except FileExistsError:
            overwrite = prompt_utils.prompt_yes_no(
                "Watchlist exists. Overwrite?", default=False
            )
            if overwrite:
                path = harvest.save_watchlist(name, packages, overwrite=True)
            else:
                default_name = f"{name}-copy"
                continue
        print(status_messages.status(f"Watchlist saved to {path}", level="success"))
        break


def print_no_artifacts_menu() -> str:
    options = {
        "1": "Rescope",
        "2": "Refresh inventory & rescope",
        "0": "Cancel",
    }
    menu_utils.print_menu(options, show_exit=False, show_descriptions=False)
    return prompt_utils.get_choice(list(options) + ["0"], default="1")


def prompt_inventory_sync() -> bool:
    return prompt_utils.prompt_yes_no("Run an inventory sync now?", default=True)


def report_profile_v3_requires_inventory_sync(summary: Mapping[str, object]) -> None:
    total_changed = summary.get("total_changed")
    total_text = f"{int(total_changed)}" if isinstance(total_changed, int) else "some"
    print()
    print("Inventory Sync Required")
    print("───────────────────────")
    print(
        status_messages.status(
            "Structural cohort harvest requires a fresh inventory snapshot before pulling APKs.",
            level="warn",
        )
    )
    print(
        status_messages.status(
            f"Device packages changed since the last snapshot ({total_text} change(s)). Sync before pulling APKs.",
            level="warn",
        )
    )


def prompt_profile_v3_inventory_sync_now() -> bool:
    return prompt_utils.prompt_yes_no("Sync inventory now before pulling structural cohort APKs?", default=True)


def report_inventory_sync_failure(exc: Exception) -> None:
    error_panels.print_error_panel("APK Pull", f"Inventory sync failed: {exc}")
    prompt_utils.press_enter_to_continue()


def report_missing_inventory_snapshot() -> None:
    error_panels.print_error_panel(
        "APK Pull",
        "No inventory snapshot found for this device.",
        hint="Run an inventory sync before attempting to harvest APKs.",
    )


def report_invalid_snapshot_after_sync() -> None:
    error_panels.print_error_panel(
        "APK Pull",
        "Unable to retrieve inventory data after sync.",
    )
    prompt_utils.press_enter_to_continue()


def report_empty_snapshot() -> None:
    error_panels.print_error_panel(
        "APK Pull",
        "Inventory snapshot contains no packages.",
    )
    prompt_utils.press_enter_to_continue()


def report_scoped_snapshot_invalid() -> None:
    error_panels.print_error_panel(
        "APK Pull",
        "Scoped refresh did not yield a valid snapshot.",
        hint="Run a full inventory sync to recover.",
    )
    prompt_utils.press_enter_to_continue()


def report_scoped_snapshot_empty() -> None:
    error_panels.print_error_panel(
        "APK Pull",
        "Scoped snapshot contains no packages.",
        hint="Adjust your selection or run a full sync.",
    )
    prompt_utils.press_enter_to_continue()


def report_refresh_snapshot_invalid() -> None:
    error_panels.print_error_panel(
        "APK Pull",
        "Inventory refresh did not yield a valid snapshot.",
        hint="Run inventory sync from the main menu.",
    )
    prompt_utils.press_enter_to_continue()


def report_refresh_snapshot_empty() -> None:
    error_panels.print_error_panel(
        "APK Pull",
        "Inventory snapshot contains no packages after refresh.",
    )
    prompt_utils.press_enter_to_continue()


def report_summary_failure(exc: Exception) -> None:
    error_panels.print_error_panel(
        "APK Harvest",
        f"Harvest completed, but summary rendering failed: {exc}",
        hint="Artifacts and logs were written; inspect harvest logs for details.",
    )


def report_apk_pull_cancelled() -> None:
    print(status_messages.status("APK pull cancelled by user.", level="warn"))


def report_no_packages_selected() -> None:
    print(status_messages.status("Selection contains no packages. Nothing to pull.", level="warn"))


def report_delta_scope_empty() -> None:
    print(
        status_messages.status(
            "Inventory delta shows no packages requiring harvest.",
            level="info",
        )
    )


def report_delta_scope_applied(delta_count: int) -> None:
    print(
        status_messages.status(
            f"Δ harvest scope: {delta_count} package(s) scheduled (changed-only mode).",
            level="info",
        )
    )


def report_full_refresh_scope_applied(selected_count: int) -> None:
    print(
        status_messages.status(
            f"Full refresh scope: {selected_count} package(s) scheduled (changed-only mode disabled).",
            level="info",
        )
    )


def report_plan_no_artifacts() -> None:
    print(
        status_messages.status(
            "Plan contains no readable artifacts. Adjust the scope and try again.",
            level="warn",
        )
    )


def report_skip_reasons(skip_reasons: dict[str, tuple[int, list[str]]]) -> None:
    labels = {
        "policy_non_root": "policy_non_root (system/vendor filtered)",
        "no_paths": "no_paths (package returned no readable APK paths)",
        "dedupe_sha256": "dedupe_sha256 (artifact already harvested)",
        "not_in_scope": "not_in_scope (scope/policy filtered)",
        "google_core": "google_core (core Google module filtered)",
    }
    sorted_items = sorted(skip_reasons.items(), key=lambda item: item[1][0], reverse=True)
    top_items = sorted_items[:5]
    for reason, (count, samples) in top_items:
        sample_text = ", ".join(samples)
        label = labels.get(reason, reason)
        print(
            status_messages.status(
                f"Skip reason: {label} ({count}) e.g., {sample_text}",
                level="info",
            )
        )
    if len(sorted_items) > len(top_items):
        remainder = len(sorted_items) - len(top_items)
        print(
            status_messages.status(
                f"Skip reasons: +{remainder} more",
                level="info",
            )
        )


def report_inventory_sync_issue(exc: Exception) -> None:
    print(
        status_messages.status(
            f"Inventory sync cancelled or failed: {exc}",
            level="warn",
        )
    )


def report_using_existing_snapshot() -> None:
    print(
        status_messages.status(
            "Proceeding with existing inventory snapshot only.",
            level="warn",
        )
    )


def report_harvest_started(
    *,
    candidate_count: int,
    selected_count: int,
    policy_eligible: int,
    scheduled: int,
    blocked_policy: int,
    blocked_scope: int,
    artifacts: int,
    policy: str,
    harvest_mode: str | None = None,
    delta_filter_applied: bool | None = None,
) -> None:
    line = (
        "APK Harvest started • "
        f"inventory={candidate_count} • selected={selected_count} • policy_eligible={policy_eligible} "
        f"• scheduled_in_scope={scheduled} • blocked_policy={blocked_policy} • blocked_scope={blocked_scope} "
        f"• artifacts≈{artifacts} • policy={policy}"
    )
    if harvest_mode:
        line += f" • harvest_mode={harvest_mode}"
    if delta_filter_applied is not None:
        line += f" • delta_filter_applied={'true' if delta_filter_applied else 'false'}"
    print(status_messages.status(line, level="info"))


def pause_after_preview() -> None:
    prompt_utils.press_enter_to_continue()


def report_no_device() -> None:
    error_panels.print_error_panel(
        "APK Pull",
        "No active device. Connect first to pull APKs.",
    )


def report_no_adb() -> None:
    error_panels.print_error_panel(
        "APK Pull",
        "adb binary not found on PATH.",
        hint="Ensure the Android platform tools are installed and exported in PATH.",
    )
