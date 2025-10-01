"""High level orchestration for enforcing inventory freshness."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages

from .. import adb_utils
from .. import inventory as inventory_module
from .constants import (
    INVENTORY_STALE_SECONDS,
    LONG_RUNNING_SYNC_THRESHOLD,
    LOW_BATTERY_THRESHOLD,
)
from .metadata import get_latest_inventory_metadata
from .prompts import prompt_inventory_decision
from .utils import coerce_float, humanize_seconds


def ensure_recent_inventory(
    serial: str,
    *,
    device_context: Optional[Dict[str, Optional[str]]] = None,
) -> bool:
    metadata = get_latest_inventory_metadata(serial, with_current_state=True)

    timestamp = metadata.get("timestamp") if metadata else None
    state_changed = bool(metadata.get("state_changed")) if metadata else False
    expected_duration = coerce_float(
        metadata.get("estimated_duration_seconds") if metadata else None
    )

    age_seconds = None
    if timestamp:
        age_seconds = (datetime.now(timezone.utc) - timestamp).total_seconds()
        if age_seconds <= INVENTORY_STALE_SECONDS and not state_changed:
            return True

    if not timestamp:
        refresh_reason = "No inventory snapshot found—inventory sync required before pull."
    elif state_changed and age_seconds is not None and age_seconds <= INVENTORY_STALE_SECONDS:
        refresh_reason = (
            "Device state changed since last inventory—sync recommended before pull. "
            "You can reuse the previous snapshot if you understand the risks."
        )
    else:
        refresh_reason = (
            "Inventory snapshot is stale—sync recommended before pull. "
            "Choose whether to refresh or proceed with the existing data."
        )

    print(status_messages.status(refresh_reason, level="info"))

    require_sync = not timestamp
    if not require_sync:
        decision = prompt_inventory_decision(
            timestamp=timestamp,
            age_seconds=age_seconds,
            state_changed=state_changed,
        )

        if decision == "use_snapshot":
            snapshot_age_text = None
            if age_seconds is not None:
                snapshot_age_text = humanize_seconds(age_seconds)
            if snapshot_age_text:
                warning = (
                    "Proceeding with existing inventory snapshot "
                    f"captured {snapshot_age_text} ago; results may be outdated."
                )
            else:
                warning = (
                    "Proceeding with existing inventory snapshot; results may be outdated."
                )
            print(status_messages.status(warning, level="warn"))
            return True

        if decision == "cancel":
            print(
                status_messages.status(
                    "APK pull cancelled until inventory sync is run.", level="warn"
                )
            )
            return False

    battery_context = _resolve_battery_context(serial, device_context)
    prompt_message = _build_sync_warning(battery_context, expected_duration)

    if prompt_message:
        print(status_messages.status(prompt_message, level="warn"))
        if not prompt_utils.prompt_yes_no(
            "Run inventory sync before pulling APKs?", default=False
        ):
            print(
                status_messages.status(
                    "APK pull cancelled until inventory sync is run.", level="warn"
                )
            )
            return False
        abort_on_long_running = False
    else:
        abort_on_long_running = True

    def _execute_sync(abort_on_threshold: bool) -> Tuple[bool, Optional[float]]:
        nonlocal expected_duration

        aborted = False
        latest_estimate = expected_duration
        last_reported = -5.0

        def _handle_progress(event: Dict[str, object]) -> bool:
            nonlocal aborted, latest_estimate, last_reported

            phase = event.get("phase")
            estimated_total = coerce_float(event.get("estimated_total_seconds")) or latest_estimate

            if phase == "start":
                total = event.get("total")
                if isinstance(total, int) and total > 0:
                    message = f"Syncing {total} packages..."
                else:
                    message = "Syncing packages..."
                print(status_messages.status(message, level="info"))
                if estimated_total is not None:
                    latest_estimate = estimated_total
                if (
                    abort_on_threshold
                    and estimated_total
                    and estimated_total > LONG_RUNNING_SYNC_THRESHOLD
                ):
                    aborted = True
                    return False

            elif phase == "progress":
                percentage = event.get("percentage")
                eta_seconds = coerce_float(event.get("eta_seconds"))
                if isinstance(percentage, (int, float)):
                    percent_value = float(percentage)
                    if percent_value >= 100 or percent_value - last_reported >= 5:
                        last_reported = percent_value
                        if eta_seconds is not None:
                            eta_text = humanize_seconds(eta_seconds)
                            message = f"Sync progress: {percent_value:.1f}% (ETA {eta_text})"
                        else:
                            message = f"Sync progress: {percent_value:.1f}%"
                        print(status_messages.status(message, level="info"))
                elif eta_seconds is not None:
                    eta_text = humanize_seconds(eta_seconds)
                    print(
                        status_messages.status(
                            f"Sync progress (ETA {eta_text})", level="info"
                        )
                    )

                elapsed_seconds = coerce_float(event.get("elapsed_seconds"))
                if eta_seconds is not None and eta_seconds > 0:
                    if elapsed_seconds is not None:
                        latest_estimate = eta_seconds + elapsed_seconds
                    else:
                        latest_estimate = eta_seconds
                elif estimated_total is not None:
                    latest_estimate = estimated_total

                if (
                    abort_on_threshold
                    and latest_estimate
                    and latest_estimate > LONG_RUNNING_SYNC_THRESHOLD
                ):
                    aborted = True
                    return False

            elif phase == "complete":
                elapsed = coerce_float(event.get("elapsed_seconds"))
                if elapsed is not None:
                    message = f"Inventory sync completed in {humanize_seconds(elapsed)}."
                else:
                    message = "Inventory sync completed."
                print(status_messages.status(message, level="success"))

            return True

        try:
            inventory_module.run_inventory_sync(
                serial,
                interactive=False,
                progress_callback=_handle_progress,
                expected_total_seconds=expected_duration,
            )
        except inventory_module.InventorySyncAborted:
            if not aborted:
                raise
        return aborted, latest_estimate

    aborted, estimate = _execute_sync(abort_on_long_running)
    if aborted:
        warning = _build_long_running_warning(estimate)
        print(status_messages.status(warning, level="warn"))
        if not prompt_utils.prompt_yes_no("Continue with inventory sync?", default=False):
            print(
                status_messages.status(
                    "APK pull cancelled until inventory sync is run.", level="warn"
                )
            )
            return False
        if estimate:
            expected_duration = estimate
        aborted, estimate = _execute_sync(False)

    return True


def _build_sync_warning(
    battery_context: Dict[str, Optional[object]],
    expected_duration: Optional[float],
) -> Optional[str]:
    reasons: List[str] = []

    level = battery_context.get("level")
    is_charging = bool(battery_context.get("is_charging"))
    if isinstance(level, int) and level < LOW_BATTERY_THRESHOLD:
        if is_charging:
            reasons.append(f"battery is low ({level}%, charging)")
        else:
            reasons.append(f"battery is low ({level}%)")

    if expected_duration and expected_duration > LONG_RUNNING_SYNC_THRESHOLD:
        reasons.append(
            f"sync may take around {humanize_seconds(expected_duration)}"
        )

    if not reasons:
        return None

    joined = " and ".join(reasons)
    return f"Inventory sync {joined}."


def _build_long_running_warning(estimate: Optional[float]) -> str:
    if estimate and estimate > 0:
        return f"Inventory sync is expected to take {humanize_seconds(estimate)}."
    return "Inventory sync may take longer than usual."


def _parse_battery_level(raw: Optional[str]) -> Optional[int]:
    if not raw:
        return None
    digits = "".join(ch for ch in raw if ch.isdigit())
    if not digits:
        return None
    try:
        return int(digits)
    except ValueError:
        return None


def _resolve_battery_context(
    serial: str,
    device_context: Optional[Dict[str, Optional[str]]],
) -> Dict[str, Optional[object]]:
    level: Optional[int] = None
    status: Optional[str] = None

    if device_context:
        level = _parse_battery_level(device_context.get("battery_level"))
        status_value = device_context.get("battery_status")
        if isinstance(status_value, str):
            status = status_value

    if level is None or status is None:
        stats = adb_utils.get_device_stats(serial)
        if level is None:
            level = _parse_battery_level(stats.get("battery_level"))
        if status is None:
            status_value = stats.get("battery_status")
            if isinstance(status_value, str):
                status = status_value

    normalized_status = status.lower() if isinstance(status, str) else ""
    is_charging = "charg" in normalized_status

    return {"level": level, "status": status, "is_charging": is_charging}
