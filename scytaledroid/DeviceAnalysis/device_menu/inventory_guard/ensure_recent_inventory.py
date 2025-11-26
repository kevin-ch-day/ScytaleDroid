"""High level orchestration for enforcing inventory freshness."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from scytaledroid.DeviceAnalysis import adb_utils
from scytaledroid.DeviceAnalysis import inventory as inventory_module
from .constants import (
    INVENTORY_STALE_SECONDS,
    LONG_RUNNING_SYNC_THRESHOLD,
    LOW_BATTERY_THRESHOLD,
)
from .metadata import get_latest_inventory_metadata
from .prompts import prompt_inventory_decision
from .utils import coerce_float, humanize_seconds, coarse_time_range


RECENT_CHANGE_WINDOW_SECONDS = 3600
RECENT_CHANGE_SOFT_LIMIT = 3
PACKAGE_DELTA_DISPLAY_LIMIT = 3


_LAST_GUARD_DECISION: Dict[str, object] = {
    "policy": None,
    "stale_level": "unknown",
    "reason": "",
    "scope_changed": False,
    "scope_hash_changed": False,
    "packages_changed": False,
    "age_seconds": None,
    "package_delta": None,
    "package_delta_brief": None,
    "guard_brief": None,
}


def ensure_recent_inventory(
    serial: str,
    *,
    device_context: Optional[Dict[str, Optional[str]]] = None,
    scope_packages: Optional[Sequence[object]] = None,
) -> bool:
    global _LAST_GUARD_DECISION

    _LAST_GUARD_DECISION = {
        "policy": None,
        "stale_level": "unknown",
        "reason": "",
        "scope_changed": False,
        "scope_hash_changed": False,
        "packages_changed": False,
        "age_seconds": None,
        "package_delta": None,
        "package_delta_brief": None,
        "guard_brief": None,
    }

    if scope_packages is None:
        snapshot_payload = inventory_module.load_latest_inventory(serial)
        if isinstance(snapshot_payload, dict):
            packages_value = snapshot_payload.get("packages")
            if isinstance(packages_value, list):
                scope_packages = packages_value

    metadata = get_latest_inventory_metadata(
        serial,
        with_current_state=True,
        scope_packages=scope_packages,
    )

    timestamp = metadata.get("timestamp") if metadata else None
    packages_changed = bool(metadata.get("packages_changed")) if metadata else False
    fingerprint_changed = bool(metadata.get("build_fingerprint_changed")) if metadata else False
    scope_changed = bool(metadata.get("scope_changed")) if metadata else False
    scope_hash_changed = bool(metadata.get("scope_hash_changed")) if metadata else False
    state_changed = (
        packages_changed or fingerprint_changed or scope_changed or scope_hash_changed
    )
    package_delta_summary: Optional[Dict[str, object]] = None
    total_delta = 0
    delta_brief: Optional[str] = None
    if metadata:
        raw_delta = metadata.get("package_delta_summary")
        if isinstance(raw_delta, dict):
            package_delta_summary = raw_delta
            try:
                total_delta = int(raw_delta.get("total_changed") or 0)
            except (TypeError, ValueError):
                total_delta = 0
            delta_brief = _format_package_delta_brief(
                package_delta_summary, limit=PACKAGE_DELTA_DISPLAY_LIMIT
            )
        else:
            package_delta_summary = None
    expected_duration = coerce_float(
        metadata.get("estimated_duration_seconds") if metadata else None
    )

    age_seconds = None
    if timestamp:
        age_seconds = (datetime.now(timezone.utc) - timestamp).total_seconds()
        if age_seconds <= INVENTORY_STALE_SECONDS and not state_changed:
            _set_guard_context(
                stale_level="fresh",
                reason="Inventory snapshot is within freshness window.",
                scope_changed=scope_changed,
                scope_hash_changed=scope_hash_changed,
                packages_changed=packages_changed,
                age_seconds=age_seconds,
                package_delta=package_delta_summary,
                package_delta_brief=delta_brief,
            )
            _record_guard_policy("quick")
            return True

    stale_level = "hard"
    refresh_reason = "Inventory snapshot is stale—sync recommended before pull."
    if not metadata or not timestamp:
        refresh_reason = (
            "No inventory snapshot found—inventory sync required before pull."
        )
    else:
        age_stale = age_seconds is not None and age_seconds >= INVENTORY_STALE_SECONDS
        if packages_changed or scope_changed or scope_hash_changed:
            refresh_reason = (
                "Inventory is fresh by age, but device packages changed since the last snapshot—sync recommended before pull."
            )
            if delta_brief:
                refresh_reason = f"{refresh_reason} Recent changes: {delta_brief}."
            stale_level = "hard"
        elif age_stale:
            refresh_reason = (
                "Inventory snapshot exceeds the freshness threshold—sync recommended before pull."
            )
            stale_level = "hard"
        elif fingerprint_changed:
            stale_level = "soft"
            refresh_reason = (
                "Build fingerprint changed since the last inventory. Packages appear unchanged, so a quick harvest is recommended."
            )
        else:
            stale_level = "fresh"

    if stale_level == "fresh" and timestamp:
        _set_guard_context(
            stale_level="fresh",
            reason="Inventory snapshot is within freshness window.",
            scope_changed=scope_changed,
            scope_hash_changed=scope_hash_changed,
            packages_changed=packages_changed,
            age_seconds=age_seconds,
        )
        _record_guard_policy("quick")
        return True

    _set_guard_context(
        stale_level=stale_level,
        reason=refresh_reason,
        scope_changed=scope_changed,
        scope_hash_changed=scope_hash_changed,
        packages_changed=packages_changed,
        age_seconds=age_seconds,
        package_delta=package_delta_summary,
        package_delta_brief=delta_brief,
    )

    # Only emit warnings here for missing/age-stale snapshots; defer change-only messaging to gating dialogs.
    age_stale = age_seconds is not None and age_seconds >= INVENTORY_STALE_SECONDS if timestamp else False
    if refresh_reason and (not timestamp or age_stale):
        print(status_messages.status(refresh_reason, level="info"))

    battery_context = _resolve_battery_context(serial, device_context)
    battery_level = battery_context.get("level")
    low_battery = (
        isinstance(battery_level, int)
        and battery_level < LOW_BATTERY_THRESHOLD
        and not battery_context.get("is_charging")
    )

    require_sync = not timestamp
    if not require_sync:
        quick_hint = None
        hints: List[str] = []
        if stale_level == "soft":
            hints.append(
                "Quick harvest recommended: build fingerprint changed but packages match the last snapshot."
            )
        if low_battery:
            hints.append(
                f"Battery is low ({battery_level}%). Defaulting to reuse the existing snapshot to avoid a long sync."
            )
        if scope_hash_changed:
            hints.append(
                "Scope selection changed since the last inventory; refresh recommended for complete coverage."
            )
        if package_delta_summary:
            delta_hint = _format_package_delta_hint(
                package_delta_summary, limit=PACKAGE_DELTA_DISPLAY_LIMIT
            )
            if delta_hint:
                hints.append(delta_hint)

        if hints:
            quick_hint = " ".join(hints)

        default_choice = "2" if (stale_level == "soft" or low_battery) else "1"

        try:
            decision = prompt_inventory_decision(
                timestamp=timestamp,
                age_seconds=age_seconds,
                state_changed=state_changed,
                stale_level=stale_level,
                default_choice=default_choice,
                quick_hint=quick_hint,
                changes_total=total_delta if total_delta else None,
            )
        except KeyboardInterrupt:
            print()
            print(
                status_messages.status(
                    "Inventory guard cancelled; APK pull aborted.", level="warn"
                )
            )
            _record_guard_policy("cancelled")
            return False

        if decision == "use_snapshot":
            snapshot_age_text = humanize_seconds(age_seconds) if age_seconds is not None else None
            warning = (
                f"Proceeding with existing inventory snapshot captured {snapshot_age_text} ago; results may be outdated."
                if snapshot_age_text
                else "Proceeding with existing inventory snapshot; results may be outdated."
            )
            print(status_messages.status(warning, level="warn"))
            _record_guard_policy("quick")
            return True

        if decision == "cancel":
            print(
                status_messages.status(
                    "APK pull cancelled until inventory sync is run.", level="warn"
                )
            )
            _record_guard_policy(None)
            return False

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
            _record_guard_policy(None)
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
            from scytaledroid.DeviceAnalysis.services import inventory_service
            inventory_service.run_full_sync(
                serial=serial,
                ui_prefs=None,
                progress_sink="cli",
            )
        except Exception:
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

    _record_guard_policy("refresh")
    _LAST_GUARD_DECISION["reason"] = "Inventory sync completed before APK pull."
    return True


def get_last_guard_decision() -> Dict[str, object]:
    """Return a copy of the most recent guard decision context."""

    return dict(_LAST_GUARD_DECISION)


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
        reasons.append(f"estimated {coarse_time_range(expected_duration)}")

    if not reasons:
        return None

    joined = "; ".join(reasons)
    return f"Estimated: {joined}."


def _build_long_running_warning(estimate: Optional[float]) -> str:
    if estimate and estimate > 0:
        return f"Estimated: {coarse_time_range(estimate)}."
    return "Estimated: longer than usual."


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


def _set_guard_context(
    *,
    stale_level: str,
    reason: str,
    scope_changed: bool,
    scope_hash_changed: bool,
    packages_changed: bool,
    age_seconds: Optional[float],
    package_delta: Optional[Dict[str, object]],
    package_delta_brief: Optional[str],
) -> None:
    _LAST_GUARD_DECISION.update(
        {
            "stale_level": stale_level,
            "reason": reason,
            "scope_changed": scope_changed,
            "scope_hash_changed": scope_hash_changed,
            "packages_changed": packages_changed,
            "age_seconds": age_seconds,
            "package_delta": package_delta,
            "package_delta_brief": package_delta_brief,
            "guard_brief": reason,
        }
    )


def _record_guard_policy(policy: Optional[str]) -> None:
    _LAST_GUARD_DECISION["policy"] = policy
    if policy:
        log.info(
            (
                f"Inventory guard policy {policy} selected "
                f"(stale_level={_LAST_GUARD_DECISION.get('stale_level')}, "
                f"scope_changed={_LAST_GUARD_DECISION.get('scope_changed')}, "
                f"scope_hash_changed={_LAST_GUARD_DECISION.get('scope_hash_changed')}, "
                f"packages_changed={_LAST_GUARD_DECISION.get('packages_changed')})"
            ),
            category="device",
        )


def _format_package_delta_brief(
    summary: Dict[str, object], *, limit: int = PACKAGE_DELTA_DISPLAY_LIMIT
) -> Optional[str]:
    parts: List[str] = []

    def _format_names(key: str, total_key: str) -> Optional[str]:
        items = summary.get(key)
        if not isinstance(items, list) or not items:
            return None
        names = [str(item) for item in items[:limit]]
        if not names:
            return None
        extra = max(_safe_int(summary.get(total_key)) - len(names), 0)
        text = ", ".join(names)
        if extra:
            text = f"{text}, …"
        return text

    updated_items = summary.get("updated")
    if isinstance(updated_items, list) and updated_items:
        formatted_updates: List[str] = []
        for entry in updated_items[:limit]:
            if not isinstance(entry, dict):
                continue
            package = entry.get("package")
            if not isinstance(package, str) or not package:
                continue
            before = entry.get("before") or "?"
            after = entry.get("after") or "?"
            formatted_updates.append(f"{package} ({before}→{after})")
        if formatted_updates:
            extra = max(
                _safe_int(summary.get("total_updated")) - len(formatted_updates), 0
            )
            text = ", ".join(formatted_updates)
            if extra:
                text = f"{text}, …"
            parts.append(f"updates: {text}")

    added_text = _format_names("added", "total_added")
    if added_text:
        parts.append(f"added: {added_text}")

    removed_text = _format_names("removed", "total_removed")
    if removed_text:
        parts.append(f"removed: {removed_text}")

    if not parts:
        return None
    return "; ".join(parts)


def _format_package_delta_hint(
    summary: Dict[str, object], *, limit: int = PACKAGE_DELTA_DISPLAY_LIMIT
) -> Optional[str]:
    total = _safe_int(summary.get("total_changed"))
    brief = _format_package_delta_brief(summary, limit=limit)
    if brief:
        if total:
            return f"Recent package changes ({total}): {brief}."
        return f"Recent package changes: {brief}."
    if total:
        return f"Recent package changes detected ({total})."
    return None


def _safe_int(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
