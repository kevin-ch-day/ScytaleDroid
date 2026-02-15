"""High level orchestration for enforcing inventory freshness."""

from __future__ import annotations

from contextvars import ContextVar
from collections.abc import Sequence
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta

from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.prompts import (
    InventoryDeltaSummary,
    describe_inventory_state,
)
from scytaledroid.DeviceAnalysis.services import device_service, inventory_service
from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages, text_blocks
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .constants import (
    INVENTORY_DELTA_SUPPRESS_SECONDS,
    INVENTORY_STALE_SECONDS,
    LONG_RUNNING_SYNC_THRESHOLD,
    LOW_BATTERY_THRESHOLD,
)
from .metadata import get_latest_inventory_metadata
from .utils import coarse_time_range, coerce_float, humanize_seconds

inventory_module = inventory_service

PACKAGE_DELTA_DISPLAY_LIMIT = 3

GUARD_DECISION_ENUMS = frozenset({"allow", "prompt", "deny", "unknown"})
GUARD_NEXT_ACTIONS = frozenset({"continue", "prompt_choice", "cancel", "none"})
GUARD_PROMPT_KEYS = frozenset(
    {
        "none",
        "inventory_guard_choice",
        "inventory_sync_confirm",
        "inventory_sync_continue",
        "inventory_sync",
    }
)
GUARD_REASON_CODES = frozenset(
    {
        "unknown",
        "fresh_unchanged",
        "message_none",
        "state_requires_choice",
        "recent_snapshot_auto_sync",
        "recent_snapshot_continue",
        "user_selected_snapshot",
        "user_cancelled",
        "sync_prompt_declined",
        "long_running_sync_declined",
        "sync_completed",
    }
)


@dataclass(frozen=True)
class GuardDecision:
    policy: str | None = None
    stale_level: str = "unknown"
    reason: str = ""
    scope_changed: bool = False
    scope_hash_changed: bool = False
    packages_changed: bool = False
    age_seconds: float | None = None
    package_delta: dict[str, object] | None = None
    package_delta_brief: str | None = None
    guard_brief: str | None = None
    decision_enum: str = "unknown"
    reason_code: str = "unknown"
    next_action: str = "none"
    prompt_key: str = "none"


_EMPTY_GUARD_DECISION = GuardDecision()
_LAST_GUARD_DECISION: ContextVar[GuardDecision] = ContextVar(
    "inventory_guard_last_decision",
    default=_EMPTY_GUARD_DECISION,
)


def _format_snapshot_reference(snapshot_id: object, timestamp: object) -> str:
    snapshot_label = ""
    if snapshot_id is not None:
        snapshot_label = f"id={snapshot_id}"
    if isinstance(timestamp, datetime):
        stamp = timestamp.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"{snapshot_label} captured_at={stamp}".strip()
    return snapshot_label


def ensure_recent_inventory(
    serial: str,
    *,
    device_context: dict[str, str | None | None] = None,
    scope_packages: Sequence[object | None] = None,
) -> bool:
    decision = _EMPTY_GUARD_DECISION

    def _finish(allowed: bool) -> bool:
        _LAST_GUARD_DECISION.set(decision)
        return allowed

    metadata = get_latest_inventory_metadata(
        serial,
        with_current_state=False,
        scope_packages=scope_packages,
    )

    timestamp = metadata.get("timestamp") if metadata else None
    snapshot_id = metadata.get("snapshot_id") if metadata else None
    scope_changed = bool(metadata.get("scope_changed")) if metadata else False
    scope_hash_changed = bool(metadata.get("scope_hash_changed")) if metadata else False
    expected_duration = coerce_float(
        metadata.get("estimated_duration_seconds") if metadata else None
    )

    age_seconds = None
    if timestamp:
        age_seconds = (datetime.now(UTC) - timestamp).total_seconds()

    threshold = timedelta(seconds=INVENTORY_STALE_SECONDS)
    age_delta = timedelta(seconds=age_seconds or 0)

    delta_obj = metadata.get("delta") if metadata else None
    if isinstance(delta_obj, dict):
        delta_obj = InventoryDeltaSummary(
            new_count=int(delta_obj.get("new") or 0),
            removed_count=int(delta_obj.get("removed") or 0),
            updated_count=int(delta_obj.get("updated") or 0),
            changed_packages_count=int(
                delta_obj.get("changed")
                or (
                    (delta_obj.get("new") or 0)
                    + (delta_obj.get("removed") or 0)
                    + (delta_obj.get("updated") or 0)
                )
            ),
        )
    elif delta_obj is None and metadata:
        delta_obj = InventoryDeltaSummary(
            new_count=int(metadata.get("delta_new") or 0),
            removed_count=int(metadata.get("delta_removed") or 0),
            updated_count=int(metadata.get("delta_updated") or 0),
            changed_packages_count=int(metadata.get("delta_changed_count") or 0),
        )
    else:
        delta_obj = delta_obj or InventoryDeltaSummary(0, 0, 0, 0)

    if timestamp is None:
        status = "NONE"
    elif age_seconds is not None and age_seconds >= INVENTORY_STALE_SECONDS:
        status = "STALE"
    else:
        status = "FRESH"

    # If we are fresh by age and the recorded delta says nothing changed, short‑circuit
    # without emitting any warnings. This prevents spurious prompts immediately after
    # a clean sync.
    if (
        status == "FRESH"
        and (age_seconds or 0) < INVENTORY_STALE_SECONDS
        and delta_obj.changed_packages_count == 0
    ):
        decision = _set_guard_context(
            decision,
            stale_level="fresh",
            reason="Inventory is fresh and unchanged.",
            decision_enum="allow",
            reason_code="fresh_unchanged",
            next_action="continue",
            prompt_key="none",
            scope_changed=scope_changed,
            scope_hash_changed=scope_hash_changed,
            packages_changed=False,
            age_seconds=age_seconds,
            package_delta=None,
            package_delta_brief=None,
        )
        decision = _record_guard_policy(decision, "quick")
        return _finish(True)

    message = describe_inventory_state(status, delta_obj, age_delta, threshold)

    if message.severity == "none":
        decision = _set_guard_context(
            decision,
            stale_level="fresh",
            reason=message.short,
            decision_enum="allow",
            reason_code="message_none",
            next_action="continue",
            prompt_key="none",
            scope_changed=scope_changed,
            scope_hash_changed=scope_hash_changed,
            packages_changed=False,
            age_seconds=age_seconds,
            package_delta=None,
            package_delta_brief=None,
        )
        decision = _record_guard_policy(decision, "quick")
        return _finish(True)

    packages_changed = bool(delta_obj.changed_packages_count if delta_obj else 0)
    decision = _set_guard_context(
        decision,
        stale_level="warn" if message.severity == "warn" else "fresh",
        reason=message.short,
        decision_enum="prompt",
        reason_code="state_requires_choice",
        next_action="prompt_choice",
        prompt_key="inventory_guard_choice",
        scope_changed=scope_changed,
        scope_hash_changed=scope_hash_changed,
        packages_changed=packages_changed,
        age_seconds=age_seconds,
        package_delta=None,
        package_delta_brief=None,
    )

    print(status_messages.status(message.short, level="warn" if message.severity == "warn" else "info"))
    if delta_obj and delta_obj.changed_packages_count:
        snapshot_stamp = _format_snapshot_reference(snapshot_id, timestamp)
        current_count = metadata.get("current_package_count") if metadata else None
        snapshot_count = metadata.get("package_count") if metadata else None
        delta_line = (
            f"Δ vs snapshot {snapshot_stamp}: +{delta_obj.new_count} "
            f"-{delta_obj.removed_count} ~{delta_obj.updated_count} "
            f"(total {delta_obj.changed_packages_count})."
        )
        print(status_messages.status(delta_line, level="info"))
        if (
            age_seconds is not None
            and age_seconds < INVENTORY_DELTA_SUPPRESS_SECONDS
            and isinstance(current_count, int)
            and isinstance(snapshot_count, int)
            and current_count > snapshot_count
        ):
            print(
                status_messages.status(
                    f"Device has {current_count - snapshot_count} new package(s); refreshing inventory now.",
                    level="info",
                )
            )
            try:
                from scytaledroid.DeviceAnalysis.workflows import inventory_workflow

                inventory_workflow.run_inventory_sync(serial=serial, ui_prefs=text_blocks.UI_PREFS)
                decision = _record_guard_policy(decision, "quick")
                decision = replace(
                    decision,
                    decision_enum="allow",
                    reason_code="recent_snapshot_auto_sync",
                    next_action="continue",
                    prompt_key="none",
                )
                return _finish(True)
            except Exception as exc:
                print(status_messages.status(f"Auto-sync failed: {exc}", level="warn"))
        if age_seconds is not None and age_seconds < INVENTORY_DELTA_SUPPRESS_SECONDS:
            print(status_messages.status("Recent snapshot; continuing without re-sync prompt.", level="info"))
            decision = _record_guard_policy(decision, "quick")
            decision = replace(
                decision,
                decision_enum="allow",
                reason_code="recent_snapshot_continue",
                next_action="continue",
                prompt_key="none",
            )
            return _finish(True)
        print(status_messages.status("Sync is recommended before pulling APKs.", level="info"))

    options = ["1", "0"]
    labels = {"1": "Sync now (recommended)", "0": "Cancel"}
    if status != "NONE":
        options.insert(1, "2")
        labels["2"] = "Use last snapshot"

    for key in options:
        print(f"  {key}) {labels[key]}")

    choice = prompt_utils.get_choice(options, default="1", prompt="Select option [1]: ")
    if choice == "2":
        snapshot_stamp = _format_snapshot_reference(snapshot_id, timestamp)
        warning = (
            f"Proceeding with selected snapshot ({snapshot_stamp}); device state may differ."
            if snapshot_stamp
            else "Proceeding with selected snapshot; device state may differ."
        )
        print(status_messages.status(warning, level="warn"))
        decision = _record_guard_policy(decision, "quick")
        decision = replace(
            decision,
            decision_enum="allow",
            reason_code="user_selected_snapshot",
            next_action="continue",
            prompt_key="inventory_guard_choice",
        )
        return _finish(True)
    if choice == "0":
        print(status_messages.status("APK pull cancelled until inventory sync is run.", level="warn"))
        decision = _record_guard_policy(decision, None)
        decision = replace(
            decision,
            decision_enum="deny",
            reason_code="user_cancelled",
            next_action="cancel",
            prompt_key="inventory_guard_choice",
        )
        return _finish(False)

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
            decision = _record_guard_policy(decision, None)
            decision = replace(
                decision,
                decision_enum="deny",
                reason_code="sync_prompt_declined",
                next_action="cancel",
                prompt_key="inventory_sync_confirm",
            )
            return _finish(False)
        abort_on_long_running = False
    else:
        abort_on_long_running = True

    def _execute_sync(abort_on_threshold: bool) -> tuple[bool, float | None]:
        nonlocal expected_duration

        aborted = False
        latest_estimate = expected_duration
        last_reported = -5.0

        def _handle_progress(event: dict[str, object]) -> bool:
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
            from scytaledroid.DeviceAnalysis.workflows import inventory_workflow

            inventory_workflow.run_inventory_sync(
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
            decision = _record_guard_policy(decision, None)
            decision = replace(
                decision,
                decision_enum="deny",
                reason_code="long_running_sync_declined",
                next_action="cancel",
                prompt_key="inventory_sync_continue",
            )
            return _finish(False)
        if estimate:
            expected_duration = estimate
        aborted, estimate = _execute_sync(False)

    decision = _record_guard_policy(decision, "refresh")
    decision = replace(
        decision,
        reason="Inventory sync completed before APK pull.",
        guard_brief="Inventory sync completed before APK pull.",
        decision_enum="allow",
        reason_code="sync_completed",
        next_action="continue",
        prompt_key="inventory_sync",
    )
    return _finish(True)


def get_last_guard_decision() -> dict[str, object]:
    """Return a copy of the most recent guard decision context."""

    return asdict(_LAST_GUARD_DECISION.get())


def _build_sync_warning(
    battery_context: dict[str, object | None],
    expected_duration: float | None,
) -> str | None:
    reasons: list[str] = []

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


def _build_long_running_warning(estimate: float | None) -> str:
    if estimate and estimate > 0:
        return f"Estimated: {coarse_time_range(estimate)}."
    return "Estimated: longer than usual."


def _parse_battery_level(raw: str | None) -> int | None:
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
    device_context: dict[str, str | None | None],
) -> dict[str, object | None]:
    level: int | None = None
    status: str | None = None

    if device_context:
        level = _parse_battery_level(device_context.get("battery_level"))
        status_value = device_context.get("battery_status")
        if isinstance(status_value, str):
            status = status_value

    if level is None or status is None:
        stats = device_service.get_device_stats(serial)
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
    current: GuardDecision,
    *,
    stale_level: str,
    reason: str,
    decision_enum: str,
    reason_code: str,
    next_action: str,
    prompt_key: str,
    scope_changed: bool,
    scope_hash_changed: bool,
    packages_changed: bool,
    age_seconds: float | None,
    package_delta: dict[str, object] | None,
    package_delta_brief: str | None,
) -> GuardDecision:
    if decision_enum not in GUARD_DECISION_ENUMS:
        raise ValueError(f"Unsupported guard decision enum: {decision_enum}")
    if next_action not in GUARD_NEXT_ACTIONS:
        raise ValueError(f"Unsupported guard next_action: {next_action}")
    if prompt_key not in GUARD_PROMPT_KEYS:
        raise ValueError(f"Unsupported guard prompt_key: {prompt_key}")
    if reason_code not in GUARD_REASON_CODES:
        raise ValueError(f"Unsupported guard reason_code: {reason_code}")

    return replace(
        current,
        stale_level=stale_level,
        reason=reason,
        scope_changed=scope_changed,
        scope_hash_changed=scope_hash_changed,
        packages_changed=packages_changed,
        age_seconds=age_seconds,
        package_delta=package_delta,
        package_delta_brief=package_delta_brief,
        guard_brief=reason,
        decision_enum=decision_enum,
        reason_code=reason_code,
        next_action=next_action,
        prompt_key=prompt_key,
    )


def _record_guard_policy(current: GuardDecision, policy: str | None) -> GuardDecision:
    updated = replace(current, policy=policy)
    if policy:
        log.info(
            (
                f"Inventory guard policy {policy} selected "
                f"(stale_level={updated.stale_level}, "
                f"scope_changed={updated.scope_changed}, "
                f"scope_hash_changed={updated.scope_hash_changed}, "
                f"packages_changed={updated.packages_changed})"
            ),
            category="device",
        )
    return updated


def _format_package_delta_brief(
    summary: dict[str, object], *, limit: int = PACKAGE_DELTA_DISPLAY_LIMIT
) -> str | None:
    parts: list[str] = []

    def _format_names(key: str, total_key: str) -> str | None:
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
        formatted_updates: list[str] = []
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
    summary: dict[str, object], *, limit: int = PACKAGE_DELTA_DISPLAY_LIMIT
) -> str | None:
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
