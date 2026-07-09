"""Manual messaging call outcome prompts for dynamic runs."""

from __future__ import annotations

import sys

from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages

_CALL_ACTIVITY_TYPES = {
    "voice_call": "voice",
    "video_call": "video",
}

_CALL_OUTCOME_PAYLOADS: dict[str, dict[str, object]] = {
    "1": {
        "call_attempted": True,
        "call_connected": True,
        "call_outcome_reason": "CALL_CONNECTED_OK",
        "call_outcome_flag": None,
    },
    "2": {
        "call_attempted": True,
        "call_connected": False,
        "call_outcome_reason": "CALL_NOT_CONNECTED",
        "call_outcome_flag": "CALL_NOT_CONNECTED",
    },
    "3": {
        "call_attempted": True,
        "call_connected": True,
        "call_outcome_reason": "CALL_CONNECTED_SHORT",
        "call_outcome_flag": "CALL_CONNECTED_SHORT",
    },
    "4": {
        "call_attempted": True,
        "call_connected": False,
        "call_outcome_reason": "CALL_CANCELED",
        "call_outcome_flag": "CALL_CANCELED",
    },
    "5": {
        "call_attempted": False,
        "call_connected": None,
        "call_outcome_reason": "CALL_NOT_ATTEMPTED",
        "call_outcome_flag": "CALL_NOT_ATTEMPTED",
    },
}

_PRIMARY_OUTCOME_COUNTS: dict[str, dict[str, int]] = {
    "1": {
        "call_attempt_count": 1,
        "call_connected_count": 1,
        "call_not_connected_count": 0,
        "call_connected_short_count": 0,
        "call_canceled_count": 0,
    },
    "2": {
        "call_attempt_count": 1,
        "call_connected_count": 0,
        "call_not_connected_count": 1,
        "call_connected_short_count": 0,
        "call_canceled_count": 0,
    },
    "3": {
        "call_attempt_count": 1,
        "call_connected_count": 1,
        "call_not_connected_count": 0,
        "call_connected_short_count": 1,
        "call_canceled_count": 0,
    },
    "4": {
        "call_attempt_count": 1,
        "call_connected_count": 0,
        "call_not_connected_count": 0,
        "call_connected_short_count": 0,
        "call_canceled_count": 1,
    },
    "5": {
        "call_attempt_count": 0,
        "call_connected_count": 0,
        "call_not_connected_count": 0,
        "call_connected_short_count": 0,
        "call_canceled_count": 0,
    },
}


def collect_manual_call_outcome(*, messaging_activity: str | None) -> dict[str, object] | None:
    """Prompt for a bounded manual call outcome and return operator protocol fields."""

    activity = str(messaging_activity or "").strip().lower()
    call_type = _CALL_ACTIVITY_TYPES.get(activity)
    if not call_type:
        return None
    if not sys.stdin.isatty():
        return {
            "call_type": call_type,
            "call_attempted": True,
            "call_connected": None,
            "call_outcome_reason": "MANUAL_CALL_OUTCOME_UNSPECIFIED",
            "call_outcome_flag": "MANUAL_CALL_OUTCOME_UNSPECIFIED",
        }

    print(
        status_messages.status(
            "Record the manual call outcome. This improves runtime interpretation only; it does not change run validity.",
            level="info",
        )
    )
    print("Call outcome")
    print("1) Connected normally")
    print("2) Failed / did not connect")
    print("3) Connected briefly / dropped")
    print("4) Canceled before connection")
    print("5) Not attempted / switched activity")
    choice = prompt_utils.get_choice(
        ["1", "2", "3", "4", "5"],
        prompt="Choose call outcome [1-5]: ",
        casefold=True,
    )
    payload = dict(_CALL_OUTCOME_PAYLOADS[choice])
    payload["call_type"] = call_type
    counts = dict(_PRIMARY_OUTCOME_COUNTS[choice])
    if counts["call_attempt_count"] > 0:
        print("Additional call attempts in this same capture")
        counts["call_connected_count"] += _prompt_count("Extra connected calls")
        counts["call_not_connected_count"] += _prompt_count("Extra failed / rang / did-not-connect calls")
        counts["call_canceled_count"] += _prompt_count("Extra canceled-before-connection calls")
        counts["call_attempt_count"] = (
            counts["call_connected_count"]
            + counts["call_not_connected_count"]
            + counts["call_canceled_count"]
        )
    payload.update(counts)
    payload["call_primary_outcome_reason"] = payload.get("call_outcome_reason")
    payload["call_outcome_summary"] = _format_outcome_summary(counts)
    payload["call_outcome_events"] = _outcome_events(
        primary_reason=str(payload.get("call_primary_outcome_reason") or ""),
        counts=counts,
    )
    return payload


def _prompt_count(label: str) -> int:
    value = prompt_utils.prompt_text(
        label,
        default="0",
        required=False,
        validator=lambda raw: raw.isdigit() and int(raw) >= 0,
        error_message="Enter 0 or a positive whole number.",
    )
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _format_outcome_summary(counts: dict[str, int]) -> str:
    parts = [
        f"attempts={int(counts.get('call_attempt_count') or 0)}",
        f"connected={int(counts.get('call_connected_count') or 0)}",
        f"not_connected={int(counts.get('call_not_connected_count') or 0)}",
        f"canceled={int(counts.get('call_canceled_count') or 0)}",
    ]
    short_count = int(counts.get("call_connected_short_count") or 0)
    if short_count:
        parts.append(f"connected_short={short_count}")
    return ";".join(parts)


def _outcome_events(*, primary_reason: str, counts: dict[str, int]) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    if primary_reason:
        events.append({"role": "primary", "outcome_reason": primary_reason, "count": 1})
    not_connected = int(counts.get("call_not_connected_count") or 0)
    canceled = int(counts.get("call_canceled_count") or 0)
    connected = int(counts.get("call_connected_count") or 0)
    connected_short = int(counts.get("call_connected_short_count") or 0)
    primary_connected = 1 if primary_reason in {"CALL_CONNECTED_OK", "CALL_CONNECTED_SHORT"} else 0
    primary_not_connected = 1 if primary_reason == "CALL_NOT_CONNECTED" else 0
    primary_canceled = 1 if primary_reason == "CALL_CANCELED" else 0
    extra_connected = max(0, connected - primary_connected)
    extra_not_connected = max(0, not_connected - primary_not_connected)
    extra_canceled = max(0, canceled - primary_canceled)
    if extra_connected:
        events.append({"role": "additional", "outcome_reason": "CALL_CONNECTED_OK", "count": extra_connected})
    if extra_not_connected:
        events.append({"role": "additional", "outcome_reason": "CALL_NOT_CONNECTED", "count": extra_not_connected})
    if extra_canceled:
        events.append({"role": "additional", "outcome_reason": "CALL_CANCELED", "count": extra_canceled})
    if connected_short:
        events.append({"role": "aggregate", "outcome_reason": "CALL_CONNECTED_SHORT", "count": connected_short})
    return events


__all__ = ["collect_manual_call_outcome"]
