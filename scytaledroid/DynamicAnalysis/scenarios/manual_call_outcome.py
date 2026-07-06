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
    return payload


__all__ = ["collect_manual_call_outcome"]
