from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DynamicAnalysis.scenarios import manual
from scytaledroid.DynamicAnalysis.scenarios.manual_call_outcome import collect_manual_call_outcome


def test_collect_manual_video_call_failure_outcome(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual_call_outcome.sys.stdin.isatty",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual_call_outcome.prompt_utils.get_choice",
        lambda *_args, **_kwargs: "2",
    )

    payload = collect_manual_call_outcome(messaging_activity="video_call")

    assert payload == {
        "call_type": "video",
        "call_attempted": True,
        "call_connected": False,
        "call_outcome_reason": "CALL_NOT_CONNECTED",
        "call_outcome_flag": "CALL_NOT_CONNECTED",
    }


def test_collect_manual_call_outcome_skips_non_call_activity() -> None:
    assert collect_manual_call_outcome(messaging_activity="manual_freeform") is None


def test_manual_call_protocol_only_applies_to_manual_interactive(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._collect_manual_call_outcome",
        lambda **_kwargs: {"call_connected": False, "call_outcome_reason": "CALL_NOT_CONNECTED"},
    )

    payload = manual._manual_call_protocol(
        "interaction_manual",
        SimpleNamespace(messaging_activity="video_call"),
    )

    assert payload == {
        "call_connected": False,
        "call_outcome_reason": "CALL_NOT_CONNECTED",
    }
    assert (
        manual._manual_call_protocol(
            "interaction_scripted",
            SimpleNamespace(messaging_activity="video_call"),
        )
        is None
    )
