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
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual_call_outcome.prompt_utils.prompt_text",
        lambda *_args, **_kwargs: "0",
    )

    payload = collect_manual_call_outcome(messaging_activity="video_call")

    assert payload | {} == {
        "call_type": "video",
        "call_attempted": True,
        "call_connected": False,
        "call_outcome_reason": "CALL_NOT_CONNECTED",
        "call_outcome_flag": "CALL_NOT_CONNECTED",
        "call_attempt_count": 1,
        "call_connected_count": 0,
        "call_not_connected_count": 1,
        "call_connected_short_count": 0,
        "call_canceled_count": 0,
        "call_primary_outcome_reason": "CALL_NOT_CONNECTED",
        "call_outcome_summary": "attempts=1;connected=0;not_connected=1;canceled=0",
        "call_outcome_events": [
            {"role": "primary", "outcome_reason": "CALL_NOT_CONNECTED", "count": 1},
        ],
    }


def test_collect_manual_voice_call_records_additional_ring_attempts(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual_call_outcome.sys.stdin.isatty",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual_call_outcome.prompt_utils.get_choice",
        lambda *_args, **_kwargs: "1",
    )
    replies = iter(["0", "2", "0"])
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual_call_outcome.prompt_utils.prompt_text",
        lambda *_args, **_kwargs: next(replies),
    )

    payload = collect_manual_call_outcome(messaging_activity="voice_call")

    assert payload["call_type"] == "voice"
    assert payload["call_attempted"] is True
    assert payload["call_connected"] is True
    assert payload["call_outcome_reason"] == "CALL_CONNECTED_OK"
    assert payload["call_attempt_count"] == 3
    assert payload["call_connected_count"] == 1
    assert payload["call_not_connected_count"] == 2
    assert payload["call_canceled_count"] == 0
    assert payload["call_outcome_summary"] == "attempts=3;connected=1;not_connected=2;canceled=0"
    assert {"role": "additional", "outcome_reason": "CALL_NOT_CONNECTED", "count": 2} in payload[
        "call_outcome_events"
    ]


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


def test_manual_call_protocol_prompts_when_foreground_call_surface_was_tagged_none(monkeypatch) -> None:
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._guided_read_device_foreground_target",
        lambda _serial: (
            "org.thoughtcrime.securesms",
            "org.thoughtcrime.securesms.components.webrtc.v2.WebRtcCallActivity",
        ),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.sys.stdin.isatty",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.get_choice",
        lambda *_args, **_kwargs: "1",
    )

    def fake_collect(**kwargs):
        captured.update(kwargs)
        return {
            "call_type": "voice",
            "call_attempted": True,
            "call_connected": True,
            "call_outcome_reason": "CALL_CONNECTED_OK",
        }

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._collect_manual_call_outcome",
        fake_collect,
    )

    payload = manual._manual_call_protocol(
        "interaction_manual",
        SimpleNamespace(
            messaging_activity="none",
            package_name="org.thoughtcrime.securesms",
            device_serial="ZY22JK89DR",
        ),
    )

    assert captured == {"messaging_activity": "voice_call"}
    assert payload is not None
    assert payload["call_activity_inferred_from_foreground"] is True
    assert payload["call_activity_original_tag"] == "none"
    assert (
        payload["call_activity_foreground_component"]
        == "org.thoughtcrime.securesms.components.webrtc.v2.WebRtcCallActivity"
    )


def test_manual_call_protocol_prompts_when_telegram_call_surface_was_tagged_none(monkeypatch) -> None:
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._guided_read_device_foreground_target",
        lambda _serial: (
            "org.telegram.messenger",
            "org.telegram.messenger.DefaultIcon",
        ),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._infer_runtime_surface",
        lambda **_kwargs: ("telegram_voice_call_surface", "telegram voice call surface"),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.sys.stdin.isatty",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual.prompt_utils.get_choice",
        lambda *_args, **_kwargs: "1",
    )

    def fake_collect(**kwargs):
        captured.update(kwargs)
        return {
            "call_type": "voice",
            "call_attempted": True,
            "call_connected": True,
            "call_outcome_reason": "CALL_CONNECTED_OK",
        }

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.scenarios.manual._collect_manual_call_outcome",
        fake_collect,
    )

    payload = manual._manual_call_protocol(
        "interaction_manual",
        SimpleNamespace(
            messaging_activity="none",
            package_name="org.telegram.messenger",
            device_serial="ZY22JK89DR",
        ),
    )

    assert captured == {"messaging_activity": "voice_call"}
    assert payload is not None
    assert payload["call_activity_inferred_from_foreground"] is True
    assert payload["call_activity_original_tag"] == "none"
    assert payload["call_activity_foreground_component"] == "org.telegram.messenger.DefaultIcon"
