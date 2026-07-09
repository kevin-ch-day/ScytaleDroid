from __future__ import annotations

from scytaledroid.DynamicAnalysis.utils.messaging_activity_labels import messaging_activity_label


def test_messaging_activity_label_maps_known_internal_tags() -> None:
    assert messaging_activity_label("manual_freeform") == "Freeform / setup"
    assert messaging_activity_label("manual_mixed") == "Mixed known activities"
    assert messaging_activity_label("voice_call") == "Voice Call"
    assert messaging_activity_label("video_call") == "Video Call"
    assert messaging_activity_label("text_only") == "Text"
    assert messaging_activity_label("connected_idle") == "Connected idle"


def test_messaging_activity_label_keeps_unknown_tags_readable() -> None:
    assert messaging_activity_label("") == "—"
    assert messaging_activity_label(None) == "—"
    assert messaging_activity_label("custom_probe") == "Custom Probe"
