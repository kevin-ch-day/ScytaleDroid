from __future__ import annotations

from pathlib import Path

from scytaledroid.DynamicAnalysis.tools.evidence import menu as evidence_menu
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


def test_render_app_runs_displays_operator_activity_label(monkeypatch, capsys, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        evidence_menu,
        "security_operator_labels_from_run_dir",
        lambda _path: {"cleartext_http_label": "no", "finding_count": 0},
    )

    from scytaledroid.Utils.DisplayUtils import display_settings, table_utils

    monkeypatch.setattr(display_settings, "apply_table_defaults", lambda kwargs: kwargs)

    def _capture_table(headers, rows, **_kwargs):
        captured["headers"] = headers
        captured["rows"] = rows

    monkeypatch.setattr(table_utils, "render_table", _capture_table)

    evidence_menu._render_app_runs(
        tmp_path,
        "Telegram",
        "org.telegram.messenger",
        [
            {
                "run_id": "run-manual-mixed",
                "ended_at": "2026-07-09 21:00:00",
                "run_profile": "interaction_manual",
                "interaction_level": "manual",
                "messaging_activity": "manual_mixed",
                "valid": True,
                "reason": None,
                "countable": True,
            }
        ],
    )

    assert "Activity" in captured["headers"]
    row_text = " ".join(str(value) for value in captured["rows"][0])
    assert "Mixed known activities" in row_text
    assert "manual_mixed" not in row_text
    out = capsys.readouterr().out
    assert "Telegram" in out
