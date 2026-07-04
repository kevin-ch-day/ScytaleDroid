from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DynamicAnalysis.scenarios import manual


def test_manual_start_prompt_skips_permission_prompt_without_high_value_permissions(
    monkeypatch,
) -> None:
    run_ctx = SimpleNamespace(static_plan={})

    def _unexpected_prompt(*_args, **_kwargs):
        raise AssertionError("permission prompt should not be shown")

    monkeypatch.setattr(manual.prompt_utils, "prompt_text", _unexpected_prompt)

    assert manual._maybe_show_raw_high_value_permissions(run_ctx) is False


def test_manual_start_prompt_allows_immediate_start_on_enter(monkeypatch, capsys) -> None:
    run_ctx = SimpleNamespace(
        static_plan={"permissions": {"high_value": ["android.permission.CAMERA"]}}
    )
    prompts: list[str] = []

    def _prompt_text(message: str, **_kwargs) -> str:
        prompts.append(message)
        return ""

    monkeypatch.setattr(manual.prompt_utils, "prompt_text", _prompt_text)

    assert manual._maybe_show_raw_high_value_permissions(run_ctx) is True
    assert prompts == ["Press Enter to begin, or P to view raw high-value permissions"]
    assert "High-value permissions (sample)" not in capsys.readouterr().out


def test_manual_start_prompt_shows_permissions_before_explicit_start(monkeypatch, capsys) -> None:
    run_ctx = SimpleNamespace(
        static_plan={
            "permissions": {
                "high_value": [
                    "android.permission.RECORD_AUDIO",
                    "android.permission.CAMERA",
                ]
            }
        }
    )
    monkeypatch.setattr(manual.prompt_utils, "prompt_text", lambda *_args, **_kwargs: "p")

    assert manual._maybe_show_raw_high_value_permissions(run_ctx) is False

    out = capsys.readouterr().out
    assert "High-value permissions (sample): android.permission.CAMERA, android.permission.RECORD_AUDIO" in out


def test_requires_explicit_begin_press_for_messaging_connected_baseline() -> None:
    run_ctx = SimpleNamespace(run_profile="baseline_connected", messaging_activity="connected_idle", package_name="com.whatsapp")

    assert manual._requires_explicit_begin_press(run_ctx=run_ctx, start_immediately=True) is True
    assert (
        manual._begin_capture_prompt_label(run_ctx)
        == "Press Enter to begin connected-idle baseline (timer starts)..."
    )


def test_requires_explicit_begin_press_skips_second_prompt_for_non_messaging_immediate_start() -> None:
    run_ctx = SimpleNamespace(run_profile="baseline_idle", messaging_activity="", package_name="com.twitter.android")

    assert manual._requires_explicit_begin_press(run_ctx=run_ctx, start_immediately=True) is False
    assert manual._begin_capture_prompt_label(run_ctx) == "Press Enter to begin (timer starts)..."
