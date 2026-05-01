from __future__ import annotations

from scytaledroid.Utils.AboutApp import about_app


def test_about_app_hides_runtime_mode_when_identity_disabled(monkeypatch) -> None:
    sections: list[str] = []

    monkeypatch.setattr(about_app.app_config, "SHOW_RUNTIME_IDENTITY", False)
    monkeypatch.setattr(about_app.menu_utils, "print_header", lambda *_a, **_k: None)
    monkeypatch.setattr(about_app.menu_utils, "print_hint", lambda *_a, **_k: None)
    monkeypatch.setattr(about_app.menu_utils, "print_section", lambda title, *_a, **_k: sections.append(title))
    monkeypatch.setattr(about_app.menu_utils, "print_metrics", lambda *_a, **_k: None)
    monkeypatch.setattr(about_app.status_messages, "status", lambda message, **_k: message)
    monkeypatch.setattr(about_app.prompt_utils, "press_enter_to_continue", lambda *_a, **_k: None)

    about_app.about_app()

    assert "Runtime Mode" not in sections


def test_about_app_shows_runtime_mode_when_identity_enabled(monkeypatch) -> None:
    sections: list[str] = []
    metrics_calls: list[list[tuple[str, str]]] = []

    monkeypatch.setattr(about_app.app_config, "SHOW_RUNTIME_IDENTITY", True)
    monkeypatch.setattr(about_app.app_config, "RUNTIME_PRESET", "validation")
    monkeypatch.setattr(about_app.app_config, "EXECUTION_MODE", "DEV")
    monkeypatch.setattr(about_app.app_config, "SYS_ENV", "VIRTUAL")
    monkeypatch.setattr(about_app.app_config, "DEBUG_MODE", True)
    monkeypatch.setattr(about_app.app_config, "SYS_TEST", False)
    monkeypatch.setattr(about_app.menu_utils, "print_header", lambda *_a, **_k: None)
    monkeypatch.setattr(about_app.menu_utils, "print_hint", lambda *_a, **_k: None)
    monkeypatch.setattr(about_app.menu_utils, "print_section", lambda title, *_a, **_k: sections.append(title))
    monkeypatch.setattr(about_app.menu_utils, "print_metrics", lambda metrics, *_a, **_k: metrics_calls.append(list(metrics)))
    monkeypatch.setattr(about_app.status_messages, "status", lambda message, **_k: message)
    monkeypatch.setattr(about_app.prompt_utils, "press_enter_to_continue", lambda *_a, **_k: None)

    about_app.about_app()

    assert "Runtime Mode" in sections
    assert any(
        metrics == [
            ("Runtime preset", "VALIDATION"),
            ("Execution mode", "DEV"),
            ("System environment", "VIRTUAL"),
            ("Debug mode", "ON"),
        ]
        for metrics in metrics_calls
    )
