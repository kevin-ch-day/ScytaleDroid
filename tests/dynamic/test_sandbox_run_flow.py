from __future__ import annotations

from scytaledroid.DynamicAnalysis.controllers import sandbox_run


def test_single_app_capture_type_prompt_is_targeted(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sandbox_run.prompt_utils, "get_choice", lambda *_args, **_kwargs: "0")

    assert sandbox_run._choose_single_app_capture_type("com.pinterest") is None

    out = capsys.readouterr().out
    assert "Single App Capture Type" in out
    assert "Target app: com.pinterest" in out
    assert "This labels the run and sets guidance; it does not automate taps." in out
    assert "Basic usage [recommended]" in out
    assert "exercise a permission/capability" in out
    assert "0) Back" in out


def test_single_app_run_selects_target_before_capture_type(monkeypatch) -> None:
    events: list[str] = []

    monkeypatch.setattr(
        sandbox_run,
        "select_device",
        lambda: events.append("device") or ("ZY22JK89DR", "moto g 5G"),
    )
    monkeypatch.setattr(
        sandbox_run,
        "_choose_single_app_capture_type",
        lambda package_name: events.append(f"capture_type:{package_name}") or None,
    )

    def _select_dynamic_target() -> tuple[str, str]:
        events.append("target")
        return ("com.pinterest", "dataset")

    sandbox_run.run_sandbox_dynamic_run(
        select_dynamic_target=_select_dynamic_target,
        select_observers=lambda *_args, **_kwargs: [],
        print_root_status=lambda _serial: events.append("root") or False,
        print_network_status=lambda _serial: events.append("network"),
    )

    assert events == [
        "device",
        "root",
        "network",
        "target",
        "capture_type:com.pinterest",
    ]
