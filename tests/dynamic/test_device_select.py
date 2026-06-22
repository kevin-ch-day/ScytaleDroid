from __future__ import annotations

from scytaledroid.DynamicAnalysis.controllers import device_select


def test_select_device_auto_uses_single_detected_device(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        device_select.device_service,
        "scan_devices",
        lambda: (
            [{"serial": "ZY22JK89DR", "model": "moto"}],
            [],
            [
                {
                    "serial": "ZY22JK89DR",
                    "model": "moto g 5G - 2024",
                    "android_version": "15",
                    "device_type": "Physical",
                    "state": "device",
                }
            ],
            {"ZY22JK89DR": {"serial": "ZY22JK89DR"}},
        ),
    )
    monkeypatch.setattr(device_select.device_service, "get_active_serial", lambda: None)
    set_calls = {"serial": None}
    monkeypatch.setattr(
        device_select.device_service,
        "set_active_serial",
        lambda serial: set_calls.__setitem__("serial", serial) or True,
    )
    prompt_calls = {"count": 0}
    monkeypatch.setattr(
        device_select.prompt_utils,
        "get_choice",
        lambda *args, **kwargs: prompt_calls.__setitem__("count", prompt_calls["count"] + 1),
    )

    selected = device_select.select_device()

    assert selected == ("ZY22JK89DR", "moto g 5G - 2024 (ZY22JK89DR)")
    assert prompt_calls["count"] == 0
    assert set_calls["serial"] == "ZY22JK89DR"
    out = capsys.readouterr().out
    assert "Using detected device: moto g 5G - 2024 (ZY22JK89DR)" in out


def test_select_device_prompts_when_multiple_devices_detected(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        device_select.device_service,
        "scan_devices",
        lambda: (
            [
                {"serial": "AAA", "model": "phone-a"},
                {"serial": "BBB", "model": "phone-b"},
            ],
            [],
            [
                {
                    "serial": "AAA",
                    "model": "Phone A",
                    "android_version": "14",
                    "device_type": "Physical",
                    "state": "device",
                },
                {
                    "serial": "BBB",
                    "model": "Phone B",
                    "android_version": "15",
                    "device_type": "Emulator",
                    "state": "device",
                },
            ],
            {"AAA": {"serial": "AAA"}, "BBB": {"serial": "BBB"}},
        ),
    )
    monkeypatch.setattr(device_select.device_service, "get_active_serial", lambda: None)
    set_calls = {"serial": None}
    prompt_capture = {"prompt": None}
    monkeypatch.setattr(
        device_select.device_service,
        "set_active_serial",
        lambda serial: set_calls.__setitem__("serial", serial) or True,
    )
    monkeypatch.setattr(
        device_select.prompt_utils,
        "get_choice",
        lambda *args, **kwargs: prompt_capture.__setitem__("prompt", kwargs.get("prompt")) or "2",
    )

    selected = device_select.select_device()

    assert selected == ("BBB", "Phone B (BBB)")
    assert set_calls["serial"] == "BBB"
    out = capsys.readouterr().out
    assert "Current device" in out
    assert "none selected" in out
    assert "Detected devices" in out
    assert "Phone A" in out
    assert "Phone B" in out
    assert prompt_capture["prompt"] == "› Choose device # [1]: "


def test_select_device_reuses_active_device_without_prompt(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        device_select.device_service,
        "scan_devices",
        lambda: (
            [
                {"serial": "AAA", "model": "phone-a"},
                {"serial": "BBB", "model": "phone-b"},
            ],
            [],
            [
                {
                    "serial": "AAA",
                    "model": "Phone A",
                    "android_version": "14",
                    "device_type": "Physical",
                    "state": "device",
                },
                {
                    "serial": "BBB",
                    "model": "Phone B",
                    "android_version": "15",
                    "device_type": "Physical",
                    "state": "device",
                },
            ],
            {"AAA": {"serial": "AAA"}, "BBB": {"serial": "BBB"}},
        ),
    )
    monkeypatch.setattr(device_select.device_service, "get_active_serial", lambda: "AAA")
    monkeypatch.setattr(device_select.device_service, "set_active_serial", lambda _serial: True)
    prompt_calls = {"count": 0}
    monkeypatch.setattr(
        device_select.prompt_utils,
        "get_choice",
        lambda *args, **kwargs: prompt_calls.__setitem__("count", prompt_calls["count"] + 1),
    )

    selected = device_select.select_device()

    assert selected == ("AAA", "Phone A (AAA)")
    assert prompt_calls["count"] == 0
    out = capsys.readouterr().out
    assert "Using current device: Phone A (AAA)" in out


def test_select_device_can_force_prompt_for_single_detected_device(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        device_select.device_service,
        "scan_devices",
        lambda: (
            [{"serial": "ZY22JK89DR", "model": "moto"}],
            [],
            [
                {
                    "serial": "ZY22JK89DR",
                    "model": "moto g 5G - 2024",
                    "android_version": "15",
                    "device_type": "Physical",
                    "state": "device",
                }
            ],
            {"ZY22JK89DR": {"serial": "ZY22JK89DR"}},
        ),
    )
    monkeypatch.setattr(device_select.device_service, "get_active_serial", lambda: None)
    set_calls = {"serial": None}
    monkeypatch.setattr(
        device_select.device_service,
        "set_active_serial",
        lambda serial: set_calls.__setitem__("serial", serial) or True,
    )
    monkeypatch.setattr(device_select.prompt_utils, "get_choice", lambda *args, **kwargs: "1")

    selected = device_select.select_device(
        header="Select Capture Device",
        prefer_active=False,
        allow_auto_single=False,
    )

    assert selected == ("ZY22JK89DR", "moto g 5G - 2024 (ZY22JK89DR)")
    assert set_calls["serial"] == "ZY22JK89DR"
    out = capsys.readouterr().out
    assert "Select Capture Device" in out
    assert "Use this device for inventory, harvest, dynamic capture, logcat, and shell actions." in out
    assert "Current device" in out
    assert "Detected devices" in out
