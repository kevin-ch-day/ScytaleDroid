from __future__ import annotations

from types import SimpleNamespace

import pytest
from scytaledroid.DynamicAnalysis.controllers import guided_run
from tests.dynamic._guided_run_state_support import (
    make_dataset_state,
    one_shot_package_selector,
    patch_guided_run_context,
)

pytestmark = [pytest.mark.contract, pytest.mark.state_contract]


def test_guided_run_selected_app_prefers_display_label(monkeypatch, capsys) -> None:
    package = "bbc.mobile.news.ww"
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="BBC News",
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(package),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "0")

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Selected app: BBC News" in out
    assert "Package: bbc.mobile.news.ww" in out


def test_guided_run_selected_app_falls_back_to_db_display_label(monkeypatch, capsys) -> None:
    package = "com.guardian"
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name=None,
    )
    monkeypatch.setattr(
        guided_run, "load_display_name_map", lambda _groups: {package: "The Guardian"}
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(package),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "0")

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Selected app: The Guardian" in out
    assert "Package: com.guardian" in out


def test_guided_run_selected_app_normalizes_x_display_label(monkeypatch, capsys) -> None:
    package = "com.twitter.android"
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="X",
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(package),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "0")

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Selected app: X (Twitter)" in out
    assert "Package: com.twitter.android" in out


def test_guided_run_reuses_selected_device_across_cohort_iterations(monkeypatch, capsys) -> None:
    package = "bbc.mobile.news.ww"
    select_device_calls = {"count": 0}
    subtitles: list[str | None] = []

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="BBC News",
        active_device=None,
    )

    def _select_device():
        select_device_calls["count"] += 1
        return ("ZY22JK89DR", "moto")

    def _select_package(_groups, title, subtitle=None):
        del title
        subtitles.append(subtitle)
        if len(subtitles) == 1:
            return package
        return None

    monkeypatch.setattr(guided_run, "select_device", _select_device)
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(package),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "prompt_yes_no", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "1")
    monkeypatch.setattr(guided_run, "time", SimpleNamespace(sleep=lambda _s: None))
    monkeypatch.setattr(
        guided_run,
        "ensure_plan_or_error",
        lambda *_a, **_k: {"plan_path": "plan.json", "static_run_id": 4099},
    )
    monkeypatch.setattr(guided_run, "_pre_run_scientific_checks", lambda **_k: True)
    monkeypatch.setattr(guided_run, "build_dynamic_run_spec", lambda **_k: SimpleNamespace())
    monkeypatch.setattr(
        guided_run,
        "execute_dynamic_run_spec",
        lambda _spec: SimpleNamespace(
            dynamic_run_id="run-1",
            evidence_path="/tmp/run-1",
            status="success",
            package_name=package,
            elapsed_seconds=10,
            duration_seconds=10,
        ),
    )
    monkeypatch.setattr(guided_run, "print_plan_selection_banner", lambda *_a, **_k: None)
    monkeypatch.setattr(guided_run, "print_run_summary", lambda *_a, **_k: None)
    monkeypatch.setattr(guided_run, "_post_run_integrity_check", lambda *_a, **_k: None)
    monkeypatch.setattr(guided_run, "_capture_protocol_fit_feedback", lambda **_k: None)

    guided_run.run_guided_dataset_run(
        select_package_from_groups=_select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_device_calls["count"] == 1
    assert subtitles[0] == "Device: not selected"
    assert subtitles[1] == "Device: moto"
    assert "Quota candidate: yes, subject to validity and quota eligibility." in out
    assert "Cohort quota impact: YES (if VALID)" not in out


def test_guided_run_dataset_baseline_uses_recommended_duration(monkeypatch) -> None:
    package = "com.zhiliaoapp.musically"
    captured = {}

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="TikTok",
        active_device={"serial": "ZY22JK89DR", "model": "moto"},
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(package),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "1")
    monkeypatch.setattr(guided_run.prompt_utils, "prompt_yes_no", lambda *_a, **_k: True)
    monkeypatch.setattr(guided_run, "time", SimpleNamespace(sleep=lambda _s: None))
    monkeypatch.setattr(
        guided_run,
        "ensure_plan_or_error",
        lambda *_a, **_k: {"plan_path": "plan.json", "static_run_id": 5838},
    )
    monkeypatch.setattr(guided_run, "_pre_run_scientific_checks", lambda **_k: True)
    monkeypatch.setattr(guided_run, "print_plan_selection_banner", lambda *_a, **_k: None)
    monkeypatch.setattr(guided_run, "print_run_summary", lambda *_a, **_k: None)
    monkeypatch.setattr(guided_run, "_post_run_integrity_check", lambda *_a, **_k: None)
    monkeypatch.setattr(guided_run, "_capture_protocol_fit_feedback", lambda **_k: None)

    def _build_spec(**kwargs):
        captured["spec"] = kwargs
        return SimpleNamespace(**kwargs)

    monkeypatch.setattr(guided_run, "build_dynamic_run_spec", _build_spec)
    monkeypatch.setattr(
        guided_run,
        "execute_dynamic_run_spec",
        lambda _spec: SimpleNamespace(
            dynamic_run_id="run-1",
            evidence_path="/tmp/run-1",
            status="success",
            package_name=package,
            elapsed_seconds=10,
            duration_seconds=10,
        ),
    )

    guided_run.run_guided_dataset_run(
        select_package_from_groups=one_shot_package_selector(package)[1],
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    assert captured["spec"]["duration_seconds"] == int(
        getattr(guided_run.profile_config, "RECOMMENDED_SAMPLING_SECONDS", 240)
    )


def test_guided_run_seeds_queue_from_active_selected_device(monkeypatch) -> None:
    package = "bbc.mobile.news.ww"
    subtitles: list[str | None] = []

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="BBC News",
        active_device={"serial": "ZY22JK89DR", "model": "moto"},
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(package),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "0")

    def _select_package(_groups, title, subtitle=None):
        del title
        subtitles.append(subtitle)
        return package if len(subtitles) == 1 else None

    guided_run.run_guided_dataset_run(
        select_package_from_groups=_select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    assert subtitles[0] == "Device: moto · ZY22JK89DR"


def test_choose_capture_device_reuses_selected_device_without_reopening_selector(
    monkeypatch, capsys
) -> None:
    selector_calls = {"count": 0}
    prompt_calls = {"count": 0}

    monkeypatch.setattr(
        guided_run,
        "get_device_selection_details",
        lambda serial: {
            "name": "moto g 5G - 2024",
            "serial": serial,
            "android": "15",
            "type": "physical",
            "label": "moto g 5G - 2024 · ZY22JK89DR · Android 15 · physical",
            "detected": "1",
        },
    )
    monkeypatch.setattr(
        guided_run,
        "select_device",
        lambda **_kwargs: (
            selector_calls.__setitem__("count", selector_calls["count"] + 1) or ("other", "other")
        ),
    )
    monkeypatch.setattr(
        guided_run.prompt_utils,
        "get_choice",
        lambda *args, **kwargs: prompt_calls.__setitem__("count", prompt_calls["count"] + 1) or "1",
    )

    selected = guided_run._choose_capture_device(
        {"serial": "ZY22JK89DR", "label": "moto g 5G - 2024 · ZY22JK89DR · Android 15 · physical"}
    )

    assert selected == ("ZY22JK89DR", "moto g 5G - 2024 · ZY22JK89DR · Android 15 · physical")
    assert selector_calls["count"] == 0
    assert prompt_calls["count"] == 0
    out = capsys.readouterr().out
    assert "Capture device" in out
    assert "Use selected device" not in out
    assert "Keep selected device" not in out
    assert "Change device" not in out


def test_choose_capture_device_can_open_change_device_selector_when_saved_device_is_not_detected(
    monkeypatch,
) -> None:
    selector_kwargs = {}

    monkeypatch.setattr(
        guided_run,
        "get_device_selection_details",
        lambda serial: {
            "name": serial,
            "serial": serial,
            "android": "15",
            "type": "physical",
            "label": "moto g 5G - 2024 · ZY22JK89DR · Android 15 · physical",
            "status": "not detected",
            "detected": "",
        },
    )

    def _select_device(**kwargs):
        selector_kwargs.update(kwargs)
        return ("BBB", "Phone B (BBB)")

    monkeypatch.setattr(guided_run, "select_device", _select_device)
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "2")

    selected = guided_run._choose_capture_device(
        {"serial": "ZY22JK89DR", "label": "moto g 5G - 2024 · ZY22JK89DR · Android 15 · physical"}
    )

    assert selected == ("BBB", "Phone B (BBB)")
    assert selector_kwargs == {
        "header": "Change Capture Device",
        "prefer_active": False,
        "allow_auto_single": False,
    }


def test_choose_capture_device_warns_when_saved_device_is_not_detected(monkeypatch, capsys) -> None:
    selector_calls = {"count": 0}

    monkeypatch.setattr(
        guided_run,
        "get_device_selection_details",
        lambda serial: {
            "name": serial,
            "serial": serial,
            "android": "—",
            "type": "device",
            "label": serial,
            "status": "not detected",
            "detected": "",
        },
    )
    monkeypatch.setattr(
        guided_run,
        "select_device",
        lambda **_kwargs: (
            selector_calls.__setitem__("count", selector_calls["count"] + 1) or ("other", "other")
        ),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "1")

    selected = guided_run._choose_capture_device(
        {"serial": "ZY22JK89DR", "label": "moto g 5G - 2024 · ZY22JK89DR · Android 15 · physical"}
    )

    assert selected == ("ZY22JK89DR", "ZY22JK89DR")
    assert selector_calls["count"] == 0
    out = capsys.readouterr().out
    assert "Capture device" in out
    assert "Selected device is not currently detected via adb." in out
    assert "Keep selected device" in out
    assert "Change device" in out
    assert "wait for adb reconnect on current serial" not in out
    assert "pick a different capture device" not in out
