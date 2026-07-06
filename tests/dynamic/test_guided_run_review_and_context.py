from __future__ import annotations

import json

import pytest
from scytaledroid.DynamicAnalysis.controllers import guided_run, selected_app_review
from tests.dynamic._guided_run_state_support import (
    make_dataset_state,
    make_recent_summary,
    one_shot_package_selector,
    patch_guided_run_context,
)

pytestmark = [pytest.mark.contract, pytest.mark.state_contract]


def test_guided_run_review_path_does_not_require_device(monkeypatch, capsys) -> None:
    package = "com.cnn.mobile.android.phone"
    select_package_calls, select_package = one_shot_package_selector(package)
    device_calls = {"select": 0, "preflight": 0}
    qa_calls = {"run_id": None}
    choices = iter(["A", "0"])

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="CNN",
    )
    monkeypatch.setattr(
        guided_run,
        "select_device",
        lambda: (
            device_calls.__setitem__("select", device_calls["select"] + 1) or ("ZY22JK89DR", "moto")
        ),
    )
    monkeypatch.setattr(
        guided_run,
        "_device_preflight_checks",
        lambda _serial: (
            device_calls.__setitem__("preflight", device_calls["preflight"] + 1) or True
        ),
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            total_runs=5,
            valid_runs=5,
            baseline_valid_runs=3,
            interactive_valid_runs=2,
            quota_met=True,
            local_evidence_dir_count=5,
            reset_available=True,
            paper_eligible_local=5,
            quota_counted_local=5,
            suggested_profile_from_tracker="interaction_scripted",
            effective_suggested_profile="interaction_scripted",
            suggested_slot=None,
            recent_runs=(
                make_recent_summary(
                    ended_at="2026-06-20T10:00:00Z",
                    run_profile="interaction_scripted",
                    interaction_level="scripted",
                    valid=False,
                    invalid_reason_code="PCAP_MISSING",
                    pcap_failure_detail="PCAP_DEVICE_FILE_MISSING",
                    run_id="cnn-run-1",
                    status_label="INVALID:PCAP_MISSING",
                ),
            ),
        ),
    )
    monkeypatch.setattr(
        guided_run,
        "recent_tracker_runs",
        lambda _package_name, limit=1: [
            make_recent_summary(
                ended_at="2026-06-20T10:00:00Z",
                run_profile="interaction_scripted",
                interaction_level="scripted",
                valid=False,
                invalid_reason_code="PCAP_MISSING",
                pcap_failure_detail="PCAP_DEVICE_FILE_MISSING",
                run_id="cnn-run-1",
                status_label="INVALID:PCAP_MISSING",
            )
        ],
    )
    monkeypatch.setattr(
        guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choices)
    )
    monkeypatch.setattr(
        guided_run.prompt_utils, "press_enter_to_continue", lambda *args, **kwargs: None
    )

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
        print_tier1_qa_result=lambda run_id: qa_calls.__setitem__("run_id", run_id),
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Stored QA Review" in out
    assert "cnn-run-1" in out
    assert "Dataset impact" in out
    assert "excluded from quota/publication" in out
    assert "PCAP detail" in out
    assert "PCAP_DEVICE_FILE_MISSING" in out
    assert (
        "This review is display-only; the stored run remains excluded from quota/publication use."
        in out
    )
    assert "Recollect a current-build run after verifying PCAP capture/export is working." in out
    assert qa_calls["run_id"] == "cnn-run-1"
    assert device_calls == {"select": 0, "preflight": 0}


@pytest.mark.parametrize(
    ("valid", "invalid_reason", "expected"),
    [
        (
            True,
            "",
            "Return to the app screen for supplemental baseline, interactive, or manual evidence.",
        ),
        (
            False,
            "PCAP_TOO_SMALL",
            "Recollect a longer or higher-signal current-build run before relying on it.",
        ),
        (
            None,
            "",
            "Use run history and diagnostics to decide whether recollection is needed.",
        ),
    ],
)
def test_selected_app_review_next_step_lines_cover_valid_invalid_and_unknown(
    valid: bool | None,
    invalid_reason: str,
    expected: str,
) -> None:
    lines = selected_app_review._next_step_lines(valid=valid, invalid_reason=invalid_reason)
    assert lines[0] == "Next step:"
    assert expected in lines


@pytest.mark.parametrize(
    ("choices", "expected_header"),
    [
        (["H", "0"], "Recent Tracker Runs"),
        (["G", "0"], "Diagnostics"),
    ],
)
def test_guided_run_history_and_diagnostics_do_not_require_device(
    monkeypatch,
    capsys,
    choices: list[str],
    expected_header: str,
) -> None:
    package = "bbc.mobile.news.ww"
    select_package_calls, select_package = one_shot_package_selector(package)
    device_calls = {"select": 0, "preflight": 0}
    choice_iter = iter(choices)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="BBC News",
    )
    monkeypatch.setattr(
        guided_run,
        "select_device",
        lambda: (
            device_calls.__setitem__("select", device_calls["select"] + 1) or ("ZY22JK89DR", "moto")
        ),
    )
    monkeypatch.setattr(
        guided_run,
        "_device_preflight_checks",
        lambda _serial: (
            device_calls.__setitem__("preflight", device_calls["preflight"] + 1) or True
        ),
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            total_runs=1,
            valid_runs=1,
            baseline_valid_runs=1,
            local_evidence_dir_count=1,
            paper_eligible_local=1,
            quota_counted_local=1,
            exclusion_reason_top=(("EXCLUDED_LOW_SIGNAL", 1),),
            suggested_slot=2,
            recent_runs=(
                make_recent_summary(
                    ended_at="2026-06-20T10:00:00Z",
                    run_profile="baseline_idle",
                    interaction_level="minimal",
                    valid=True,
                    run_id="bbc-run-1",
                    status_label="VALID",
                ),
            ),
        ),
    )
    monkeypatch.setattr(
        guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choice_iter)
    )
    monkeypatch.setattr(
        guided_run.prompt_utils, "press_enter_to_continue", lambda *args, **kwargs: None
    )

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert expected_header in out
    if expected_header == "Diagnostics":
        assert "Study" in out
        assert "Live device" in out
        assert "Capture" in out
        assert "Publication" in out
    assert device_calls == {"select": 0, "preflight": 0}


def test_selected_app_diagnostics_show_latest_media_plane(monkeypatch, tmp_path, capsys) -> None:
    run_id = "wa-run-1"
    run_dir = tmp_path / "evidence" / "dynamic" / run_id / "analysis"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "pcap_report.json").write_text(
        json.dumps(
            {
                "media_plane": {
                    "status": "ok",
                    "summary": {
                        "classification": "relay_media_likely",
                        "relay_endpoint_count": 3,
                        "turn_allocate_success_count": 16,
                        "stun_frame_count": 480,
                        "dominant_udp_flow": {
                            "endpoint_a": "10.0.0.2:46485",
                            "endpoint_b": "157.240.146.35:3478",
                            "share_of_udp_bytes": 0.99,
                        },
                        "reason_codes": ["turn_allocate_success", "relay_media_pattern"],
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(selected_app_review.app_config, "OUTPUT_DIR", str(tmp_path))
    state = make_dataset_state(
        "com.whatsapp",
        valid_runs=1,
        baseline_valid_runs=0,
        interactive_valid_runs=1,
        local_evidence_dir_count=1,
        paper_eligible_local=1,
        quota_counted_local=1,
    )
    latest_recent = make_recent_summary(
        ended_at="2026-07-05T18:59:00Z",
        run_profile="interaction_manual",
        interaction_level="manual",
        valid=True,
        run_id=run_id,
        status_label="VALID",
    )

    selected_app_review.render_selected_app_diagnostics(
        package_name="com.whatsapp",
        display_label="WhatsApp",
        state=state,
        queue_action="interactive",
        db_active_sessions=1,
        db_historical_sessions=0,
        latest_recent=latest_recent,
        has_identity_mismatch=False,
        live_build_drift=False,
        menu_utils=guided_run.menu_utils,
    )

    out = capsys.readouterr().out
    assert "Latest Run Media Plane" in out
    assert "relay media likely" in out
    assert "157.240.146.35:3478" in out
    assert "turn_allocate_success, relay_media_pattern" in out
