from __future__ import annotations

import pytest

from scytaledroid.DynamicAnalysis.controllers import guided_run

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
        lambda: device_calls.__setitem__("select", device_calls["select"] + 1) or ("ZY22JK89DR", "moto"),
    )
    monkeypatch.setattr(
        guided_run,
        "_device_preflight_checks",
        lambda _serial: device_calls.__setitem__("preflight", device_calls["preflight"] + 1) or True,
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
                    run_id="cnn-run-1",
                    status_label="INVALID:PCAP_MISSING",
                ),
            ),
        ),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choices))
    monkeypatch.setattr(guided_run.prompt_utils, "press_enter_to_continue", lambda *args, **kwargs: None)

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
    assert qa_calls["run_id"] == "cnn-run-1"
    assert device_calls == {"select": 0, "preflight": 0}


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
        lambda: device_calls.__setitem__("select", device_calls["select"] + 1) or ("ZY22JK89DR", "moto"),
    )
    monkeypatch.setattr(
        guided_run,
        "_device_preflight_checks",
        lambda _serial: device_calls.__setitem__("preflight", device_calls["preflight"] + 1) or True,
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
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choice_iter))
    monkeypatch.setattr(guided_run.prompt_utils, "press_enter_to_continue", lambda *args, **kwargs: None)

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert expected_header in out
    assert device_calls == {"select": 0, "preflight": 0}


def test_guided_run_reports_historical_and_supplemental_context(monkeypatch, capsys) -> None:
    package = "com.facebook.katana"
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="Facebook",
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            total_runs=4,
            valid_runs=3,
            baseline_valid_runs=3,
            interactive_valid_runs=0,
            quota_met=False,
            extra_valid_runs=1,
            local_evidence_dir_count=4,
            reset_available=True,
            paper_eligible_local=4,
            quota_counted_local=3,
            suggested_profile_from_tracker="interaction_manual",
            effective_suggested_profile="interaction_manual",
            suggested_slot=4,
            historical_valid_runs=2,
            historical_build_count=1,
        ),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "0")

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Historical evidence: 2 legacy valid run(s) across 1 older build(s) retained for comparison; not counted toward current quota." in out
    assert "Supplemental current-build evidence: 1 extra valid run(s) retained outside quota." in out


def test_guided_run_reports_historical_db_only_context(monkeypatch, capsys) -> None:
    package = "com.facebook.orca"
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="Facebook Messenger",
        lineage_context={"db_active_sessions": 0, "db_historical_sessions": 11, "db_total_sessions": 11},
    )
    monkeypatch.setattr(guided_run, "load_dataset_run_state", lambda _package_name, config=None: make_dataset_state(package))
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "0")

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Why:" in out
    assert "Historical DB-only evidence exists, but no current-build evidence pack is present in this workspace." in out
    assert "1) Baseline run [default]" in out
    assert "Reason: 3 baseline runs needed" in out
    assert "Collect baseline evidence for the installed build." in out


def test_guided_run_current_build_db_only_offers_restore_or_recollect(monkeypatch, capsys) -> None:
    package = "com.linkedin.android"
    select_package_calls, select_package = one_shot_package_selector(package)
    prompts: list[str] = []
    choices = iter(["R", "0"])

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="LinkedIn",
        lineage_context={"db_active_sessions": 4, "db_historical_sessions": 0, "db_total_sessions": 4},
    )
    monkeypatch.setattr(guided_run, "load_dataset_run_state", lambda _package_name, config=None: make_dataset_state(package))
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choices))

    def _prompt_yes_no(message, default=False):
        del default
        prompts.append(str(message))
        return False

    monkeypatch.setattr(guided_run.prompt_utils, "prompt_yes_no", _prompt_yes_no)

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Current build · current-build evidence (db-only) · QA unknown · quota 0/5" in out
    assert "R) Restore / recollect [default]" in out
    assert "Reason: current-build evidence exists in the DB, but the local evidence pack is missing from this workspace." in out
    assert "Restore / Recollect" in out
    assert "Restore the missing evidence pack if you have it, or recollect a current-build baseline now." in out
    assert any("Start baseline recollection for the installed build now?" in prompt for prompt in prompts)


def test_guided_run_reports_no_evidence_anywhere_context(monkeypatch, capsys) -> None:
    package = "com.guardian"
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="The Guardian",
    )
    monkeypatch.setattr(guided_run, "load_dataset_run_state", lambda _package_name, config=None: make_dataset_state(package))
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "0")

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Unknown build · no current-build evidence · QA unknown · quota 0/5" in out
    assert "No dynamic evidence exists yet for com.guardian." in out
    assert "1) Baseline run [default]" in out
    assert "Reason: 3 baseline runs needed" in out
