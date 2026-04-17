from __future__ import annotations

from types import SimpleNamespace

import pytest

from scytaledroid.DynamicAnalysis.controllers import guided_run
from scytaledroid.DynamicAnalysis.services.dataset_run_state import DatasetRunRecentSummary, DatasetRunState
from scytaledroid.DynamicAnalysis.utils.run_cleanup import PackageRunCounts


pytestmark = [pytest.mark.contract, pytest.mark.state_contract]


def test_guided_run_uses_dataset_state_for_summary_and_default(monkeypatch, capsys) -> None:
    package = "com.google.android.apps.messaging"
    monkeypatch.setattr(guided_run, "_print_paper_mode_constants", lambda: None)
    monkeypatch.setattr(guided_run, "select_device", lambda: ("ZY22JK89DR", "moto"))
    monkeypatch.setattr(guided_run, "_device_preflight_checks", lambda _serial: True)
    monkeypatch.setattr(
        guided_run,
        "group_artifacts",
        lambda: [SimpleNamespace(package_name=package)],
    )
    monkeypatch.setattr(guided_run, "load_dataset_packages", lambda: [package])
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: DatasetRunState(
            package_name=package,
            tracker_status="ok",
            evidence_status="ok",
            state_status="ok",
            counts=PackageRunCounts(
                total_runs=2,
                valid_runs=1,
                baseline_valid_runs=0,
                interactive_valid_runs=1,
                quota_met=False,
                extra_valid_runs=0,
            ),
            baseline_required=1,
            interactive_required=2,
            total_required=3,
            local_evidence_dir_count=1,
            reset_available=False,
            paper_eligible_local=1,
            quota_counted_local=1,
            exclusion_reason_top=(("EXCLUDED_LOW_SIGNAL", 1),),
            suggested_profile_from_tracker="baseline_connected",
            effective_suggested_profile="interaction_scripted",
            suggested_slot=2,
            recent_runs=(
                DatasetRunRecentSummary(
                    ended_at="2026-04-16T12:00:00Z",
                    run_profile="baseline_idle",
                    interaction_level="minimal",
                    messaging_activity=None,
                    valid=False,
                    invalid_reason_code="PCAP_MISSING",
                    low_signal=None,
                    run_id="run12345",
                    status_label="INVALID:PCAP_MISSING",
                ),
            ),
            baseline_idle_pcap_missing_streak=0,
            baseline_idle_low_signal_streak=0,
            baseline_connected_insufficient_duration_streak=0,
        ),
    )

    monkeypatch.setattr(guided_run.menu_utils, "render_menu", lambda spec: None)
    monkeypatch.setattr(guided_run.prompt_utils, "prompt_text", lambda *_args, **_kwargs: "v")

    def _fake_choice(choices, *, default=None, disabled=None, **_kwargs):
        assert default == "2"
        assert "D" in (disabled or [])
        return "0"

    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", _fake_choice)

    guided_run.run_guided_dataset_run(
        select_package_from_groups=lambda groups, title: package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )
    out = capsys.readouterr().out

    assert "quota_counted(local)=1/3" in out
    assert "evidence_dirs=1" in out
    assert "Suggested by quota (counts toward completion): interaction_scripted" in out
    assert "local_exclusion_top: EXCLUDED_LOW_SIGNAL=1" in out
