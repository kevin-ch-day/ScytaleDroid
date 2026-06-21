from __future__ import annotations

from types import SimpleNamespace

import pytest

from scytaledroid.DynamicAnalysis.controllers import guided_run
from scytaledroid.DynamicAnalysis.services.dataset_run_state import DatasetRunRecentSummary, DatasetRunState
from scytaledroid.DynamicAnalysis.utils.run_cleanup import PackageRunCounts


pytestmark = [pytest.mark.contract, pytest.mark.state_contract]


def test_guided_run_uses_dataset_state_for_summary_and_default(monkeypatch, capsys) -> None:
    package = "com.google.android.apps.messaging"
    select_package_calls = {"count": 0}
    monkeypatch.setattr(guided_run, "_detect_static_plan_build_drift", lambda **_k: None)
    monkeypatch.setattr(guided_run, "_load_db_dynamic_lineage_context", lambda _pkg: {})
    monkeypatch.setattr(guided_run, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(guided_run, "_print_paper_mode_constants", lambda: None)
    monkeypatch.setattr(guided_run, "select_device", lambda: ("ZY22JK89DR", "moto"))
    monkeypatch.setattr(guided_run, "_device_preflight_checks", lambda _serial: True)
    monkeypatch.setattr(
        guided_run,
        "group_artifacts",
        lambda: [SimpleNamespace(package_name=package)],
    )
    monkeypatch.setattr(guided_run, "active_research_cohort_packages", lambda: (package,))
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
            baseline_required=3,
            interactive_required=2,
            total_required=5,
            local_evidence_dir_count=1,
            reset_available=False,
            paper_eligible_local=1,
            quota_counted_local=1,
            exclusion_reason_top=(("EXCLUDED_LOW_SIGNAL", 1),),
            suggested_profile_from_tracker="baseline_connected",
            effective_suggested_profile="baseline_connected",
            suggested_slot=1,
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

    def _fake_choice(choices, *, default=None, disabled=None, **_kwargs):
        assert default == "1"
        assert "D" in (disabled or [])
        return "0"

    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", _fake_choice)

    def _select_package(_groups, title, subtitle=None):
        select_package_calls["count"] += 1
        if select_package_calls["count"] == 1:
            return package
        return None

    guided_run.run_guided_dataset_run(
        select_package_from_groups=_select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )
    out = capsys.readouterr().out

    assert "Selected app: com.google.android.apps.messaging" in out
    assert "Run readiness:" not in out
    assert "Press Enter to continue, V for details, or B to go back" not in out
    assert "Select Run Intent" in out


def test_guided_run_selected_app_prefers_display_label(monkeypatch, capsys) -> None:
    package = "bbc.mobile.news.ww"
    select_package_calls = {"count": 0}
    monkeypatch.setattr(guided_run, "_detect_static_plan_build_drift", lambda **_k: None)
    monkeypatch.setattr(guided_run, "_load_db_dynamic_lineage_context", lambda _pkg: {})
    monkeypatch.setattr(guided_run, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(guided_run, "_print_paper_mode_constants", lambda: None)
    monkeypatch.setattr(guided_run, "select_device", lambda: ("ZY22JK89DR", "moto"))
    monkeypatch.setattr(guided_run, "_device_preflight_checks", lambda _serial: True)
    monkeypatch.setattr(
        guided_run,
        "group_artifacts",
        lambda: [SimpleNamespace(package_name=package, display_name="BBC News")],
    )
    monkeypatch.setattr(guided_run, "active_research_cohort_packages", lambda: (package,))
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: DatasetRunState(
            package_name=package,
            tracker_status="ok",
            evidence_status="ok",
            state_status="ok",
            counts=PackageRunCounts(
                total_runs=0,
                valid_runs=0,
                baseline_valid_runs=0,
                interactive_valid_runs=0,
                quota_met=False,
                extra_valid_runs=0,
            ),
            baseline_required=3,
            interactive_required=2,
            total_required=5,
            local_evidence_dir_count=0,
            reset_available=False,
            paper_eligible_local=0,
            quota_counted_local=0,
            exclusion_reason_top=(),
            suggested_profile_from_tracker="baseline_idle",
            effective_suggested_profile="baseline_idle",
            suggested_slot=1,
            recent_runs=(),
            baseline_idle_pcap_missing_streak=0,
            baseline_idle_low_signal_streak=0,
            baseline_connected_insufficient_duration_streak=0,
        ),
    )
    monkeypatch.setattr(
        guided_run.prompt_utils,
        "get_choice",
        lambda *args, **kwargs: "0",
    )

    def _select_package(_groups, title, subtitle=None):
        select_package_calls["count"] += 1
        if select_package_calls["count"] == 1:
            return package
        return None

    guided_run.run_guided_dataset_run(
        select_package_from_groups=_select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert "Selected app: BBC News" in out
    assert "Package: bbc.mobile.news.ww" in out


def test_guided_run_reuses_selected_device_across_cohort_iterations(monkeypatch) -> None:
    package = "bbc.mobile.news.ww"
    select_device_calls = {"count": 0}
    select_package_calls = {"count": 0}
    subtitles: list[str | None] = []
    monkeypatch.setattr(guided_run, "_detect_static_plan_build_drift", lambda **_k: None)
    monkeypatch.setattr(guided_run, "_load_db_dynamic_lineage_context", lambda _pkg: {})

    monkeypatch.setattr(guided_run, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(guided_run, "_print_paper_mode_constants", lambda: None)

    def _select_device():
        select_device_calls["count"] += 1
        return ("ZY22JK89DR", "moto")

    def _select_package(_groups, title, subtitle=None):
        select_package_calls["count"] += 1
        subtitles.append(subtitle)
        if select_package_calls["count"] == 1:
            return package
        return None

    monkeypatch.setattr(guided_run, "select_device", _select_device)
    monkeypatch.setattr(guided_run, "_device_preflight_checks", lambda _serial: True)
    monkeypatch.setattr(
        guided_run,
        "group_artifacts",
        lambda: [SimpleNamespace(package_name=package, display_name="BBC News")],
    )
    monkeypatch.setattr(guided_run, "active_research_cohort_packages", lambda: (package,))
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: DatasetRunState(
            package_name=package,
            tracker_status="ok",
            evidence_status="ok",
            state_status="ok",
            counts=PackageRunCounts(
                total_runs=0,
                valid_runs=0,
                baseline_valid_runs=0,
                interactive_valid_runs=0,
                quota_met=False,
                extra_valid_runs=0,
            ),
            baseline_required=3,
            interactive_required=2,
            total_required=5,
            local_evidence_dir_count=0,
            reset_available=False,
            paper_eligible_local=0,
            quota_counted_local=0,
            exclusion_reason_top=(),
            suggested_profile_from_tracker="baseline_idle",
            effective_suggested_profile="baseline_idle",
            suggested_slot=1,
            recent_runs=(),
            baseline_idle_pcap_missing_streak=0,
            baseline_idle_low_signal_streak=0,
            baseline_connected_insufficient_duration_streak=0,
        ),
    )
    monkeypatch.setattr(guided_run, "select_device", _select_device)
    monkeypatch.setattr(guided_run.prompt_utils, "prompt_yes_no", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        guided_run.prompt_utils,
        "get_choice",
        lambda *args, **kwargs: "1",
    )
    monkeypatch.setattr(guided_run, "select_device", _select_device)
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

    assert select_device_calls["count"] == 1
    assert select_package_calls["count"] == 2
    assert subtitles[0] == "Device: moto"


def test_guided_run_defaults_to_manual_when_script_template_missing(monkeypatch, capsys) -> None:
    package = "bbc.mobile.news.ww"
    select_package_calls = {"count": 0}
    rendered = {}
    monkeypatch.setattr(guided_run, "_detect_static_plan_build_drift", lambda **_k: None)
    monkeypatch.setattr(guided_run, "_load_db_dynamic_lineage_context", lambda _pkg: {})

    monkeypatch.setattr(guided_run, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(guided_run, "_print_paper_mode_constants", lambda: None)
    monkeypatch.setattr(guided_run, "select_device", lambda: ("ZY22JK89DR", "moto"))
    monkeypatch.setattr(guided_run, "_device_preflight_checks", lambda _serial: True)
    monkeypatch.setattr(
        guided_run,
        "group_artifacts",
        lambda: [SimpleNamespace(package_name=package, display_name="BBC News")],
    )
    monkeypatch.setattr(guided_run, "active_research_cohort_packages", lambda: (package,))
    monkeypatch.setattr(guided_run, "resolved_template_for_package", lambda _pkg: None)
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: DatasetRunState(
            package_name=package,
            tracker_status="ok",
            evidence_status="ok",
            state_status="ok",
            counts=PackageRunCounts(
                total_runs=3,
                valid_runs=3,
                baseline_valid_runs=3,
                interactive_valid_runs=0,
                quota_met=False,
                extra_valid_runs=0,
            ),
            baseline_required=3,
            interactive_required=2,
            total_required=5,
            local_evidence_dir_count=3,
            reset_available=False,
            paper_eligible_local=3,
            quota_counted_local=3,
            exclusion_reason_top=(),
            suggested_profile_from_tracker="interaction_manual",
            effective_suggested_profile="interaction_manual",
            suggested_slot=4,
            recent_runs=(),
            baseline_idle_pcap_missing_streak=0,
            baseline_idle_low_signal_streak=0,
            baseline_connected_insufficient_duration_streak=0,
        ),
    )
    def _render_menu(spec):
        rendered["items"] = {item.key: item for item in spec.items}
        rendered["default"] = spec.default

    monkeypatch.setattr(guided_run.menu_utils, "render_menu", _render_menu)

    def _fake_choice(_choices, *, default=None, disabled=None, **_kwargs):
        assert default == "3"
        assert "2" in (disabled or [])
        return "0"

    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", _fake_choice)

    def _select_package(_groups, title, subtitle=None):
        select_package_calls["count"] += 1
        if select_package_calls["count"] == 1:
            return package
        return None

    guided_run.run_guided_dataset_run(
        select_package_from_groups=_select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert "Select Run Intent" in out
    assert rendered["default"] == "3"
    assert rendered["items"]["2"].disabled is True
    assert rendered["items"]["3"].badge == "suggested"
    assert "Standard cohort interaction path for paper #3" in str(rendered["items"]["3"].description)


def test_guided_run_reports_historical_and_supplemental_context(monkeypatch, capsys) -> None:
    package = "com.facebook.katana"
    select_package_calls = {"count": 0}
    monkeypatch.setattr(guided_run, "_detect_static_plan_build_drift", lambda **_k: None)
    monkeypatch.setattr(guided_run, "_load_db_dynamic_lineage_context", lambda _pkg: {})

    monkeypatch.setattr(guided_run, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(guided_run, "_print_paper_mode_constants", lambda: None)
    monkeypatch.setattr(guided_run, "select_device", lambda: ("ZY22JK89DR", "moto"))
    monkeypatch.setattr(guided_run, "_device_preflight_checks", lambda _serial: True)
    monkeypatch.setattr(
        guided_run,
        "group_artifacts",
        lambda: [SimpleNamespace(package_name=package, display_name="Facebook")],
    )
    monkeypatch.setattr(guided_run, "active_research_cohort_packages", lambda: (package,))
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: DatasetRunState(
            package_name=package,
            tracker_status="ok",
            evidence_status="ok",
            state_status="ok",
            counts=PackageRunCounts(
                total_runs=4,
                valid_runs=3,
                baseline_valid_runs=3,
                interactive_valid_runs=0,
                quota_met=False,
                extra_valid_runs=1,
            ),
            baseline_required=3,
            interactive_required=2,
            total_required=5,
            local_evidence_dir_count=4,
            reset_available=True,
            paper_eligible_local=4,
            quota_counted_local=3,
            exclusion_reason_top=(),
            suggested_profile_from_tracker="interaction_manual",
            effective_suggested_profile="interaction_manual",
            suggested_slot=4,
            recent_runs=(),
            baseline_idle_pcap_missing_streak=0,
            baseline_idle_low_signal_streak=0,
            baseline_connected_insufficient_duration_streak=0,
            historical_valid_runs=2,
            historical_build_count=1,
        ),
    )
    monkeypatch.setattr(guided_run.menu_utils, "render_menu", lambda spec: None)
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "0")

    def _select_package(_groups, title, subtitle=None):
        select_package_calls["count"] += 1
        if select_package_calls["count"] == 1:
            return package
        return None

    guided_run.run_guided_dataset_run(
        select_package_from_groups=_select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert "Historical context: 2 legacy valid run(s) across 1 older build(s) retained for comparison; not counted toward current quota." in out
    assert "Supplemental current-build evidence: 1 extra valid run(s) retained outside quota." in out


def test_guided_run_reports_historical_db_only_context(monkeypatch, capsys) -> None:
    package = "com.facebook.orca"
    select_package_calls = {"count": 0}
    monkeypatch.setattr(guided_run, "_detect_static_plan_build_drift", lambda **_k: None)
    monkeypatch.setattr(
        guided_run,
        "_load_db_dynamic_lineage_context",
        lambda _pkg: {"db_active_sessions": 0, "db_historical_sessions": 11, "db_total_sessions": 11},
    )
    monkeypatch.setattr(guided_run, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(guided_run, "_print_paper_mode_constants", lambda: None)
    monkeypatch.setattr(guided_run, "select_device", lambda: ("ZY22JK89DR", "moto"))
    monkeypatch.setattr(guided_run, "_device_preflight_checks", lambda _serial: True)
    monkeypatch.setattr(
        guided_run,
        "group_artifacts",
        lambda: [SimpleNamespace(package_name=package, display_name="Facebook Messenger")],
    )
    monkeypatch.setattr(guided_run, "active_research_cohort_packages", lambda: (package,))
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: DatasetRunState(
            package_name=package,
            tracker_status="ok",
            evidence_status="ok",
            state_status="ok",
            counts=PackageRunCounts(
                total_runs=0,
                valid_runs=0,
                baseline_valid_runs=0,
                interactive_valid_runs=0,
                quota_met=False,
                extra_valid_runs=0,
            ),
            baseline_required=3,
            interactive_required=2,
            total_required=5,
            local_evidence_dir_count=0,
            reset_available=False,
            paper_eligible_local=0,
            quota_counted_local=0,
            exclusion_reason_top=(),
            suggested_profile_from_tracker="baseline_idle",
            effective_suggested_profile="baseline_idle",
            suggested_slot=1,
            recent_runs=(),
            baseline_idle_pcap_missing_streak=0,
            baseline_idle_low_signal_streak=0,
            baseline_connected_insufficient_duration_streak=0,
        ),
    )
    monkeypatch.setattr(guided_run.menu_utils, "render_menu", lambda spec: None)
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "0")

    def _select_package(_groups, title, subtitle=None):
        select_package_calls["count"] += 1
        if select_package_calls["count"] == 1:
            return package
        return None

    guided_run.run_guided_dataset_run(
        select_package_from_groups=_select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert "Historical DB-only context: 11 older DB-backed session(s) exist" in out
    assert "Queue action: baseline" in out
    assert "Reason: 3 baseline runs needed" in out
    assert "Recommended action: collect baseline evidence for the installed build" in out


def test_guided_run_reports_no_evidence_anywhere_context(monkeypatch, capsys) -> None:
    package = "com.guardian"
    select_package_calls = {"count": 0}
    monkeypatch.setattr(guided_run, "_detect_static_plan_build_drift", lambda **_k: None)
    monkeypatch.setattr(guided_run, "_load_db_dynamic_lineage_context", lambda _pkg: {})
    monkeypatch.setattr(guided_run, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(guided_run, "_print_paper_mode_constants", lambda: None)
    monkeypatch.setattr(guided_run, "select_device", lambda: ("ZY22JK89DR", "moto"))
    monkeypatch.setattr(guided_run, "_device_preflight_checks", lambda _serial: True)
    monkeypatch.setattr(
        guided_run,
        "group_artifacts",
        lambda: [SimpleNamespace(package_name=package, display_name="The Guardian")],
    )
    monkeypatch.setattr(guided_run, "active_research_cohort_packages", lambda: (package,))
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: DatasetRunState(
            package_name=package,
            tracker_status="ok",
            evidence_status="ok",
            state_status="ok",
            counts=PackageRunCounts(
                total_runs=0,
                valid_runs=0,
                baseline_valid_runs=0,
                interactive_valid_runs=0,
                quota_met=False,
                extra_valid_runs=0,
            ),
            baseline_required=3,
            interactive_required=2,
            total_required=5,
            local_evidence_dir_count=0,
            reset_available=False,
            paper_eligible_local=0,
            quota_counted_local=0,
            exclusion_reason_top=(),
            suggested_profile_from_tracker="baseline_idle",
            effective_suggested_profile="baseline_idle",
            suggested_slot=1,
            recent_runs=(),
            baseline_idle_pcap_missing_streak=0,
            baseline_idle_low_signal_streak=0,
            baseline_connected_insufficient_duration_streak=0,
        ),
    )
    monkeypatch.setattr(guided_run.menu_utils, "render_menu", lambda spec: None)
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "0")

    def _select_package(_groups, title, subtitle=None):
        select_package_calls["count"] += 1
        if select_package_calls["count"] == 1:
            return package
        return None

    guided_run.run_guided_dataset_run(
        select_package_from_groups=_select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert "App state" in out
    assert "Build" in out
    assert "Evidence" in out
    assert "QA" in out
    assert "Need" in out
    assert "Action" in out
    assert "Quota" in out
    assert "unknown" in out
    assert "empty" in out
    assert "base 0/3" in out
    assert "0/5 n5" in out
    assert "No prior dynamic evidence exists yet for com.guardian." in out
    assert "Queue action: baseline" in out
    assert "Reason: 3 baseline runs needed" in out


def test_guided_run_reports_review_queue_action_for_invalid_complete_current_build(monkeypatch, capsys) -> None:
    package = "com.cnn.mobile.android.phone"
    select_package_calls = {"count": 0}
    monkeypatch.setattr(guided_run, "_detect_static_plan_build_drift", lambda **_k: None)
    monkeypatch.setattr(
        guided_run,
        "_load_db_dynamic_lineage_context",
        lambda _pkg: {"db_active_sessions": 6, "db_historical_sessions": 0, "db_total_sessions": 6},
    )
    monkeypatch.setattr(guided_run, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(guided_run, "_print_paper_mode_constants", lambda: None)
    monkeypatch.setattr(guided_run, "select_device", lambda: ("ZY22JK89DR", "moto"))
    monkeypatch.setattr(guided_run, "_device_preflight_checks", lambda _serial: True)
    monkeypatch.setattr(
        guided_run,
        "group_artifacts",
        lambda: [SimpleNamespace(package_name=package, display_name="CNN")],
    )
    monkeypatch.setattr(guided_run, "active_research_cohort_packages", lambda: (package,))
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: DatasetRunState(
            package_name=package,
            tracker_status="ok",
            evidence_status="ok",
            state_status="ok",
            counts=PackageRunCounts(
                total_runs=6,
                valid_runs=5,
                baseline_valid_runs=3,
                interactive_valid_runs=2,
                quota_met=True,
                extra_valid_runs=0,
            ),
            baseline_required=3,
            interactive_required=2,
            total_required=5,
            local_evidence_dir_count=6,
            reset_available=True,
            paper_eligible_local=5,
            quota_counted_local=5,
            exclusion_reason_top=(),
            suggested_profile_from_tracker="interaction_scripted",
            effective_suggested_profile="interaction_scripted",
            suggested_slot=None,
            recent_runs=(
                DatasetRunRecentSummary(
                    ended_at="2026-06-19T10:00:00Z",
                    run_profile="interaction_scripted",
                    interaction_level="scripted",
                    messaging_activity=None,
                    valid=False,
                    invalid_reason_code="PCAP_MISSING",
                    low_signal=None,
                    run_id="cnnrun1",
                    status_label="INVALID:PCAP_MISSING",
                ),
            ),
            baseline_idle_pcap_missing_streak=0,
            baseline_idle_low_signal_streak=0,
            baseline_connected_insufficient_duration_streak=0,
        ),
    )
    monkeypatch.setattr(guided_run.menu_utils, "render_menu", lambda spec: None)
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "0")

    def _select_package(_groups, title, subtitle=None):
        select_package_calls["count"] += 1
        if select_package_calls["count"] == 1:
            return package
        return None

    guided_run.run_guided_dataset_run(
        select_package_from_groups=_select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert "App state" in out
    assert "current" in out
    assert "local+db" in out
    assert "inv" in out
    assert "review" in out
    assert "5/5" in out
    assert "Queue action: review QA" in out
    assert "Reason: latest current-build run is invalid (PCAP_MISSING)" in out


def test_guided_run_blocks_early_when_static_plan_identity_drift_exists(monkeypatch, capsys) -> None:
    package = "com.facebook.katana"
    select_package_calls = {"count": 0}
    render_menu_calls = {"count": 0}

    monkeypatch.setattr(guided_run, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(guided_run, "_print_paper_mode_constants", lambda: None)
    monkeypatch.setattr(guided_run, "select_device", lambda: ("ZY22JK89DR", "moto"))
    monkeypatch.setattr(guided_run, "_device_preflight_checks", lambda _serial: True)
    monkeypatch.setattr(
        guided_run,
        "group_artifacts",
        lambda: [SimpleNamespace(package_name=package, display_name="Facebook")],
    )
    monkeypatch.setattr(guided_run, "active_research_cohort_packages", lambda: (package,))
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: DatasetRunState(
            package_name=package,
            tracker_status="ok",
            evidence_status="ok",
            state_status="ok",
            counts=PackageRunCounts(
                total_runs=4,
                valid_runs=3,
                baseline_valid_runs=3,
                interactive_valid_runs=0,
                quota_met=False,
                extra_valid_runs=1,
            ),
            baseline_required=3,
            interactive_required=2,
            total_required=5,
            local_evidence_dir_count=4,
            reset_available=True,
            paper_eligible_local=4,
            quota_counted_local=3,
            exclusion_reason_top=(),
            suggested_profile_from_tracker="interaction_manual",
            effective_suggested_profile="interaction_manual",
            suggested_slot=4,
            recent_runs=(),
            baseline_idle_pcap_missing_streak=0,
            baseline_idle_low_signal_streak=0,
            baseline_connected_insufficient_duration_streak=0,
            historical_valid_runs=2,
            historical_build_count=1,
        ),
    )
    monkeypatch.setattr(
        guided_run,
        "ensure_plan_or_error",
        lambda *_args, **_kwargs: {
            "plan_path": "plan.json",
            "static_run_id": 4290,
            "version_name": "565.0.0.49.74",
            "version_code": "472143276",
        },
    )
    monkeypatch.setattr(
        guided_run,
        "_load_plan_identity",
        lambda _path: {"version_code": "472143276"},
    )
    monkeypatch.setattr(
        guided_run,
        "_read_observed_version_code_details",
        lambda _serial, _package: {
            "version_code": "472224766",
            "command": "dumpsys package com.facebook.katana",
            "pattern": "scoped:versionCode+minSdk",
            "matched_line": "versionCode=472224766 minSdk=30 targetSdk=36",
        },
    )
    monkeypatch.setattr(guided_run.prompt_utils, "press_enter_to_continue", lambda: None)

    def _render_menu(_spec):
        render_menu_calls["count"] += 1

    monkeypatch.setattr(guided_run.menu_utils, "render_menu", _render_menu)

    def _select_package(_groups, title, subtitle=None):
        select_package_calls["count"] += 1
        if select_package_calls["count"] == 1:
            return package
        return None

    guided_run.run_guided_dataset_run(
        select_package_from_groups=_select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert "Static Plan / Device Drift" in out
    assert "Queue action: refresh static" in out
    assert "Reason: installed build 472224766 does not match the newest static-plan build 472143276." in out
    assert "Dataset-mode dynamic runs require the installed build to match the selected static plan." in out
    assert "Refresh harvest/static for this app or choose another app." in out
    assert "472224766" in out
    assert "472143276" in out
    assert "Select Run Intent" not in out
    assert render_menu_calls["count"] == 0
