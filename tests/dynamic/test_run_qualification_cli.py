from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DynamicAnalysis.controllers import selected_app_actions
from scytaledroid.DynamicAnalysis.menus import status_reports as menu_reports
from scytaledroid.DynamicAnalysis.utils.run_cleanup import PackageRunCounts


def _noop_evidence_context(**_kwargs) -> None:
    return None


def _print_workbench_summary(app) -> str:
    from io import StringIO
    import sys

    buffer = StringIO()
    stdout = sys.stdout
    sys.stdout = buffer
    try:
        selected_app_actions.print_selected_app_workbench_summary(
            app,
            status_messages=SimpleNamespace(status=lambda msg, level: msg),
            selected_app_active_valid_runs_fn=lambda _app: (
                int(_app.counts.baseline_valid_runs) + int(_app.counts.interactive_valid_runs)
            ),
            print_selected_app_evidence_context_fn=_noop_evidence_context,
            is_messaging_package_or_category_fn=lambda _pkg: False,
        )
    finally:
        sys.stdout = stdout
    return buffer.getvalue()


def _make_app(
    *,
    display_label: str,
    baseline_valid_runs: int,
    interactive_valid_runs: int,
    baseline_extra_valid: int = 0,
    baseline_low_signal_valid: int = 0,
    interactive_extra_valid: int = 0,
    interactive_low_signal_valid: int = 0,
    baseline_required: int = 3,
    interactive_required: int = 4,
) -> SimpleNamespace:
    extra_total = (
        baseline_extra_valid
        + baseline_low_signal_valid
        + interactive_extra_valid
        + interactive_low_signal_valid
    )
    return SimpleNamespace(
        package_name="com.example.app",
        display_label=display_label,
        meta_family_note=False,
        historical_valid_local=0,
        historical_build_count=0,
        db_active_sessions=0,
        db_historical_sessions=0,
        cfg=SimpleNamespace(
            baseline_required=baseline_required,
            interactive_required=interactive_required,
        ),
        counts=PackageRunCounts(
            total_runs=baseline_valid_runs + interactive_valid_runs + extra_total,
            valid_runs=baseline_valid_runs + interactive_valid_runs + extra_total,
            baseline_valid_runs=baseline_valid_runs,
            interactive_valid_runs=interactive_valid_runs,
            quota_met=(
                baseline_valid_runs >= baseline_required
                and interactive_valid_runs >= interactive_required
            ),
            extra_valid_runs=extra_total,
            baseline_extra_valid=baseline_extra_valid,
            baseline_low_signal_valid=baseline_low_signal_valid,
            interactive_extra_valid=interactive_extra_valid,
            interactive_low_signal_valid=interactive_low_signal_valid,
        ),
    )


def test_cohort_status_summary_includes_evidence_qualification(monkeypatch, capsys) -> None:
    monkeypatch.setattr(menu_reports.prompt_utils, "press_enter_to_continue", lambda: None)

    menu_reports.render_cohort_status_details(
        dataset_apps_total=2,
        dataset_apps_complete=1,
        dataset_valid_runs_total=10,
        current_build_ready_count=1,
        current_build_in_progress_count=1,
        current_build_review_count=0,
        stale_app_count=0,
        current_build_db_only_count=0,
        historical_valid_runs_total=0,
        historical_build_count_total=0,
        mixed_identity_app_count=0,
        legacy_only_app_count=0,
        historical_local_only_app_count=0,
        historical_db_only_app_count=0,
        no_evidence_anywhere_count=0,
        expected_runs=14,
        evidence_summary={"apps_satisfied": 1, "quota_runs_counted": 10},
        row_models=[
            SimpleNamespace(
                display_name="CNN",
                baseline_countable=3,
                baseline_extra=1,
                baseline_low_signal_supplemental=0,
                interactive_countable=3,
                interactive_extra=1,
                interactive_low_signal_supplemental=0,
                need_baseline=0,
                need_interactive=1,
                live_build_drift=False,
            ),
            SimpleNamespace(
                display_name="X (Twitter)",
                baseline_countable=2,
                baseline_extra=0,
                baseline_low_signal_supplemental=1,
                interactive_countable=0,
                interactive_extra=0,
                interactive_low_signal_supplemental=0,
                need_baseline=1,
                need_interactive=4,
                live_build_drift=False,
            ),
        ],
        baseline_required=3,
        interactive_required=4,
    )

    out = capsys.readouterr().out
    assert "Evidence qualification (tracker-scoped, current build)" in out
    assert "Quota-counted valid     : 8" in out
    assert "Extra valid             : 2" in out
    assert "Low-signal retained     : 1" in out
    assert "Total valid retained    : 11" in out
    assert "Analysis-included valid : 11" in out
    assert "Apps quota-satisfied    : 0 / 2" in out
    assert "CNN" in out
    assert "4/3" in out
    assert "4/4" in out
    assert "3/3" in out


def test_workbench_shows_cnn_style_qualification() -> None:
    out = _print_workbench_summary(
        _make_app(
            display_label="CNN",
            baseline_valid_runs=3,
            baseline_extra_valid=1,
            interactive_valid_runs=3,
            interactive_extra_valid=1,
        )
    )

    assert "Current build evidence" in out
    assert "Baseline     3/3 (+1 extra)" in out
    assert "Interactive  3/4 (+1 extra)" in out
    assert "Qualification" in out
    assert "Quota-counted valid     : 6" in out
    assert "Extra valid             : 2" in out
    assert "Total valid retained    : 8" in out
    assert "Analysis-included valid : 8" in out
    assert "Quota satisfied         : no" in out
    assert "ML training pool: 1 (1 supplemental)" in out


def test_workbench_shows_ml_pool_hint_when_quota_met_without_supplementals() -> None:
    out = _print_workbench_summary(
        _make_app(
            display_label="Reddit",
            baseline_valid_runs=3,
            interactive_valid_runs=4,
        )
    )

    assert "Baseline     3/3" in out
    assert "Interactive  4/4" in out
    assert "Quota satisfied         : yes" in out
    assert "ML training pool: none yet — supplemental baselines improve pattern averages" in out


def test_workbench_shows_x_style_qualification() -> None:
    out = _print_workbench_summary(
        _make_app(
            display_label="X (Twitter)",
            baseline_valid_runs=2,
            baseline_low_signal_valid=1,
            interactive_valid_runs=0,
        )
    )

    assert "Baseline     2/3 (+1 low)" in out
    assert "Interactive  0/4" in out
    assert "Quota-counted valid     : 2" in out
    assert "Low-signal retained     : 1" in out
    assert "Total valid retained    : 3" in out
    assert "Quota satisfied         : no" in out
    assert "ML training pool: 1 (1 low-signal)" in out


def test_workbench_shows_whatsapp_style_qualification() -> None:
    out = _print_workbench_summary(
        _make_app(
            display_label="WhatsApp",
            baseline_valid_runs=3,
            interactive_valid_runs=2,
            interactive_extra_valid=1,
            interactive_low_signal_valid=1,
        )
    )

    assert "Baseline     3/3" in out
    assert "Interactive  2/4 (+1 extra, +1 low)" in out
    assert "Quota-counted valid     : 5" in out
    assert "Extra valid             : 1" in out
    assert "Low-signal retained     : 1" in out
    assert "Total valid retained    : 7" in out
    assert "Quota satisfied         : no" in out
