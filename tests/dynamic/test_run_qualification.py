from __future__ import annotations

import json
from pathlib import Path

import pytest
from scytaledroid.DynamicAnalysis import app_queue_state, tracker_scope
from scytaledroid.DynamicAnalysis.core.manifest import RunManifest
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
    DatasetTrackerConfig,
    evaluate_dataset_validity,
)
from scytaledroid.DynamicAnalysis.pcap.low_signal import compute_low_signal_for_run
from scytaledroid.DynamicAnalysis.run_qualification import (
    format_quota_progress_label,
    run_included_in_default_analysis,
    summarize_evidence_qualification,
    summarize_tracker_runs_qualification,
)


class _Cfg:
    baseline_required = 3
    interactive_required = 4


def _identity_resolver(_pkg, row):
    return (
        str(row.get("version_code") or "") or None,
        str(row.get("base_apk_sha256") or "") or None,
    )


def _baseline_run(
    run_id: str,
    *,
    ended_at: str,
    countable: bool | None = None,
    low_signal: bool = False,
    extra_run: bool = False,
    baseline_not_idle: bool = False,
) -> dict:
    row = {
        "run_id": run_id,
        "valid_dataset_run": True,
        "paper_eligible": True,
        "run_profile": "baseline_idle",
        "version_code": "100",
        "base_apk_sha256": "sha-active",
        "ended_at": ended_at,
    }
    if countable is not None:
        row["countable"] = countable
    if low_signal:
        row["low_signal"] = True
        row["extra_run"] = 1
        row["countable"] = False
    elif baseline_not_idle:
        row["baseline_not_idle"] = True
        row["extra_run"] = 1
        row["countable"] = False
    elif extra_run:
        row["extra_run"] = 1
        row["countable"] = False
    return row


def _interactive_run(
    run_id: str,
    *,
    ended_at: str,
    countable: bool | None = None,
    low_signal: bool = False,
    extra_run: bool = False,
) -> dict:
    row = {
        "run_id": run_id,
        "valid_dataset_run": True,
        "paper_eligible": True,
        "run_profile": "interaction_manual",
        "version_code": "100",
        "base_apk_sha256": "sha-active",
        "ended_at": ended_at,
    }
    if countable is not None:
        row["countable"] = countable
    if low_signal:
        row["low_signal"] = True
        row["extra_run"] = 1
        row["countable"] = False
    elif extra_run:
        row["extra_run"] = 1
        row["countable"] = False
    return row


def test_cnn_baseline_four_normal_valid_runs_quota_and_analysis() -> None:
    runs = [
        _baseline_run("b1", ended_at="2026-01-01T10:00:00+00:00", countable=True),
        _baseline_run("b2", ended_at="2026-01-01T11:00:00+00:00", countable=True),
        _baseline_run("b3", ended_at="2026-01-01T12:00:00+00:00", countable=True),
        _baseline_run("b4", ended_at="2026-01-01T13:00:00+00:00", extra_run=True),
    ]

    scoped = tracker_scope.build_scoped_dataset_counts(
        "com.cnn.mobile.android.phone",
        runs,
        cfg=_Cfg(),
        resolve_tracker_run_identity_fn=_identity_resolver,
        active_identity_fn=lambda _pkg: ("100", "sha-active"),
    )
    summary = summarize_evidence_qualification(scoped, baseline_required=3, interactive_required=4)

    label = format_quota_progress_label(
        countable=scoped["baseline_countable"],
        required=3,
        extra=scoped["baseline_extra"],
        low_signal=scoped["baseline_low_signal_supplemental"],
    )

    assert label == "3/3 (+1 extra)"
    assert summary.baseline.quota_satisfied is True
    assert summary.baseline.total_valid_retained == 4
    assert summary.baseline.analysis_included_valid == 4
    assert all(run_included_in_default_analysis(valid_dataset_run=True) for _ in runs)


def test_x_baseline_two_countable_plus_one_low_signal() -> None:
    runs = [
        _baseline_run("b1", ended_at="2026-01-01T10:00:00+00:00", countable=True),
        _baseline_run("b2", ended_at="2026-01-01T11:00:00+00:00", countable=True),
        _baseline_run("b3", ended_at="2026-01-01T12:00:00+00:00", low_signal=True),
    ]

    scoped = tracker_scope.build_scoped_dataset_counts(
        "com.twitter.android",
        runs,
        cfg=_Cfg(),
        resolve_tracker_run_identity_fn=_identity_resolver,
        active_identity_fn=lambda _pkg: ("100", "sha-active"),
    )
    summary = summarize_evidence_qualification(scoped, baseline_required=3, interactive_required=4)
    label = format_quota_progress_label(
        countable=scoped["baseline_countable"],
        required=3,
        extra=scoped["baseline_extra"],
        low_signal=scoped["baseline_low_signal_supplemental"],
    )

    assert label == "2/3 (+1 low)"
    assert summary.baseline.quota_satisfied is False
    assert summary.baseline.total_valid_retained == 3
    assert summary.baseline.quota_counted_valid == 2
    assert summary.baseline.low_signal_retained == 1


def test_non_idle_baseline_uses_dedicated_retained_lane_not_generic_extra() -> None:
    runs = [
        _baseline_run("b1", ended_at="2026-01-01T10:00:00+00:00", countable=True),
        _baseline_run("b2", ended_at="2026-01-01T11:00:00+00:00", countable=True),
        _baseline_run("b3", ended_at="2026-01-01T12:00:00+00:00", baseline_not_idle=True),
    ]

    summary = summarize_tracker_runs_qualification(
        runs,
        baseline_required=3,
        interactive_required=4,
    )
    label = format_quota_progress_label(
        countable=summary.baseline.quota_counted_valid,
        required=3,
        extra=summary.baseline.extra_valid,
        low_signal=summary.baseline.low_signal_retained,
        non_idle=summary.baseline.non_idle_retained,
    )

    assert label == "2/3 (+1 non-idle)"
    assert summary.baseline.quota_counted_valid == 2
    assert summary.baseline.extra_valid == 0
    assert summary.baseline.non_idle_retained == 1
    assert summary.baseline.total_valid_retained == 3


def test_whatsapp_interactive_two_countable_plus_extra_and_low() -> None:
    runs = [
        _baseline_run("b1", ended_at="2026-01-01T08:00:00+00:00", countable=True),
        _baseline_run("b2", ended_at="2026-01-01T09:00:00+00:00", countable=True),
        _baseline_run("b3", ended_at="2026-01-01T10:00:00+00:00", countable=True),
        _interactive_run("i1", ended_at="2026-01-01T11:00:00+00:00", countable=True),
        _interactive_run("i2", ended_at="2026-01-01T12:00:00+00:00", countable=True),
        _interactive_run("i3", ended_at="2026-01-01T13:00:00+00:00", extra_run=True),
        _interactive_run("i4", ended_at="2026-01-01T14:00:00+00:00", low_signal=True),
    ]

    scoped = tracker_scope.build_scoped_dataset_counts(
        "com.whatsapp",
        runs,
        cfg=_Cfg(),
        resolve_tracker_run_identity_fn=_identity_resolver,
        active_identity_fn=lambda _pkg: ("100", "sha-active"),
    )
    summary = summarize_evidence_qualification(scoped, baseline_required=3, interactive_required=4)
    label = format_quota_progress_label(
        countable=scoped["interactive_countable"],
        required=4,
        extra=scoped["interactive_extra"],
        low_signal=scoped["interactive_low_signal_supplemental"],
    )

    assert label == "2/4 (+1 extra, +1 low)"
    assert summary.interactive.quota_satisfied is False
    assert summary.interactive.total_valid_retained == 4
    assert summary.interactive.quota_counted_valid == 2


def test_queue_table_app_label_shortens_common_cohort_names() -> None:
    assert app_queue_state.queue_table_app_label("Facebook Messenger") == "Facebook Msg"
    assert app_queue_state.queue_table_app_label("X (Twitter)") == "X"
    assert app_queue_state.queue_table_app_label("The Guardian") == "Guardian"
    assert app_queue_state.queue_table_app_label("BBC News") == "BBC News"
    assert app_queue_state.queue_table_app_label("Facebook") == "Facebook"


def test_bucket_evidence_label_rolls_retained_runs_into_minimum_fraction() -> None:
    from scytaledroid.DynamicAnalysis.run_qualification import bucket_evidence_label

    assert bucket_evidence_label(countable=3, extra=1, required=3) == "4/3"
    assert bucket_evidence_label(countable=2, extra=1, low_signal=1, required=4) == "4/4"
    assert bucket_evidence_label(countable=2, low_signal=1, required=3) == "3/3"


def test_format_bucket_queue_label_uses_total_retained_and_need_suffix() -> None:
    from scytaledroid.DynamicAnalysis.run_qualification import format_bucket_queue_label

    assert format_bucket_queue_label(countable=3, extra=1, required=3) == "4/3"
    assert format_bucket_queue_label(countable=0, required=2, need=2) == "0/2 need 2"
    assert format_bucket_queue_label(countable=2, low_signal=1, required=3, need=1) == "3/3 need 1"


def test_bucket_detail_column_label_shows_quota_gap_and_supplemental() -> None:
    from scytaledroid.DynamicAnalysis.run_qualification import bucket_detail_column_label

    assert bucket_detail_column_label(countable=3, extra=1, required=3) == "+1 extra"
    assert bucket_detail_column_label(countable=2, low_signal=1, required=3) == "q2/3 · +1 low"
    assert bucket_detail_column_label(countable=3, required=3) == "—"
    assert bucket_detail_column_label(countable=0, required=3) == "q0/3"
    assert (
        bucket_detail_column_label(countable=2, extra=1, low_signal=1, required=4)
        == "q2/4 · +1 extra, +1 low"
    )
    assert bucket_detail_column_label(countable=0, non_idle=3, required=3) == "q0/3 · +3 non-idle"


def test_queue_quota_gap_label_formats_baseline_and_interactive_shortfalls() -> None:
    class _Row:
        need_baseline = 3
        need_interactive = 2

    assert app_queue_state.queue_quota_gap_label(_Row()) == "3B 2I"
    assert (
        app_queue_state.queue_quota_gap_label(
            type("_R", (), {"need_baseline": 0, "need_interactive": 2})()
        )
        == "2I"
    )
    assert (
        app_queue_state.queue_quota_gap_label(
            type("_R", (), {"need_baseline": 0, "need_interactive": 0})()
        )
        == "—"
    )


def test_queue_labels_use_evidence_and_detail_columns() -> None:
    class _Row:
        baseline_countable = 3
        baseline_extra = 1
        baseline_not_idle_supplemental = 0
        baseline_low_signal_supplemental = 0
        interactive_countable = 2
        interactive_extra = 1
        interactive_low_signal_supplemental = 1

    row = _Row()
    assert app_queue_state.queue_baseline_runs_label(row, baseline_required=3) == "4/3"
    assert app_queue_state.queue_baseline_quota_label(row, baseline_required=3) == "3/3"
    assert app_queue_state.queue_baseline_supplemental_label(row, baseline_required=3) == "+1 extra"
    assert app_queue_state.queue_supplemental_column_label() == "—"
    assert app_queue_state.queue_supplemental_column_label(extra=0, low_signal=0) == "—"
    assert app_queue_state.queue_interactive_runs_label(row, interactive_required=4) == "4/4"
    assert app_queue_state.queue_interactive_quota_label(row, interactive_required=4) == "2/4"
    assert (
        app_queue_state.queue_interactive_supplemental_label(row, interactive_required=4)
        == "q2/4 · +1 extra, +1 low"
    )

    non_idle_row = type(
        "_R",
        (),
        {
            "baseline_countable": 0,
            "baseline_extra": 0,
            "baseline_not_idle_supplemental": 3,
            "baseline_low_signal_supplemental": 0,
        },
    )()
    assert (
        app_queue_state.queue_baseline_progress_label(non_idle_row, baseline_required=3)
        == "0/3 (+3 non-idle)"
    )


@pytest.mark.parametrize(
    ("package_name",),
    [
        ("com.whatsapp",),
        ("org.thoughtcrime.securesms",),
        ("org.telegram.messenger",),
    ],
)
def test_messaging_interaction_low_traffic_stays_valid_not_auto_low_signal(
    tmp_path: Path, package_name: str
) -> None:
    run_dir = tmp_path / "run"
    _write_json(
        run_dir / "analysis" / "pcap_features.json",
        {
            "metrics": {
                "capture_duration_s": 420.0,
                "data_size_bytes": 120_000,
                "packet_count": 420,
            },
            "proxies": {
                "unique_domains_topn": 1,
                "unique_ja4_count": 1,
            },
            "quality": {
                "report_status": "ok",
                "pcap_valid": True,
            },
        },
    )

    decision = compute_low_signal_for_run(
        run_dir,
        package_name=package_name,
        run_profile="interaction_manual",
    )

    assert decision is not None
    assert decision["low_signal"] is False
    assert decision["low_signal_reasons"] == []


def test_missing_pcap_remains_invalid_not_low_signal(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-1",
        created_at="2026-01-01T10:00:00+00:00",
        operator={"run_profile": "interaction_manual"},
        target={"package_name": "com.whatsapp"},
    )
    validity = evaluate_dataset_validity(run_dir, manifest, {}, DatasetTrackerConfig())

    assert validity["valid_dataset_run"] is False
    assert validity.get("invalid_reason_code") in {"PCAP_MISSING", "PCAP_PARSE_ERROR"}
    decision = compute_low_signal_for_run(
        run_dir,
        package_name="com.whatsapp",
        run_profile="interaction_manual",
    )
    assert decision is None


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_group_queue_sections_includes_scripted_interactive_apps() -> None:
    class _Row:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)

    ready_scripted = _Row(
        live_build_drift=False,
        need_baseline=0,
        need_interactive=2,
        next_label="scripted interaction",
    )
    ready_manual = _Row(
        live_build_drift=False,
        need_baseline=0,
        need_interactive=1,
        next_label="manual interaction",
    )
    blocked = _Row(
        live_build_drift=False,
        need_baseline=0,
        need_interactive=1,
        next_label="review QA",
    )

    sections = dict(app_queue_state.group_queue_sections([ready_scripted, ready_manual, blocked]))

    assert "Ready for interactive capture" in sections
    assert ready_scripted in sections["Ready for interactive capture"]
    assert ready_manual in sections["Ready for interactive capture"]
    assert blocked in sections.get("Other / blocked", [])


def test_group_queue_sections_includes_ml_training_pool_when_quota_complete() -> None:
    class _Row:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)

    ml_ready = _Row(
        live_build_drift=False,
        need_baseline=0,
        need_interactive=0,
        next_label="supplemental baseline",
        baseline_extra=2,
        baseline_low_signal_supplemental=0,
    )
    complete = _Row(
        live_build_drift=False,
        need_baseline=0,
        need_interactive=0,
        next_label="—",
    )

    sections = dict(app_queue_state.group_queue_sections([ml_ready, complete]))

    assert ml_ready in sections.get("ML training pool (optional)", [])
    assert complete in sections.get("Complete / over-quota", [])
