from __future__ import annotations

import json
from pathlib import Path

from scripts.db import report_dynamic_pcap_behavior_ml as pcap_ml_report
from scytaledroid.DynamicAnalysis.ml.selectors.models import QueryParams
from scytaledroid.DynamicAnalysis.ml.selectors.query_selector import QuerySelector
from scytaledroid.DynamicAnalysis.run_qualification import (
    analysis_included_rows,
    row_analysis_included,
    run_included_in_default_analysis,
    summarize_tracker_runs_qualification,
)


def _baseline_row(
    run_id: str,
    *,
    countable: bool = True,
    extra_run: bool = False,
    low_signal: bool = False,
    paper_eligible: bool = True,
    domain_count: int = 10,
) -> dict:
    row = {
        "dynamic_run_id": run_id,
        "run_profile": "baseline_idle",
        "valid_dataset_run": 1,
        "paper_eligible": paper_eligible,
        "stats_eligible": 1,
        "interaction_mode": "baseline",
        "domain_count": domain_count,
        "unique_ja4_count": 2,
        "unique_ja3_count": 2,
        "unique_ja3s_count": 1,
        "top1_ja4_share": 0.8,
        "service_families_observed": "news",
        "top_service_family": "news",
        "unique_service_families": 1,
        "pcap_bytes": 1000,
        "adtech_share": 0.0,
        "unresolved_share": 0.0,
    }
    if low_signal:
        row["countable"] = 0
        row["low_signal"] = 1
        row["extra_run"] = 1
        row["quota_state"] = "SUPPLEMENTAL_VALID"
    elif extra_run:
        row["countable"] = 0
        row["extra_run"] = 1
        row["quota_state"] = "SUPPLEMENTAL_VALID"
    elif countable:
        row["countable"] = 1
        row["quota_state"] = "QUOTA_VALID"
    else:
        row["countable"] = 0
        row["quota_state"] = "SUPPLEMENTAL_VALID"
    return row


def _interactive_row(
    run_id: str,
    *,
    countable: bool = True,
    extra_run: bool = False,
    low_signal: bool = False,
    paper_eligible: bool = True,
    domain_count: int = 10,
) -> dict:
    row = _baseline_row(
        run_id,
        countable=countable,
        extra_run=extra_run,
        low_signal=low_signal,
        paper_eligible=paper_eligible,
        domain_count=domain_count,
    )
    row["run_profile"] = "interaction_manual"
    row["interaction_mode"] = "manual"
    return row


def test_cnn_style_downstream_analysis_includes_extra_valid_runs() -> None:
    runs = [
        _baseline_row("b1", countable=True, domain_count=10),
        _baseline_row("b2", countable=True, domain_count=12),
        _baseline_row("b3", countable=True, domain_count=14),
        _baseline_row("b4", extra_run=True, domain_count=100),
    ]
    for row in runs:
        row["package_name"] = "com.cnn.mobile.android.phone"
        row["app_label"] = "CNN"

    summary = summarize_tracker_runs_qualification(
        runs,
        baseline_required=3,
        interactive_required=4,
    )
    included = analysis_included_rows(runs)

    assert summary.baseline.quota_satisfied is True
    assert summary.baseline.quota_counted_valid == 3
    assert summary.baseline.extra_valid == 1
    assert summary.baseline.total_valid_retained == 4
    assert len(included) == 4

    by_package = {"com.cnn.mobile.android.phone": runs}
    app_rollups, _, paper_rows, _, _ = pcap_ml_report._build_app_rollups(by_package)

    assert app_rollups[0]["countable_runs"] == 3
    assert app_rollups[0]["analysis_included_runs"] == 4
    assert paper_rows[0]["countable_runs"] == 3
    assert paper_rows[0]["analysis_included_runs"] == 4
    assert paper_rows[0]["runtime_domains_median"] == 13.0


def test_x_style_downstream_retains_low_signal_without_quota_complete() -> None:
    runs = [
        _baseline_row("b1", countable=True),
        _baseline_row("b2", countable=True),
        _baseline_row("b3", low_signal=True),
    ]
    for row in runs:
        row["package_name"] = "com.twitter.android"
        row["app_label"] = "X (Twitter)"

    summary = summarize_tracker_runs_qualification(
        runs,
        baseline_required=3,
        interactive_required=4,
    )
    included = analysis_included_rows(runs)

    assert summary.baseline.quota_satisfied is False
    assert summary.baseline.quota_counted_valid == 2
    assert summary.baseline.low_signal_retained == 1
    assert summary.baseline.total_valid_retained == 3
    assert len(included) == 3
    assert all(run_included_in_default_analysis(valid_dataset_run=True) for _ in included)


def test_whatsapp_style_interactive_includes_extra_and_preserves_low_signal() -> None:
    runs = [
        _interactive_row("i1", countable=True),
        _interactive_row("i2", countable=True),
        _interactive_row("i3", extra_run=True),
        _interactive_row("i4", low_signal=True),
    ]
    for row in runs:
        row["package_name"] = "com.whatsapp"
        row["app_label"] = "WhatsApp"

    summary = summarize_tracker_runs_qualification(
        runs,
        baseline_required=3,
        interactive_required=4,
    )
    included = analysis_included_rows(runs)
    roles = {
        row["dynamic_run_id"]: (
            "low_signal" if row.get("low_signal") else ("extra" if row.get("extra_run") else "quota")
        )
        for row in runs
    }

    assert summary.interactive.quota_satisfied is False
    assert summary.interactive.quota_counted_valid == 2
    assert summary.interactive.extra_valid == 1
    assert summary.interactive.low_signal_retained == 1
    assert summary.interactive.total_valid_retained == 4
    assert len(included) == 4
    assert roles["i3"] == "extra"
    assert roles["i4"] == "low_signal"
    assert row_analysis_included(runs[2]) is True
    assert row_analysis_included(runs[3]) is True


def test_query_selector_includes_extra_valid_excludes_paper_ineligible(tmp_path: Path) -> None:
    def _write_run(run_id: str, *, valid: bool, paper_eligible: bool, extra: bool) -> None:
        run_dir = tmp_path / run_id
        run_dir.mkdir()
        inputs_dir = run_dir / "inputs"
        inputs_dir.mkdir()
        dataset = {
            "valid_dataset_run": valid,
            "paper_eligible": paper_eligible,
            "tier": "dataset",
        }
        if extra:
            dataset["countable"] = False
            dataset["extra_run"] = True
        else:
            dataset["countable"] = True
        manifest = {
            "dynamic_run_id": run_id,
            "started_at": "2026-01-01T10:00:00+00:00",
            "ended_at": "2026-01-01T10:05:00+00:00",
            "dataset": dataset,
            "operator": {"run_profile": "baseline_idle", "tier": "dataset"},
            "target": {"package_name": "com.example.app"},
        }
        (run_dir / "run_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        (inputs_dir / "static_dynamic_plan.json").write_text(
            json.dumps({"run_identity": {"base_apk_sha256": "sha-example"}}),
            encoding="utf-8",
        )

    _write_run("quota-run", valid=True, paper_eligible=True, extra=False)
    _write_run("extra-run", valid=True, paper_eligible=True, extra=True)
    _write_run("ineligible-run", valid=True, paper_eligible=False, extra=False)

    selector = QuerySelector(
        evidence_root=tmp_path,
        params=QueryParams(require_valid_dataset_run=True),
        allow_db_index=False,
    )
    result = selector.select()

    included_ids = {row.run_id for row in result.included}
    assert included_ids == {"quota-run", "extra-run"}
    assert result.excluded["ineligible-run"]["reason"] == "paper_ineligible"
