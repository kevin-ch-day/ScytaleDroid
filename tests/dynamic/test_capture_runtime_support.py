from __future__ import annotations

from scytaledroid.DynamicAnalysis.menus import capture_runtime_support


def test_print_tier1_qa_result_uses_advisory_for_non_blocking_quality_gate_issues(
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(
        capture_runtime_support,
        "run_sql",
        lambda *_args, **_kwargs: {
            "dynamic_run_id": "run-1",
            "status": "success",
            "tier": "dataset",
            "sampling_rate_s": 2,
            "expected_samples": 216,
            "captured_samples": 216,
            "sample_max_gap_s": 4.27,
            "telemetry_partial": 0,
        },
    )

    capture_runtime_support.print_tier1_qa_result("run-1")

    out = capsys.readouterr().out
    assert "Tier-1 QA: advisory (max_gap_exceeded)" in out
    assert "Tier-1 QA: FAIL" not in out


def test_print_tier1_qa_result_keeps_fail_for_blocking_status_issues(
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(
        capture_runtime_support,
        "run_sql",
        lambda *_args, **_kwargs: {
            "dynamic_run_id": "run-2",
            "status": "failed",
            "tier": "dataset",
            "sampling_rate_s": 2,
            "expected_samples": 216,
            "captured_samples": 216,
            "sample_max_gap_s": 1.0,
            "telemetry_partial": 0,
        },
    )

    capture_runtime_support.print_tier1_qa_result("run-2")

    out = capsys.readouterr().out
    assert "Tier-1 QA: FAIL (status_not_success)" in out
