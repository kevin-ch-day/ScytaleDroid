from __future__ import annotations

from collections import Counter

from scytaledroid.StaticAnalysis.cli.persistence.run_summary import (
    _FindingPreparationAccumulator,
    _build_findings_persistence_context,
)


def test_persisted_totals_match_finding_rows_after_cap() -> None:
    acc = _FindingPreparationAccumulator()
    acc.severity_counter.update({"High": 40})
    acc.total_findings = 40
    acc.capped_by_detector.update({"det_x": 25})
    acc.finding_rows = [{"severity": "High", "masvs": "A"} for _ in range(15)]
    ctx = _build_findings_persistence_context(accumulator=acc, baseline_counts=Counter())

    assert ctx.persisted_totals.get("High", 0) == 15
    assert sum(ctx.persisted_totals.values()) == 15


def test_persisted_totals_zero_when_all_capped() -> None:
    acc = _FindingPreparationAccumulator()
    acc.severity_counter.update({"High": 100})
    acc.total_findings = 100
    acc.capped_by_detector.update({"ipc": 80})
    acc.finding_rows = []
    ctx = _build_findings_persistence_context(
        accumulator=acc, baseline_counts=Counter({"High": 2, "Medium": 1})
    )

    assert ctx.persisted_totals.get("High", 0) == 0
    assert ctx.persisted_totals.get("Medium", 0) == 0


def test_persisted_totals_fallback_baseline_when_no_runtime_findings() -> None:
    acc = _FindingPreparationAccumulator()
    acc.total_findings = 0
    base = Counter({"High": 1, "Medium": 0, "Low": 0, "Info": 3})
    ctx = _build_findings_persistence_context(accumulator=acc, baseline_counts=base)

    assert ctx.persisted_totals.get("High", 0) == 1
    assert ctx.persisted_totals.get("Info", 0) == 3
