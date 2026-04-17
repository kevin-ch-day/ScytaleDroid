from __future__ import annotations

import pytest

from scytaledroid.Reporting.services import publication_status


pytestmark = [pytest.mark.contract, pytest.mark.report_contract]


def test_fetch_latest_analysis_snapshot_marks_ready(monkeypatch) -> None:
    monkeypatch.setattr(
        publication_status.core_q,
        "run_sql",
        lambda *_a, **_k: {
            "cohort_id": "freeze-20260416",
            "name": "Frozen archive",
            "selector_type": "freeze",
            "receipt_id": 17,
            "receipt_status": "OK",
            "finished_at_utc": "2026-04-16 19:00:00",
            "run_count": 36,
            "baseline_count": 12,
            "interactive_count": 24,
            "app_count": 12,
            "static_count": 12,
            "ml_metric_count": 48,
            "regime_count": 12,
        },
    )

    snapshot = publication_status.fetch_latest_analysis_snapshot()

    assert snapshot is not None
    assert snapshot["ready"] is True
    assert snapshot["summary_label"] == "36 runs / 12 apps"
    assert snapshot["cohort_id"] == "freeze-20260416"


def test_fetch_latest_analysis_snapshot_returns_none_without_rows(monkeypatch) -> None:
    monkeypatch.setattr(publication_status.core_q, "run_sql", lambda *_a, **_k: None)

    assert publication_status.fetch_latest_analysis_snapshot() is None
