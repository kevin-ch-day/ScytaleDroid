"""Unit tests for ``intel_gate`` (governance + preflight evaluation)."""

from __future__ import annotations

import pytest
from scytaledroid.StaticAnalysis.cli import intel_gate


def test_governance_ready_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(intel_gate.intel_db, "governance_snapshot_count", lambda: 2)
    monkeypatch.setattr(intel_gate.intel_db, "governance_row_count", lambda: 10)
    ok, detail = intel_gate.governance_ready()
    assert ok is True
    assert detail is None


def test_governance_ready_missing_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(intel_gate.intel_db, "governance_snapshot_count", lambda: 0)
    monkeypatch.setattr(intel_gate.intel_db, "governance_row_count", lambda: 0)
    ok, detail = intel_gate.governance_ready()
    assert ok is False
    assert detail == "governance_missing"


def test_evaluate_intel_for_preflight_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(intel_gate.intel_db, "is_permission_intel_configured", lambda: False)
    ev = intel_gate.evaluate_intel_for_preflight()
    assert ev.label == "missing"


def test_evaluate_intel_for_preflight_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(intel_gate.intel_db, "is_permission_intel_configured", lambda: True)
    monkeypatch.setattr(intel_gate.intel_db, "governance_snapshot_count", lambda: 1)
    monkeypatch.setattr(intel_gate.intel_db, "governance_row_count", lambda: 5)
    ev = intel_gate.evaluate_intel_for_preflight()
    assert ev.label == "ok"
