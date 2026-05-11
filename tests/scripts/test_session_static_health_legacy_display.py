"""Policy strings for legacy mirror lines in ``session_static_health.py``."""

from __future__ import annotations

from scripts.db import session_static_health as ssh


def test_legacy_findings_skip_when_runs_missing() -> None:
    line = ssh._legacy_findings_status_line(
        runs_present=False,
        findings_present=True,
        count_ok=True,
        count=0,
        err_detail=None,
    )
    assert "SKIP" in line
    assert "table absent" in line.lower()


def test_legacy_findings_skip_when_findings_missing() -> None:
    line = ssh._legacy_findings_status_line(
        runs_present=True,
        findings_present=False,
        count_ok=True,
        count=0,
        err_detail=None,
    )
    assert "SKIP" in line


def test_legacy_findings_info_when_zero_rows() -> None:
    line = ssh._legacy_findings_status_line(
        runs_present=True,
        findings_present=True,
        count_ok=True,
        count=0,
        err_detail=None,
    )
    assert "INFO" in line
    assert "0" in line


def test_legacy_findings_warn_on_query_error() -> None:
    line = ssh._legacy_findings_status_line(
        runs_present=True,
        findings_present=True,
        count_ok=False,
        count=None,
        err_detail="ERROR: 1146",
    )
    assert "WARN" in line

