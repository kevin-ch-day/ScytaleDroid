"""Regression: direct persistence-audit counts must scope via ``static_analysis_runs``, not bogus child columns."""

from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.flows import run_persistence_queries as rp


def _norm_sql(sql: str) -> str:
    return " ".join(str(sql).split()).lower()


def test_canonical_direct_counts_joins_static_analysis_runs_for_child_tables(monkeypatch) -> None:
    captured: list[str] = []

    def capture_scalar(sql: str, params: tuple[object, ...]) -> int:
        captured.append(sql)
        return 0

    def capture_row_count(sql: str, params: tuple[object, ...]) -> int:
        captured.append(sql)
        return 0

    monkeypatch.setattr(rp, "_static_run_status_counts", lambda _session: {})
    monkeypatch.setattr(rp, "_scalar_count", capture_scalar)
    monkeypatch.setattr(rp, "_row_count", capture_row_count)

    rp._canonical_direct_counts("example-session-label")

    blob = _norm_sql("\n".join(captured))

    assert "from static_analysis_findings where session_label" not in blob
    assert "from static_permission_matrix where session_stamp" not in blob
    assert "from static_permission_risk_vnext where session_stamp" not in blob

    assert "from static_analysis_findings f inner join static_analysis_runs sar" in blob
    assert "from static_permission_matrix spm inner join static_analysis_runs sar" in blob
    assert "from static_permission_risk_vnext pr inner join static_analysis_runs sar" in blob
    assert blob.count("inner join static_analysis_runs sar on sar.id =") >= 3
