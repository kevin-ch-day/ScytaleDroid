from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.persistence import static_session_summary as sss


def test_maybe_refresh_static_analysis_session_summary_noop_blank_stamp(monkeypatch):
    called: list[object] = []

    def boom(*_a, **_k):
        called.append(True)
        raise RuntimeError("should not run")

    monkeypatch.setattr(sss, "refresh_static_analysis_session_summary", boom)
    sss.maybe_refresh_static_analysis_session_summary("  ", "x", reason="t")
    assert called == []


def test_maybe_refresh_static_analysis_session_summary_swallows_errors(monkeypatch):
    warnings: list[str] = []

    def boom(**_k):
        raise RuntimeError("db unavailable")

    monkeypatch.setattr(sss, "refresh_static_analysis_session_summary", boom)
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.static_session_summary.log.warning",
        lambda msg, **_kw: warnings.append(msg),
    )

    sss.maybe_refresh_static_analysis_session_summary("s1", "scope-a", reason="unit")
    assert len(warnings) == 1
    assert "session_refresh" in warnings[0] or "unit" in warnings[0]
