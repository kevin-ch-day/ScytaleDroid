"""Reconcile overlay onto persistence audit bridge counts (legacy mirror per table)."""

from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.flows.run_persistence_audit import _empty_audit_summary
from scytaledroid.StaticAnalysis.cli.flows.run_persistence_queries import _apply_reconcile_summary


def test_apply_reconcile_summary_maps_distinct_legacy_mirror_package_counts(monkeypatch) -> None:
    """Bridge JSON must not copy secondary_compat_mirror_packages into all three keys."""
    fake_reconcile = SimpleNamespace(
        completed_runs=2,
        started_runs=0,
        failed_runs=0,
        canonical_findings=99,
        canonical_permission_matrix=1,
        canonical_permission_risk=2,
        findings_summary_packages=3,
        string_summary_packages=4,
        handoff_paths=5,
        legacy_runs_packages=6,
        legacy_risk_packages=7,
        secondary_compat_mirror_packages=100,
        legacy_metrics_mirror_packages=3,
        legacy_buckets_mirror_packages=2,
        legacy_contributors_mirror_packages=7,
        session_run_links=9,
        session_rollups=10,
        missing_findings_summary=set(),
        missing_string_summary=set(),
        missing_legacy_runs=set(),
        missing_risk_scores=set(),
        missing_secondary_compat_mirror_count=0,
        bridge_only_runs=set(),
        bridge_only_risk_scores=set(),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.flows.run_persistence_queries.reconcile_static_session",
        lambda _session_label: fake_reconcile,
    )

    outcome = SimpleNamespace(
        canonical_failed=False,
        persistence_failed=False,
        compat_export_failed=False,
        compat_export_stage=None,
    )
    summary = _empty_audit_summary(expected_packages=[], outcome=outcome, report_paths=[])
    _apply_reconcile_summary(summary, "sess-x")

    bridge = summary["bridge"]
    assert bridge["metrics_packages"] == 3
    assert bridge["buckets_packages"] == 2
    assert bridge["contributors_packages"] == 7
    assert bridge["secondary_compat_mirror_packages"] == 100
