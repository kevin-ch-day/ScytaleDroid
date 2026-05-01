from __future__ import annotations

from scytaledroid.Database.db_utils import permission_intel_freeze


def test_archive_name_stays_within_mysql_limit():
    name = permission_intel_freeze._archive_name(
        "permission_governance_snapshot_rows",
        "20260429",
    )
    assert len(name) <= 64
    assert name.endswith("__legacy_20260429")


def test_freeze_operational_managed_tables_refuses_when_cutover_inactive(monkeypatch):
    monkeypatch.setattr(
        permission_intel_freeze.intel_db,
        "describe_target",
        lambda: {"compatibility_mode": True},
    )

    try:
        permission_intel_freeze.freeze_operational_managed_tables(stamp="20260429")
    except RuntimeError as exc:
        assert "cutover is not active" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected RuntimeError")


def test_freeze_operational_managed_tables_refuses_when_target_incomplete(monkeypatch):
    monkeypatch.setattr(
        permission_intel_freeze.intel_db,
        "describe_target",
        lambda: {"compatibility_mode": False},
    )
    monkeypatch.setattr(
        permission_intel_freeze.intel_db,
        "MANAGED_TABLES",
        ("table_a", "table_b"),
    )
    monkeypatch.setattr(
        permission_intel_freeze.intel_db,
        "intel_table_exists",
        lambda table: table == "table_a",
    )

    try:
        permission_intel_freeze.freeze_operational_managed_tables(stamp="20260429")
    except RuntimeError as exc:
        assert "table_b" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected RuntimeError")


def test_drop_archived_operational_managed_tables_requires_stamp():
    try:
        permission_intel_freeze.drop_archived_operational_managed_tables(stamp="")
    except RuntimeError as exc:
        assert "Archive stamp is required" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected RuntimeError")


def test_governance_legacy_detach_outcome_lines():
    outcome = permission_intel_freeze.GovernanceLegacyDetachOutcome(
        dropped_constraints=["permission_signal_observations.fk_sig_gov_version"],
        missing_constraints=["static_correlation_results.fk_corr_gov_version"],
    )
    lines = list(outcome.as_lines())
    assert "Dropped legacy governance FKs:" in lines[0]
    assert "Already absent:" in lines[1]
