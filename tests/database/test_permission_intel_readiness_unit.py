"""Unit tests for Permission Intel readiness (no live Intel DB required)."""

from __future__ import annotations

from scytaledroid.Database.db_utils import permission_intel_readiness as pir
from scytaledroid.Database.db_utils.permission_intel_readiness import (
    assess_permission_intel_readiness,
    render_permission_intel_readiness,
)


def test_assess_when_not_configured(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.permission_intel_readiness.intel_db.is_permission_intel_configured",
        lambda: False,
    )
    st = assess_permission_intel_readiness()
    assert st.configured is False
    assert st.resolved_database is None
    assert st.catalog_name_matches_expected is False


def test_assess_resolved_catalog_name(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.permission_intel_readiness.intel_db.is_permission_intel_configured",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.permission_intel_readiness.intel_db.describe_target",
        lambda: {"database": "android_permission_intel", "host": "h", "port": 3306, "user": "u", "source": "t"},
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.permission_intel_readiness.intel_db.intel_table_exists",
        lambda _t: False,
    )
    st = assess_permission_intel_readiness()
    assert st.resolved_database == "android_permission_intel"
    assert st.catalog_name_matches_expected is True


def test_render_paper_grade_errors_on_wrong_catalog(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.permission_intel_readiness.assess_permission_intel_readiness",
        lambda: pir.PermissionIntelReadiness(
            configured=True,
            resolved_database="wrong_db",
            catalog_name_matches_expected=False,
            connect_ok=True,
            missing_tables=(),
            governance_ok=True,
            governance_detail="ok",
            dictionary_select_ok=True,
        ),
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.permission_intel_readiness.intel_db.describe_target",
        lambda: {"database": "wrong_db", "host": "h", "port": 3306, "user": "u", "source": "t"},
    )
    label = render_permission_intel_readiness(paper_grade_requested=True)
    assert label == "ERROR"
    out = capsys.readouterr().out
    assert "android_permission_intel" in out


def test_render_non_paper_experimental_on_wrong_catalog(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.permission_intel_readiness.assess_permission_intel_readiness",
        lambda: pir.PermissionIntelReadiness(
            configured=True,
            resolved_database="other",
            catalog_name_matches_expected=False,
            connect_ok=True,
            missing_tables=(),
            governance_ok=True,
            governance_detail="ok",
            dictionary_select_ok=True,
        ),
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.permission_intel_readiness.intel_db.describe_target",
        lambda: {"database": "other", "host": "h", "port": 3306, "user": "u", "source": "t"},
    )
    label = render_permission_intel_readiness(paper_grade_requested=False)
    assert label == "EXPERIMENTAL"
    out = capsys.readouterr().out.lower()
    assert "android_permission_intel" in out


def test_render_experimental_when_not_configured(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.permission_intel_readiness.intel_db.is_permission_intel_configured",
        lambda: False,
    )
    label = render_permission_intel_readiness(paper_grade_requested=False)
    out = capsys.readouterr().out
    assert "EXPERIMENTAL" in label or "EXPERIMENTAL" in out
    assert label == "EXPERIMENTAL"


def test_render_error_when_paper_grade_and_not_configured(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.permission_intel_readiness.intel_db.is_permission_intel_configured",
        lambda: False,
    )
    label = render_permission_intel_readiness(paper_grade_requested=True)
    assert label == "ERROR"
    out = capsys.readouterr().out
    assert "ERROR" in out
