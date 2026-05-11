"""Session digest required-table policy (canonical vs legacy findings)."""

from __future__ import annotations

from scytaledroid.Database.db_utils.menus.query_runner import (
    SESSION_DIGEST_REQUIRED_GROUP_TABLES,
    SESSION_DIGEST_REQUIRED_SINGLE_TABLES,
)


def test_session_digest_single_requires_canonical_findings_not_legacy() -> None:
    assert "static_analysis_findings" in SESSION_DIGEST_REQUIRED_SINGLE_TABLES
    assert "findings" not in SESSION_DIGEST_REQUIRED_SINGLE_TABLES


def test_session_digest_group_does_not_require_findings_table() -> None:
    assert "findings" not in SESSION_DIGEST_REQUIRED_GROUP_TABLES
    assert "static_analysis_findings" not in SESSION_DIGEST_REQUIRED_GROUP_TABLES
