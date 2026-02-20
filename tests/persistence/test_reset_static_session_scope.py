from __future__ import annotations

from scytaledroid.Database.db_utils.reset_static import reset_static_analysis_data


def test_reset_static_session_scoped_requires_session_label():
    outcome = reset_static_analysis_data(include_harvest=False, truncate_all=False, session_label=None)
    assert outcome.failed
    assert "session_label required" in outcome.failed[0][1]
