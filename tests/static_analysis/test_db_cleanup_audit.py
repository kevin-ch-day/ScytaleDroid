from __future__ import annotations

from scripts.static_analysis.audit_db_cleanup_candidates import is_dev_or_legacy_session


def test_is_dev_or_legacy_session_matches_known_legacy_patterns():
    assert is_dev_or_legacy_session("20260220-gatefix2")
    assert is_dev_or_legacy_session("static-batch-v3-20260228T041349Z-com.discord")
    assert is_dev_or_legacy_session("20260328-smoke-fb-base")
    assert is_dev_or_legacy_session("static-postfix-20260228T031618Z-com.adobe.reader")


def test_is_dev_or_legacy_session_ignores_normal_session_labels():
    assert not is_dev_or_legacy_session("20260328-rda-full-headless-fixed")
    assert not is_dev_or_legacy_session("20260328-all-full")
    assert not is_dev_or_legacy_session("20260221-rda-full")
