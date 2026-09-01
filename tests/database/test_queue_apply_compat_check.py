"""queue_row_apply_outcome mirrors the hardened Erebus queue contract."""

from __future__ import annotations

import pytest
from scripts.db.audit_permission_intel_queue_compatibility import (
    _bind_semantic_digest,
    _write_private_report,
)
from scytaledroid.Database.db_func.permissions.queue_apply_compat_check import (
    queue_row_apply_outcome,
)


def test_aosp_is_blocked_from_creating_platform_truth() -> None:
    b, d = queue_row_apply_outcome(
        {
            "permission_string": "android.permission.X",
            "queue_action": "aosp",
            "proposed_classification": "",
            "proposed_bucket": "",
            "triage_status": "aosp_missing",
            "status": "queued",
        }
    )
    assert b == "error"
    assert d and "accepted AOSP truth" in d


def test_aosp_promote_alias_is_recognized_but_blocked() -> None:
    b, d = queue_row_apply_outcome(
        {
            "permission_string": "android.permission.X",
            "queue_action": "aosp_promote",
            "proposed_classification": "",
            "triage_status": "aosp_missing",
            "status": "queued",
        }
    )
    assert b == "error"
    assert d and "accepted AOSP truth" in d


def test_missing_permission_string_errors() -> None:
    b, d = queue_row_apply_outcome(
        {
            "queue_action": "defer",
            "permission_string": "  ",
            "triage_status": "aosp_missing",
            "status": "queued",
        }
    )
    assert b == "error"
    assert d == "missing_permission_string"


def test_invalid_queue_vocabulary_fails_closed() -> None:
    b, d = queue_row_apply_outcome(
        {
            "queue_action": "approve",
            "permission_string": "android.permission.X",
            "triage_status": "aosp_missing",
            "status": "queued",
        }
    )
    assert b == "error"
    assert d == "unsupported queue action: approve"


def test_compatibility_report_digest_is_deterministic() -> None:
    first = _bind_semantic_digest({"report_format": "test", "rows": 3})
    second = _bind_semantic_digest({"rows": 3, "report_format": "test"})
    assert first["semantic_digest"] == second["semantic_digest"]


def test_private_report_refuses_repository_path(tmp_path, monkeypatch) -> None:
    import scripts.db.audit_permission_intel_queue_compatibility as audit

    monkeypatch.setattr(audit, "_REPO_ROOT", tmp_path)
    target = tmp_path / "report.json"
    with pytest.raises(ValueError, match="outside the repository"):
        _write_private_report(target, {"status": "test"})
