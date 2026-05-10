"""queue_row_apply_outcome mirrors Erebus apply for default ``aosp`` map."""

from __future__ import annotations

from scytaledroid.Database.db_func.permissions.queue_apply_compat_check import (
    queue_row_apply_outcome,
)


def test_aosp_maps_to_apply_bucket() -> None:
    b, d = queue_row_apply_outcome(
        {
            "permission_string": "android.permission.X",
            "queue_action": "aosp",
            "proposed_classification": "",
            "proposed_bucket": "",
        }
    )
    assert b == "apply"
    assert d is None


def test_aosp_promote_is_unknown_action() -> None:
    b, d = queue_row_apply_outcome(
        {
            "permission_string": "android.permission.X",
            "queue_action": "aosp_promote",
            "proposed_classification": "",
        }
    )
    assert b == "error"
    assert d and str(d).startswith("unknown_action")


def test_missing_permission_string_errors() -> None:
    b, d = queue_row_apply_outcome({"queue_action": "aosp", "permission_string": "  "})
    assert b == "error"
    assert d == "missing_permission_string"
