from __future__ import annotations

from scytaledroid.Database.db_utils.menus.static_session_diagnostics_menu import (
    run_static_session_canonical_audit,
)


def test_run_static_session_canonical_audit_rejects_empty_stamp() -> None:
    assert run_static_session_canonical_audit("  ") == 1
