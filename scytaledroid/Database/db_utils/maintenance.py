"""Maintenance helpers for provisioning database support tables."""

from __future__ import annotations

from typing import Dict


def provision_permission_analysis_tables(
    *, seed_defaults: bool = True
) -> Dict[str, Dict[str, object]]:
    """Ensure permission-analysis support tables exist and optionally seed them.

    The helper mirrors the bootstrap workflow documented in
    ``docs/database/permission_analysis_schema.md`` and reuses the
    :mod:`scytaledroid.Database.db_func.permissions.permission_support`
    adapter so the CLI and tests share the same provisioning logic.
    """

    try:
        from scytaledroid.Database.db_func.permissions import permission_support as support
    except Exception:
        return {"created": {}, "seeded": {}}

    created = support.ensure_all()
    if not seed_defaults:
        return {"created": created, "seeded": {}}

    try:
        seeded = support.seed_defaults()
    except Exception:
        seeded = {}
    return {"created": created, "seeded": seeded}


__all__ = ["provision_permission_analysis_tables"]

