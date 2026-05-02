"""Operator hints when MariaDB/MySQL analyst VIEWs are absent (schema drift)."""

from __future__ import annotations


def sql_object_missing_error(exc: BaseException) -> bool:
    """True for missing table/view messages (errno 1146 or common driver text)."""
    args = getattr(exc, "args", None)
    if isinstance(args, tuple) and args:
        code = args[0]
        if isinstance(code, int) and code == 1146:
            return True
    text = str(exc).lower()
    if "1146" in text:
        return True
    return any(
        s in text
        for s in (
            "doesn't exist",
            "does not exist",
            "unknown table",
            "no such table",
        )
    )


def remediation_text(*, recreate_cmd: bool = True) -> str:
    """Human-readable remediation (printed by audit scripts)."""
    lines = [
        "Canonical analyst VIEWs (e.g. v_static_masvs_matrix_v1) are not deployed on this catalog.",
        "Data in static_analysis_* tables can still be valid; create/repair VIEWs from this repo:",
    ]
    if recreate_cmd:
        lines.append(
            "  PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py recreate --confirm"
        )
    lines.append(
        "Or apply ordered_schema_statements VIEW DDL (database_governance_runbook.md → VIEW repair)."
    )
    return "\n".join(lines)


__all__ = ["remediation_text", "sql_object_missing_error"]
