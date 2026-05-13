"""Permission Intel + paper-grade governance gate (single wiring surface).

Static preflight, DB health menus, run summaries, and scripts should prefer this
module (or ``execution.pipeline`` re-exports) so snapshot/count logic stays in one
place.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from scytaledroid.Database.db_core import permission_intel as intel_db

IntelPreflightLabel = Literal["ok", "missing", "governance_missing", "query_failed"]


@dataclass(frozen=True)
class IntelPreflightEvaluation:
    """Intel + governance snapshot state for operator preflight (no writes)."""

    label: IntelPreflightLabel
    governance_detail: str | None = None
    governance_query_exc: BaseException | None = None


def governance_ready() -> tuple[bool, str | None]:
    """Return ``(ok, detail)`` when Permission Intel governance snapshots are populated."""

    try:
        snapshot_count = intel_db.governance_snapshot_count()
        row_count = intel_db.governance_row_count()
    except Exception as exc:
        return False, f"governance_query_failed:{exc}"
    if snapshot_count <= 0 or row_count <= 0:
        return False, "governance_missing"
    return True, None


def evaluate_intel_for_preflight() -> IntelPreflightEvaluation:
    """Resolve Intel DSN + governance for static run preflight (matches legacy preflight branches)."""

    if not intel_db.is_permission_intel_configured():
        return IntelPreflightEvaluation("missing")

    try:
        gov_ok, gov_detail = governance_ready()
    except Exception as exc:
        return IntelPreflightEvaluation("query_failed", governance_query_exc=exc)

    if gov_ok:
        return IntelPreflightEvaluation("ok")

    if gov_detail == "governance_missing":
        return IntelPreflightEvaluation("governance_missing", governance_detail=gov_detail)

    return IntelPreflightEvaluation("query_failed", governance_detail=gov_detail)


__all__ = [
    "IntelPreflightEvaluation",
    "IntelPreflightLabel",
    "evaluate_intel_for_preflight",
    "governance_ready",
]
