"""Erebus-shaped queue row outcome check (read-only; no DB).

Used by ``scripts/db/audit_permission_intel_queue_compatibility.py`` and tests.
Mirrors Erebus queue vocabulary, action normalization, and the rule that queue
promotion cannot create accepted AOSP platform truth.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

CLASS_ACTION_MAP: dict[str, str] = {
    "aosp": "AOSP",
    "aosp_promote": "AOSP",
    "oem": "OEM",
    "google": "GOOGLE",
    "app_defined": "APP_DEFINED",
}
QUEUE_ACTIONS = frozenset((*CLASS_ACTION_MAP, "reject", "rejected", "defer"))
QUEUE_STATUSES = frozenset(
    ("queued", "pending", "applied", "error", "skipped", "rejected")
)
TRIAGE_STATUSES = frozenset(
    (
        "new",
        "in_review",
        "deferred",
        "aosp_missing",
        "malformed",
        "gms_known",
        "oem_candidate",
        "launcher_ecosystem",
        "app_defined",
        "brand_spoof",
        "malicious_dga",
        "resolved_aosp",
        "resolved_oem",
        "reviewed",
        "classified",
        "ignore",
    )
)
AOSP_PROMOTION_BLOCKED_MESSAGE = (
    "queue promotion cannot create accepted AOSP truth; use an accepted "
    "catalog-linked resolution event"
)


def queue_row_apply_outcome(row: Mapping[str, Any]) -> tuple[str, str | None]:
    """Return (bucket, detail) where bucket is apply|skipped|rejected|error."""
    permission = str(row.get("permission_string") or "").strip()
    action_raw = str(row.get("queue_action") or "")
    proposed_classification = str(row.get("proposed_classification") or "")
    triage_status = str(row.get("triage_status") or "").strip().lower()

    action_key = action_raw.strip().lower()
    if action_key not in QUEUE_ACTIONS:
        return "error", f"unsupported queue action: {action_key or 'blank'}"
    if "status" in row:
        status = str(row.get("status") or "").strip().lower()
        if status not in QUEUE_STATUSES:
            return "error", f"unsupported queue status: {status or 'blank'}"
    if triage_status not in TRIAGE_STATUSES:
        return "error", f"unsupported triage status: {triage_status or 'blank'}"

    normalized = action_key
    proposed = proposed_classification.strip().upper()
    if normalized in CLASS_ACTION_MAP:
        proposed = CLASS_ACTION_MAP[normalized]
        normalized = "apply"
    if not normalized and proposed:
        normalized = "apply"

    if not permission:
        return "error", "missing_permission_string"
    if normalized in {"defer", "skip"}:
        return "skipped", None
    if normalized in {"reject", "rejected"}:
        return "rejected", None
    if normalized in {"apply", "approve", "accept"}:
        if proposed == "AOSP":
            return "error", AOSP_PROMOTION_BLOCKED_MESSAGE
        return "apply", None
    return "error", f"unknown_action:{normalized or 'blank'}"


__all__ = [
    "AOSP_PROMOTION_BLOCKED_MESSAGE",
    "CLASS_ACTION_MAP",
    "QUEUE_ACTIONS",
    "QUEUE_STATUSES",
    "TRIAGE_STATUSES",
    "queue_row_apply_outcome",
]
