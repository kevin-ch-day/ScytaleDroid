"""Erebus-shaped queue row outcome check (read-only; no DB).

Used by ``scripts/db/audit_permission_intel_queue_compatibility.py`` and tests.
Mirrors ``evaluate_queue_row`` / ``normalize_action`` from Erebus
``permission_queue_actions`` for the default ``aosp`` → ``AOSP`` map only.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

CLASS_ACTION_MAP: dict[str, str] = {"aosp": "AOSP"}


def queue_row_apply_outcome(row: Mapping[str, Any]) -> tuple[str, str | None]:
    """Return (bucket, detail) where bucket is apply|skipped|rejected|error."""
    permission = str(row.get("permission_string") or "").strip()
    action_raw = str(row.get("queue_action") or "")
    proposed_classification = str(row.get("proposed_classification") or "")

    normalized = action_raw.strip().lower()
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
        return "apply", None
    return "error", f"unknown_action:{normalized or 'blank'}"


__all__ = ["CLASS_ACTION_MAP", "queue_row_apply_outcome"]
