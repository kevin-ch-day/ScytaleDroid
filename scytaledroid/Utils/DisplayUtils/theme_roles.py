"""Semantic color-role mappings shared by CLI renderers.

Keep color selection here so menus, status lines, severity strips, and summary
cards do not drift into competing palettes for the same operator meaning.
"""

from __future__ import annotations

from types import MappingProxyType

STATUS_STYLE_ROLES = MappingProxyType(
    {
        "info": ("info", "text"),
        "warn": ("warning", "warning"),
        "error": ("error", "error"),
        "success": ("success", "success"),
        "blocked": ("blocked", "blocked"),
        "progress": ("progress", "text"),
        "delta_new": ("success", "success"),
        "delta_removed": ("error", "error"),
        "delta_updated": ("warning", "warning"),
        "evidence": ("accent", "highlight"),
    }
)

SEVERITY_STYLE_ROLES = MappingProxyType(
    {
        "critical": "severity_critical",
        "criticality": "severity_critical",
        "crit": "severity_critical",
        "p0": "severity_critical",
        "sev0": "severity_critical",
        "high": "severity_high",
        "p1": "severity_high",
        "sev1": "severity_high",
        "medium": "severity_medium",
        "med": "severity_medium",
        "p2": "severity_medium",
        "sev2": "severity_medium",
        "low": "severity_low",
        "p3": "severity_low",
        "sev3": "severity_low",
        "info": "severity_info",
        "information": "severity_info",
        "note": "severity_info",
        "notes": "severity_info",
        "p4": "severity_info",
        "sev4": "severity_info",
    }
)

DELTA_STYLE_ROLES = MappingProxyType(
    {
        "new": "success",
        "added": "success",
        "removed": "error",
        "deleted": "error",
        "updated": "warning",
        "changed": "warning",
    }
)


def status_roles(level: str) -> tuple[str, str]:
    return STATUS_STYLE_ROLES.get(level, STATUS_STYLE_ROLES["info"])


def severity_role(token: str) -> str | None:
    return SEVERITY_STYLE_ROLES.get(token.strip().lower())


def delta_role(kind: str) -> str:
    return DELTA_STYLE_ROLES.get(kind.strip().lower(), "muted")


__all__ = [
    "DELTA_STYLE_ROLES",
    "SEVERITY_STYLE_ROLES",
    "STATUS_STYLE_ROLES",
    "delta_role",
    "severity_role",
    "status_roles",
]
