"""Namespaced SQL query modules grouped by feature area."""

from __future__ import annotations

from .harvest import apk_repository, dynamic_loading, storage_surface
from .permissions import (
    detected_permissions,
    framework_permissions,
    permission_support,
    taxonomy,
    unknown_permissions,
    vendor_permissions,
)
from .static_analysis import (
    risk_scores,
    static_findings,
    static_permission_risk,
    string_analysis,
)

__all__ = [
    "apk_repository",
    "dynamic_loading",
    "storage_surface",
    "detected_permissions",
    "framework_permissions",
    "permission_support",
    "taxonomy",
    "unknown_permissions",
    "vendor_permissions",
    "risk_scores",
    "static_findings",
    "static_permission_risk",
    "string_analysis",
]

