"""Namespaced SQL query modules grouped by feature area."""

from __future__ import annotations

from .harvest import apk_repository, dynamic_loading, storage_surface
from .permissions import (
    permission_dicts,
    permission_support,
)
from .static_analysis import (
    risk_scores,
    static_findings,
    static_permission_risk,
    string_analysis,
)
from .dynamic import schema as dynamic_schema

__all__ = [
    "apk_repository",
    "dynamic_loading",
    "storage_surface",
    "permission_dicts",
    "permission_support",
    "risk_scores",
    "static_findings",
    "static_permission_risk",
    "string_analysis",
    "dynamic_schema",
]
