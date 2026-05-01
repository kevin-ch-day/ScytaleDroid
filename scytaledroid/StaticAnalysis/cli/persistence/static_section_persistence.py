"""Narrow boundary helpers for static section persistence."""

from __future__ import annotations

from collections.abc import Mapping

from .static_sections import persist_static_sections


def persist_static_sections_boundary(
    *,
    package_name: str,
    session_stamp: str,
    scope_label: str,
    finding_totals: Mapping[str, int],
    baseline_section: Mapping[str, object],
    string_payload: Mapping[str, object],
    manifest: object | None,
    app_metadata: Mapping[str, object] | object,
    run_id: int | None,
    static_run_id: int | None = None,
) -> tuple[list[str], bool, int]:
    return persist_static_sections(
        package_name=package_name,
        session_stamp=session_stamp,
        scope_label=scope_label,
        finding_totals=finding_totals,
        baseline_section=baseline_section,
        string_payload=string_payload,
        manifest=manifest,
        app_metadata=app_metadata,
        static_run_id=static_run_id,
    )


__all__ = ["persist_static_sections_boundary"]
