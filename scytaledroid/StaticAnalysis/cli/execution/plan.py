"""Helpers for generating dynamic plans from static analysis output."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.System import output_prefs

from ..views.view_renderers import build_dynamic_plan, write_dynamic_plan_json


def build_dynamic_plan_artifact(
    base_report,
    payload: Mapping[str, object],
    *,
    package_name: str,
    profile: str,
    scope: str,
    static_run_id: int,
) -> Path | None:
    metadata_map = base_report.metadata if isinstance(base_report.metadata, Mapping) else {}
    identity_valid = metadata_map.get("identity_valid") if isinstance(metadata_map, Mapping) else None
    if identity_valid is False:
        print(
            status_messages.status(
                f"Skipping dynamic plan generation for {package_name}: run identity invalid.",
                level="warn",
            )
        )
        return None
    try:
        # Freeze provenance into the plan at build time; dynamic must not do
        # ad-hoc DB lookups to understand the static snapshot.
        from scytaledroid.Database.db_utils import diagnostics as db_diagnostics

        plan_payload = build_dynamic_plan(
            base_report,
            payload,
            static_run_id=static_run_id,
            schema_version=db_diagnostics.get_schema_version() or "<unknown>",
            batch_id=(
                getattr(output_prefs.get_run_context(), "batch_id", None)
                if output_prefs.get_run_context()
                else None
            ),
        )
        return write_dynamic_plan_json(
            plan_payload,
            package=package_name,
            profile=profile,
            scope=scope,
            static_run_id=static_run_id,
        )
    except Exception as exc:
        warning = f"Failed to write dynamic plan for {package_name}: {exc}"
        print(status_messages.status(warning, level="warn"))
        return None


__all__ = ["build_dynamic_plan_artifact"]
