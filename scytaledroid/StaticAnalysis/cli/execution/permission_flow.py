"""Permission-focused scan helpers."""

from __future__ import annotations

from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import status_messages

from ...modules.permissions import collect_permissions_and_sdk
from ...modules.permissions.render_postcard import render as render_permission_postcard
from ...modules.permissions.audit import PermissionAuditAccumulator
from ..models import RunParameters, ScopeSelection
from .scan_flow import generate_report


def execute_permission_scan(
    selection: ScopeSelection,
    params: RunParameters,
    *,
    persist_detections: bool = True,
) -> None:
    """Run the permission analysis workflow for the selected packages."""

    scope_groups = selection.groups
    if not scope_groups:
        print(status_messages.status("No scope groups resolved for permission scan.", level="warn"))
        return

    base_dir = Path(app_config.DATA_DIR) / "apks"
    accumulator = PermissionAuditAccumulator(
        scope_label=params.scope_label or selection.label,
        scope_type=selection.scope,
        total_groups=len(scope_groups),
    )

    for group in scope_groups:
        artifacts = group.artifacts
        if not artifacts:
            continue
        artifact = artifacts[0]
        report, _, error, skipped = generate_report(artifact, base_dir, params)
        if skipped or error:
            continue

        permissions, defined, sdk = collect_permissions_and_sdk(str(artifact.path))
        render_permission_postcard(
            group.package_name,
            group.package_name,
            permissions,
            defined,
            sdk=sdk,
            index=1,
            total=1,
        )

        if persist_detections and report is not None:
            try:
                from scytaledroid.StaticAnalysis.persistence.permissions_db import persist_permissions_to_db

                counts = persist_permissions_to_db(report)
                total = sum(counts.values()) if isinstance(counts, dict) else 0
                print(
                    status_messages.status(
                        f"Permission Analysis persisted: total={total} "
                        f"(fw={counts.get('framework', 0)}, vendor={counts.get('vendor', 0)}, "
                        f"unk={counts.get('unknown', 0)})",
                        level="info",
                    )
                )
            except Exception:
                pass

        accumulator.observe(group.package_name, permissions, defined)

    accumulator.persist()


__all__ = ["execute_permission_scan"]
