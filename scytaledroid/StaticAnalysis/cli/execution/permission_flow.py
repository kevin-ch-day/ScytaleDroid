"""Permission-focused scan helpers."""

from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import status_messages

from ...modules.permissions import collect_permissions_and_sdk
from ...modules.permissions.render_postcard import render as render_permission_postcard
from ...modules.permissions.audit import PermissionAuditAccumulator
from ..models import RunParameters, ScopeSelection
from ..persistence.run_summary import create_static_run_ledger, update_static_run_status
from ...session import make_session_stamp
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
    session_stamp = params.session_stamp or ""
    if not session_stamp:
        session_stamp = make_session_stamp()
    snapshot_id = f"perm-audit:app:{session_stamp}"
    accumulator = PermissionAuditAccumulator(
        scope_label=params.scope_label or selection.label,
        scope_type=selection.scope,
        total_groups=len(scope_groups),
        snapshot_id=snapshot_id,
    )

    last_report = None
    last_category = None
    for group in scope_groups:
        artifacts = group.artifacts
        if not artifacts:
            continue
        artifact = artifacts[0]
        report, _, error, skipped = generate_report(artifact, base_dir, params)
        if skipped or error:
            continue
        last_report = report
        last_category = group.category

        permissions, defined, sdk = collect_permissions_and_sdk(str(artifact.path))
        profile = render_permission_postcard(
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

        declared_permissions = [name for name, _tag in permissions]
        declared_in = {name.split(".")[-1].upper(): tag for name, tag in permissions if name}
        profile = profile if isinstance(profile, dict) else {}
        counts = {
            "dangerous": int(profile.get("risk_counts", {}).get("dangerous", 0)),
            "signature": int(profile.get("risk_counts", {}).get("signature", 0)),
            "vendor": int(profile.get("V", 0)),
        }
        accumulator.add_app(
            package=group.package_name,
            label=group.package_name,
            cohort=group.category,
            sdk=sdk or {},
            counts=counts,
            groups=profile.get("groups", {}),
            declared_in=declared_in,
            declared_permissions=declared_permissions,
            score_detail=profile.get("score_detail", {}),
            vendor_present=bool(profile.get("V", 0)),
        )

    snapshot_payload = accumulator.finalize()
    run_id = None
    static_run_id = None
    if session_stamp and len(accumulator.apps) == 1:
        package_name = accumulator.apps[0].package
        try:
            from scytaledroid.Database.db_core import db_queries as core_q

            row = core_q.run_sql(
                """
                SELECT run_id
                FROM runs
                WHERE session_stamp=%s AND package=%s
                ORDER BY run_id DESC
                LIMIT 1
                """,
                (session_stamp, package_name),
                fetch="one",
            )
            if row and row[0]:
                run_id = int(row[0])
        except Exception:
            run_id = None
        if run_id is None:
            try:
                from scytaledroid.Persistence import db_writer as _dw

                manifest = getattr(last_report, "manifest", None) if last_report else None
                run_id = _dw.create_run(
                    package=package_name,
                    app_label=getattr(manifest, "app_label", None) if manifest else None,
                    version_code=getattr(manifest, "version_code", None) if manifest else None,
                    version_name=getattr(manifest, "version_name", None) if manifest else None,
                    target_sdk=getattr(manifest, "target_sdk", None) if manifest else None,
                    session_stamp=session_stamp,
                    threat_profile="Unknown",
                    env_profile="consumer",
                )
                run_id = int(run_id) if run_id is not None else None
            except Exception:
                run_id = None
        try:
            scope_label = params.scope_label or selection.label
            row = core_q.run_sql(
                """
                SELECT id
                FROM static_analysis_runs
                WHERE session_stamp=%s
                  AND (scope_label=%s OR scope_label=%s)
                ORDER BY id DESC
                LIMIT 1
                """,
                (session_stamp, package_name, scope_label),
                fetch="one",
            )
            if row and row[0]:
                static_run_id = int(row[0])
        except Exception:
            static_run_id = None
        if static_run_id is None:
            try:
                manifest = getattr(last_report, "manifest", None) if last_report else None
                static_run_id = create_static_run_ledger(
                    package_name=package_name,
                    session_stamp=session_stamp,
                    scope_label=params.scope_label or selection.label,
                    category=last_category,
                    profile=params.profile_label,
                    display_name=getattr(manifest, "app_label", None) if manifest else None,
                    version_name=getattr(manifest, "version_name", None) if manifest else None,
                    version_code=getattr(manifest, "version_code", None) if manifest else None,
                    min_sdk=getattr(manifest, "min_sdk", None) if manifest else None,
                    target_sdk=getattr(manifest, "target_sdk", None) if manifest else None,
                    run_started_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    dry_run=not persist_detections,
                )
            except Exception:
                static_run_id = None
    snapshot_payload["run_id"] = run_id
    snapshot_payload["static_run_id"] = static_run_id
    linkage = {}
    if len(accumulator.apps) != 1:
        linkage = {"status": "partial", "reason": "multi_app_scope"}
    elif run_id is None:
        linkage = {"status": "partial", "reason": "run_id_missing"}
    elif static_run_id is None:
        linkage = {"status": "partial", "reason": "static_run_id_missing"}
    if linkage:
        snapshot_payload["linkage"] = linkage
    accumulator.persist_to_db(snapshot_payload)
    if static_run_id and persist_detections:
        update_static_run_status(
            static_run_id=static_run_id,
            status="COMPLETED",
            ended_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )


__all__ = ["execute_permission_scan"]
