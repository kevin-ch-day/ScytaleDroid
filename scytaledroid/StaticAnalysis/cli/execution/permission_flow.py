"""Permission-focused scan helpers."""

from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_engine

from ...modules.permissions import collect_permissions_and_sdk
from ...modules.permissions.render_postcard import render as render_permission_postcard
from ...modules.permissions.audit import PermissionAuditAccumulator
from ..core.models import RunParameters, ScopeSelection
from ..persistence.run_summary import create_static_run_ledger
from ..core.run_lifecycle import finalize_static_run
from ..core.abort_reasons import classify_exception, normalize_abort_reason
from ...session import make_session_stamp, normalize_session_stamp
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
    normalized = normalize_session_stamp(session_stamp)
    if normalized != session_stamp:
        print(
            status_messages.status(
                (
                    "Session label normalized for cross-table safety "
                    f"({len(session_stamp)}→{len(normalized)} chars): "
                    f"'{session_stamp}' → '{normalized}'."
                ),
                level="warn",
            )
        )
        session_stamp = normalized
    snapshot_id = f"perm-audit:app:{session_stamp}"
    accumulator = PermissionAuditAccumulator(
        scope_label=params.scope_label or selection.label,
        scope_type=selection.scope,
        total_groups=len(scope_groups),
        snapshot_id=snapshot_id,
    )

    last_report = None
    last_category = None
    permission_persist_failed = False
    audit_persist_failed = False
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
                permission_persist_failed = True
                logging_engine.get_error_logger().exception(
                    "Permission analysis persistence failed",
                    extra=logging_engine.ensure_trace(
                        {
                            "event": "permission_analysis.persist_failed",
                            "session_stamp": session_stamp,
                            "package": group.package_name,
                            "scope_label": params.scope_label or selection.label,
                        }
                    ),
                )
                print(
                    status_messages.status(
                        "Persistence failed — see logs for traceback.",
                        level="warn",
                    )
                )

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
            logging_engine.get_error_logger().exception(
                "Failed to resolve run_id for permission-only scan",
                extra=logging_engine.ensure_trace(
                    {
                        "event": "permission_scan.run_id_lookup_failed",
                        "session_stamp": session_stamp,
                        "package": package_name,
                    }
                ),
            )
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
                logging_engine.get_error_logger().exception(
                    "Failed to create run row for permission-only scan",
                    extra=logging_engine.ensure_trace(
                        {
                            "event": "permission_scan.run_id_create_failed",
                            "session_stamp": session_stamp,
                            "package": package_name,
                        }
                    ),
                )
                run_id = None
        try:
            scope_label = params.scope_label or selection.label
            row = core_q.run_sql(
                """
                SELECT sar.id
                FROM static_analysis_runs sar
                JOIN app_versions av ON av.id = sar.app_version_id
                JOIN apps a ON a.id = av.app_id
                WHERE sar.session_stamp=%s
                  AND a.package_name=%s
                  AND sar.profile=%s
                  AND (sar.scope_label=%s OR sar.scope_label=%s)
                ORDER BY sar.id DESC
                LIMIT 1
                """,
                (session_stamp, package_name, params.profile_label, package_name, scope_label),
                fetch="one",
            )
            if row and row[0]:
                static_run_id = int(row[0])
        except Exception:
            logging_engine.get_error_logger().exception(
                "Failed to resolve static_run_id for permission-only scan",
                extra=logging_engine.ensure_trace(
                    {
                        "event": "permission_scan.static_run_id_lookup_failed",
                        "session_stamp": session_stamp,
                        "package": package_name,
                    }
                ),
            )
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
                logging_engine.get_error_logger().exception(
                    "Failed to create static run ledger for permission-only scan",
                    extra=logging_engine.ensure_trace(
                        {
                            "event": "permission_scan.static_run_id_create_failed",
                            "session_stamp": session_stamp,
                            "package": package_name,
                        }
                    ),
                )
                static_run_id = None
        snapshot_payload["package"] = package_name
    snapshot_payload["run_id"] = run_id
    snapshot_payload["static_run_id"] = static_run_id
    snapshot_payload["session_stamp"] = session_stamp
    linkage = {}
    if len(accumulator.apps) != 1:
        linkage = {"status": "partial", "reason": "multi_app_scope"}
    elif run_id is None:
        linkage = {"status": "partial", "reason": "run_id_missing"}
    elif static_run_id is None:
        linkage = {"status": "partial", "reason": "static_run_id_missing"}
    if linkage:
        snapshot_payload["linkage"] = linkage
    run_status = "COMPLETED"
    abort_reason = None
    try:
        try:
            persist_result = accumulator.persist_to_db(snapshot_payload)
        except TypeError:
            # Support legacy test doubles that accept only a single bound argument.
            persist_result = accumulator.persist_to_db()
        if not persist_result.ok:
            audit_persist_failed = True
            message = persist_result.user_message or "Permission audit persistence failed."
            print(status_messages.status(f"{message} See logs for traceback.", level="warn"))
    except Exception as exc:
        audit_persist_failed = True
        abort_reason = classify_exception(exc)
        print(status_messages.status("Permission audit persistence failed — see logs.", level="warn"))
    if audit_persist_failed:
        run_status = "FAILED"
        abort_reason = abort_reason or "persist_error"
    if static_run_id and persist_detections:
        finalize_static_run(
            static_run_id=static_run_id,
            status=run_status,
            abort_reason=normalize_abort_reason(abort_reason),
        )


__all__ = ["execute_permission_scan"]
