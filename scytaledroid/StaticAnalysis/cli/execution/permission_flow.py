"""Permission-focused scan helpers."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.DeviceAnalysis.services import artifact_store
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Utils.System import output_prefs

from ...modules.permissions import collect_permissions_and_sdk
from ...modules.permissions.audit import PermissionAuditAccumulator
from ...session import make_session_stamp, normalize_session_stamp
from ..core.abort_reasons import classify_exception, normalize_abort_reason
from ..core.models import RunParameters, ScopeSelection
from ..core.run_lifecycle import finalize_static_run
from ..persistence.run_summary import create_static_run_ledger
from .permission_view import (
    render_compact_notice,
    render_permission_persist_failed,
    render_permission_persisted,
    render_permission_profile,
)
from .scan_flow import generate_report
from .static_run_map import load_run_map, validate_run_map


def execute_permission_scan(
    selection: ScopeSelection,
    params: RunParameters,
    *,
    persist_detections: bool = True,
    run_map: dict | None = None,
    require_run_map: bool = False,
    allow_partial_audit: bool = False,
    compact_output: bool | None = None,
    fail_on_persist_error: bool = False,
) -> None:
    """Run the permission analysis workflow for the selected packages."""

    scope_groups = selection.groups
    if not scope_groups:
        print(status_messages.status("No scope groups resolved for permission scan.", level="warn"))
        return

    base_dir = artifact_store.analysis_apk_root()
    session_stamp = params.session_stamp or ""
    if not session_stamp:
        session_stamp = make_session_stamp()
    normalized = normalize_session_stamp(session_stamp)
    if normalized != session_stamp:
        if not output_prefs.effective_batch():
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
    audit_persist_failed = False
    persisted_counts_total: dict[str, int] = {}
    persisted_apps = 0
    if compact_output is None:
        if params.perm_snapshot_compact is not None:
            compact_output = params.perm_snapshot_compact
        else:
            compact_output = selection.scope in {"all", "profile"} or len(scope_groups) > 15
    if compact_output:
        if not output_prefs.effective_batch():
            render_compact_notice()

    for idx, group in enumerate(scope_groups, start=1):
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
        manifest_label = None
        try:
            manifest_label = getattr(report.manifest, "app_label", None) if report else None
        except Exception:
            manifest_label = None
        profile = render_permission_profile(
            package_name=group.package_name,
            app_label=manifest_label or group.package_name,
            permissions=permissions,
            defined=defined,
            sdk=sdk,
            index=idx,
            total=len(scope_groups),
            compact=bool(compact_output),
            silent=bool(output_prefs.effective_batch()),
        )

        if persist_detections and report is not None:
            try:
                from scytaledroid.StaticAnalysis.persistence.permissions_db import (
                    persist_permissions_to_db,
                )

                counts = persist_permissions_to_db(report)
                if isinstance(counts, dict):
                    for key, value in counts.items():
                        try:
                            persisted_counts_total[key] = persisted_counts_total.get(key, 0) + int(value)
                        except Exception:
                            continue
                persisted_apps += 1
                if not output_prefs.effective_batch() and not bool(compact_output):
                    render_permission_persisted(counts)
            except Exception:
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
                if not output_prefs.effective_batch():
                    render_permission_persist_failed()

        declared_permissions = [name for name, _tag in permissions]
        declared_in = {name.split(".")[-1].upper(): tag for name, tag in permissions if name}
        profile = profile if isinstance(profile, dict) else {}
        counts = {
            "dangerous": int(profile.get("risk_counts", {}).get("dangerous", 0)),
            "signature": int(profile.get("risk_counts", {}).get("signature", 0)),
            "oem": int(profile.get("V", 0)),
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

    if (
        persist_detections
        and persisted_apps
        and not output_prefs.effective_batch()
        and bool(compact_output)
    ):
        render_permission_persisted(persisted_counts_total)

    if require_run_map and not run_map:
        run_map = load_run_map(session_stamp)
        if not run_map:
            raise RuntimeError(
                "Cannot refresh permission audit: no run_map.json available for this session. "
                "Re-run the static analysis (or refresh immediately after a scan) to regenerate it."
            )
    if run_map:
        validate_run_map(run_map, session_stamp)

    snapshot_payload = accumulator.finalize()
    run_id = None
    static_run_id = None
    if session_stamp and len(accumulator.apps) == 1 and getattr(params, "persistence_ready", False):
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
                    session_label=params.session_label or session_stamp,
                    canonical_action=params.canonical_action,
                    scope_label=params.scope_label or selection.label,
                    category=last_category,
                    profile=params.profile_label,
                    display_name=getattr(manifest, "app_label", None) if manifest else None,
                    version_name=getattr(manifest, "version_name", None) if manifest else None,
                    version_code=getattr(manifest, "version_code", None) if manifest else None,
                    min_sdk=getattr(manifest, "min_sdk", None) if manifest else None,
                    target_sdk=getattr(manifest, "target_sdk", None) if manifest else None,
                    run_started_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
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
    if run_map:
        snapshot_payload["run_map"] = run_map
        snapshot_payload["run_map_required"] = bool(require_run_map)
        snapshot_payload["allow_partial_audit"] = bool(allow_partial_audit)
    # run_map is authoritative for linkage; do not emit partial linkage hints here.

    if run_map:
        try:
            snapshot_path = (
                snapshot_payload.get("paths", {}).get("snapshot")
                if isinstance(snapshot_payload, dict)
                else None
            )
            if snapshot_path:
                Path(snapshot_path).write_text(
                    json.dumps(snapshot_payload, indent=2, sort_keys=True, default=str),
                    encoding="utf-8",
                )
        except Exception:
            logging_engine.get_error_logger().exception(
                "Failed to update permission snapshot with run map",
                extra=logging_engine.ensure_trace(
                    {
                        "event": "permission_audit.run_map_write_failed",
                        "session_stamp": session_stamp,
                    }
                ),
            )
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
            if fail_on_persist_error:
                raise RuntimeError(
                    f"Permission audit persistence failed: {persist_result.error_code or 'unknown_error'}"
                )
    except Exception as exc:
        audit_persist_failed = True
        abort_reason = classify_exception(exc)
        print(status_messages.status("Permission audit persistence failed — see logs.", level="warn"))
        if fail_on_persist_error:
            raise
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
