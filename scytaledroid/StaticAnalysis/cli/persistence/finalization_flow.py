"""Post-commit finalization flow for persisted static runs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from scytaledroid.Utils.LoggingUtils import logging_utils as log


@dataclass(slots=True)
class StaticRunFinalizationCallbacks:
    run_sql: Callable[..., Any]
    export_dep_json: Callable[..., Any]
    maybe_set_canonical_static_run: Callable[..., None]
    update_static_run_metadata: Callable[..., None]
    update_static_run_status: Callable[..., None]
    normalize_run_status: Callable[[str], str]


def finalize_persisted_static_run(
    *,
    static_run_id: int | None,
    dry_run: bool,
    package_for_run: str,
    session_stamp: str,
    scope_label: str,
    run_package: str,
    run_status: str,
    paper_grade_requested: bool | None,
    canonical_action: str | None,
    persistence_failed: bool,
    outcome: object,
    ended_at_utc: str | None,
    abort_reason: str | None,
    abort_signal: str | None,
    callbacks: StaticRunFinalizationCallbacks,
) -> str:
    if not static_run_id or dry_run:
        return run_status

    dep_path = callbacks.export_dep_json(static_run_id)
    if dep_path:
        log.info(
            f"DEP snapshot written for static_run_id={static_run_id}",
            category="static_analysis",
        )

    if paper_grade_requested is None:
        paper_grade_requested = False

    if persistence_failed:
        run_status = "FAILED"

    enforced_session_label: str | None = None
    try:
        row = callbacks.run_sql(
            "SELECT session_label FROM static_analysis_runs WHERE id=%s",
            (static_run_id,),
            fetch="one",
        )
        if row and row[0]:
            enforced_session_label = str(row[0])
    except Exception:
        enforced_session_label = None
    if not enforced_session_label:
        enforced_session_label = session_stamp

    if not persistence_failed and canonical_action in {"first_run", "replace"}:
        try:
            row = callbacks.run_sql(
                "SELECT run_class FROM static_analysis_runs WHERE id=%s",
                (static_run_id,),
                fetch="one",
            )
            run_class_value = str(row[0] or "").upper() if row else ""
        except Exception:
            run_class_value = ""
        if run_class_value == "CANONICAL":
            try:
                callbacks.maybe_set_canonical_static_run(
                    session_label=enforced_session_label or session_stamp,
                    static_run_id=int(static_run_id),
                    canonical_action=canonical_action,
                )
            except Exception:
                pass

    if not persistence_failed and enforced_session_label and paper_grade_requested:
        is_group_scope = False
        scope_label_norm = str(scope_label or "").strip().lower()
        package_norm = str(package_for_run or "").strip().lower()
        if scope_label_norm and package_norm and scope_label_norm != package_norm:
            is_group_scope = True
        try:
            if not is_group_scope:
                row = callbacks.run_sql(
                    """
                    SELECT
                      COUNT(*) AS run_rows,
                      COUNT(DISTINCT sar.app_version_id) AS distinct_app_versions,
                      COUNT(DISTINCT a.package_name) AS distinct_packages
                    FROM static_analysis_runs sar
                    LEFT JOIN app_versions av ON av.id = sar.app_version_id
                    LEFT JOIN apps a ON a.id = av.app_id
                    WHERE sar.session_label=%s
                    """,
                    (enforced_session_label,),
                    fetch="one",
                )
                run_rows = int(row[0] or 0) if row else 0
                distinct_app_versions = int(row[1] or 0) if row else 0
                distinct_packages = int(row[2] or 0) if row else 0
                is_group_scope = bool(
                    distinct_packages > 1
                    or distinct_app_versions > 1
                    or (run_rows > 1 and distinct_packages == 0 and distinct_app_versions == 0)
                )
        except Exception:
            is_group_scope = True

        if is_group_scope:
            log.info(
                f"Skipping canonical singleton enforcement for group scope session_label={enforced_session_label}",
                category="static_analysis",
            )
        else:
            try:
                row = callbacks.run_sql(
                    """
                    SELECT COUNT(*)
                    FROM static_analysis_runs
                    WHERE session_label=%s AND is_canonical=1
                    """,
                    (enforced_session_label,),
                    fetch="one",
                )
                canonical_count = int(row[0] or 0) if row else 0
            except Exception:
                canonical_count = 0
            if canonical_count != 1:
                outcome.canonical_failed = True
                run_status = "FAILED"
                message = (
                    "canonical_enforcement_failed: expected exactly one canonical row "
                    f"for session_label={enforced_session_label}, found {canonical_count}."
                )
                log.warning(message, category="static_analysis")
                outcome.add_error(message)

    total_findings = int(outcome.persisted_findings)
    try:
        callbacks.run_sql(
            "UPDATE static_analysis_runs SET findings_total=%s WHERE id=%s",
            (total_findings, static_run_id),
        )
    except Exception:
        pass

    if callbacks.normalize_run_status(run_status) != "COMPLETED":
        failure_reasons = ["RUN_STATUS_FAILED"]
        if persistence_failed:
            failure_reasons.append("PERSISTENCE_ERROR")
        try:
            callbacks.update_static_run_metadata(
                int(static_run_id),
                run_class="NON_CANONICAL",
                non_canonical_reasons=json.dumps(
                    sorted(set(failure_reasons)),
                    ensure_ascii=True,
                ),
            )
        except Exception as exc:
            outcome.add_error(
                f"db_write_failed:static_run.classification_update:{exc.__class__.__name__}:{exc}"
            )

    callbacks.update_static_run_status(
        static_run_id=static_run_id,
        status=callbacks.normalize_run_status(run_status),
        ended_at_utc=ended_at_utc,
        abort_reason=abort_reason,
        abort_signal=abort_signal,
    )
    return run_status


__all__ = ["StaticRunFinalizationCallbacks", "finalize_persisted_static_run"]
