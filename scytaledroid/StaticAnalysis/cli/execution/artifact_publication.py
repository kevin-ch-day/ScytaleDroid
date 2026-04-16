"""Post-persistence artifact publication helpers for static run results."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Utils.DisplayUtils import status_messages


@dataclass(slots=True)
class ArtifactPublicationResult:
    """Outcome of publishing persisted static-analysis artifacts for one app."""

    saved_path: Path | None = None
    dynamic_plan_path: Path | None = None
    warnings: list[str] = field(default_factory=list)
    skip_remaining_processing: bool = False


def publish_persisted_artifacts(
    *,
    base_report: Any,
    payload: Mapping[str, object],
    package_name: str,
    static_run_id: int,
    profile: str,
    scope: str,
    report_path: Path | None,
    paper_grade_requested: bool,
    required_paper_artifacts: Sequence[str],
    ended_at_utc: str,
    abort_signal: str | None,
    write_baseline_json_fn,
    write_dynamic_plan_json_fn,
    governance_ready_fn,
    write_manifest_evidence_fn,
    build_artifact_registry_entries_fn,
    record_artifacts_fn,
    run_sql_fn,
    refresh_static_run_manifest_fn,
    finalize_static_run_fn,
) -> ArtifactPublicationResult:
    """Write and register post-persistence artifacts for a single app result."""

    outcome = ArtifactPublicationResult()

    try:
        outcome.saved_path = write_baseline_json_fn(
            payload,
            package=package_name,
            profile=profile,
            scope=scope,
        )
    except Exception as exc:
        warning = f"Failed to write baseline JSON for {package_name}: {exc}"
        print(status_messages.status(warning, level="warn"))

    try:
        outcome.dynamic_plan_path = write_dynamic_plan_json_fn(
            base_report,
            payload,
            package=package_name,
            profile=profile,
            scope=scope,
            static_run_id=static_run_id,
        )
    except Exception:
        outcome.dynamic_plan_path = None

    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    grade = "PAPER_GRADE" if paper_grade_requested else "EXPERIMENTAL"
    grade_reasons: list[str] = []
    if paper_grade_requested:
        gov_ready, gov_detail = governance_ready_fn()
        if not gov_ready:
            grade = "EXPERIMENTAL"
            grade_reasons.append("MISSING_GOVERNANCE")
            if gov_detail and gov_detail != "governance_missing":
                warning = f"Governance check failed: {gov_detail}"
                print(status_messages.status(warning, level="warn"))
            warning = "Run grade: EXPERIMENTAL (MISSING_GOVERNANCE)"
            print(status_messages.status(warning, level="warn"))
            outcome.warnings.append(warning)

    manifest_evidence_path = write_manifest_evidence_fn(
        base_report,
        package_name=package_name,
        static_run_id=static_run_id,
        generated_at_utc=now,
    )

    missing_required: list[str] = []
    if grade == "PAPER_GRADE":
        if not outcome.saved_path or not outcome.saved_path.exists():
            missing_required.append("static_baseline_json")
        if not outcome.dynamic_plan_path or not outcome.dynamic_plan_path.exists():
            missing_required.append("static_dynamic_plan_json")
        if not report_path or not report_path.exists():
            missing_required.append("static_report")
        if not manifest_evidence_path or not manifest_evidence_path.exists():
            missing_required.append("manifest_evidence")

    artifacts = build_artifact_registry_entries_fn(
        saved_path=outcome.saved_path,
        dynamic_plan_path=outcome.dynamic_plan_path,
        manifest_evidence_path=manifest_evidence_path,
        report_path=report_path,
        created_at_utc=now,
    )
    if artifacts:
        record_artifacts_fn(
            run_id=str(static_run_id),
            run_type="static",
            artifacts=artifacts,
            origin="host",
            pull_status="n/a",
        )

    if grade != "PAPER_GRADE":
        return outcome

    try:
        rows = run_sql_fn(
            """
            SELECT DISTINCT artifact_type
            FROM artifact_registry
            WHERE run_id=%s AND run_type='static'
            """,
            (str(static_run_id),),
            fetch="all",
        )
        registry_types = {str(row[0]) for row in rows or [] if row and row[0]}
    except Exception:
        registry_types = set()

    for artifact_type in required_paper_artifacts:
        if artifact_type not in registry_types and artifact_type not in missing_required:
            missing_required.append(artifact_type)
    if missing_required:
        warning = (
            f"Canonical-grade artifacts missing for static_run_id={static_run_id}: "
            + ", ".join(missing_required)
        )
        print(status_messages.status(warning, level="warn"))
        outcome.warnings.append(warning)
        finalize_static_run_fn(
            static_run_id=static_run_id,
            status="FAILED",
            ended_at_utc=ended_at_utc,
            abort_reason="missing_required_artifacts",
            abort_signal=abort_signal,
        )
        outcome.skip_remaining_processing = True
        return outcome

    manifest_ok = refresh_static_run_manifest_fn(
        static_run_id,
        grade=grade,
        grade_reasons=grade_reasons,
    )
    if not manifest_ok:
        warning = f"Failed to publish run_manifest.json for static_run_id={static_run_id}"
        print(status_messages.status(warning, level="warn"))
        outcome.warnings.append(warning)
        finalize_static_run_fn(
            static_run_id=static_run_id,
            status="FAILED",
            ended_at_utc=ended_at_utc,
            abort_reason="manifest_write_failed",
            abort_signal=abort_signal,
        )

    return outcome


__all__ = ["ArtifactPublicationResult", "publish_persisted_artifacts"]
