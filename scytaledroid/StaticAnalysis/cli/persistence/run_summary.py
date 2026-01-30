"""High-level static analysis run persistence pipeline."""

from __future__ import annotations

import json
import os
from pathlib import Path
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_core.db_queries import run_sql_write

from ..core.cvss_v4 import apply_profiles
from ...core.findings import Badge, Finding
from ..reports.evidence_report import normalize_evidence
from ..core.masvs_mapper import summarise_controls, rule_to_area
from ..core.rule_ids import derive_rule_id
from .metrics_writer import compute_metrics_bundle, write_buckets, write_contributors, write_metrics
from .findings_writer import (
    compute_cvss_base,
    derive_masvs_tag,
    extract_rule_hint,
    persist_findings,
    persist_masvs_controls,
)
from .run_envelope import prepare_run_envelope
from .permission_risk import persist_permission_risk
from .permission_matrix import persist_permission_matrix
from .static_sections import (
    coerce_severity_counts,
    normalise_string_counts,
    persist_static_sections,
    persist_storage_surface_data,
)
from .utils import (
    canonical_severity_counts,
    coerce_mapping,
    first_text,
    normalise_severity_token,
    safe_int,
    truncate,
)


def _normalize_datetime_value(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if "T" in candidate or candidate.endswith("Z"):
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
            return parsed.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return candidate
    return candidate


def _severity_band_from_badge(badge: Badge) -> str:
    if badge is Badge.FAIL:
        return "FAIL"
    if badge is Badge.WARN:
        return "WARN"
    return "INFO"


def _score_from_finding(finding: Finding) -> int:
    metrics = finding.metrics
    if isinstance(metrics, Mapping):
        value = metrics.get("score")
        try:
            return safe_int(value, default=0)
        except (TypeError, ValueError):
            pass
    try:
        from scytaledroid.StaticAnalysis.detectors.correlation.scoring import finding_weight

        return safe_int(finding_weight(finding), default=0)
    except Exception:
        return 0


def _correlation_rows_from_result(
    result: object,
    *,
    static_run_id: int,
    package_name: str,
) -> list[Dict[str, object]]:
    findings = getattr(result, "findings", None)
    if not isinstance(findings, Sequence):
        return []
    rows: list[Dict[str, object]] = []
    for finding in findings:
        if not isinstance(finding, Finding):
            continue
        band = _severity_band_from_badge(finding.status)
        score = _score_from_finding(finding)
        rationale = finding.because or finding.title
        evidence_path = None
        evidence_preview = None
        if finding.evidence:
            pointer = finding.evidence[0]
            evidence_path = getattr(pointer, "location", None)
            evidence_preview = getattr(pointer, "description", None)
        if not evidence_preview:
            evidence_preview = rationale
        rows.append(
            {
                "static_run_id": static_run_id,
                "package_name": package_name,
                "correlation_key": finding.finding_id,
                "severity_band": band,
                "score": score,
                "rationale": truncate(rationale, 512),
                "evidence_path": truncate(evidence_path, 1024),
                "evidence_preview": truncate(evidence_preview, 1024),
            }
        )
    return rows


@dataclass(slots=True)
class PersistenceOutcome:
    run_id: int | None = None
    static_run_id: int | None = None
    runtime_findings: int = 0
    persisted_findings: int = 0
    baseline_written: bool = False
    string_samples_persisted: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return not self.errors

    def add_error(self, message: str) -> None:
        self.errors.append(message)


def _persist_static_sections_wrapper(
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
) -> Tuple[list[str], bool, int]:
    return persist_static_sections(
        package_name=package_name,
        session_stamp=session_stamp,
        scope_label=scope_label,
        finding_totals=finding_totals,
        baseline_section=baseline_section,
        string_payload=string_payload,
        manifest=manifest,
        app_metadata=app_metadata,
        run_id=run_id,
        static_run_id=static_run_id,
    )


def _persist_correlation_results(rows: Sequence[Mapping[str, object]]) -> bool:
    if not rows:
        return True
    try:
        gov_version = None
        gov_sha = None
        try:
            row = core_q.run_sql(
                """
                SELECT s.governance_version, s.snapshot_sha256, COUNT(r.permission_string) AS row_count
                FROM permission_governance_snapshots s
                LEFT JOIN permission_governance_snapshot_rows r
                  ON r.governance_version = s.governance_version
                GROUP BY s.governance_version, s.snapshot_sha256
                ORDER BY s.loaded_at_utc DESC
                LIMIT 1
                """,
                fetch="one",
            )
            if row and row[0] and int(row[2] or 0) > 0:
                gov_version, gov_sha = row[0], row[1]
        except Exception:
            pass
        if gov_version is None or gov_sha is None:
            try:
                row = core_q.run_sql(
                    "SELECT COUNT(*) FROM permission_governance_snapshot_rows",
                    fetch="one",
                )
                if row and int(row[0] or 0) > 0:
                    log.warning(
                        "Governance snapshot rows exist without header; correlation persistence skipped.",
                        category="static_analysis",
                    )
            except Exception:
                pass
            log.warning(
                "Governance snapshot missing; skipping correlation persistence.",
                category="static_analysis",
            )
            return True
        log.info(
            f"Using governance snapshot {gov_version} (sha256={gov_sha})",
            category="static_analysis",
        )
        columns = [
            "static_run_id",
            "package_name",
            "correlation_key",
            "severity_band",
            "score",
            "rationale",
            "evidence_path",
            "evidence_preview",
        ]
        placeholders = ["%s"] * len(columns)
        values_base = [
            "static_run_id",
            "package_name",
            "correlation_key",
            "severity_band",
            "score",
            "rationale",
            "evidence_path",
            "evidence_preview",
        ]
        if gov_version is not None or gov_sha is not None:
            columns.extend(["governance_version", "governance_sha256"])
            placeholders.extend(["%s", "%s"])
            values_base.extend(["governance_version", "governance_sha256"])

        for row in rows:
            payload = dict(row)
            static_run_id = payload.get("static_run_id")
            package_name = payload.get("package_name")
            artifact_token = f"run_{static_run_id}"
            if static_run_id is not None:
                try:
                    sha_row = core_q.run_sql(
                        "SELECT sha256 FROM static_analysis_runs WHERE id=%s",
                        (static_run_id,),
                        fetch="one",
                    )
                    if sha_row and sha_row[0]:
                        artifact_token = str(sha_row[0])
                except Exception:
                    pass
            rel_path = Path("evidence") / "static_runs" / str(static_run_id) / str(package_name) / artifact_token
            rel_path.mkdir(parents=True, exist_ok=True)
            corr_key = payload.get("correlation_key") or "correlation"
            corr_file = rel_path / f"correlation_{corr_key}.json"
            wrote_evidence = False
            try:
                corr_payload = {
                    "static_run_id": static_run_id,
                    "package_name": package_name,
                    "correlation_key": corr_key,
                    "severity_band": payload.get("severity_band"),
                    "score": payload.get("score"),
                    "rationale": payload.get("rationale"),
                    "evidence_preview": payload.get("evidence_preview"),
                    "governance_version": gov_version,
                    "governance_sha256": gov_sha,
                }
                corr_file.write_text(
                    json.dumps(corr_payload, ensure_ascii=True, indent=2),
                    encoding="utf-8",
                )
                wrote_evidence = True
            except Exception:
                log.warning(
                    f"Failed to write correlation evidence for static_run_id={static_run_id}",
                    category="static_analysis",
                )
            if not wrote_evidence:
                continue
            payload["evidence_path"] = str(
                Path("evidence")
                / "static_runs"
                / str(static_run_id)
                / str(package_name)
                / artifact_token
                / corr_file.name
            )
            payload["governance_version"] = gov_version
            payload["governance_sha256"] = gov_sha
            core_q.run_sql(
                "INSERT INTO static_correlation_results ("
                + ", ".join(columns)
                + ") VALUES ("
                + ",".join(placeholders)
                + ") ON DUPLICATE KEY UPDATE "
                + ", ".join(f"{col}=VALUES({col})" for col in columns if col not in {"static_run_id", "package_name", "correlation_key"}),
                tuple(payload.get(key) for key in values_base),
            )
        return True
    except Exception as exc:
        log.warning(
            f"Failed to persist correlation results: {exc}",
            category="static_analysis",
        )
        return False


def _ensure_app_version(
    *,
    package_for_run: str,
    display_name: str,
    version_name: str | None,
    version_code: int | None,
    min_sdk: int | None,
    target_sdk: int | None,
) -> int | None:
    """Fetch or create an app_version row for static_analysis_runs."""
    try:
        from scytaledroid.Database.db_utils.package_utils import normalize_package_name
        from scytaledroid.Database.db_utils.publisher_rules import apply_publisher_mapping

        cleaned_package = normalize_package_name(package_for_run, context="database")
        if not cleaned_package:
            return None
        app_id = None
        row = core_q.run_sql(
            "SELECT id, display_name FROM apps WHERE package_name=%s",
            (cleaned_package,),
            fetch="one",
        )
        if row and row[0]:
            app_id = int(row[0])
            existing_name = row[1] if len(row) > 1 else None
            if (
                isinstance(display_name, str)
                and display_name.strip()
                and display_name != package_for_run
                and (existing_name is None or existing_name == "" or existing_name == package_for_run)
            ):
                core_q.run_sql(
                    "UPDATE apps SET display_name=%s WHERE id=%s",
                    (display_name, app_id),
                )
        else:
            app_id = core_q.run_sql(
                "INSERT INTO apps (package_name, display_name) VALUES (%s,%s)",
                (cleaned_package, display_name),
                return_lastrowid=True,
            )
            app_id = int(app_id) if app_id else None
            apply_publisher_mapping([cleaned_package])
        if app_id is None:
            return None

        params = (app_id, version_name, version_code)
        row = core_q.run_sql(
            """
            SELECT id FROM app_versions
            WHERE app_id=%s AND version_name<=>%s AND version_code<=>%s
            ORDER BY id DESC LIMIT 1
            """,
            params,
            fetch="one",
        )
        if row and row[0]:
            return int(row[0])

        av_id = core_q.run_sql(
            """
            INSERT INTO app_versions (app_id, version_name, version_code, min_sdk, target_sdk)
            VALUES (%s,%s,%s,%s,%s)
            """,
            (app_id, version_name, version_code, min_sdk, target_sdk),
            return_lastrowid=True,
        )
        return int(av_id) if av_id else None
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(
            f"Failed to resolve/create app_version for {package_for_run}: {exc}",
            category="static_analysis",
        )
        return None


def _create_static_run(
    *,
    app_version_id: int,
    session_stamp: str,
    scope_label: str,
    category: str | None,
    profile: str,
    findings_total: int,
    run_started_utc: str | None,
    status: str,
    sha256: str | None = None,
    base_apk_sha256: str | None = None,
    artifact_set_hash: str | None = None,
    run_signature: str | None = None,
    run_signature_version: str | None = None,
    identity_valid: bool | None = None,
    identity_error_reason: str | None = None,
    config_hash: str | None = None,
    pipeline_version: str | None = None,
    analysis_version: str | None = None,
    catalog_versions: str | None = None,
    study_tag: str | None = None,
) -> int | None:
    normalized_started_at = _normalize_datetime_value(run_started_utc)
    try:
        run_id = core_q.run_sql(
            """
            INSERT INTO static_analysis_runs (
                app_version_id,
                session_stamp,
                scope_label,
                category,
                sha256,
                base_apk_sha256,
                artifact_set_hash,
                run_signature,
                run_signature_version,
                identity_valid,
                identity_error_reason,
                analysis_version,
                pipeline_version,
                catalog_versions,
                config_hash,
                study_tag,
                profile,
                findings_total,
                run_started_utc,
                status
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                app_version_id,
                session_stamp,
                scope_label,
                category,
                sha256,
                base_apk_sha256,
                artifact_set_hash,
                run_signature,
                run_signature_version,
                identity_valid,
                identity_error_reason,
                analysis_version,
                pipeline_version,
                catalog_versions,
                config_hash,
                study_tag,
                profile,
                findings_total,
                normalized_started_at,
                status,
            ),
            return_lastrowid=True,
        )
        return int(run_id) if run_id else None
    except Exception:
        try:
            run_id = core_q.run_sql(
                """
                INSERT INTO static_analysis_runs (
                    app_version_id,
                    session_stamp,
                    scope_label,
                    sha256,
                    base_apk_sha256,
                    artifact_set_hash,
                    run_signature,
                    run_signature_version,
                    identity_valid,
                    identity_error_reason,
                    analysis_version,
                    pipeline_version,
                    catalog_versions,
                    config_hash,
                    study_tag,
                    profile,
                    findings_total,
                    run_started_utc,
                    status
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    app_version_id,
                    session_stamp,
                    scope_label,
                    sha256,
                    base_apk_sha256,
                    artifact_set_hash,
                    run_signature,
                    run_signature_version,
                    identity_valid,
                    identity_error_reason,
                    analysis_version,
                    pipeline_version,
                    catalog_versions,
                    config_hash,
                    study_tag,
                    profile,
                    findings_total,
                    normalized_started_at,
                    status,
                ),
                return_lastrowid=True,
            )
            return int(run_id) if run_id else None
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                f"Failed to create static_analysis_runs row for session={session_stamp}: {exc}",
                category="db",
            )
            return None


def create_static_run_ledger(
    *,
    package_name: str,
    session_stamp: str,
    scope_label: str,
    category: str | None = None,
    profile: str,
    display_name: str | None = None,
    version_name: str | None = None,
    version_code: int | None = None,
    min_sdk: int | None = None,
    target_sdk: int | None = None,
    sha256: str | None = None,
    base_apk_sha256: str | None = None,
    artifact_set_hash: str | None = None,
    run_signature: str | None = None,
    run_signature_version: str | None = None,
    identity_valid: bool | None = None,
    identity_error_reason: str | None = None,
    config_hash: str | None = None,
    pipeline_version: str | None = None,
    analysis_version: str | None = None,
    catalog_versions: str | None = None,
    study_tag: str | None = None,
    run_started_utc: str | None = None,
    dry_run: bool = False,
) -> int | None:
    """Create a RUNNING static_analysis_runs row before scanning begins."""
    if dry_run:
        return None

    try:
        row = core_q.run_sql(
            """
            SELECT sar.id
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            WHERE sar.session_stamp = %s
              AND a.package_name = %s
            ORDER BY sar.id DESC
            LIMIT 1
            """,
            (session_stamp, package_name),
            fetch="one",
        )
        if row and row[0]:
            log.warning(
                (
                    f"static_analysis_runs already exists for session={session_stamp} "
                    f"package={package_name}; reusing static_run_id={row[0]}"
                ),
                category="static_analysis",
            )
            return int(row[0])
    except Exception:
        pass

    display_name = display_name or package_name
    app_version_id = _ensure_app_version(
        package_for_run=package_name,
        display_name=display_name,
        version_name=version_name,
        version_code=version_code,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
    )
    if app_version_id is None:
        return None
    if sha256 and config_hash and pipeline_version:
        try:
            row = core_q.run_sql(
                """
                SELECT id, status
                FROM static_analysis_runs
                WHERE app_version_id=%s
                  AND base_apk_sha256=%s
                  AND artifact_set_hash=%s
                  AND config_hash=%s
                  AND profile=%s
                  AND (pipeline_version<=>%s)
                  AND (run_signature_version<=>%s)
                  AND (identity_valid=1)
                ORDER BY id DESC
                LIMIT 1
                """,
                (
                    app_version_id,
                    base_apk_sha256 or sha256,
                    artifact_set_hash,
                    config_hash,
                    profile,
                    pipeline_version,
                    run_signature_version,
                ),
                fetch="one",
            )
            if row and row[0] and str(row[1] or "").upper() == "COMPLETED":
                log.info(
                    (
                        f"Reusing static_run_id={row[0]} for {package_name} "
                        f"(sha256/config_hash match)."
                    ),
                    category="static_analysis",
                )
                return int(row[0])
        except Exception:
            pass
    elif sha256 and config_hash and not pipeline_version:
        log.warning(
            "pipeline_version missing; static run reuse disabled for this scan.",
            category="static_analysis",
        )
    run_started_utc = _normalize_datetime_value(
        run_started_utc or datetime.utcnow().isoformat(timespec="seconds") + "Z"
    )
    return _create_static_run(
        app_version_id=app_version_id,
        session_stamp=session_stamp,
        scope_label=scope_label,
        category=category,
        profile=profile,
        findings_total=0,
        run_started_utc=run_started_utc,
        status="RUNNING",
        sha256=sha256,
        base_apk_sha256=base_apk_sha256,
        artifact_set_hash=artifact_set_hash,
        run_signature=run_signature,
        run_signature_version=run_signature_version,
        identity_valid=identity_valid,
        identity_error_reason=identity_error_reason,
        config_hash=config_hash,
        pipeline_version=pipeline_version,
        analysis_version=analysis_version,
        catalog_versions=catalog_versions,
        study_tag=study_tag,
    )


def _update_static_run_metadata(
    static_run_id: int,
    *,
    sha256_value: str | None = None,
    base_apk_sha256: str | None = None,
    artifact_set_hash: str | None = None,
    run_signature: str | None = None,
    run_signature_version: str | None = None,
    identity_valid: bool | None = None,
    identity_error_reason: str | None = None,
    config_hash: str | None = None,
    pipeline_version: str | None = None,
    analysis_version: str | None = None,
    catalog_versions: str | None = None,
    study_tag: str | None = None,
) -> None:
    updates: list[str] = []
    params: list[object] = []
    if sha256_value:
        updates.append("sha256=%s")
        params.append(sha256_value)
    if base_apk_sha256:
        updates.append("base_apk_sha256=%s")
        params.append(base_apk_sha256)
    if artifact_set_hash:
        updates.append("artifact_set_hash=%s")
        params.append(artifact_set_hash)
    if run_signature:
        updates.append("run_signature=%s")
        params.append(run_signature)
    if run_signature_version:
        updates.append("run_signature_version=%s")
        params.append(run_signature_version)
    if identity_valid is not None:
        updates.append("identity_valid=%s")
        params.append(1 if identity_valid else 0)
    if identity_error_reason:
        updates.append("identity_error_reason=%s")
        params.append(identity_error_reason)
    if config_hash:
        updates.append("config_hash=%s")
        params.append(config_hash)
    if pipeline_version:
        updates.append("pipeline_version=%s")
        params.append(pipeline_version)
    if analysis_version:
        updates.append("analysis_version=%s")
        params.append(analysis_version)
    if catalog_versions:
        updates.append("catalog_versions=%s")
        params.append(catalog_versions)
    if study_tag:
        updates.append("study_tag=%s")
        params.append(study_tag)
    if not updates:
        return
    params.append(static_run_id)
    try:
        run_sql_write(
            f"""
            UPDATE static_analysis_runs
            SET {', '.join(updates)}
            WHERE id=%s
            """,
            tuple(params),
        )
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(
            f"Failed to update static_analysis_runs metadata for id={static_run_id}: {exc}",
            category="db",
        )


def update_static_run_status(
    *,
    static_run_id: int,
    status: str,
    ended_at_utc: str | None = None,
    abort_reason: str | None = None,
    abort_signal: str | None = None,
) -> None:
    normalized_ended_at = _normalize_datetime_value(ended_at_utc)
    from ..core.abort_reasons import normalize_abort_reason

    normalized_abort_reason = normalize_abort_reason(abort_reason)
    try:
        run_sql_write(
            """
            UPDATE static_analysis_runs
            SET status=%s,
                ended_at_utc=%s,
                abort_reason=%s,
                abort_signal=%s
            WHERE id=%s
            """,
            (
                status,
                normalized_ended_at,
                normalized_abort_reason,
                abort_signal,
                static_run_id,
            ),
        )
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(
            f"Failed to update static_analysis_runs status for id={static_run_id}: {exc}",
            category="db",
        )


def finalize_open_static_runs(
    static_run_ids: Sequence[int],
    *,
    status: str,
    ended_at_utc: str | None = None,
    abort_reason: str | None = None,
    abort_signal: str | None = None,
) -> None:
    if not static_run_ids:
        return
    normalized_ended_at = _normalize_datetime_value(ended_at_utc)
    from ..core.abort_reasons import normalize_abort_reason

    normalized_abort_reason = normalize_abort_reason(abort_reason)
    placeholders = ", ".join(["%s"] * len(static_run_ids))
    params = (
        status,
        normalized_ended_at,
        normalized_abort_reason,
        abort_signal,
        *static_run_ids,
    )
    try:
        run_sql_write(
            f"""
            UPDATE static_analysis_runs
            SET status=%s,
                ended_at_utc=%s,
                abort_reason=%s,
                abort_signal=%s
            WHERE status='RUNNING'
              AND ended_at_utc IS NULL
              AND id IN ({placeholders})
            """,
            params,
        )
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(
            f"Failed to finalize open static runs for ids={static_run_ids}: {exc}",
            category="db",
        )

def persist_run_summary(
    base_report,
    string_data: Mapping[str, object],
    run_package: str,
    *,
    session_stamp: str | None,
    scope_label: str,
    finding_totals: Mapping[str, int],
    baseline_payload: Mapping[str, object],
    static_run_id: int | None = None,
    run_status: str = "COMPLETED",
    ended_at_utc: str | None = None,
    abort_reason: str | None = None,
    abort_signal: str | None = None,
    dry_run: bool = False,
) -> PersistenceOutcome:
    outcome = PersistenceOutcome()
    br = base_report
    try:
        metadata_map: Mapping[str, object] = getattr(br, "metadata", {}) or {}
    except Exception:
        metadata_map = {}
    manifest_obj = getattr(br, "manifest", None)
    package_for_run = getattr(manifest_obj, "package_name", None) or run_package

    if dry_run:
        log.info(
            f"Dry-run enabled; persistence for {run_package} will be simulated",
            category="static_analysis",
        )

    if not session_stamp and metadata_map:
        value = metadata_map.get("session_stamp")
        if isinstance(value, str) and value.strip():
            session_stamp = value.strip()

    if not session_stamp:
        message = f"Missing session stamp for {run_package}; static persistence will be skipped."
        log.warning(message, category="static_analysis")
        outcome.add_error(message)
        return outcome

    envelope, envelope_errors = prepare_run_envelope(
        report=br,
        baseline_payload=baseline_payload,
        run_package=run_package,
        session_stamp=session_stamp,
        dry_run=dry_run,
    )
    for err in envelope_errors:
        outcome.add_error(err)
    run_id = envelope.run_id
    if run_id:
        outcome.run_id = run_id
    if static_run_id is None:
        try:
            # Prefer an existing static_analysis_runs entry for this session/package.
            rows = core_q.run_sql(
                """
                SELECT sar.id
                FROM static_analysis_runs sar
                JOIN app_versions av ON av.id = sar.app_version_id
                JOIN apps a ON a.id = av.app_id
                WHERE sar.session_stamp = %s
                  AND a.package_name = %s
                """,
                (session_stamp, package_for_run),
                fetch="all",
            )
            if rows:
                if len(rows) > 1:
                    message = (
                        f"Multiple static_analysis_runs found for session={session_stamp} "
                        f"package={package_for_run}; cannot disambiguate. Use a unique session label."
                    )
                    outcome.add_error(message)
                    return outcome
                # Enforce immutable runs: do not reuse an existing static_run_id for the same session/package.
                message = (
                    f"Session label already used for package={package_for_run} "
                    f"(static_run_id={rows[0][0]}). Please rerun with a unique session label."
                )
                outcome.add_error(message)
                return outcome
        except Exception:
            static_run_id = None

    if static_run_id is None and not dry_run:
        # Attempt to create a static_analysis_runs row so downstream tables can
        # be keyed by static_run_id even on fresh schemas.
        display_name = getattr(manifest_obj, "app_label", None) or package_for_run
        version_name = getattr(manifest_obj, "version_name", None) if manifest_obj else None
        min_sdk = safe_int(getattr(manifest_obj, "min_sdk", None) or getattr(manifest_obj, "min_sdk_version", None))
        target_sdk = safe_int(getattr(manifest_obj, "target_sdk", None))
        try:
            version_code = safe_int(getattr(manifest_obj, "version_code", None)) if manifest_obj else None
        except Exception:
            version_code = None

        app_version_id = _ensure_app_version(
            package_for_run=package_for_run,
            display_name=display_name,
            version_name=version_name,
            version_code=version_code,
            min_sdk=min_sdk,
            target_sdk=target_sdk,
        )
        if app_version_id is not None:
            profile_token = first_text(
                metadata_map.get("scan_profile") if isinstance(metadata_map, Mapping) else None,
                metadata_map.get("run_profile") if isinstance(metadata_map, Mapping) else None,
                baseline_payload.get("scan_profile") if isinstance(baseline_payload, Mapping) else None,
                baseline_payload.get("profile") if isinstance(baseline_payload, Mapping) else None,
                "Full",
            )
            category_token = first_text(
                metadata_map.get("category") if isinstance(metadata_map, Mapping) else None,
                metadata_map.get("category_name") if isinstance(metadata_map, Mapping) else None,
                baseline_payload.get("category") if isinstance(baseline_payload, Mapping) else None,
                baseline_payload.get("category_name") if isinstance(baseline_payload, Mapping) else None,
            )
            static_run_id = _create_static_run(
                app_version_id=app_version_id,
                session_stamp=session_stamp,
                scope_label=scope_label,
                category=category_token,
                profile=profile_token,
                findings_total=int(finding_totals.get("total", 0) or 0),
                run_started_utc=None,
                status="RUNNING",
            )
            if static_run_id:
                log.info(
                    f"Resolved static_run_id={static_run_id} for {package_for_run} (session={session_stamp})",
                    category="static_analysis",
                )
        else:
            log.warning(
                (
                    f"Could not resolve app_version_id for {package_for_run}; "
                    f"static_run_id will remain unset and persistence will be legacy-only."
                ),
                category="static_analysis",
            )

    outcome.static_run_id = static_run_id
    if static_run_id and not dry_run:
        manifest_sha = None
        base_apk_sha256 = None
        artifact_set_hash = None
        run_signature = None
        run_signature_version = None
        identity_valid = None
        identity_error_reason = None
        if isinstance(metadata_map, Mapping):
            manifest_sha = first_text(
                metadata_map.get("artifact_manifest_sha256"),
                metadata_map.get("manifest_sha256"),
            )
            base_apk_sha256 = first_text(metadata_map.get("base_apk_sha256"))
            artifact_set_hash = first_text(metadata_map.get("artifact_set_hash"))
            run_signature = first_text(metadata_map.get("run_signature"))
            run_signature_version = first_text(metadata_map.get("run_signature_version"))
            identity_valid = metadata_map.get("identity_valid")
            identity_error_reason = first_text(metadata_map.get("identity_error_reason"))
        if not manifest_sha:
            try:
                manifest_sha = first_text(getattr(br, "hashes", {}).get("sha256"))
            except Exception:
                manifest_sha = None
        config_hash = first_text(
            metadata_map.get("config_hash") if isinstance(metadata_map, Mapping) else None,
            os.getenv("SCYTALEDROID_CONFIG_HASH"),
        )
        pipeline_version = first_text(
            metadata_map.get("pipeline_version") if isinstance(metadata_map, Mapping) else None,
            os.getenv("SCYTALEDROID_PIPELINE_VERSION"),
        )
        catalog_versions = first_text(
            metadata_map.get("catalog_versions") if isinstance(metadata_map, Mapping) else None,
            os.getenv("SCYTALEDROID_CATALOG_VERSIONS"),
        )
        study_tag = first_text(
            metadata_map.get("study_tag") if isinstance(metadata_map, Mapping) else None,
            os.getenv("SCYTALEDROID_STUDY_TAG"),
        )
        analysis_version = first_text(getattr(br, "analysis_version", None))
        _update_static_run_metadata(
            static_run_id,
            sha256_value=base_apk_sha256 or manifest_sha,
            base_apk_sha256=base_apk_sha256,
            artifact_set_hash=artifact_set_hash,
            run_signature=run_signature,
            run_signature_version=run_signature_version,
            identity_valid=identity_valid if isinstance(identity_valid, bool) else None,
            identity_error_reason=identity_error_reason,
            config_hash=config_hash,
            pipeline_version=pipeline_version,
            analysis_version=analysis_version,
            catalog_versions=catalog_versions,
            study_tag=study_tag,
        )
    metrics_bundle = compute_metrics_bundle(br, string_data)
    code_http_hosts = metrics_bundle.code_http_hosts
    asset_http_hosts = metrics_bundle.asset_http_hosts

    if run_id is not None:
        if not write_buckets(int(run_id), metrics_bundle.buckets, static_run_id=static_run_id):
            message = f"Failed to persist scoring buckets for run_id={run_id}"
            log.warning(message, category="static_analysis")
            outcome.add_error(message)

    baseline_counts = coerce_severity_counts(finding_totals)
    severity_counter: Counter[str] = Counter()
    downgraded_high = 0

    finding_rows: list[Dict[str, Any]] = []
    control_entries: list[Tuple[str, Mapping[str, Any]]] = []
    correlation_rows: list[Dict[str, object]] = []
    total_findings = 0
    rule_assigned = 0
    base_vector_count = 0
    bte_vector_count = 0
    preview_assigned = 0
    path_assigned = 0

    try:
        for result in (br.detector_results or ()):  # type: ignore[attr-defined]
            detector_id = str(getattr(result, "detector_id", getattr(result, "section_key", None)) or "unknown")
            module_id_val = getattr(result, "module_id", None)
            module_id = str(module_id_val) if module_id_val not in (None, "") else None
            if detector_id == "correlation_engine" and static_run_id:
                correlation_rows.extend(
                    _correlation_rows_from_result(
                        result,
                        static_run_id=static_run_id,
                        package_name=package_for_run,
                    )
                )
            for f in result.findings:
                total_findings += 1
                detector_sev = normalise_severity_token(getattr(f, "severity", None))
                if detector_sev is None:
                    detector_sev = normalise_severity_token(getattr(f, "severity_label", None))
                metrics_map = getattr(f, "metrics", None)
                if isinstance(metrics_map, Mapping):
                    detector_sev = detector_sev or normalise_severity_token(
                        metrics_map.get("severity")
                    )
                    detector_sev = detector_sev or normalise_severity_token(
                        metrics_map.get("severity_level")
                    )
                gate_value = getattr(getattr(f, "severity_gate", None), "value", None)
                gate_sev = normalise_severity_token(gate_value)
                sev = detector_sev or gate_sev or "Info"
                if detector_sev == "High" and sev != "High":
                    downgraded_high += 1
                severity_counter[sev] += 1
                evidence = normalize_evidence(
                    f.evidence,
                    detail_hint=getattr(f, "detail", None)
                    or getattr(f, "headline", None)
                    or getattr(f, "summary", None)
                    or getattr(f, "because", None),
                    path_hint=getattr(f, "path", None),
                    offset_hint=getattr(f, "offset", None),
                )
                evidence_payload = json.dumps(evidence.as_payload(), ensure_ascii=False)
                evidence_path = evidence.path
                evidence_offset = evidence.offset
                evidence_preview = evidence.detail
                if evidence_preview:
                    preview_assigned += 1
                if evidence_path:
                    path_assigned += 1
                rule_id = derive_rule_id(
                    detector_id,
                    module_id,
                    evidence_path,
                    evidence_preview,
                    rule_id_hint=extract_rule_hint(f),
                )
                if rule_id:
                    rule_assigned += 1
                masvs_area = derive_masvs_tag(f, rule_id, lookup_rule_area=rule_to_area)
                base_vector, base_score, base_meta = compute_cvss_base(rule_id)
                if base_vector:
                    base_vector_count += 1
                (
                    bt_vector,
                    bt_score,
                    be_vector,
                    be_score,
                    bte_vector,
                    bte_score,
                    profile_meta,
                ) = apply_profiles(base_vector, envelope.threat_profile, envelope.env_profile)
                if bte_vector:
                    bte_vector_count += 1
                meta_combined: Dict[str, Any] = {}
                if base_meta:
                    meta_combined.update(base_meta)
                if profile_meta:
                    meta_combined.update(profile_meta)
                finding_rows.append(
                    {
                        "severity": sev,
                        "masvs": masvs_area,
                        "cvss": truncate(base_vector, 128),
                        "kind": detector_id,
                        "module_id": module_id,
                        "evidence": truncate(evidence_payload, 512),
                        "evidence_path": truncate(evidence_path, 512),
                        "evidence_offset": truncate(evidence_offset, 64),
                        "evidence_preview": truncate(evidence_preview, 256),
                        "rule_id": rule_id,
                        "cvss_v40_b_vector": base_vector,
                        "cvss_v40_b_score": base_score,
                        "cvss_v40_bt_vector": bt_vector,
                        "cvss_v40_bt_score": bt_score,
                        "cvss_v40_be_vector": be_vector,
                        "cvss_v40_be_score": be_score,
                        "cvss_v40_bte_vector": bte_vector,
                        "cvss_v40_bte_score": bte_score,
                        "cvss_v40_meta": json.dumps(meta_combined, ensure_ascii=False) if meta_combined else None,
                    }
                )
                control_entries.extend(getattr(result, "masvs_coverage", []))
    except Exception as exc:
        message = f"Failed to coerce findings for {run_package}: {exc}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)

    control_summary = summarise_controls(control_entries)
    outcome.runtime_findings = int(total_findings)
    outcome.persisted_findings = len(finding_rows)

    if severity_counter:
        severity_counts = canonical_severity_counts(severity_counter)
        persisted_totals = Counter(severity_counts)
        mismatch = {
            key: severity_counts[key] - baseline_counts.get(key, 0)
            for key in severity_counts
            if severity_counts[key] != baseline_counts.get(key, 0)
        }
        if mismatch:
            log.info(
                f"Adjusted severity totals for {run_package} based on detector output: {mismatch}",
                category="static_analysis",
            )
    else:
        severity_counts = baseline_counts
        persisted_totals = Counter(severity_counts)

    if finding_rows:
        if run_id is None:
            sample = finding_rows[0] if finding_rows else {}
            sample_view = {
                key: sample.get(key)
                for key in ("rule_id", "evidence_path", "evidence_preview", "severity")
            }
            log.info(
                (
                    f"Dry-run persistence payload for {run_package}: "
                    f"findings={total_findings} "
                    f"sample={json.dumps(sample_view, ensure_ascii=False)}"
                ),
                category="static_analysis",
            )
        elif not persist_findings(int(run_id), finding_rows, static_run_id=static_run_id):
            message = (
                f"Failed to persist findings for run_id={run_id} "
                f"static_run_id={static_run_id}"
            )
            log.warning(message, category="static_analysis")
            outcome.add_error(message)

    if static_run_id and correlation_rows and not dry_run:
        if not _persist_correlation_results(correlation_rows):
            log.warning(
                f"Correlation results persistence failed for static_run_id={static_run_id}",
                category="static_analysis",
            )

    if run_id is not None:
        if control_summary:
            persist_masvs_controls(
                int(run_id),
                package_for_run,
                control_summary,
            )
        else:
            log.info(
                (
                    f"No MASVS control coverage derived for {run_package}; "
                    f"total_findings={total_findings} entries={len(control_entries)}"
                ),
                category="static_analysis",
            )
        persist_storage_surface_data(br, session_stamp, scope_label)
        apk_identifier = safe_int(metadata_map.get("apk_id")) if metadata_map else None
        if apk_identifier is None and metadata_map:
            apk_identifier = safe_int(metadata_map.get("apkId"))
        if apk_identifier is None:
            apk_identifier = safe_int(metadata_map.get("android_apk_id"))
        if apk_identifier is None:
            apk_identifier = int(run_id)

        permission_profiles_map: Mapping[str, Mapping[str, object]] | None = None
        detector_metrics = getattr(br, "detector_metrics", None)
        if isinstance(detector_metrics, Mapping):
            permission_metrics = detector_metrics.get("permissions_profile")
            if isinstance(permission_metrics, Mapping):
                profiles = permission_metrics.get("permission_profiles")
                if isinstance(profiles, Mapping):
                    permission_profiles_map = profiles

        persist_permission_matrix(
            static_run_id=int(static_run_id) if static_run_id is not None else None,
            package_name=package_for_run,
            apk_id=apk_identifier,
            permission_profiles=permission_profiles_map,
        )
        persist_permission_risk(
            run_id=int(run_id),
            report=br,
            package_name=package_for_run,
            session_stamp=session_stamp,
            scope_label=scope_label,
            metrics_bundle=metrics_bundle,
            baseline_payload=baseline_payload,
        )

    perm_detail_map: Mapping[str, object] = (
        metrics_bundle.permission_detail
        if isinstance(metrics_bundle.permission_detail, Mapping)
        else {}
    )
    flagged_normal_metric = float(perm_detail_map.get("flagged_normal_count", 0) or 0)
    weak_guard_metric = float(perm_detail_map.get("weak_guard_count", 0) or 0)

    metrics_payload = {
        "network.code_http_hosts": (float(code_http_hosts), None),
        "network.asset_http_hosts": (float(asset_http_hosts), None),
        "exports.total": (float(getattr(getattr(br, "exported_components", None), "total", lambda: 0)()), None),
        "permissions.dangerous_count": (float(getattr(metrics_bundle, "dangerous_permissions", 0)), None),
        "permissions.signature_count": (float(getattr(metrics_bundle, "signature_permissions", 0)), None),
        "permissions.oem_count": (float(getattr(metrics_bundle, "oem_permissions", 0)), None),
        "permissions.flagged_normal_count": (flagged_normal_metric, None),
        "permissions.weak_guard_count": (weak_guard_metric, None),
        "permissions.risk_score": (float(getattr(metrics_bundle, "permission_score", 0.0)), None),
        "permissions.risk_grade": (None, getattr(metrics_bundle, "permission_grade", "")),
    }
    metrics_payload["findings.total"] = (float(total_findings), None)
    if downgraded_high:
        metrics_payload["findings.high_downgraded"] = (float(downgraded_high), None)
    rule_cov_pct = (float(rule_assigned) / float(total_findings) * 100.0) if total_findings else 0.0
    base_cov_pct = (float(base_vector_count) / float(total_findings) * 100.0) if total_findings else 0.0
    bte_cov_pct = (float(bte_vector_count) / float(total_findings) * 100.0) if total_findings else 0.0
    preview_cov_pct = (float(preview_assigned) / float(total_findings) * 100.0) if total_findings else 0.0
    path_cov_pct = (float(path_assigned) / float(total_findings) * 100.0) if total_findings else 0.0
    metrics_payload["findings.ruleid_coverage_pct"] = (rule_cov_pct, None)
    metrics_payload["findings.preview_coverage_pct"] = (preview_cov_pct, None)
    metrics_payload["findings.path_coverage_pct"] = (path_cov_pct, None)
    metrics_payload["cvss.base_vector_coverage_pct"] = (base_cov_pct, None)
    metrics_payload["cvss.bte_vector_coverage_pct"] = (bte_cov_pct, None)

    if run_id is not None and not write_metrics(int(run_id), metrics_payload, static_run_id=static_run_id):
        message = f"Failed to persist metrics for run_id={run_id}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)

    summary_run_id = run_id if run_id is not None else "dry-run"
    log.info(
        (
            f"Persistence summary for {run_package} (run_id={summary_run_id}): "
            f"findings={total_findings} "
            f"rule_id={rule_cov_pct:.1f}% "
            f"preview={preview_cov_pct:.1f}% "
            f"path={path_cov_pct:.1f}% "
            f"bte={bte_cov_pct:.1f}%"
        ),
        category="static_analysis",
    )

    contributors = metrics_bundle.contributors
    if contributors and run_id is not None:
        if not write_contributors(int(run_id), contributors):
            message = f"Failed to persist contributor breakdown for run_id={run_id}"
            log.warning(message, category="static_analysis")
            outcome.add_error(message)

    if run_id is not None:
        baseline_section = baseline_payload.get("baseline") if isinstance(baseline_payload, Mapping) else {}
        string_payload = baseline_section.get("string_analysis") if isinstance(baseline_section, Mapping) else {}
        static_errors, baseline_written, sample_total = _persist_static_sections_wrapper(
            package_name=package_for_run,
            session_stamp=session_stamp,
            scope_label=scope_label,
            finding_totals=persisted_totals,
            baseline_section=baseline_section if isinstance(baseline_section, Mapping) else {},
            string_payload=string_payload if isinstance(string_payload, Mapping) else {},
            manifest=br.manifest,
            app_metadata=baseline_payload.get("app") if isinstance(baseline_payload, Mapping) else {},
            run_id=run_id,
            static_run_id=static_run_id,
        )
        if baseline_written:
            outcome.baseline_written = True
        outcome.string_samples_persisted = sample_total
        for err in static_errors:
            outcome.add_error(err)

    if static_run_id and not dry_run:
        update_static_run_status(
            static_run_id=static_run_id,
            status=run_status,
            ended_at_utc=ended_at_utc,
            abort_reason=abort_reason,
            abort_signal=abort_signal,
        )

    return outcome


__all__ = [
    "persist_run_summary",
    "create_static_run_ledger",
    "update_static_run_status",
    "finalize_open_static_runs",
    "PersistenceOutcome",
]
