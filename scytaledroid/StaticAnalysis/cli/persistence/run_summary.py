"""High-level static analysis run persistence pipeline."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_core.session import database_session
from scytaledroid.Database.db_func.static_analysis.persistence_failures import (
    record_static_persistence_failure,
)
from scytaledroid.Database.db_utils.package_utils import normalize_package_name
from scytaledroid.Database.db_utils import diagnostics as db_diagnostics
from scytaledroid.Persistence import db_writer as _dw
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.version_utils import get_git_commit

from ...core.findings import Badge, Finding
from ..core.cvss_v4 import apply_profiles
from ..core.masvs_mapper import rule_to_area, summarise_controls
from ..core.rule_ids import derive_rule_id
from ..reports.evidence_report import normalize_evidence
from . import assembly as _assembly
from . import manifest_writer as _manifest_writer
from . import run_writers as _run_writers
from .dep_export import export_dep_json
from .findings_writer import (
    compute_cvss_base,
    derive_masvs_tag,
    extract_rule_hint,
    persist_findings,
    persist_masvs_controls,
)
from .metrics_writer import compute_metrics_bundle, write_buckets, write_contributors, write_metrics
from .permission_matrix import persist_permission_matrix
from .permission_risk import persist_permission_risk
from .run_envelope import prepare_run_envelope
from .contracts import normalize_run_status
from .static_sections import (
    coerce_severity_counts,
    persist_static_sections,
    persist_storage_surface_data,
)
from .utils import (
    canonical_decimal_text,
    canonical_severity_counts,
    first_text,
    normalise_severity_token,
    require_canonical_schema,
    safe_int,
    truncate,
)


def _normalize_datetime_value(value: str | None) -> str | None:
    return _run_writers._normalize_datetime_value(value)


def _severity_band_from_badge(badge: Badge) -> str:
    return _assembly.severity_band_from_badge(badge)


def _score_from_finding(finding: Finding) -> int:
    return _assembly.score_from_finding(finding)


def _correlation_rows_from_result(
    result: object,
    *,
    static_run_id: int,
    package_name: str,
) -> list[dict[str, object]]:
    return _assembly.correlation_rows_from_result(
        result,
        static_run_id=static_run_id,
        package_name=package_name,
    )


@dataclass(slots=True)
class PersistenceOutcome:
    run_id: int | None = None
    static_run_id: int | None = None
    runtime_findings: int = 0
    persisted_findings: int = 0
    baseline_written: bool = False
    string_samples_persisted: int = 0
    persistence_failed: bool = False
    canonical_failed: bool = False
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


def _json_safe(value: object) -> object:
    return _manifest_writer._json_safe(value)


def _finding_cap_for_detector(detector_id: str) -> int:
    default_cap = int(getattr(app_config, "STATIC_FINDINGS_CAP_PER_DETECTOR", 20) or 20)
    overrides_raw = getattr(app_config, "STATIC_FINDINGS_CAP_OVERRIDES", {})
    overrides = overrides_raw if isinstance(overrides_raw, Mapping) else {}
    value = overrides.get(detector_id)
    if value is None:
        return max(1, default_cap)
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return max(1, default_cap)


def _taxonomy_label(*, severity: str, detector_status: object, policy_gate: bool) -> str:
    status_text = str(getattr(detector_status, "value", detector_status) or "").upper()
    if severity == "Info":
        return "INFO"
    if status_text == "FAIL" and not policy_gate:
        return "FINDING"
    return "RISK"


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
                    json.dumps(corr_payload, ensure_ascii=True, indent=2, default=str),
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


def _persist_static_analysis_findings(
    *,
    static_run_id: int,
    rows: Sequence[Mapping[str, object]],
) -> None:
    """Persist canonical per-finding rows for a static run."""

    core_q.run_sql(
        "DELETE FROM static_analysis_findings WHERE run_id=%s",
        (static_run_id,),
        query_name="static_findings_canonical.delete",
    )
    if not rows:
        return
    sql = """
        INSERT INTO static_analysis_findings (
          run_id, finding_id, status, severity, category, title, tags, evidence, fix,
          rule_id, cvss_score, masvs_control, detector, module, evidence_refs
        ) VALUES (
          %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
    """
    params: list[tuple[object, ...]] = []
    for row in rows:
        params.append(
            (
                static_run_id,
                row.get("finding_id"),
                row.get("status"),
                row.get("severity"),
                row.get("category"),
                row.get("title"),
                row.get("tags"),
                row.get("evidence"),
                row.get("fix"),
                row.get("rule_id"),
                row.get("cvss_score"),
                row.get("masvs_control"),
                row.get("detector"),
                row.get("module"),
                row.get("evidence_refs"),
            )
        )
    core_q.run_sql_many(sql, params, query_name="static_findings_canonical.insert")


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
    return _run_writers._ensure_app_version(
        package_for_run=package_for_run,
        display_name=display_name,
        version_name=version_name,
        version_code=version_code,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
    )


def _create_static_run(
    *,
    app_version_id: int,
    session_stamp: str,
    session_label: str,
    scope_label: str,
    category: str | None,
    profile: str,
    profile_key: str | None,
    scenario_id: str | None,
    device_serial: str | None,
    tool_semver: str | None,
    tool_git_commit: str | None,
    schema_version: str | None,
    findings_total: int,
    run_started_utc: str | None,
    status: str,
    is_canonical: bool | None = None,
    canonical_set_at_utc: str | None = None,
    canonical_reason: str | None = None,
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
    return _run_writers._create_static_run(
        app_version_id=app_version_id,
        session_stamp=session_stamp,
        session_label=session_label,
        scope_label=scope_label,
        category=category,
        profile=profile,
        profile_key=profile_key,
        scenario_id=scenario_id,
        device_serial=device_serial,
        tool_semver=tool_semver,
        tool_git_commit=tool_git_commit,
        schema_version=schema_version,
        findings_total=findings_total,
        run_started_utc=run_started_utc,
        status=status,
        is_canonical=is_canonical,
        canonical_set_at_utc=canonical_set_at_utc,
        canonical_reason=canonical_reason,
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


def create_static_run_ledger(
    *,
    package_name: str,
    session_stamp: str,
    session_label: str,
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
    canonical_action: str | None = None,
    dry_run: bool = False,
) -> int | None:
    """Create a STARTED static_analysis_runs row before scanning begins."""
    canonical_actions = {"first_run", "replace", "auto_suffix", "append"}
    canonical_enabled = canonical_action in canonical_actions if canonical_action else False
    return _run_writers.create_static_run_ledger(
        package_name=package_name,
        display_name=display_name or package_name,
        version_name=version_name,
        version_code=version_code,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        session_stamp=session_stamp,
        session_label=session_label,
        scope_label=scope_label,
        category=category,
        profile=profile,
        profile_key=profile,
        scenario_id="static_default",
        device_serial=None,
        tool_semver=app_config.APP_VERSION,
        tool_git_commit=get_git_commit(),
        schema_version=db_diagnostics.get_schema_version() or "<unknown>",
        findings_total=0,
        run_started_utc=run_started_utc,
        status="STARTED",
        is_canonical=True if canonical_enabled else False if canonical_action else None,
        canonical_set_at_utc=run_started_utc if canonical_enabled else None,
        canonical_reason=canonical_action if canonical_enabled else None,
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
    _run_writers.update_static_run_metadata(
        static_run_id=static_run_id,
        sha256=sha256_value,
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


def _maybe_set_canonical_static_run(
    *,
    session_label: str,
    static_run_id: int,
    canonical_action: str,
) -> None:
    if canonical_action not in {"first_run", "replace"}:
        return
    _run_writers.maybe_set_canonical_static_run(
        session_label=session_label,
        static_run_id=static_run_id,
        canonical_reason=canonical_action,
    )


def update_static_run_status(
    *,
    static_run_id: int,
    status: str,
    ended_at_utc: str | None = None,
    abort_reason: str | None = None,
    abort_signal: str | None = None,
) -> None:
    _run_writers.update_static_run_status(
        static_run_id=static_run_id,
        status=status,
        ended_at_utc=ended_at_utc,
        abort_reason=abort_reason,
        abort_signal=abort_signal,
    )


def finalize_open_static_runs(
    static_run_ids: Sequence[int] | None = None,
    *,
    status: str,
    ended_at_utc: str | None = None,
    abort_reason: str | None = None,
    abort_signal: str | None = None,
) -> int:
    """Finalize any STARTED static runs left open by crashes.

    If `static_run_ids` is None, finalize all open runs.
    If `static_run_ids` is an empty sequence, no-op.
    Returns number of rows updated (best-effort; 0 on error).
    """
    if static_run_ids is not None and not static_run_ids:
        return 0
    return int(
        _run_writers.finalize_open_static_runs(
            static_run_ids,
            status=status,
            ended_at_utc=ended_at_utc,
            abort_reason=abort_reason,
            abort_signal=abort_signal,
        )
        or 0
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
    paper_grade_requested: bool | None = None,
    dry_run: bool = False,
) -> PersistenceOutcome:
    outcome = PersistenceOutcome()
    br = base_report
    failure_stage: str | None = None
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
    else:
        try:
            require_canonical_schema()
        except Exception as exc:
            message = f"Canonical schema guard failed for {run_package}: {exc}"
            log.warning(message, category="static_analysis")
            outcome.add_error(message)
            return outcome

    if not session_stamp and metadata_map:
        value = metadata_map.get("session_stamp")
        if isinstance(value, str) and value.strip():
            session_stamp = value.strip()

    if not session_stamp:
        message = f"Missing session stamp for {run_package}; static persistence will be skipped."
        log.warning(message, category="static_analysis")
        outcome.add_error(message)
        return outcome
    package_for_run = normalize_package_name(package_for_run, context="static_analysis")
    if not package_for_run:
        message = "identity_validation_failed: package_name missing or invalid."
        outcome.add_error(message)
        return outcome
    if not str(scope_label or "").strip():
        message = "identity_validation_failed: scope_label missing."
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
    display_name = getattr(manifest_obj, "app_label", None) or package_for_run
    version_name = getattr(manifest_obj, "version_name", None) if manifest_obj else None
    min_sdk = safe_int(
        getattr(manifest_obj, "min_sdk", None)
        or getattr(manifest_obj, "min_sdk_version", None)
    )
    target_sdk = safe_int(getattr(manifest_obj, "target_sdk", None))
    try:
        version_code = safe_int(getattr(manifest_obj, "version_code", None)) if manifest_obj else None
    except Exception:
        version_code = None
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
    scenario_id_token = first_text(
        metadata_map.get("scenario_id") if isinstance(metadata_map, Mapping) else None,
        baseline_payload.get("scenario_id") if isinstance(baseline_payload, Mapping) else None,
        "static_default",
    )
    device_serial_token = first_text(
        metadata_map.get("device_serial") if isinstance(metadata_map, Mapping) else None,
        baseline_payload.get("device_serial") if isinstance(baseline_payload, Mapping) else None,
    )
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
    )
    pipeline_version = first_text(
        metadata_map.get("pipeline_version") if isinstance(metadata_map, Mapping) else None,
    )
    catalog_versions = first_text(
        metadata_map.get("catalog_versions") if isinstance(metadata_map, Mapping) else None,
    )
    study_tag = first_text(
        metadata_map.get("study_tag") if isinstance(metadata_map, Mapping) else None,
    )
    analysis_version = first_text(getattr(br, "analysis_version", None))
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

    outcome.static_run_id = static_run_id
    run_status = normalize_run_status(run_status)
    metrics_bundle = compute_metrics_bundle(br, string_data)
    code_http_hosts = metrics_bundle.code_http_hosts
    asset_http_hosts = metrics_bundle.asset_http_hosts

    db_errors: list[str] = []

    def _note_db_error(message: str) -> None:
        # Standardize DB persistence blockers so batch mode can display actionable reasons.
        normalized = message if message.startswith("db_write_failed:") else f"db_write_failed:{message}"
        outcome.add_error(normalized)
        db_errors.append(normalized)

    def _raise_db_error(op: str, reason: str) -> None:
        token = truncate(f"{op}:{reason}", 240)
        nonlocal failure_stage
        failure_stage = op
        _note_db_error(token)
        raise RuntimeError(token)

    def _canonical_cvss_score(value: object, *, field: str) -> str | None:
        if value is None:
            return None
        try:
            return canonical_decimal_text(
                value,
                field=field,
                scale=1,
                min_value=0.0,
                max_value=10.0,
            )
        except ValueError as exc:
            _raise_db_error("cvss.validation", str(exc))

    baseline_counts = coerce_severity_counts(finding_totals)
    severity_counter: Counter[str] = Counter()
    downgraded_high = 0
    persisted_by_detector: Counter[str] = Counter()
    capped_by_detector: Counter[str] = Counter()
    taxonomy_counter: Counter[str] = Counter()

    finding_rows: list[dict[str, Any]] = []
    canonical_finding_rows: list[dict[str, object]] = []
    control_entries: list[tuple[str, Mapping[str, Any]]] = []
    correlation_rows: list[dict[str, object]] = []
    total_findings = 0
    rule_assigned = 0
    base_vector_count = 0
    bte_vector_count = 0
    preview_assigned = 0
    path_assigned = 0

    try:
        for result in (br.detector_results or ()):  # type: ignore[attr-defined]
            detector_id = str(getattr(result, "detector_id", getattr(result, "section_key", None)) or "unknown")
            detector_cap = _finding_cap_for_detector(detector_id)
            module_id_val = getattr(result, "module_id", None)
            module_id = str(module_id_val) if module_id_val not in (None, "") else None
            result_metrics = getattr(result, "metrics", None)
            policy_gate = bool(result_metrics.get("policy_gate", False)) if isinstance(result_metrics, Mapping) else False
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
                if persisted_by_detector[detector_id] >= detector_cap:
                    capped_by_detector[detector_id] += 1
                    continue
                evidence = normalize_evidence(
                    f.evidence,
                    detail_hint=getattr(f, "detail", None)
                    or getattr(f, "headline", None)
                    or getattr(f, "summary", None)
                    or getattr(f, "because", None),
                    path_hint=getattr(f, "path", None),
                    offset_hint=getattr(f, "offset", None),
                )
                evidence_payload = json.dumps(evidence.as_payload(), ensure_ascii=False, default=str)
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
                base_score_c = _canonical_cvss_score(base_score, field="cvss.base_score")
                bt_score_c = _canonical_cvss_score(bt_score, field="cvss.bt_score")
                be_score_c = _canonical_cvss_score(be_score, field="cvss.be_score")
                bte_score_c = _canonical_cvss_score(bte_score, field="cvss.bte_score")
                if bte_vector:
                    bte_vector_count += 1
                taxonomy = _taxonomy_label(
                    severity=sev,
                    detector_status=getattr(result, "status", Badge.INFO),
                    policy_gate=policy_gate,
                )
                taxonomy_counter[taxonomy] += 1
                meta_combined: dict[str, Any] = {}
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
                        "cvss_v40_b_score": base_score_c,
                        "cvss_v40_bt_vector": bt_vector,
                        "cvss_v40_bt_score": bt_score_c,
                        "cvss_v40_be_vector": be_vector,
                        "cvss_v40_be_score": be_score_c,
                        "cvss_v40_bte_vector": bte_vector,
                        "cvss_v40_bte_score": bte_score_c,
                        "cvss_v40_meta": (
                            json.dumps(meta_combined, ensure_ascii=False, default=str)
                            if meta_combined
                            else None
                        ),
                    }
                )
                status_value = str(
                    getattr(getattr(f, "status", None), "value", getattr(f, "status", None))
                    or ""
                ).upper()
                tags_value = getattr(f, "tags", None)
                tags_json = None
                if isinstance(tags_value, Sequence) and not isinstance(tags_value, (str, bytes)):
                    tags_json = json.dumps([str(tag) for tag in tags_value], ensure_ascii=False)
                evidence_refs_payload = None
                if isinstance(metrics_map, Mapping):
                    hashes_payload = metrics_map.get("hashes") or metrics_map.get("evidence_refs")
                    if hashes_payload is not None:
                        evidence_refs_payload = json.dumps(hashes_payload, ensure_ascii=False, default=str)
                canonical_finding_rows.append(
                    {
                        "finding_id": truncate(first_text(getattr(f, "finding_id", None), rule_id), 128),
                        "status": truncate(status_value, 32),
                        "severity": truncate(sev, 32),
                        "category": truncate(masvs_area, 64),
                        "title": truncate(
                            first_text(getattr(f, "title", None), evidence_preview, detector_id),
                            512,
                        ),
                        "tags": tags_json,
                        "evidence": evidence_payload,
                        "fix": truncate(first_text(getattr(f, "remediate", None)), 2048),
                        "rule_id": truncate(rule_id, 128),
                        "cvss_score": base_score_c,
                        "masvs_control": truncate(masvs_area, 32),
                        "detector": truncate(detector_id, 64),
                        "module": truncate(module_id, 64),
                        "evidence_refs": evidence_refs_payload,
                    }
                )
                persisted_by_detector[detector_id] += 1
                control_entries.extend(getattr(result, "masvs_coverage", []))
    except Exception as exc:
        message = f"Failed to coerce findings for {run_package}: {exc}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)

    control_summary = summarise_controls(control_entries)
    outcome.runtime_findings = int(total_findings)
    outcome.persisted_findings = len(finding_rows)
    missing_masvs = sum(1 for row in finding_rows if not row.get("masvs"))
    if missing_masvs:
        log.warning(
            f"{missing_masvs} findings missing MASVS tags for {run_package}; "
            "DB MASVS Summary may be incomplete.",
            category="static_analysis",
        )

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

    perm_detail_map: Mapping[str, object] = (
        metrics_bundle.permission_detail
        if isinstance(metrics_bundle.permission_detail, Mapping)
        else {}
    )
    flagged_normal_metric = float(perm_detail_map.get("flagged_normal_count", 0) or 0)
    weak_guard_metric = float(perm_detail_map.get("weak_guard_count", 0) or 0)

    exported = getattr(br, "exported_components", None)
    exp_total = float(getattr(exported, "total", lambda: 0)()) if exported else 0.0
    exp_activities = float(len(getattr(exported, "activities", []) or [])) if exported else 0.0
    exp_services = float(len(getattr(exported, "services", []) or [])) if exported else 0.0
    exp_receivers = float(len(getattr(exported, "receivers", []) or [])) if exported else 0.0
    exp_providers = float(len(getattr(exported, "providers", []) or [])) if exported else 0.0

    metrics_payload = {
        "network.code_http_hosts": (float(code_http_hosts), None),
        "network.asset_http_hosts": (float(asset_http_hosts), None),
        "exports.total": (exp_total, None),
        "exports.activities": (exp_activities, None),
        "exports.services": (exp_services, None),
        "exports.receivers": (exp_receivers, None),
        "exports.providers": (exp_providers, None),
        "permissions.dangerous_count": (float(getattr(metrics_bundle, "dangerous_permissions", 0)), None),
        "permissions.signature_count": (float(getattr(metrics_bundle, "signature_permissions", 0)), None),
        "permissions.oem_count": (float(getattr(metrics_bundle, "oem_permissions", 0)), None),
        "permissions.flagged_normal_count": (flagged_normal_metric, None),
        "permissions.weak_guard_count": (weak_guard_metric, None),
        "permissions.risk_score": (float(getattr(metrics_bundle, "permission_score", 0.0)), None),
        "permissions.risk_grade": (None, getattr(metrics_bundle, "permission_grade", "")),
    }
    metrics_payload["findings.total"] = (float(total_findings), None)
    metrics_payload["findings.persisted_total"] = (float(len(finding_rows)), None)
    if downgraded_high:
        metrics_payload["findings.high_downgraded"] = (float(downgraded_high), None)
    capped_total = int(sum(capped_by_detector.values()))
    metrics_payload["findings.capped_total"] = (float(capped_total), None)
    metrics_payload["findings.cap_per_detector_default"] = (float(_finding_cap_for_detector("__default__")), None)
    for detector_id, dropped in sorted(capped_by_detector.items()):
        metrics_payload[f"findings.capped.{detector_id}"] = (float(dropped), None)
    for label in ("RISK", "FINDING", "INFO"):
        metrics_payload[f"findings.taxonomy.{label.lower()}"] = (float(taxonomy_counter.get(label, 0)), None)
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

    # Canonicalize numeric metrics to deterministic fixed precision before write.
    canonical_metrics_payload: dict[str, tuple[object | None, str | None]] = {}
    for key, (num_value, text_value) in metrics_payload.items():
        if num_value is None:
            canonical_metrics_payload[key] = (None, text_value)
            continue
        try:
            canonical_num = canonical_decimal_text(
                num_value,
                field=f"metrics.{key}",
                scale=6,
            )
        except ValueError as exc:
            _raise_db_error("metrics.validation", str(exc))
        canonical_metrics_payload[key] = (canonical_num, text_value)
    metrics_payload = canonical_metrics_payload

    persistence_failed = False
    if not dry_run:
        try:
            with database_session() as db:
                with db.transaction():
                    if run_id is None:
                        try:
                            run_id = _dw.create_run(
                                package=package_for_run,
                                app_label=display_name,
                                version_code=version_code,
                                version_name=version_name,
                                target_sdk=target_sdk,
                                session_stamp=session_stamp,
                                threat_profile=envelope.threat_profile,
                                env_profile=envelope.env_profile,
                            )
                        except Exception as exc:
                            _raise_db_error("run.create", f"{exc.__class__.__name__}:{exc}")
                        if run_id is None:
                            _raise_db_error("run.create", "returned_null")
                        outcome.run_id = int(run_id)

                    if static_run_id is None:
                        app_version_id = _ensure_app_version(
                            package_for_run=package_for_run,
                            display_name=display_name,
                            version_name=version_name,
                            version_code=version_code,
                            min_sdk=min_sdk,
                            target_sdk=target_sdk,
                        )
                        if app_version_id is None:
                            _raise_db_error("static_run.create", "app_version_unresolved")
                        static_run_id = _create_static_run(
                            app_version_id=app_version_id,
                            session_stamp=session_stamp,
                            session_label=session_stamp,
                            scope_label=scope_label,
                            category=category_token,
                            profile=profile_token,
                            profile_key=profile_token,
                            scenario_id=scenario_id_token,
                            device_serial=device_serial_token,
                            tool_semver=app_config.APP_VERSION,
                            tool_git_commit=get_git_commit(),
                            schema_version=db_diagnostics.get_schema_version() or "<unknown>",
                            findings_total=int(finding_totals.get("total", 0) or 0),
                            run_started_utc=None,
                            status="STARTED",
                        )
                        if static_run_id is None:
                            _raise_db_error("static_run.create", "create_failed")
                        log.info(
                            f"Resolved static_run_id={static_run_id} for {package_for_run} (session={session_stamp})",
                            category="static_analysis",
                        )
                    outcome.static_run_id = static_run_id

                    if static_run_id:
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

                    try:
                        ok = write_buckets(int(run_id), metrics_bundle.buckets, static_run_id=static_run_id)
                    except Exception as exc:
                        _raise_db_error("buckets.write", f"{exc.__class__.__name__}:{exc}")
                    if not ok:
                        _raise_db_error("buckets.write", "returned_false")

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
                                    f"sample={json.dumps(sample_view, ensure_ascii=False, default=str)}"
                                ),
                                category="static_analysis",
                            )
                        elif not persist_findings(int(run_id), finding_rows, static_run_id=static_run_id):
                            _raise_db_error(
                                "findings.write",
                                f"returned_false:run_id={run_id}:static_run_id={static_run_id}",
                            )
                        if static_run_id is not None:
                            try:
                                _persist_static_analysis_findings(
                                    static_run_id=int(static_run_id),
                                    rows=canonical_finding_rows,
                                )
                            except Exception as exc:
                                _raise_db_error(
                                    "canonical_findings.write",
                                    f"{exc.__class__.__name__}:{exc}",
                                )

                    if static_run_id and correlation_rows:
                        try:
                            ok = _persist_correlation_results(correlation_rows)
                        except Exception as exc:
                            _raise_db_error("correlations.write", f"{exc.__class__.__name__}:{exc}")
                        if not ok:
                            _raise_db_error("correlations.write", f"returned_false:static_run_id={static_run_id}")

                    if run_id is not None:
                        if control_summary:
                            try:
                                persist_masvs_controls(
                                    int(run_id),
                                    package_for_run,
                                    control_summary,
                                )
                            except Exception as exc:
                                _raise_db_error("masvs_controls.write", f"{exc.__class__.__name__}:{exc}")
                        else:
                            log.info(
                                (
                                    f"No MASVS control coverage derived for {run_package}; "
                                    f"total_findings={total_findings} entries={len(control_entries)}"
                                ),
                                category="static_analysis",
                            )
                        try:
                            persist_storage_surface_data(br, session_stamp, scope_label)
                        except Exception as exc:
                            _raise_db_error("storage_surface.write", f"{exc.__class__.__name__}:{exc}")
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

                        try:
                            persist_permission_matrix(
                                static_run_id=int(static_run_id) if static_run_id is not None else None,
                                package_name=package_for_run,
                                apk_id=apk_identifier,
                                permission_profiles=permission_profiles_map,
                            )
                        except Exception as exc:
                            _raise_db_error("permission_matrix.write", f"{exc.__class__.__name__}:{exc}")
                        try:
                            persist_permission_risk(
                                run_id=int(run_id),
                                report=br,
                                package_name=package_for_run,
                                session_stamp=session_stamp,
                                scope_label=scope_label,
                                metrics_bundle=metrics_bundle,
                                baseline_payload=baseline_payload,
                                permission_profiles=permission_profiles_map,
                            )
                        except Exception as exc:
                            _raise_db_error("permission_risk.write", f"{exc.__class__.__name__}:{exc}")

                    try:
                        ok = write_metrics(int(run_id), metrics_payload, static_run_id=static_run_id)
                    except Exception as exc:
                        _raise_db_error("metrics.write", f"{exc.__class__.__name__}:{exc}")
                    if not ok:
                        _raise_db_error("metrics.write", f"returned_false:run_id={run_id}")

                    contributors = metrics_bundle.contributors
                    if contributors:
                        try:
                            ok = write_contributors(int(run_id), contributors)
                        except Exception as exc:
                            _raise_db_error("contributors.write", f"{exc.__class__.__name__}:{exc}")
                        if not ok:
                            _raise_db_error("contributors.write", f"returned_false:run_id={run_id}")

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
                        _note_db_error(err)

                    if db_errors:
                        raise RuntimeError(db_errors[-1])
        except Exception as exc:
            persistence_failed = True
            message = f"Static persistence transaction failed for {run_package}: {exc}"
            log.warning(message, category="static_analysis")
            if message not in outcome.errors:
                outcome.add_error(message)
            # Best-effort durable failure record (outside the rolled-back transaction).
            if static_run_id:
                try:
                    record_static_persistence_failure(
                        static_run_id=int(static_run_id),
                        stage=failure_stage,
                        exc_class=exc.__class__.__name__,
                        exc_message=str(exc),
                        errors_tail=list(outcome.errors)[-10:],
                    )
                except Exception:
                    pass
            # Transaction failed: scientific rows are rolled back and no run_id is authoritative.
            static_run_id = None
            outcome.static_run_id = None
        outcome.persistence_failed = persistence_failed
    else:
        if finding_rows:
            sample = finding_rows[0] if finding_rows else {}
            sample_view = {
                key: sample.get(key)
                for key in ("rule_id", "evidence_path", "evidence_preview", "severity")
            }
            log.info(
                (
                    f"Dry-run persistence payload for {run_package}: "
                    f"findings={total_findings} "
                    f"sample={json.dumps(sample_view, ensure_ascii=False, default=str)}"
                ),
                category="static_analysis",
            )

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

    if static_run_id and not dry_run:
        dep_path = export_dep_json(static_run_id)
        if dep_path:
            log.info(
                f"DEP snapshot written for static_run_id={static_run_id}",
                category="static_analysis",
            )

    if static_run_id and not dry_run:
        if paper_grade_requested is None:
            paper_grade_requested = True

        if persistence_failed:
            run_status = "FAILED"
        # Canonical enforcement must check the *session_label* that was actually written for this run.
        # session_stamp may differ (e.g., auto-suffix collisions), and using the stamp here can
        # incorrectly fail PAPER_GRADE runs with "found 0 canonicals".
        enforced_session_label: str | None = None
        if static_run_id:
            try:
                row = core_q.run_sql(
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

        if not persistence_failed and enforced_session_label and paper_grade_requested:
            try:
                row = core_q.run_sql(
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

        # Keep static_analysis_runs.findings_total consistent with persisted findings.
        # This value is used by DB health summaries and run listings; leaving it at 0
        # makes completed runs look empty even when static_findings rows exist.
        try:
            total_findings = int(finding_totals.get("total", 0) or 0)
        except Exception:
            total_findings = 0
        try:
            core_q.run_sql(
                "UPDATE static_analysis_runs SET findings_total=%s WHERE id=%s",
                (total_findings, static_run_id),
            )
        except Exception:
            # Never fail the run due to a rollup write; the per-finding rows are authoritative.
            pass

        update_static_run_status(
            static_run_id=static_run_id,
            status=normalize_run_status(run_status),
            ended_at_utc=ended_at_utc,
            abort_reason=abort_reason,
            abort_signal=abort_signal,
        )
        # Manifest publication is deferred until artifacts are registered.

    return outcome


def _write_static_run_manifest(
    static_run_id: int,
    *,
    grade: str,
    grade_reasons: Sequence[str] | None = None,
) -> bool:
    return _manifest_writer.write_static_run_manifest(
        static_run_id,
        grade=grade,
        grade_reasons=grade_reasons,
    )


def refresh_static_run_manifest(
    static_run_id: int,
    *,
    grade: str,
    grade_reasons: Sequence[str] | None = None,
) -> bool:
    return _manifest_writer.refresh_static_run_manifest(
        static_run_id,
        grade=grade,
        grade_reasons=grade_reasons,
    )


__all__ = [
    "persist_run_summary",
    "create_static_run_ledger",
    "update_static_run_status",
    "finalize_open_static_runs",
    "refresh_static_run_manifest",
    "PersistenceOutcome",
]
