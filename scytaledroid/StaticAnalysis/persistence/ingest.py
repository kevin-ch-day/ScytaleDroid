"""Idempotent ingest helpers for canonical static-analysis tables.

This module provides minimal utilities to upsert app/app_version and attach
observations (endpoints, secrets, analytics IDs, findings). It is safe to
import without a live database; functions return booleans or IDs and swallow
errors where appropriate.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Mapping, MutableMapping, Optional, Sequence

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_queries.canonical import schema as canonical_schema


def _ensure_schema_ready() -> bool:
    try:
        return canonical_schema.ensure_all()
    except Exception:
        return False


def _normalise_optional_str(value: object) -> Optional[str]:
    if value is None:
        return None
    candidate = value
    if hasattr(candidate, "value"):
        try:
            candidate = getattr(candidate, "value")
        except Exception:
            candidate = value
    text = str(candidate).strip()
    return text or None


def _serialise_json(value: object) -> Optional[str]:
    if value is None:
        return None
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return None


def _loads_json(value: object) -> Optional[object]:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", errors="ignore")
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    if isinstance(value, Mapping):
        return dict(value)
    return None


def _prepare_tags(value: object) -> Optional[object]:
    if isinstance(value, Mapping):
        return {str(key): val for key, val in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        prepared: list[str] = []
        for entry in value:
            text = _normalise_optional_str(entry)
            if text:
                prepared.append(text)
        return prepared or None
    return None


def _prepare_evidence(value: object) -> Optional[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        return {str(key): val for key, val in value.items()}
    return None


def _first_non_empty_str(*values: object) -> Optional[str]:
    for value in values:
        text = _normalise_optional_str(value)
        if text:
            return text
    return None


def _extract_findings(payload: Mapping[str, object]) -> Sequence[Mapping[str, object]]:
    findings_payload = payload.get("findings")
    if isinstance(findings_payload, Sequence) and not isinstance(
        findings_payload, (str, bytes)
    ):
        return [
            entry
            for entry in findings_payload
            if isinstance(entry, Mapping)
        ]
    baseline_section = payload.get("baseline")
    if isinstance(baseline_section, Mapping):
        baseline_findings = baseline_section.get("findings")
        if isinstance(baseline_findings, Sequence) and not isinstance(
            baseline_findings, (str, bytes)
        ):
            return [
                entry
                for entry in baseline_findings
                if isinstance(entry, Mapping)
            ]
    return []


def _build_finding_context(
    payload: Mapping[str, object]
) -> Mapping[str, Mapping[str, object]]:
    context: MutableMapping[str, Mapping[str, object]] = {}
    results = payload.get("detector_results")
    if not isinstance(results, Sequence) or isinstance(results, (str, bytes)):
        return context
    for result in results:
        if not isinstance(result, Mapping):
            continue
        detector_id = _normalise_optional_str(result.get("detector_id"))
        module = _normalise_optional_str(result.get("section_key"))
        findings = result.get("findings")
        if not isinstance(findings, Sequence) or isinstance(findings, (str, bytes)):
            continue
        for entry in findings:
            if not isinstance(entry, Mapping):
                continue
            finding_id = _first_non_empty_str(
                entry.get("finding_id"),
                entry.get("id"),
            )
            if not finding_id:
                continue
            metrics = (
                entry.get("metrics")
                if isinstance(entry.get("metrics"), Mapping)
                else {}
            )
            context[finding_id] = {
                "detector": detector_id,
                "module": module,
                "cvss": entry.get("cvss") or metrics.get("cvss") or metrics.get("cvss_score"),
                "masvs_control": entry.get("masvs_control") or metrics.get("masvs_control"),
                "evidence_refs": metrics.get("hashes") or metrics.get("evidence_refs"),
            }
    return context


def _get_or_create_app(package_name: str, display_name: Optional[str] = None) -> Optional[int]:
    try:
        row = core_q.run_sql(
            "SELECT id FROM apps WHERE package_name = %s",
            (package_name,),
            fetch="one",
        )
        if row and row[0]:
            return int(row[0])
        new_id = core_q.run_sql(
            "INSERT INTO apps (package_name, display_name) VALUES (%s, %s)",
            (package_name, display_name),
            return_lastrowid=True,
        )
        return int(new_id) if new_id else None
    except Exception:
        return None


def _get_or_create_version(
    app_id: int,
    *,
    version_name: Optional[str],
    version_code: Optional[int],
    min_sdk: Optional[int],
    target_sdk: Optional[int],
) -> Optional[int]:
    try:
        row = core_q.run_sql(
            "SELECT id FROM app_versions WHERE app_id = %s AND version_name <=> %s AND version_code <=> %s",
            (app_id, version_name, version_code),
            fetch="one",
        )
        if row and row[0]:
            return int(row[0])
        new_id = core_q.run_sql(
            (
                "INSERT INTO app_versions (app_id, version_name, version_code, min_sdk, target_sdk) "
                "VALUES (%s, %s, %s, %s, %s)"
            ),
            (app_id, version_name, version_code, min_sdk, target_sdk),
            return_lastrowid=True,
        )
        return int(new_id) if new_id else None
    except Exception:
        return None


def ingest_baseline_payload(payload: Mapping[str, object]) -> bool:
    """Upsert app + version rows from a baseline payload. Returns True on success.

    This function does not yet persist observations; it establishes the app and
    version records to support later canonical ingestion.
    """
    try:
        if not isinstance(payload, Mapping):
            return False
        if not _ensure_schema_ready():
            return False

        app_section = payload.get("app")
        app = app_section if isinstance(app_section, Mapping) else {}
        package = _first_non_empty_str(app.get("package"), app.get("package_name")) or ""
        if not package:
            return False
        display_name = _first_non_empty_str(app.get("label"), app.get("app_label")) or package
        app_id = _get_or_create_app(package, display_name)
        if not app_id:
            return False
        version_name = app.get("version_name")
        version_code = app.get("version_code")
        min_sdk = app.get("min_sdk")
        target_sdk = app.get("target_sdk")
        version_id = _get_or_create_version(
            int(app_id),
            version_name=str(version_name) if version_name is not None else None,
            version_code=int(version_code) if version_code is not None else None,
            min_sdk=int(min_sdk) if min_sdk is not None else None,
            target_sdk=int(target_sdk) if target_sdk is not None else None,
        )
        if version_id and isinstance(payload, Mapping):
            _persist_analysis_snapshot(int(version_id), payload)
        return True
    except Exception:
        return False


__all__ = [
    "ingest_baseline_payload",
    "ensure_provider_plumbing",
    "upsert_base002_for_session",
    "build_session_string_view",
]


def _persist_analysis_snapshot(app_version_id: int, payload: Mapping[str, object]) -> None:
    findings: Sequence[Mapping[str, object]] = _extract_findings(payload)

    hashes_raw = payload.get("hashes")
    hashes_payload = hashes_raw if isinstance(hashes_raw, Mapping) else {}
    sha256 = _first_non_empty_str(hashes_payload.get("sha256"))
    analysis_version = _first_non_empty_str(
        payload.get("analysis_version"),
        hashes_payload.get("analysis_version"),
    )
    metadata_raw = payload.get("metadata")
    metadata = metadata_raw if isinstance(metadata_raw, Mapping) else {}
    profile = _first_non_empty_str(
        payload.get("scan_profile"),
        metadata.get("scan_profile"),
        metadata.get("run_profile"),
    )
    session_stamp = _first_non_empty_str(
        metadata.get("session_stamp"),
        payload.get("session_stamp"),
    )
    scope_label = _first_non_empty_str(
        metadata.get("run_scope_label"),
        metadata.get("scope_label"),
        payload.get("run_scope_label"),
        payload.get("scope_label"),
    )
    detector_metrics_raw = payload.get("detector_metrics")
    if not isinstance(detector_metrics_raw, Mapping):
        detector_metrics_raw = metadata.get("detector_metrics") if isinstance(metadata, Mapping) else {}
    detector_metrics = (
        dict(detector_metrics_raw)
        if isinstance(detector_metrics_raw, Mapping)
        else {}
    )
    repro_bundle: Optional[Mapping[str, object]]
    repro_bundle = (
        metadata.get("repro_bundle")
        if isinstance(metadata, Mapping)
        else None
    )
    if repro_bundle is None:
        baseline_section = payload.get("baseline")
        if isinstance(baseline_section, Mapping):
            repro_bundle = baseline_section

    analytics_section = payload.get("analytics")
    matrices_payload: Mapping[str, object] | None = None
    indicators_payload: Mapping[str, object] | None = None
    workload_payload: Mapping[str, object] | None = None
    if isinstance(analytics_section, Mapping):
        matrices_candidate = analytics_section.get("matrices")
        if isinstance(matrices_candidate, Mapping):
            matrices_payload = matrices_candidate
        indicators_candidate = analytics_section.get("indicators")
        if isinstance(indicators_candidate, Mapping):
            indicators_payload = indicators_candidate
        workload_candidate = analytics_section.get("workload")
        if isinstance(workload_candidate, Mapping):
            workload_payload = workload_candidate

    run_id = _create_run_row(
        app_version_id,
        sha256=sha256,
        analysis_version=analysis_version,
        profile=profile,
        session_stamp=session_stamp,
        scope_label=scope_label,
        findings_total=len(findings),
        detector_metrics=detector_metrics,
        repro_bundle=repro_bundle,
        analysis_matrices=matrices_payload,
        analysis_indicators=indicators_payload,
        workload_profile=workload_payload,
    )

    if run_id is None:
        return

    context_map = _build_finding_context(payload)
    for finding in findings:
        finding_id = _first_non_empty_str(
            finding.get("finding_id"),
            finding.get("id"),
        )
        context = context_map.get(finding_id or "") if finding_id else None
        _create_finding_row(run_id, finding, context=context)

    _persist_provider_acl(run_id, detector_metrics)


def _create_run_row(
    app_version_id: int,
    *,
    sha256: object,
    analysis_version: object,
    profile: object,
    session_stamp: object,
    scope_label: object,
    findings_total: int,
    detector_metrics: Mapping[str, object] | None,
    repro_bundle: object,
    analysis_matrices: Mapping[str, object] | None,
    analysis_indicators: Mapping[str, object] | None,
    workload_profile: Mapping[str, object] | None,
) -> Optional[int]:
    try:
        run_id = core_q.run_sql(
            (
                "INSERT INTO static_analysis_runs (app_version_id, session_stamp, scope_label, sha256, analysis_version, "
                "profile, findings_total, detector_metrics, repro_bundle, analysis_matrices, analysis_indicators, workload_profile) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            ),
            (
                app_version_id,
                _normalise_optional_str(session_stamp),
                _normalise_optional_str(scope_label),
                _normalise_optional_str(sha256),
                _normalise_optional_str(analysis_version),
                _normalise_optional_str(profile),
                findings_total,
                _serialise_json(detector_metrics),
                _serialise_json(repro_bundle),
                _serialise_json(analysis_matrices),
                _serialise_json(analysis_indicators),
                _serialise_json(workload_profile),
            ),
            return_lastrowid=True,
        )
        return int(run_id) if run_id else None
    except Exception:
        return None


def _create_finding_row(
    run_id: int,
    finding: Mapping[str, object],
    *,
    context: Mapping[str, object] | None = None,
) -> None:
    try:
        finding_id = _first_non_empty_str(
            finding.get("finding_id"),
            finding.get("id"),
        )
        status = _first_non_empty_str(finding.get("status"), finding.get("state"))
        severity = _first_non_empty_str(
            finding.get("severity_gate"),
            finding.get("severity"),
            finding.get("level"),
        ) or "Info"
        category = _first_non_empty_str(
            finding.get("category_masvs"),
            finding.get("category"),
        )
        title = _first_non_empty_str(finding.get("title"), finding.get("message"))
        if title:
            title = title[:512]
        fix_text = _first_non_empty_str(finding.get("fix"))
        if fix_text:
            fix_text = fix_text[:2048]
        rule_id = _first_non_empty_str(finding.get("rule_id"))
        tags_payload = _prepare_tags(finding.get("tags"))
        evidence_payload = _prepare_evidence(finding.get("evidence"))
        context_payload = context or {}
        cvss_value = context_payload.get("cvss") if isinstance(context_payload, Mapping) else None
        masvs_control = context_payload.get("masvs_control") if isinstance(context_payload, Mapping) else None
        detector = context_payload.get("detector") if isinstance(context_payload, Mapping) else None
        module = context_payload.get("module") if isinstance(context_payload, Mapping) else None
        evidence_refs = context_payload.get("evidence_refs") if isinstance(context_payload, Mapping) else None
        core_q.run_sql(
            (
                "INSERT INTO static_analysis_findings (run_id, finding_id, status, severity, category, title, tags, evidence, fix, rule_id, cvss_score, masvs_control, detector, module, evidence_refs) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            ),
            (
                run_id,
                finding_id,
                status,
                severity,
                category,
                title,
                _serialise_json(tags_payload),
                _serialise_json(evidence_payload),
                fix_text,
                rule_id,
                cvss_value,
                _normalise_optional_str(masvs_control),
                _normalise_optional_str(detector),
                _normalise_optional_str(module),
                _serialise_json(evidence_refs),
            ),
        )
    except Exception:
        return


def _persist_provider_acl(
    run_id: int,
    detector_metrics: Mapping[str, object] | None,
) -> None:
    if not detector_metrics:
        return
    provider_metrics = detector_metrics.get("provider_acl")
    if not isinstance(provider_metrics, Mapping):
        return
    snapshot = provider_metrics.get("acl_snapshot")
    if not isinstance(snapshot, Sequence) or isinstance(snapshot, (str, bytes)):
        return
    for entry in snapshot:
        if not isinstance(entry, Mapping):
            continue
        provider_id = _create_provider_row(run_id, entry)
        if not provider_id:
            continue
        path_rules = entry.get("path_permissions")
        if isinstance(path_rules, Sequence) and not isinstance(path_rules, (str, bytes)):
            for rule in path_rules:
                if isinstance(rule, Mapping):
                    _create_provider_acl_row(provider_id, rule)


def _create_provider_row(run_id: int, entry: Mapping[str, object]) -> Optional[int]:
    try:
        metrics_payload = {
            key: value
            for key, value in entry.items()
            if key in {"base_levels", "read_levels", "write_levels"}
        }
        provider_id = core_q.run_sql(
            (
                "INSERT INTO static_fileproviders (run_id, component_name, authorities, exported, base_permission, read_permission, "
                "write_permission, base_guard, read_guard, write_guard, effective_guard, grant_uri_permissions, metrics) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            ),
            (
                run_id,
                _normalise_optional_str(entry.get("name")),
                _serialise_json(entry.get("authorities")),
                1 if entry.get("exported") else 0,
                _normalise_optional_str(entry.get("base_permission")),
                _normalise_optional_str(entry.get("read_permission")),
                _normalise_optional_str(entry.get("write_permission")),
                _normalise_optional_str(entry.get("base_guard")),
                _normalise_optional_str(entry.get("read_guard")),
                _normalise_optional_str(entry.get("write_guard")),
                _normalise_optional_str(entry.get("effective_guard")),
                1 if entry.get("grant_uri_permissions") else 0,
                _serialise_json(metrics_payload),
            ),
            return_lastrowid=True,
        )
        return int(provider_id) if provider_id else None
    except Exception:
        return None


def _create_provider_acl_row(provider_id: int, entry: Mapping[str, object]) -> None:
    try:
        core_q.run_sql(
            (
                "INSERT INTO static_provider_acl (provider_id, path, path_prefix, path_pattern, read_permission, write_permission, "
                "read_guard, write_guard, metadata) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
            ),
            (
                provider_id,
                _normalise_optional_str(entry.get("path")),
                _normalise_optional_str(entry.get("pathPrefix")),
                _normalise_optional_str(entry.get("pathPattern")),
                _normalise_optional_str(entry.get("read_permission")),
                _normalise_optional_str(entry.get("write_permission")),
                _normalise_optional_str(entry.get("read_guard")),
                _normalise_optional_str(entry.get("write_guard")),
                _serialise_json(
                    {
                        key: value
                        for key, value in entry.items()
                        if key not in {
                            "path",
                            "pathPrefix",
                            "pathPattern",
                            "read_permission",
                            "write_permission",
                            "read_guard",
                            "write_guard",
                        }
                    }
                ),
            ),
        )
    except Exception:
        return


def ensure_provider_plumbing() -> bool:
    """Ensure canonical schema and provider views exist."""

    return _ensure_schema_ready()


def _canonical_severity(*guards: object) -> str:
    strengths = [str(guard or "").strip().lower() for guard in guards if guard]
    if any(level in {"none", ""} for level in strengths) or not strengths:
        return "High"
    if any(level in {"weak", "dangerous", "unknown"} for level in strengths):
        return "Medium"
    return "Low"


def _provider_evidence(row: Mapping[str, object]) -> Mapping[str, object]:
    authorities = row.get("authorities")
    parsed_authorities = _loads_json(authorities)
    if isinstance(parsed_authorities, Iterable) and not isinstance(parsed_authorities, (str, bytes)):
        authority_list = list(parsed_authorities)
    elif isinstance(authorities, str) and authorities:
        authority_list = [authorities]
    else:
        authority_list = []

    return {
        "component": row.get("component_name"),
        "package": row.get("package_name"),
        "authorities": authority_list,
        "guards": {
            "effective": row.get("effective_guard"),
            "read": row.get("read_guard"),
            "write": row.get("write_guard"),
        },
        "permissions": {
            "base": row.get("base_permission"),
            "read": row.get("read_permission"),
            "write": row.get("write_permission"),
        },
        "grant_uri_permissions": bool(row.get("grant_uri_permissions")),
        "session_stamp": row.get("session_stamp"),
        "scope_label": row.get("scope_label"),
    }


def upsert_base002_for_session(session_stamp: Optional[str]) -> int:
    """Promote provider exposure candidates into canonical findings."""

    if not _ensure_schema_ready():
        return 0

    clause = ""
    params: tuple[object, ...] = ()
    if session_stamp:
        clause = " WHERE session_stamp = %s"
        params = (session_stamp,)

    try:
        rows = core_q.run_sql(
            (
                "SELECT provider_id, run_id, app_version_id, session_stamp, scope_label, package_name, component_name, "
                "authorities, effective_guard, read_guard, write_guard, base_permission, read_permission, write_permission, "
                "grant_uri_permissions FROM v_base002_candidates" + clause
            ),
            params,
            fetch="all_dict",
        )
    except Exception:
        return 0

    if not rows:
        return 0

    cleared: set[int] = set()
    inserted = 0
    for row in rows:
        run_id = int(row.get("run_id") or 0)
        if not run_id:
            continue
        if run_id not in cleared:
            try:
                core_q.run_sql(
                    "DELETE FROM static_analysis_findings WHERE run_id = %s AND rule_id = 'BASE-002'",
                    (run_id,),
                )
            except Exception:
                pass
            cleared.add(run_id)

        severity = _canonical_severity(
            row.get("effective_guard"),
            row.get("read_guard"),
            row.get("write_guard"),
        )
        evidence_payload = _provider_evidence(row)
        finding_id = f"provider_{row.get('provider_id')}"

        try:
            core_q.run_sql(
                (
                    "INSERT INTO static_analysis_findings (run_id, finding_id, status, severity, category, title, tags, evidence, "
                    "fix, rule_id, detector, module, evidence_refs) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                ),
                (
                    run_id,
                    finding_id,
                    "open",
                    severity,
                    "Platform",
                    "Exported ContentProvider lacks strong guard",
                    _serialise_json(["content_provider", "ipc", "exposure"]),
                    _serialise_json(evidence_payload),
                    "Restrict provider exposure with signature-level permissions or remove exports.",
                    "BASE-002",
                    "provider_acl",
                    "manifest",
                    None,
                ),
            )
            inserted += 1
        except Exception:
            continue

    return inserted


def build_session_string_view(session_stamp: Optional[str]) -> int:
    """Force materialisation of session string samples and return row count."""

    if not _ensure_schema_ready():
        return 0

    clause = ""
    params: tuple[object, ...] = ()
    if session_stamp:
        clause = " WHERE session_stamp = %s"
        params = (session_stamp,)

    try:
        row = core_q.run_sql(
            f"SELECT COUNT(*) FROM v_session_string_samples{clause}",
            params,
            fetch="one",
        )
    except Exception:
        return 0

    if not row:
        return 0
    count = row[0]
    return int(count or 0)

