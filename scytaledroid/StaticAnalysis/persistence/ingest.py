"""Idempotent ingest helpers for canonical static-analysis tables.

This module provides minimal utilities to upsert app/app_version and attach
observations (endpoints, secrets, analytics IDs, findings). It is safe to
import without a live database; functions return booleans or IDs and swallow
errors where appropriate.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, MutableMapping, Sequence
from typing import Any

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_queries.canonical import schema as canonical_schema
from scytaledroid.StaticAnalysis.cli.persistence.utils import first_text
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def _ensure_schema_ready() -> bool:
    try:
        return canonical_schema.ensure_all()
    except Exception:
        return False


def _require_canonical_schema() -> None:
    if not _ensure_schema_ready():
        raise RuntimeError("DB schema is outdated; run migrations to use canonical schema.")


def _normalise_optional_str(value: object) -> str | None:
    if value is None:
        return None
    candidate = value
    if hasattr(candidate, "value"):
        try:
            candidate = candidate.value
        except Exception:
            candidate = value
    text = str(candidate).strip()
    return text or None


def _serialise_json(value: object) -> str | None:
    if value is None:
        return None
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return None


def _loads_json(value: object) -> object | None:
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


def _prepare_tags(value: object) -> object | None:
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


def _prepare_evidence(value: object) -> Mapping[str, Any | None]:
    if isinstance(value, Mapping):
        return {str(key): val for key, val in value.items()}
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
            finding_id = first_text(
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


def _get_or_create_app(package_name: str, display_name: str | None = None) -> int | None:
    try:
        from scytaledroid.Database.db_utils.package_utils import normalize_package_name
        from scytaledroid.Database.db_utils.publisher_rules import apply_publisher_mapping

        cleaned_package = normalize_package_name(package_name, context="database")
        if not cleaned_package:
            return None
        row = core_q.run_sql(
            "SELECT id FROM apps WHERE package_name = %s",
            (cleaned_package,),
            fetch="one",
        )
        if row and row[0]:
            return int(row[0])
        new_id = core_q.run_sql(
            "INSERT INTO apps (package_name, display_name) VALUES (%s, %s)",
            (cleaned_package, display_name),
            return_lastrowid=True,
        )
        apply_publisher_mapping([cleaned_package])
        return int(new_id) if new_id else None
    except Exception as exc:
        log.warning(f"App insert failed: {exc}", category="static_ingest")
        return None


def _get_or_create_version(
    app_id: int,
    *,
    version_name: str | None,
    version_code: int | None,
    min_sdk: int | None,
    target_sdk: int | None,
) -> int | None:
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
    def _warn(reason: str) -> None:
        try:
            pkg = ""
            app = payload.get("app") if isinstance(payload, Mapping) else None
            if isinstance(app, Mapping):
                pkg = first_text(app.get("package"), app.get("package_name")) or ""
            log.warning(f"[ingest] {reason}" + (f" (package={pkg})" if pkg else ""), category="static_ingest")
        except Exception:
            pass

    try:
        if not isinstance(payload, Mapping):
            _warn("payload not a mapping; skipping ingest")
            return False
        _require_canonical_schema()

        app_section = payload.get("app")
        app = app_section if isinstance(app_section, Mapping) else {}
        package = first_text(app.get("package"), app.get("package_name")) or ""
        if not package:
            _warn("missing package name in payload")
            return False
        display_name = first_text(app.get("label"), app.get("app_label")) or package
        app_id = _get_or_create_app(package, display_name)
        if not app_id:
            _warn("failed to upsert app row")
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
        if not version_id:
            _warn("failed to upsert version row")
            return False
        if isinstance(payload, Mapping):
            try:
                _persist_analysis_snapshot(int(version_id), payload)
            except Exception as exc:
                _warn(f"persist_analysis_snapshot failed: {exc}")
                return False
        return True
    except Exception as exc:
        _warn(f"ingest_baseline_payload raised: {exc}")
        return False


__all__ = [
    "ingest_baseline_payload",
    "ensure_provider_plumbing",
    "upsert_base002_for_session",
    "build_session_string_view",
]


_PROVIDER_PARENT_CACHE: dict[int, dict[str, str | None]] = {}


def _persist_analysis_snapshot(app_version_id: int, payload: Mapping[str, object]) -> None:
    metadata_raw = payload.get("metadata")
    metadata = metadata_raw if isinstance(metadata_raw, Mapping) else {}
    profile = first_text(
        payload.get("scan_profile"),
        metadata.get("scan_profile"),
        metadata.get("run_profile"),
    )
    session_stamp = first_text(
        metadata.get("session_stamp"),
        payload.get("session_stamp"),
    )
    scope_label = first_text(
        metadata.get("run_scope_label"),
        metadata.get("scope_label"),
        payload.get("run_scope_label"),
        payload.get("scope_label"),
    )
    category = first_text(
        metadata.get("run_category"),
        metadata.get("category"),
        payload.get("run_category"),
        payload.get("category"),
    )
    detector_metrics_raw = payload.get("detector_metrics")
    if not isinstance(detector_metrics_raw, Mapping):
        detector_metrics_raw = metadata.get("detector_metrics") if isinstance(metadata, Mapping) else {}
    detector_metrics = (
        dict(detector_metrics_raw)
        if isinstance(detector_metrics_raw, Mapping)
        else {}
    )
    repro_bundle: Mapping[str, object | None]
    repro_bundle = (
        metadata.get("repro_bundle")
        if isinstance(metadata, Mapping)
        else None
    )
    if repro_bundle is None:
        baseline_section = payload.get("baseline")
        if isinstance(baseline_section, Mapping):
            repro_bundle = baseline_section


    static_run_id = None
    if session_stamp and profile:
        try:
            row = core_q.run_sql(
                """
                SELECT id
                FROM static_analysis_runs
                WHERE app_version_id=%s
                  AND session_stamp=%s
                  AND profile=%s
                  AND (scope_label=%s OR scope_label=%s)
                ORDER BY id DESC
                LIMIT 1
                """,
                (app_version_id, session_stamp, profile, scope_label, category),
                fetch="one",
            )
            if row and row[0]:
                static_run_id = int(row[0])
        except Exception:
            static_run_id = None

    if static_run_id is None:
        log.warning(
            "No matching static_analysis_runs row for ingest payload; "
            "skipping run-scoped persistence to avoid creating duplicates.",
            category="static_ingest",
        )
        return

    # Legacy static_analysis_findings writes are disabled in Phase-B.
    _persist_provider_acl(static_run_id, detector_metrics)


def _create_run_row(
    app_version_id: int,
    *,
    sha256: object,
    analysis_version: object,
    pipeline_version: object,
    catalog_versions: object,
    config_hash: object,
    study_tag: object,
    run_started_utc: object,
    profile: object,
    session_stamp: object,
    scope_label: object,
    category: object,
    findings_total: int,
    detector_metrics: Mapping[str, object] | None,
    repro_bundle: object,
    analysis_matrices: Mapping[str, object] | None,
    analysis_indicators: Mapping[str, object] | None,
    workload_profile: Mapping[str, object] | None,
) -> int | None:
    try:
        row_data: dict[str, object] = {
            "app_version_id": app_version_id,
            "session_stamp": _normalise_optional_str(session_stamp),
            "scope_label": _normalise_optional_str(scope_label),
            "category": _normalise_optional_str(category),
            "sha256": _normalise_optional_str(sha256),
            "analysis_version": _normalise_optional_str(analysis_version),
            "pipeline_version": _normalise_optional_str(pipeline_version),
            "catalog_versions": _normalise_optional_str(catalog_versions),
            "config_hash": _normalise_optional_str(config_hash),
            "study_tag": _normalise_optional_str(study_tag),
            "run_started_utc": _normalise_optional_str(run_started_utc),
            "profile": _normalise_optional_str(profile),
            "findings_total": findings_total,
            "detector_metrics": _serialise_json(detector_metrics),
            "repro_bundle": _serialise_json(repro_bundle),
            "analysis_matrices": _serialise_json(analysis_matrices),
            "analysis_indicators": _serialise_json(analysis_indicators),
            "workload_profile": _serialise_json(workload_profile),
        }
        columns = list(row_data.keys())
        placeholders = ", ".join(["%s"] * len(columns))
        sql = f"INSERT INTO static_analysis_runs ({', '.join(columns)}) VALUES ({placeholders})"
        run_id = core_q.run_sql(sql, tuple(row_data[col] for col in columns), return_lastrowid=True)
        return int(run_id) if run_id else None
    except Exception:
        return None


def _create_finding_row(
    run_id: int,
    finding: Mapping[str, object],
    *,
    context: Mapping[str, object] | None = None,
) -> None:
    # Phase-B: legacy static_analysis_findings writes removed.
    return


def _persist_provider_acl(
    run_id: int,
    detector_metrics: Mapping[str, object] | None,
) -> None:
    _PROVIDER_PARENT_CACHE.clear()
    _require_canonical_schema()
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


def _authority_from_entry(entry: Mapping[str, object]) -> str | None:
    authorities = entry.get("authorities")
    if isinstance(authorities, Sequence) and not isinstance(authorities, (str, bytes)):
        for candidate in authorities:
            text = _normalise_optional_str(candidate)
            if text:
                return _clamp_authority(text)
    return _clamp_authority(_normalise_optional_str(authorities))


def _clamp_authority(value: str | None, limit: int = 191) -> str | None:
    if not value:
        return value
    text = str(value)
    return text[:limit]


def _create_provider_row(run_id: int, entry: Mapping[str, object]) -> int | None:
    try:
        metrics_payload = {
            key: value
            for key, value in entry.items()
            if key
            in {
                "base_levels",
                "read_levels",
                "write_levels",
                "exported_explicit",
                "export_reason",
            }
        }
        component_name = _normalise_optional_str(entry.get("name"))
        authority = _authority_from_entry(entry) or component_name or f"provider_{run_id}"
        authority = _clamp_authority(authority)
        row_data: dict[str, object | None] = {
            "run_id": run_id,
            "component_name": component_name,
            "provider_name": component_name,
            "authority": authority,
            "authorities": _serialise_json(entry.get("authorities")),
            "exported": 1 if entry.get("exported") else 0,
            "base_permission": _normalise_optional_str(entry.get("base_permission")),
            "read_permission": _normalise_optional_str(entry.get("read_permission")),
            "write_permission": _normalise_optional_str(entry.get("write_permission")),
            "base_guard": _normalise_optional_str(entry.get("base_guard")),
            "read_guard": _normalise_optional_str(entry.get("read_guard")),
            "write_guard": _normalise_optional_str(entry.get("write_guard")),
            "effective_guard": _normalise_optional_str(entry.get("effective_guard")),
            "grant_uri_permissions": 1 if entry.get("grant_uri_permissions") else 0,
            "metrics": _serialise_json(metrics_payload),
        }

        columns = list(row_data.keys())
        placeholders = ", ".join(["%s"] * len(columns))
        sql = f"INSERT INTO static_fileproviders ({', '.join(columns)}) VALUES ({placeholders})"
        provider_id = core_q.run_sql(
            sql,
            tuple(row_data[column] for column in columns),
            return_lastrowid=True,
        )
        provider_id_int = int(provider_id) if provider_id else None
        if provider_id_int:
            _PROVIDER_PARENT_CACHE[provider_id_int] = {
                "authority": authority,
                "provider_name": component_name,
                "exported": row_data.get("exported"),
            }
        return provider_id_int
    except Exception:
        return None


def _create_provider_acl_row(provider_id: int, entry: Mapping[str, object]) -> None:
    try:
        path_value = _normalise_optional_str(entry.get("path")) or "*"
        path_type = _normalise_optional_str(entry.get("pathType")) or "base"

        row_data: dict[str, object | None] = {
            "provider_id": provider_id,
            "path": path_value,
            "path_prefix": _normalise_optional_str(entry.get("pathPrefix")),
            "path_pattern": _normalise_optional_str(entry.get("pathPattern")),
            "read_permission": _normalise_optional_str(entry.get("read_permission")),
            "write_permission": _normalise_optional_str(entry.get("write_permission")),
            "read_guard": _normalise_optional_str(entry.get("read_guard")),
            "write_guard": _normalise_optional_str(entry.get("write_guard")),
            "metadata": _serialise_json(
                {
                    key: value
                    for key, value in entry.items()
                    if key
                    not in {
                        "path",
                        "pathPrefix",
                        "pathPattern",
                        "read_permission",
                        "write_permission",
                        "read_guard",
                        "write_guard",
                        "pathType",
                    }
                }
            ),
        }
        row_data["path_type"] = path_type

        columns = list(row_data.keys())
        placeholders = ", ".join(["%s"] * len(columns))
        sql = f"INSERT INTO static_provider_acl ({', '.join(columns)}) VALUES ({placeholders})"
        core_q.run_sql(
            sql,
            tuple(row_data[column] for column in columns),
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


def upsert_base002_for_session(session_stamp: str | None) -> int:
    """Promote provider exposure candidates into canonical findings."""

    # Phase-B: legacy static_analysis_findings writes removed.
    return 0


def build_session_string_view(session_stamp: str | None) -> int:
    """Return the row count for session-scoped string samples (no DB views)."""

    if not _ensure_schema_ready():
        return 0

    clause = ""
    params: tuple[object, ...] = ()
    if session_stamp:
        clause = " WHERE session_stamp = %s"
        params = (session_stamp,)

    row = None
    try:
        row = core_q.run_sql(
            (
                "SELECT COUNT(*) "
                "FROM static_string_selected_samples x "
                "JOIN static_string_summary s ON s.id = x.summary_id"
                f"{clause}"
            ),
            params,
            fetch="one",
        )
    except Exception:
        row = None
    if row is None:
        try:
            row = core_q.run_sql(
                (
                    "SELECT COUNT(*) "
                    "FROM static_string_samples x "
                    "JOIN static_string_summary s ON s.id = x.summary_id"
                    f"{clause}"
                ),
                params,
                fetch="one",
            )
        except Exception:
            return 0

    if not row:
        return 0
    count = row[0]
    return int(count or 0)
