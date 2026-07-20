"""Validation and verification for reviewed research-capsule selection ledgers."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .research_capsule import sha256_file

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DISPOSITIONS = {"included", "excluded"}


def load_json_object(path: Path | str) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"ledger must contain a JSON object: {path}")
    return payload


def _required_string(entry: Mapping[str, Any], field: str, *, issues: list[str], prefix: str) -> str:
    value = str(entry.get(field) or "").strip()
    if not value:
        issues.append(f"{prefix}.{field}:missing")
    return value


def _valid_sha(value: str) -> bool:
    return bool(_SHA256_RE.fullmatch(value.lower()))


def validate_apk_ledger(payload: Mapping[str, Any]) -> list[str]:
    """Validate a reviewed APK ledger without inspecting the filesystem."""

    issues: list[str] = []
    if int(payload.get("schema_version") or 0) != 1:
        issues.append("schema_version:expected_1")
    if not str(payload.get("paper_id") or "").strip():
        issues.append("paper_id:missing")
    if str(payload.get("review_status") or "").upper() != "APPROVED":
        issues.append("review_status:not_approved")
    entries = payload.get("entries")
    if not isinstance(entries, list) or not entries:
        return [*issues, "entries:missing_or_empty"]

    seen: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(entries):
        prefix = f"entries[{index}]"
        if not isinstance(raw, Mapping):
            issues.append(f"{prefix}:not_object")
            continue
        package = _required_string(raw, "package_name", issues=issues, prefix=prefix)
        _required_string(raw, "app_name", issues=issues, prefix=prefix)
        version_code = _required_string(raw, "version_code", issues=issues, prefix=prefix)
        _required_string(raw, "version_name", issues=issues, prefix=prefix)
        apk_hash = _required_string(raw, "base_apk_sha256", issues=issues, prefix=prefix).lower()
        _required_string(raw, "selected_apk_path", issues=issues, prefix=prefix)
        _required_string(raw, "static_run_id", issues=issues, prefix=prefix)
        _required_string(raw, "paper_build_relation", issues=issues, prefix=prefix)
        disposition = _required_string(raw, "inclusion_disposition", issues=issues, prefix=prefix).lower()
        if apk_hash and not _valid_sha(apk_hash):
            issues.append(f"{prefix}.base_apk_sha256:invalid")
        if disposition and disposition not in _DISPOSITIONS:
            issues.append(f"{prefix}.inclusion_disposition:invalid")
        key = (package, version_code, apk_hash)
        if all(key) and key in seen:
            issues.append(f"{prefix}:duplicate_build")
        seen.add(key)
    return issues


def validate_evidence_ledger(payload: Mapping[str, Any]) -> list[str]:
    """Validate a reviewed dynamic-evidence ledger without scanning evidence roots."""

    issues: list[str] = []
    if int(payload.get("schema_version") or 0) != 1:
        issues.append("schema_version:expected_1")
    if not str(payload.get("paper_id") or "").strip():
        issues.append("paper_id:missing")
    if str(payload.get("review_status") or "").upper() != "APPROVED":
        issues.append("review_status:not_approved")
    entries = payload.get("entries")
    if not isinstance(entries, list) or not entries:
        return [*issues, "entries:missing_or_empty"]

    seen_runs: set[str] = set()
    for index, raw in enumerate(entries):
        prefix = f"entries[{index}]"
        if not isinstance(raw, Mapping):
            issues.append(f"{prefix}:not_object")
            continue
        _required_string(raw, "package_name", issues=issues, prefix=prefix)
        _required_string(raw, "version_code", issues=issues, prefix=prefix)
        apk_hash = _required_string(raw, "base_apk_sha256", issues=issues, prefix=prefix).lower()
        run_id = _required_string(raw, "dynamic_run_id", issues=issues, prefix=prefix)
        _required_string(raw, "run_profile", issues=issues, prefix=prefix)
        _required_string(raw, "capture_started_at_utc", issues=issues, prefix=prefix)
        _required_string(raw, "paper_eligibility", issues=issues, prefix=prefix)
        _required_string(raw, "validity_state", issues=issues, prefix=prefix)
        pcap = raw.get("pcap")
        if not isinstance(pcap, Mapping):
            issues.append(f"{prefix}.pcap:missing")
        else:
            _required_string(pcap, "path", issues=issues, prefix=f"{prefix}.pcap")
            sha = _required_string(pcap, "sha256", issues=issues, prefix=f"{prefix}.pcap")
            if sha and not _valid_sha(sha):
                issues.append(f"{prefix}.pcap.sha256:invalid")
        artifacts = raw.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            issues.append(f"{prefix}.artifacts:missing_or_empty")
        else:
            for artifact_index, artifact in enumerate(artifacts):
                artifact_prefix = f"{prefix}.artifacts[{artifact_index}]"
                if not isinstance(artifact, Mapping):
                    issues.append(f"{artifact_prefix}:not_object")
                    continue
                _required_string(artifact, "role", issues=issues, prefix=artifact_prefix)
                _required_string(artifact, "path", issues=issues, prefix=artifact_prefix)
                sha = _required_string(artifact, "sha256", issues=issues, prefix=artifact_prefix)
                if sha and not _valid_sha(sha):
                    issues.append(f"{artifact_prefix}.sha256:invalid")
        dependencies = raw.get("manuscript_dependencies")
        if not isinstance(dependencies, list):
            issues.append(f"{prefix}.manuscript_dependencies:missing")
        if apk_hash and not _valid_sha(apk_hash):
            issues.append(f"{prefix}.base_apk_sha256:invalid")
        if run_id and run_id in seen_runs:
            issues.append(f"{prefix}.dynamic_run_id:duplicate")
        seen_runs.add(run_id)
    return issues


def verify_apk_ledger(payload: Mapping[str, Any], *, repo_root: Path | str) -> list[str]:
    """Verify included APK paths and hashes from an explicit reviewed ledger."""

    root = Path(repo_root)
    issues = validate_apk_ledger(payload)
    for entry in payload.get("entries") or []:
        if not isinstance(entry, Mapping) or str(entry.get("inclusion_disposition") or "").lower() != "included":
            continue
        path = root / str(entry.get("selected_apk_path") or "")
        expected = str(entry.get("base_apk_sha256") or "").lower()
        if not path.is_file():
            issues.append(f"apk_missing:{path}")
        elif expected and sha256_file(path) != expected:
            issues.append(f"apk_hash_mismatch:{path}")
    return issues


def verify_evidence_ledger(
    payload: Mapping[str, Any],
    *,
    repo_root: Path | str,
    apk_ledger: Mapping[str, Any],
) -> list[str]:
    """Verify selected evidence and reject runs that do not match selected APK builds."""

    root = Path(repo_root)
    issues = validate_evidence_ledger(payload)
    selected_builds = {
        (str(entry.get("package_name") or ""), str(entry.get("version_code") or ""), str(entry.get("base_apk_sha256") or "").lower())
        for entry in apk_ledger.get("entries") or []
        if isinstance(entry, Mapping) and str(entry.get("inclusion_disposition") or "").lower() == "included"
    }
    for entry in payload.get("entries") or []:
        if not isinstance(entry, Mapping):
            continue
        identity = (
            str(entry.get("package_name") or ""),
            str(entry.get("version_code") or ""),
            str(entry.get("base_apk_sha256") or "").lower(),
        )
        if identity not in selected_builds:
            issues.append(f"evidence_unselected_build:{identity[0]}:{identity[1]}")
        pcap = entry.get("pcap")
        artifacts: list[Mapping[str, Any]] = []
        if isinstance(pcap, Mapping):
            artifacts.append(pcap)
        artifacts.extend(item for item in (entry.get("artifacts") or []) if isinstance(item, Mapping))
        for artifact in artifacts:
            path = root / str(artifact.get("path") or "")
            expected = str(artifact.get("sha256") or "").lower()
            if not path.is_file():
                issues.append(f"evidence_missing:{path}")
            elif expected and sha256_file(path) != expected:
                issues.append(f"evidence_hash_mismatch:{path}")
    return issues


def _safe_identifier(value: str) -> bool:
    return bool(_SAFE_IDENTIFIER_RE.fullmatch(value))


def validate_db_export_spec(payload: Mapping[str, Any]) -> list[str]:
    """Validate that an export specification is scoped and read-only preview safe."""

    issues: list[str] = []
    if int(payload.get("schema_version") or 0) != 1:
        issues.append("schema_version:expected_1")
    if not str(payload.get("paper_id") or "").strip():
        issues.append("paper_id:missing")
    if str(payload.get("review_status") or "").upper() != "APPROVED":
        issues.append("review_status:not_approved")
    scope = payload.get("scope")
    if not isinstance(scope, Mapping) or not any(scope.get(key) for key in ("run_ids", "static_run_ids", "package_names", "apk_sha256")):
        issues.append("scope:missing_identifiers")
    exclusions = payload.get("exclusions")
    if not isinstance(exclusions, list) or not exclusions:
        issues.append("exclusions:missing")
    if payload.get("schema_definition_included") is not True:
        issues.append("schema_definition_included:required")
    tables = payload.get("tables")
    if not isinstance(tables, list) or not tables:
        return [*issues, "tables:missing_or_empty"]
    forbidden = (";", "--", "/*", "*/", " drop ", " delete ", " update ", " insert ", " alter ")
    for index, table in enumerate(tables):
        prefix = f"tables[{index}]"
        if not isinstance(table, Mapping):
            issues.append(f"{prefix}:not_object")
            continue
        schema = _required_string(table, "schema", issues=issues, prefix=prefix)
        name = _required_string(table, "table", issues=issues, prefix=prefix)
        predicate = _required_string(table, "predicate", issues=issues, prefix=prefix)
        if schema and not _safe_identifier(schema):
            issues.append(f"{prefix}.schema:invalid")
        if name and not _safe_identifier(name):
            issues.append(f"{prefix}.table:invalid")
        normalized = f" {predicate.lower()} "
        if predicate and (normalized.strip() in {"1", "true", "1=1"} or any(token in normalized for token in forbidden)):
            issues.append(f"{prefix}.predicate:unscoped_or_unsafe")
    return issues


def verify_db_export_receipt(
    payload: Mapping[str, Any],
    *,
    repo_root: Path | str,
    expected_paper_id: str,
) -> list[str]:
    """Verify metadata for a completed, explicitly scoped database export."""

    issues: list[str] = []
    if int(payload.get("schema_version") or 0) != 1:
        issues.append("db_export_receipt.schema_version:expected_1")
    if str(payload.get("artifact_type") or "") != "research_capsule_db_export_receipt":
        issues.append("db_export_receipt.artifact_type:invalid")
    if str(payload.get("paper_id") or "") != expected_paper_id:
        issues.append("db_export_receipt.paper_id:mismatch")
    if str(payload.get("status") or "").lower() != "complete":
        issues.append("db_export_receipt.status:not_complete")
    for field in ("database_engine", "database_version", "exported_at_utc", "consistency_method", "spec_sha256"):
        _required_string(payload, field, issues=issues, prefix="db_export_receipt")
    export_path = _required_string(payload, "export_path", issues=issues, prefix="db_export_receipt")
    export_sha = _required_string(payload, "export_sha256", issues=issues, prefix="db_export_receipt").lower()
    if export_sha and not _valid_sha(export_sha):
        issues.append("db_export_receipt.export_sha256:invalid")
    rows_by_table = payload.get("rows_by_table")
    if not isinstance(rows_by_table, Mapping) or not rows_by_table:
        issues.append("db_export_receipt.rows_by_table:missing")
    if export_path:
        candidate = Path(repo_root) / export_path
        if not candidate.is_file():
            issues.append(f"db_export_missing:{candidate}")
        elif export_sha and sha256_file(candidate) != export_sha:
            issues.append(f"db_export_hash_mismatch:{candidate}")
    return issues


def preview_db_export_spec(
    payload: Mapping[str, Any],
    *,
    row_counter: Callable[[str, str, str], int],
) -> dict[str, Any]:
    """Return count-only preview results through an injected database reader."""

    issues = validate_db_export_spec(payload)
    rows: list[dict[str, Any]] = []
    if not issues:
        for table in payload["tables"]:
            count = int(row_counter(str(table["schema"]), str(table["table"]), str(table["predicate"])))
            rows.append({"schema": table["schema"], "table": table["table"], "predicate": table["predicate"], "expected_rows": count})
            if count == 0:
                issues.append(f"zero_matching_rows:{table['schema']}.{table['table']}")
    return {"ok": not issues, "issues": issues, "tables": rows}
