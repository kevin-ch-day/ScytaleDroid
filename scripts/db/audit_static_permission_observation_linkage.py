#!/usr/bin/env python3
"""Fail-closed read-only audit of static permission to APK content identity.

The audit compares SHA-256 values as validated bytes, never through text
collation. It can write a restricted exact repair *proposal*, but it cannot
execute SQL or modify any database row.

Exit codes:
  0 — every required section passed
  1 — import failure or unexpected internal error
  2 — database configuration or connection failure
  3 — required schema evidence is missing or incompatible
  4 — a required audit query failed
  5 — linkage is incomplete, ambiguous, or contains malformed hashes
  6 — requested evidence output could not be written safely
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_CONNECTION = 2
EXIT_SCHEMA = 3
EXIT_QUERY = 4
EXIT_INCOMPLETE = 5
EXIT_OUTPUT = 6

_SHA256_RE = re.compile(r"^[0-9A-Fa-f]{64}$")
_REQUIRED_SECTIONS = (
    "schema_discovery",
    "matrix_inventory",
    "repository_inventory",
    "linkage_recalculation",
    "proposal_generation",
)


class AuditQueryError(RuntimeError):
    """A required read-only audit query did not complete."""


class AuditSchemaError(RuntimeError):
    """The live schema cannot support the required audit semantics."""


def normalize_sha256(value: object) -> bytes | None:
    """Return validated SHA-256 bytes from hexadecimal character storage."""

    if value is None:
        return None
    text = str(value).strip()
    if not _SHA256_RE.fullmatch(text):
        return None
    return bytes.fromhex(text)


def _semantic_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _write_private_json(path: Path, payload: object) -> Path:
    from scytaledroid.Utils.IO.atomic_write import atomic_write_text

    resolved = path.expanduser().resolve()
    if _inside(resolved, _REPO_ROOT):
        raise ValueError("linkage evidence must remain outside the repository")
    resolved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(resolved.parent, 0o700)
    atomic_write_text(
        resolved,
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True, default=str)
        + "\n",
    )
    os.chmod(resolved, 0o600)
    return resolved


def classify_linkage_row(
    row: Mapping[str, Any],
    *,
    repository_by_id: Mapping[int, Mapping[str, Any]],
    repository_ids_by_hash: Mapping[bytes, Sequence[int]],
) -> dict[str, Any]:
    """Classify one matrix row without treating numeric equality as identity."""

    matrix_row_id = int(row["matrix_row_id"])
    run_id = int(row["run_id"])
    current_apk_id = int(row["current_apk_id"])
    base_hash = normalize_sha256(row.get("base_apk_sha256"))
    numeric_repository = repository_by_id.get(current_apk_id)
    numeric_hash = normalize_sha256(
        None if numeric_repository is None else numeric_repository.get("sha256")
    )

    proposed_apk_id: int | None = None
    ambiguity_reason: str | None = None
    if base_hash is None:
        classification = "MALFORMED_HASH"
        resolution_status = "MANUAL_REVIEW_REQUIRED"
        ambiguity_reason = "run base_apk_sha256 is NULL or not exactly 64 hexadecimal characters"
        content_matches: list[int] = []
    else:
        content_matches = sorted(int(value) for value in repository_ids_by_hash.get(base_hash, ()))
        if not content_matches:
            classification = "BASE_HASH_NOT_FOUND"
            resolution_status = "MANUAL_REVIEW_REQUIRED"
            ambiguity_reason = "validated base SHA-256 has no repository match"
        elif len(content_matches) > 1:
            classification = "BASE_HASH_AMBIGUOUS"
            resolution_status = "MANUAL_REVIEW_REQUIRED"
            ambiguity_reason = "validated base SHA-256 resolves to multiple repository rows"
        else:
            proposed_apk_id = content_matches[0]
            if current_apk_id == proposed_apk_id and numeric_hash == base_hash:
                classification = "CORRECT"
                resolution_status = "CORRECT"
            elif current_apk_id == run_id:
                classification = "RUN_ID_SUBSTITUTED"
                resolution_status = "UNIQUE_BASE_HASH_REPAIR_CANDIDATE"
            elif numeric_repository is not None:
                classification = "ACCIDENTAL_NUMERIC_MATCH_HASH_MISMATCH"
                resolution_status = "UNIQUE_BASE_HASH_REPAIR_CANDIDATE"
            else:
                classification = "MISSING_REPOSITORY_ID_MATCH"
                resolution_status = "UNIQUE_BASE_HASH_REPAIR_CANDIDATE"

    base_hash_hex = None if base_hash is None else base_hash.hex()
    before = {
        "matrix_row_id": matrix_row_id,
        "run_id": run_id,
        "apk_id": current_apk_id,
        "base_apk_sha256": base_hash_hex,
    }
    after = {**before, "apk_id": proposed_apk_id}
    return {
        "matrix_row_id": matrix_row_id,
        "run_id": run_id,
        "current_apk_id": current_apk_id,
        "current_apk_id_equals_run_id": current_apk_id == run_id,
        "current_repository_row_exists": numeric_repository is not None,
        "current_numeric_match_has_verified_content_identity": (
            base_hash is not None and numeric_hash == base_hash
        ),
        "normalized_base_apk_sha256": base_hash_hex,
        "verified_content_match_count": len(content_matches),
        "proposed_repository_apk_id": proposed_apk_id,
        "classification": classification,
        "resolution_status": resolution_status,
        "ambiguity_reason": ambiguity_reason,
        "before_image_digest": _semantic_digest(before),
        "expected_after_image_digest": _semantic_digest(after),
        "required_update_preconditions": {
            "matrix_row_id": matrix_row_id,
            "run_id": run_id,
            "current_apk_id": current_apk_id,
            "base_apk_sha256": base_hash_hex,
            "unique_repository_hash_match": proposed_apk_id,
        },
    }


def _run_required(
    run_sql: Callable[..., Any],
    sql: str,
    *,
    fetch: str,
    dictionary: bool = False,
) -> Any:
    try:
        return run_sql(sql, fetch=fetch, dictionary=dictionary)
    except Exception as exc:
        raise AuditQueryError(f"required {fetch} query failed: {exc.__class__.__name__}") from exc


def _schema_evidence(run_sql: Callable[..., Any]) -> dict[str, Any]:
    create_digests: dict[str, str] = {}
    for table in (
        "static_permission_matrix",
        "android_apk_repository",
        "static_analysis_runs",
    ):
        row = _run_required(run_sql, f"SHOW CREATE TABLE `{table}`", fetch="one")
        if not row or len(row) < 2:
            raise AuditSchemaError(f"SHOW CREATE TABLE incomplete for {table}")
        create_digests[table] = hashlib.sha256(str(row[1]).encode("utf-8")).hexdigest()

    rows = _run_required(
        run_sql,
        """
        SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE,
               CHARACTER_SET_NAME, COLLATION_NAME, COLUMN_KEY, EXTRA
          FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE()
           AND ((TABLE_NAME='static_permission_matrix' AND COLUMN_NAME IN ('id','run_id','apk_id'))
             OR (TABLE_NAME='android_apk_repository' AND COLUMN_NAME IN ('apk_id','sha256'))
             OR (TABLE_NAME='static_analysis_runs' AND COLUMN_NAME IN ('id','base_apk_sha256')))
         ORDER BY TABLE_NAME, ORDINAL_POSITION
        """,
        fetch="all",
        dictionary=True,
    )
    columns = {
        (str(row["TABLE_NAME"]), str(row["COLUMN_NAME"])): dict(row)
        for row in rows or []
    }
    required = {
        ("static_permission_matrix", "id"),
        ("static_permission_matrix", "run_id"),
        ("static_permission_matrix", "apk_id"),
        ("android_apk_repository", "apk_id"),
        ("android_apk_repository", "sha256"),
        ("static_analysis_runs", "id"),
        ("static_analysis_runs", "base_apk_sha256"),
    }
    missing = sorted(required - set(columns))
    if missing:
        raise AuditSchemaError("required columns missing: " + ", ".join(f"{t}.{c}" for t, c in missing))
    if columns[("android_apk_repository", "apk_id")]["COLUMN_KEY"] != "PRI":
        raise AuditSchemaError("android_apk_repository.apk_id is not the primary key")
    if columns[("android_apk_repository", "sha256")]["COLUMN_KEY"] != "UNI":
        raise AuditSchemaError("android_apk_repository.sha256 is not unique")
    for table, column in (
        ("android_apk_repository", "sha256"),
        ("static_analysis_runs", "base_apk_sha256"),
    ):
        if str(columns[(table, column)]["COLUMN_TYPE"]).lower() != "char(64)":
            raise AuditSchemaError(f"{table}.{column} is not hexadecimal CHAR(64) storage")
    return {
        "status": "PASS",
        "repository_primary_key": "apk_id",
        "matrix_primary_key": "id",
        "hash_semantics": "validated_64_hex_then_bytes_fromhex",
        "create_table_sha256": create_digests,
        "columns": [columns[key] for key in sorted(columns)],
    }


def run_audit(run_sql: Callable[..., Any]) -> dict[str, Any]:
    """Execute all required read-only sections and return deterministic evidence."""

    schema = _schema_evidence(run_sql)
    total_row = _run_required(
        run_sql, "SELECT COUNT(*) FROM static_permission_matrix", fetch="one"
    )
    total_matrix_rows = int(total_row[0])
    repository_rows = _run_required(
        run_sql,
        "SELECT apk_id, sha256 FROM android_apk_repository ORDER BY apk_id",
        fetch="all",
        dictionary=True,
    )
    matrix_rows = _run_required(
        run_sql,
        """
        SELECT spm.id AS matrix_row_id,
               spm.run_id AS run_id,
               spm.apk_id AS current_apk_id,
               sar.base_apk_sha256 AS base_apk_sha256
          FROM static_permission_matrix AS spm
          JOIN static_analysis_runs AS sar ON sar.id = spm.run_id
         WHERE spm.apk_id IS NOT NULL
         ORDER BY spm.id
        """,
        fetch="all",
        dictionary=True,
    )

    repository_by_id: dict[int, dict[str, Any]] = {}
    repository_ids_by_hash: defaultdict[bytes, list[int]] = defaultdict(list)
    malformed_repository_hashes = 0
    for raw in repository_rows or []:
        row = dict(raw)
        apk_id = int(row["apk_id"])
        repository_by_id[apk_id] = row
        digest = normalize_sha256(row.get("sha256"))
        if row.get("sha256") is not None and digest is None:
            malformed_repository_hashes += 1
        if digest is not None:
            repository_ids_by_hash[digest].append(apk_id)

    proposals = [
        classify_linkage_row(
            row,
            repository_by_id=repository_by_id,
            repository_ids_by_hash=repository_ids_by_hash,
        )
        for row in matrix_rows or []
    ]
    classifications = Counter(row["classification"] for row in proposals)
    resolutions = Counter(row["resolution_status"] for row in proposals)
    affected_runs = {int(row["run_id"]) for row in proposals}
    unique_candidate_runs = {
        int(row["run_id"])
        for row in proposals
        if row["resolution_status"] == "UNIQUE_BASE_HASH_REPAIR_CANDIDATE"
    }
    incomplete_count = sum(
        count
        for name, count in resolutions.items()
        if name not in {"CORRECT", "UNIQUE_BASE_HASH_REPAIR_CANDIDATE"}
    ) + malformed_repository_hashes
    sections = {
        "schema_discovery": schema,
        "matrix_inventory": {
            "status": "PASS",
            "total_matrix_rows": total_matrix_rows,
            "nonnull_apk_id_rows": len(proposals),
            "nonnull_apk_id_runs": len(affected_runs),
            "apk_id_equals_run_id_rows": sum(
                bool(row["current_apk_id_equals_run_id"]) for row in proposals
            ),
            "apk_id_equals_run_id_runs": len(
                {
                    int(row["run_id"])
                    for row in proposals
                    if row["current_apk_id_equals_run_id"]
                }
            ),
        },
        "repository_inventory": {
            "status": "PASS" if malformed_repository_hashes == 0 else "INCOMPLETE",
            "repository_rows": len(repository_by_id),
            "validated_unique_hashes": len(repository_ids_by_hash),
            "malformed_nonnull_hash_rows": malformed_repository_hashes,
        },
        "linkage_recalculation": {
            "status": "PASS" if incomplete_count == 0 else "INCOMPLETE",
            "classification_counts": dict(sorted(classifications.items())),
            "resolution_counts": dict(sorted(resolutions.items())),
            "repository_id_missing_rows": sum(
                not bool(row["current_repository_row_exists"]) for row in proposals
            ),
            "accidental_numeric_match_hash_mismatch_rows": sum(
                bool(row["current_repository_row_exists"])
                and not bool(row["current_numeric_match_has_verified_content_identity"])
                for row in proposals
            ),
            "verified_current_content_match_rows": sum(
                bool(row["current_numeric_match_has_verified_content_identity"])
                for row in proposals
            ),
            "unique_base_hash_candidate_rows": resolutions[
                "UNIQUE_BASE_HASH_REPAIR_CANDIDATE"
            ],
            "unique_base_hash_candidate_runs": len(unique_candidate_runs),
            "incomplete_rows": incomplete_count,
        },
        "proposal_generation": {
            "status": "PASS" if incomplete_count == 0 else "INCOMPLETE",
            "proposal_format": "scytaledroid-static-permission-apk-linkage-proposal-v1",
            "production_effect": "none",
            "executable_sql_present": False,
            "row_count": len(proposals),
            "proposal_digest": _semantic_digest(proposals),
        },
    }
    overall = "PASS" if all(sections[name]["status"] == "PASS" for name in _REQUIRED_SECTIONS) else "INCOMPLETE"
    summary = {
        "report_format": "scytaledroid-static-permission-apk-linkage-audit-v2",
        "status": overall,
        "query_mode": "read_only",
        "production_effect": "none",
        "required_sections": list(_REQUIRED_SECTIONS),
        "sections": sections,
    }
    summary["semantic_digest"] = _semantic_digest(summary)
    exact = {
        "proposal_format": "scytaledroid-static-permission-apk-linkage-proposal-v1",
        "query_mode": "read_only",
        "production_effect": "none",
        "executable_sql_present": False,
        "proposal_digest": sections["proposal_generation"]["proposal_digest"],
        "rows": proposals,
    }
    return {"summary": summary, "exact_proposal": exact}


def audit_from_runner(run_sql: Callable[..., Any]) -> tuple[dict[str, Any], int]:
    """Convert fail-closed audit exceptions to stable status and exit codes."""

    try:
        result = run_audit(run_sql)
    except AuditSchemaError as exc:
        return {"status": "FAIL", "error_class": "schema", "detail": str(exc)}, EXIT_SCHEMA
    except AuditQueryError as exc:
        return {"status": "FAIL", "error_class": "query", "detail": str(exc)}, EXIT_QUERY
    summary = result["summary"]
    return result, EXIT_OK if summary["status"] == "PASS" else EXIT_INCOMPLETE


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print the sanitized summary as JSON.")
    parser.add_argument(
        "--proposal-output",
        type=Path,
        help="Write the exact row-level proposal mode 0600 outside the repository.",
    )
    parser.add_argument(
        "--summary-output",
        type=Path,
        help="Write the sanitized digest-bound summary mode 0600 outside the repository.",
    )
    args = parser.parse_args(argv)

    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except ImportError as exc:
        sys.stderr.write(f"Import failed (PYTHONPATH=.): {exc}\n")
        return EXIT_INTERNAL

    result, exit_code = audit_from_runner(core_q.run_sql)
    if "summary" not in result:
        sys.stderr.write(json.dumps(result, sort_keys=True) + "\n")
        return exit_code
    summary = result["summary"]
    try:
        if args.proposal_output is not None:
            _write_private_json(args.proposal_output, result["exact_proposal"])
        if args.summary_output is not None:
            _write_private_json(args.summary_output, summary)
    except Exception as exc:
        sys.stderr.write(f"Evidence output failed: {exc.__class__.__name__}\n")
        return EXIT_OUTPUT

    if args.json:
        print(json.dumps(summary, sort_keys=True, default=str))
    else:
        print("# Static permission to APK linkage audit (read-only)")
        print(f"status: {summary['status']}")
        for name in _REQUIRED_SECTIONS:
            print(f"{name}: {summary['sections'][name]['status']}")
        inventory = summary["sections"]["matrix_inventory"]
        linkage = summary["sections"]["linkage_recalculation"]
        proposal = summary["sections"]["proposal_generation"]
        print(f"total_matrix_rows: {inventory['total_matrix_rows']}")
        print(f"nonnull_apk_id_rows: {inventory['nonnull_apk_id_rows']}")
        print(f"nonnull_apk_id_runs: {inventory['nonnull_apk_id_runs']}")
        print(f"apk_id_equals_run_id_rows: {inventory['apk_id_equals_run_id_rows']}")
        print(f"repository_id_missing_rows: {linkage['repository_id_missing_rows']}")
        print(
            "accidental_numeric_match_hash_mismatch_rows: "
            f"{linkage['accidental_numeric_match_hash_mismatch_rows']}"
        )
        print(f"unique_base_hash_candidate_rows: {linkage['unique_base_hash_candidate_rows']}")
        print(f"unique_base_hash_candidate_runs: {linkage['unique_base_hash_candidate_runs']}")
        print(f"proposal_digest: {proposal['proposal_digest']}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
