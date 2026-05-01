#!/usr/bin/env python3
"""Run a strict static-analysis determinism gate for a single APK."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.StaticAnalysis.cli.flows import headless_run
from scytaledroid.StaticAnalysis.cli.flows.headless_run import _artifact_group_from_path
from scytaledroid.Utils.version_utils import get_git_commit

DEFAULT_RULES_PATH = REPO_ROOT / "docs" / "contracts" / "determinism_static_rules.json"


@dataclass(frozen=True)
class GateRules:
    schema_version: str
    compare_type: str
    allowed_diff_fields: tuple[str, ...]
    table_coverage_lock: tuple[str, ...]


def _load_rules(path: Path) -> GateRules:
    payload = json.loads(path.read_text(encoding="utf-8"))
    schema_version = str(payload.get("schema_version") or "v1")
    compare_type = str(payload.get("compare_type") or "static_analysis")
    allowed = tuple(sorted(str(item) for item in (payload.get("allowed_diff_fields") or [])))
    table_lock = tuple(str(item) for item in (payload.get("table_coverage_lock") or []))
    if not table_lock:
        raise RuntimeError("determinism rules must include non-empty table_coverage_lock")
    return GateRules(
        schema_version=schema_version,
        compare_type=compare_type,
        allowed_diff_fields=allowed,
        table_coverage_lock=table_lock,
    )


def _load_waiver(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    required = ("reason", "scope", "approver", "expires_utc")
    missing = [field for field in required if not str(payload.get(field) or "").strip()]
    if missing:
        raise RuntimeError(f"waiver file missing required fields: {', '.join(missing)}")
    expires = str(payload.get("expires_utc"))
    expires_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
    if expires_dt.tzinfo is None:
        expires_dt = expires_dt.replace(tzinfo=UTC)
    if expires_dt < datetime.now(UTC):
        raise RuntimeError("waiver expired")
    return payload


def _configure_db_target(db_target: str) -> None:
    parsed = urlparse(db_target)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"mysql", "mariadb"}:
        raise RuntimeError("Unsupported --db-target scheme. Use mysql://... (SQLite is not supported).")

    os.environ["SCYTALEDROID_DB_URL"] = db_target

    db_config.DB_CONFIG = {
        "engine": "mysql",
        "host": parsed.hostname or "localhost",
        "port": int(parsed.port or 3306),
        "user": unquote(parsed.username or ""),
        "password": unquote(parsed.password or ""),
        "database": (parsed.path or "").lstrip("/"),
        "charset": "utf8mb4",
    }
    db_config.DB_CONFIG_SOURCE = "cli:--db-target"
    print(
        "[DB TARGET] "
        f"backend=mysql host={db_config.DB_CONFIG['host']} "
        f"port={db_config.DB_CONFIG['port']} db={db_config.DB_CONFIG['database']}"
    )


def _now_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%d%H%M%S")


def _default_output_path() -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%SZ")
    return Path("output") / "audit" / "comparators" / "static_analysis" / stamp / "diff.json"


def _normalize_json_like(value: Any) -> Any:
    if isinstance(value, str):
        text = value.strip()
        if text and text[0] in "[{":
            try:
                parsed = json.loads(text)
                return _normalize_json_like(parsed)
            except Exception:
                return value
        return value
    if isinstance(value, dict):
        return {str(key): _normalize_json_like(val) for key, val in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, list):
        return [_normalize_json_like(item) for item in value]
    return value


def _json_hash(value: Any) -> str:
    normalized = _normalize_json_like(value)
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(payload.encode("utf-8")).hexdigest()


def _safe_decimal(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _table_exists(table_name: str) -> bool:
    try:
        row = core_q.run_sql(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s",
            (table_name,),
            fetch="one",
        )
        return bool(row and int(row[0]) > 0)
    except Exception:
        try:
            row = core_q.run_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table_name,),
                fetch="one",
            )
            return bool(row)
        except Exception:
            return False


def _row_fingerprints(table_name: str, where_field: str, where_value: int) -> list[str]:
    rows = core_q.run_sql(
        f"SELECT * FROM {table_name} WHERE {where_field} = %s",
        (where_value,),
        fetch="all_dict",
    ) or []
    return sorted(_json_hash(_normalize_json_like(row)) for row in rows)


def _table_snapshot(table_name: str, where_field: str, where_value: int) -> dict[str, Any]:
    if not _table_exists(table_name):
        return {"table": table_name, "present": False, "row_count": 0, "fingerprints": []}
    fingerprints = _row_fingerprints(table_name, where_field, where_value)
    return {
        "table": table_name,
        "present": True,
        "row_count": len(fingerprints),
        "fingerprints": fingerprints,
    }


def _collect_permission_risk_vnext(run_id: int) -> dict[str, Any]:
    table_ready = _table_exists("static_permission_risk_vnext")

    if not table_ready:
        return {
            "table_ready": False,
            "row_count": 0,
            "rows_by_key": {},
            "validation": {
                "missing_key_fields": [],
                "duplicate_keys": [],
                "non_canonical_permission_names": [],
            },
        }

    rows = core_q.run_sql(
        """
        SELECT permission_name, risk_score, risk_class, rationale_code
        FROM static_permission_risk_vnext
        WHERE run_id = %s
        ORDER BY permission_name ASC
        """,
        (run_id,),
        fetch="all_dict",
    ) or []

    rows_by_key: dict[str, dict[str, Any]] = {}
    duplicates: list[str] = []
    missing_keys: list[str] = []
    non_canonical: list[str] = []
    for row in rows:
        raw_name = str(row.get("permission_name") or "").strip()
        if not raw_name:
            missing_keys.append("<empty>")
            continue
        canonical_name = raw_name.lower()
        if raw_name != canonical_name:
            non_canonical.append(raw_name)
        if canonical_name in rows_by_key:
            duplicates.append(canonical_name)
        rows_by_key[canonical_name] = {
            "permission_name": raw_name,
            "risk_score": _safe_decimal(row.get("risk_score")),
            "risk_class": row.get("risk_class"),
            "rationale_code": row.get("rationale_code"),
        }

    return {
        "table_ready": True,
        "row_count": len(rows_by_key),
        "rows_by_key": {key: rows_by_key[key] for key in sorted(rows_by_key)},
        "validation": {
            "missing_key_fields": missing_keys,
            "duplicate_keys": sorted(set(duplicates)),
            "non_canonical_permission_names": sorted(set(non_canonical)),
        },
    }


@dataclass(frozen=True)
class RunRef:
    session_stamp: str
    run_id: int
    package_name: str
    scope_label: str


def _run_scan(apk_path: Path, *, profile: str, session_stamp: str, allow_reuse: bool) -> None:
    argv = ["--apk", str(apk_path), "--profile", profile, "--session", session_stamp]
    if allow_reuse:
        argv.append("--allow-session-reuse")
    rc = headless_run.main(argv)
    if rc != 0:
        raise RuntimeError(f"Static scan failed for session {session_stamp} (exit={rc})")


def _resolve_run(package_name: str, session_stamp: str) -> RunRef:
    row = core_q.run_sql(
        """
        SELECT sar.id, sar.scope_label
        FROM static_analysis_runs sar
        JOIN app_versions av ON av.id = sar.app_version_id
        JOIN apps a ON a.id = av.app_id
        WHERE a.package_name = %s
          AND sar.session_stamp = %s
        ORDER BY sar.id DESC
        LIMIT 1
        """,
        (package_name, session_stamp),
        fetch="one",
    )
    if not row:
        raise RuntimeError(f"No static_analysis_runs row found for package={package_name} session={session_stamp}")
    return RunRef(
        session_stamp=session_stamp,
        run_id=int(row[0]),
        package_name=package_name,
        scope_label=str(row[1] or ""),
    )


def _finding_fingerprints(run_id: int) -> list[str]:
    rows = core_q.run_sql(
        """
        SELECT
          status,
          severity,
          category,
          title,
          rule_id,
          cvss_score,
          masvs_control,
          detector,
          module,
          tags,
          evidence,
          evidence_refs
        FROM static_analysis_findings
        WHERE run_id = %s
        ORDER BY id
        """,
        (run_id,),
        fetch="all_dict",
    ) or []
    fingerprints: list[str] = []
    for row in rows:
        record = {
            "status": row.get("status"),
            "severity": row.get("severity"),
            "category": row.get("category"),
            "title": row.get("title"),
            "rule_id": row.get("rule_id"),
            "cvss_score": _safe_decimal(row.get("cvss_score")),
            "masvs_control": row.get("masvs_control"),
            "detector": row.get("detector"),
            "module": row.get("module"),
            "tags_hash": _json_hash(row.get("tags")),
            "evidence_hash": _json_hash(row.get("evidence")),
            "evidence_refs_hash": _json_hash(row.get("evidence_refs")),
        }
        fingerprints.append(_json_hash(record))
    return sorted(fingerprints)


def _collector_payload(run_ref: RunRef, *, rules: GateRules) -> dict[str, Any]:
    run_row = core_q.run_sql(
        """
        SELECT
          sar.sha256,
          sar.base_apk_sha256,
          sar.artifact_set_hash,
          sar.run_signature,
          sar.run_signature_version,
          sar.identity_valid,
          sar.identity_error_reason,
          sar.analysis_version,
          sar.pipeline_version,
          sar.catalog_versions,
          sar.config_hash,
          sar.profile,
          sar.category,
          sar.findings_total,
          sar.status,
          a.profile_key
        FROM static_analysis_runs sar
        JOIN app_versions av ON av.id = sar.app_version_id
        JOIN apps a ON a.id = av.app_id
        WHERE sar.id = %s
        """,
        (run_ref.run_id,),
        fetch="one_dict",
    )
    if not run_row:
        raise RuntimeError(f"Missing static run row for id={run_ref.run_id}")

    detector_rows = core_q.run_sql(
        """
        SELECT
          COALESCE(NULLIF(detector, ''), NULLIF(module, ''), '<unknown>') AS detector_key,
          COUNT(*) AS n
        FROM static_analysis_findings
        WHERE run_id = %s
        GROUP BY COALESCE(NULLIF(detector, ''), NULLIF(module, ''), '<unknown>')
        ORDER BY detector_key ASC
        """,
        (run_ref.run_id,),
        fetch="all",
    ) or []

    category_rows = core_q.run_sql(
        """
        SELECT COALESCE(category, 'UNKNOWN') AS category_key, COUNT(*) AS n
        FROM static_analysis_findings
        WHERE run_id = %s
        GROUP BY COALESCE(category, 'UNKNOWN')
        ORDER BY category_key ASC
        """,
        (run_ref.run_id,),
        fetch="all",
    ) or []

    score_rows = core_q.run_sql(
        """
        SELECT scope_label, risk_score, risk_grade, dangerous, signature, vendor
        FROM risk_scores
        WHERE package_name = %s
          AND session_stamp = %s
        ORDER BY scope_label ASC
        """,
        (run_ref.package_name, run_ref.session_stamp),
        fetch="all",
    ) or []

    permission_risk_vnext = _collect_permission_risk_vnext(run_ref.run_id)
    table_snapshots: dict[str, dict[str, Any]] = {}
    for table_name in rules.table_coverage_lock:
        if table_name == "risk_scores":
            table_snapshots[table_name] = {"table": table_name, "present": True, "note": "covered by scoped query"}
            continue
        where_field = "run_id"
        if table_name in {"static_analysis_runs"}:
            where_field = "id"
        table_snapshots[table_name] = _table_snapshot(table_name, where_field, run_ref.run_id)

    payload = {
        "identity": {
            "package_name": run_ref.package_name,
            "scope_label": run_ref.scope_label,
            "profile_key": run_row.get("profile_key") or "UNKNOWN",
            "sha256": run_row.get("sha256"),
            "base_apk_sha256": run_row.get("base_apk_sha256"),
            "artifact_set_hash": run_row.get("artifact_set_hash"),
            "run_signature": run_row.get("run_signature"),
            "run_signature_version": run_row.get("run_signature_version"),
            "identity_valid": run_row.get("identity_valid"),
            "identity_error_reason": run_row.get("identity_error_reason"),
            "category": run_row.get("category"),
            "status": run_row.get("status"),
            "profile": run_row.get("profile"),
            "analysis_version": run_row.get("analysis_version"),
            "pipeline_version": run_row.get("pipeline_version"),
            "catalog_versions": run_row.get("catalog_versions"),
            "config_hash": run_row.get("config_hash"),
        },
        "analytics": {
            "findings_total": int(run_row.get("findings_total") or 0),
            "detector_counts": {str(row[0]): int(row[1]) for row in detector_rows},
            "finding_category_counts": {str(row[0]): int(row[1]) for row in category_rows},
            "risk_scores": [
                {
                    "scope_label": row[0],
                    "risk_score": _safe_decimal(row[1]),
                    "risk_grade": row[2],
                    "dangerous": int(row[3] or 0),
                    "signature": int(row[4] or 0),
                    "vendor": int(row[5] or 0),
                }
                for row in score_rows
            ],
            "finding_fingerprints": _finding_fingerprints(run_ref.run_id),
            "permission_risk_vnext": permission_risk_vnext,
            "table_snapshots": table_snapshots,
        },
        "persisted_row_counts": {
            "static_analysis_runs": int(table_snapshots.get("static_analysis_runs", {}).get("row_count", 0) or 0),
            "static_analysis_findings": int(table_snapshots.get("static_analysis_findings", {}).get("row_count", 0) or 0),
            "static_permission_matrix": int(table_snapshots.get("static_permission_matrix", {}).get("row_count", 0) or 0),
            "static_permission_risk": int(table_snapshots.get("static_permission_risk", {}).get("row_count", 0) or 0),
            "risk_scores": len(score_rows),
            "static_permission_risk_vnext": int(permission_risk_vnext.get("row_count") or 0),
        },
    }
    return payload


def _is_allowed(path: str, *, rules: GateRules) -> bool:
    return path in set(rules.allowed_diff_fields)


def _collect_diffs(left: Any, right: Any, *, rules: GateRules, prefix: str = "") -> list[dict[str, Any]]:
    diffs: list[dict[str, Any]] = []
    if isinstance(left, dict) and isinstance(right, dict):
        keys = sorted(set(left.keys()) | set(right.keys()))
        for key in keys:
            child = f"{prefix}.{key}" if prefix else str(key)
            if key not in left:
                diffs.append({"path": child, "left": None, "right": right.get(key), "allowed": _is_allowed(child, rules=rules)})
                continue
            if key not in right:
                diffs.append({"path": child, "left": left.get(key), "right": None, "allowed": _is_allowed(child, rules=rules)})
                continue
            diffs.extend(_collect_diffs(left[key], right[key], rules=rules, prefix=child))
        return diffs
    if isinstance(left, list) and isinstance(right, list):
        max_len = max(len(left), len(right))
        for idx in range(max_len):
            child = f"{prefix}[{idx}]"
            l_item = left[idx] if idx < len(left) else None
            r_item = right[idx] if idx < len(right) else None
            diffs.extend(_collect_diffs(l_item, r_item, rules=rules, prefix=child))
        return diffs
    if left != right:
        diffs.append({"path": prefix, "left": left, "right": right, "allowed": _is_allowed(prefix, rules=rules)})
    return diffs


def _build_result_payload(
    *,
    apk_path: Path,
    profile: str,
    rules: GateRules,
    rules_path: str,
    left_meta: dict[str, Any],
    right_meta: dict[str, Any],
    payload_a: dict[str, Any],
    payload_b: dict[str, Any],
    waiver: dict[str, Any] | None = None,
) -> dict[str, Any]:
    validation_issues: list[str] = []
    for side_name, payload in (("left", payload_a), ("right", payload_b)):
        analytics = payload.get("analytics", {})
        if not isinstance(analytics, dict):
            continue
        permission_risk = analytics.get("permission_risk_vnext", {})
        if not isinstance(permission_risk, dict):
            continue
        validation = permission_risk.get("validation", {})
        if not isinstance(validation, dict):
            continue
        if isinstance(validation.get("missing_key_fields"), list) and validation.get("missing_key_fields"):
            validation_issues.append(f"{side_name}.permission_risk_vnext.missing_key_fields")
        if isinstance(validation.get("duplicate_keys"), list) and validation.get("duplicate_keys"):
            validation_issues.append(f"{side_name}.permission_risk_vnext.duplicate_keys")
        if (
            isinstance(validation.get("non_canonical_permission_names"), list)
            and validation.get("non_canonical_permission_names")
        ):
            validation_issues.append(f"{side_name}.permission_risk_vnext.non_canonical_permission_names")

    diffs = _collect_diffs(payload_a, payload_b, rules=rules)
    allowed_count = sum(1 for item in diffs if bool(item.get("allowed")))
    disallowed_count = sum(1 for item in diffs if not bool(item.get("allowed")))
    passed = disallowed_count == 0 and not validation_issues
    waived = (not passed) and waiver is not None

    return {
        "tool_semver": app_config.APP_VERSION,
        "git_commit": get_git_commit(),
        "compare_type": rules.compare_type,
        "apk_path": str(apk_path),
        "profile": profile,
        "rules": {
            "path": rules_path,
            "schema_version": rules.schema_version,
            "allowed_diff_fields": list(rules.allowed_diff_fields),
            "table_coverage_lock": list(rules.table_coverage_lock),
        },
        "left": left_meta,
        "right": right_meta,
        "allowed_diff_fields": list(rules.allowed_diff_fields),
        "result": {
            "pass": passed or waived,
            "pass_raw": passed,
            "degraded": False,
            "degraded_reasons": [],
            "waived": waived,
            "fail_reason": None if (passed or waived) else ("validation_error" if validation_issues else "disallowed_diffs"),
            "validation_issues": validation_issues,
            "diff_counts": {
                "total": len(diffs),
                "allowed": allowed_count,
                "disallowed": disallowed_count,
            },
        },
        "waiver": waiver or {},
        "diffs": diffs,
        "comparison": {
            "first": payload_a,
            "second": payload_b,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Static-analysis determinism gate (run same APK twice).")
    parser.add_argument(
        "--db-target",
        required=True,
        help="Explicit DB target DSN (mysql://...). Required for audit safety (SQLite is not supported).",
    )
    parser.add_argument("--apk", required=True, help="Path to APK under analysis.")
    parser.add_argument(
        "--profile",
        default="full",
        choices=["full", "permissions", "metadata", "lightweight", "split"],
        help="Static analysis profile.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="JSON output path. Default: output/audit/comparators/static_analysis/<stamp>/diff.json",
    )
    parser.add_argument(
        "--allow-session-reuse",
        action="store_true",
        help="Allow session reuse during scan invocations.",
    )
    parser.add_argument(
        "--rules",
        default=str(DEFAULT_RULES_PATH),
        help="Comparator rules JSON (allowed fields + table coverage lock).",
    )
    parser.add_argument(
        "--waiver",
        default=None,
        help="Optional waiver JSON. Required fields: reason, scope, approver, expires_utc.",
    )
    args = parser.parse_args(argv)
    _configure_db_target(str(args.db_target))
    rules_path = Path(str(args.rules)).expanduser().resolve()
    if not rules_path.exists():
        raise SystemExit(f"Comparator rules file not found: {rules_path}")
    rules = _load_rules(rules_path)
    waiver_payload: dict[str, Any] | None = None
    if args.waiver:
        waiver_path = Path(str(args.waiver)).expanduser().resolve()
        if not waiver_path.exists():
            raise SystemExit(f"Waiver file not found: {waiver_path}")
        waiver_payload = _load_waiver(waiver_path)
        waiver_payload = {**waiver_payload, "path": str(waiver_path)}

    apk_path = Path(args.apk).expanduser().resolve()
    if not apk_path.exists():
        raise SystemExit(f"APK not found: {apk_path}")

    group = _artifact_group_from_path(apk_path)
    session_a = f"det-{_now_stamp()}-a"
    session_b = f"det-{_now_stamp()}-b"
    run_started_utc = datetime.now(UTC).isoformat()

    _run_scan(apk_path, profile=args.profile, session_stamp=session_a, allow_reuse=args.allow_session_reuse)
    run_a = _resolve_run(group.package_name, session_a)
    payload_a = _collector_payload(run_a, rules=rules)

    _run_scan(apk_path, profile=args.profile, session_stamp=session_b, allow_reuse=args.allow_session_reuse)
    run_b = _resolve_run(group.package_name, session_b)
    payload_b = _collector_payload(run_b, rules=rules)

    result = _build_result_payload(
        apk_path=apk_path,
        profile=args.profile,
        rules=rules,
        rules_path=str(rules_path),
        left_meta={
            "run_id": run_a.run_id,
            "session_stamp": session_a,
            "timestamp_utc": run_started_utc,
        },
        right_meta={
            "run_id": run_b.run_id,
            "session_stamp": session_b,
            "timestamp_utc": datetime.now(UTC).isoformat(),
        },
        payload_a=payload_a,
        payload_b=payload_b,
        waiver=waiver_payload,
    )
    output_path = Path(args.output) if args.output else _default_output_path()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    passed = bool(result.get("result", {}).get("pass"))
    print(
        json.dumps(
            {
                "status": "PASS" if passed else "FAIL",
                "output": str(output_path),
                "diff_count": int(result.get("result", {}).get("diff_counts", {}).get("disallowed", 0)),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
