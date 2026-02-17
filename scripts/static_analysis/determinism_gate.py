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

ALLOWED_DIFF_FIELDS: tuple[str, ...] = ()


def _configure_db_target(db_target: str) -> None:
    parsed = urlparse(db_target)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"mysql", "mariadb", "sqlite", "file"}:
        raise RuntimeError("Unsupported --db-target scheme. Use mysql://... or sqlite:///...")

    os.environ["SCYTALEDROID_DB_URL"] = db_target
    if scheme in {"sqlite", "file"}:
        db_path = parsed.path or parsed.netloc
        if not db_path:
            raise RuntimeError("sqlite --db-target must include a path, e.g. sqlite:///abs/path.db")
        db_config.DB_CONFIG = {
            "engine": "sqlite",
            "database": db_path,
            "charset": "utf8",
            "readonly": False,
        }
        db_config.DB_CONFIG_SOURCE = "cli:--db-target"
        print(f"[DB TARGET] backend=sqlite path={db_path}")
        return

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


def _collect_permission_risk_vnext(run_id: int) -> dict[str, Any]:
    table_ready = False
    try:
        row = core_q.run_sql(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'static_permission_risk_vnext'",
            fetch="one",
        )
        table_ready = bool(row and int(row[0]) > 0)
    except Exception:
        try:
            row = core_q.run_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='static_permission_risk_vnext'",
                fetch="one",
            )
            table_ready = bool(row)
        except Exception:
            table_ready = False

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


def _collector_payload(run_ref: RunRef) -> dict[str, Any]:
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

    persisted_counts = core_q.run_sql(
        """
        SELECT
          (SELECT COUNT(*) FROM static_analysis_runs WHERE id = %s) AS runs,
          (SELECT COUNT(*) FROM static_analysis_findings WHERE run_id = %s) AS findings,
          (SELECT COUNT(*) FROM static_permission_matrix WHERE run_id = %s) AS permission_matrix,
          (SELECT COUNT(*) FROM static_permission_risk WHERE package_name = %s AND session_stamp = %s) AS permission_risk,
          (SELECT COUNT(*) FROM risk_scores WHERE package_name = %s AND session_stamp = %s) AS risk_scores
        """,
        (
            run_ref.run_id,
            run_ref.run_id,
            run_ref.run_id,
            run_ref.package_name,
            run_ref.session_stamp,
            run_ref.package_name,
            run_ref.session_stamp,
        ),
        fetch="one_dict",
    ) or {}

    permission_risk_vnext = _collect_permission_risk_vnext(run_ref.run_id)
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
        },
        "persisted_row_counts": {
            "static_analysis_runs": int(persisted_counts.get("runs") or 0),
            "static_analysis_findings": int(persisted_counts.get("findings") or 0),
            "static_permission_matrix": int(persisted_counts.get("permission_matrix") or 0),
            "static_permission_risk": int(persisted_counts.get("permission_risk") or 0),
            "risk_scores": int(persisted_counts.get("risk_scores") or 0),
            "static_permission_risk_vnext": int(permission_risk_vnext.get("row_count") or 0),
        },
    }
    return payload


def _is_allowed(path: str) -> bool:
    return path in ALLOWED_DIFF_FIELDS


def _collect_diffs(left: Any, right: Any, prefix: str = "") -> list[dict[str, Any]]:
    diffs: list[dict[str, Any]] = []
    if isinstance(left, dict) and isinstance(right, dict):
        keys = sorted(set(left.keys()) | set(right.keys()))
        for key in keys:
            child = f"{prefix}.{key}" if prefix else str(key)
            if key not in left:
                diffs.append({"path": child, "left": None, "right": right.get(key), "allowed": _is_allowed(child)})
                continue
            if key not in right:
                diffs.append({"path": child, "left": left.get(key), "right": None, "allowed": _is_allowed(child)})
                continue
            diffs.extend(_collect_diffs(left[key], right[key], child))
        return diffs
    if isinstance(left, list) and isinstance(right, list):
        max_len = max(len(left), len(right))
        for idx in range(max_len):
            child = f"{prefix}[{idx}]"
            l_item = left[idx] if idx < len(left) else None
            r_item = right[idx] if idx < len(right) else None
            diffs.extend(_collect_diffs(l_item, r_item, child))
        return diffs
    if left != right:
        diffs.append({"path": prefix, "left": left, "right": right, "allowed": _is_allowed(prefix)})
    return diffs


def _build_result_payload(
    *,
    apk_path: Path,
    profile: str,
    left_meta: dict[str, Any],
    right_meta: dict[str, Any],
    payload_a: dict[str, Any],
    payload_b: dict[str, Any],
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

    diffs = _collect_diffs(payload_a, payload_b)
    allowed_count = sum(1 for item in diffs if bool(item.get("allowed")))
    disallowed_count = sum(1 for item in diffs if not bool(item.get("allowed")))
    passed = disallowed_count == 0 and not validation_issues

    return {
        "tool_semver": app_config.APP_VERSION,
        "git_commit": get_git_commit(),
        "compare_type": "static_analysis",
        "apk_path": str(apk_path),
        "profile": profile,
        "left": left_meta,
        "right": right_meta,
        "allowed_diff_fields": list(ALLOWED_DIFF_FIELDS),
        "result": {
            "pass": passed,
            "degraded": False,
            "degraded_reasons": [],
            "fail_reason": None if passed else ("validation_error" if validation_issues else "disallowed_diffs"),
            "validation_issues": validation_issues,
            "diff_counts": {
                "total": len(diffs),
                "allowed": allowed_count,
                "disallowed": disallowed_count,
            },
        },
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
        help="Explicit DB target DSN (mysql://... or sqlite:///...). Required for audit safety.",
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
    args = parser.parse_args(argv)
    _configure_db_target(str(args.db_target))

    apk_path = Path(args.apk).expanduser().resolve()
    if not apk_path.exists():
        raise SystemExit(f"APK not found: {apk_path}")

    group = _artifact_group_from_path(apk_path)
    session_a = f"det-{_now_stamp()}-a"
    session_b = f"det-{_now_stamp()}-b"
    run_started_utc = datetime.now(UTC).isoformat()

    _run_scan(apk_path, profile=args.profile, session_stamp=session_a, allow_reuse=args.allow_session_reuse)
    run_a = _resolve_run(group.package_name, session_a)
    payload_a = _collector_payload(run_a)

    _run_scan(apk_path, profile=args.profile, session_stamp=session_b, allow_reuse=args.allow_session_reuse)
    run_b = _resolve_run(group.package_name, session_b)
    payload_b = _collector_payload(run_b)

    result = _build_result_payload(
        apk_path=apk_path,
        profile=args.profile,
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
