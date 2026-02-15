#!/usr/bin/env python3
"""Run a strict static-analysis determinism gate for a single APK."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.StaticAnalysis.cli.flows import headless_run
from scytaledroid.StaticAnalysis.cli.flows.headless_run import _artifact_group_from_path
from scytaledroid.Utils.version_utils import get_git_commit


def _now_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%d%H%M%S")


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
        },
        "persisted_row_counts": {
            "static_analysis_runs": int(persisted_counts.get("runs") or 0),
            "static_analysis_findings": int(persisted_counts.get("findings") or 0),
            "static_permission_matrix": int(persisted_counts.get("permission_matrix") or 0),
            "static_permission_risk": int(persisted_counts.get("permission_risk") or 0),
            "risk_scores": int(persisted_counts.get("risk_scores") or 0),
        },
    }
    return payload


def _collect_diff(left: Any, right: Any, prefix: str = "") -> list[str]:
    diffs: list[str] = []
    if isinstance(left, dict) and isinstance(right, dict):
        keys = sorted(set(left.keys()) | set(right.keys()))
        for key in keys:
            child = f"{prefix}.{key}" if prefix else str(key)
            if key not in left:
                diffs.append(f"{child}: missing in first run")
                continue
            if key not in right:
                diffs.append(f"{child}: missing in second run")
                continue
            diffs.extend(_collect_diff(left[key], right[key], child))
        return diffs
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            diffs.append(f"{prefix}: length {len(left)} != {len(right)}")
            return diffs
        for idx, (l_item, r_item) in enumerate(zip(left, right, strict=True)):
            child = f"{prefix}[{idx}]"
            diffs.extend(_collect_diff(l_item, r_item, child))
        return diffs
    if left != right:
        diffs.append(f"{prefix}: {left!r} != {right!r}")
    return diffs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Static-analysis determinism gate (run same APK twice).")
    parser.add_argument("--apk", required=True, help="Path to APK under analysis.")
    parser.add_argument(
        "--profile",
        default="full",
        choices=["full", "permissions", "metadata", "lightweight", "split"],
        help="Static analysis profile.",
    )
    parser.add_argument(
        "--output",
        default="output/audit/determinism/result.json",
        help="JSON output path.",
    )
    parser.add_argument(
        "--allow-session-reuse",
        action="store_true",
        help="Allow session reuse during scan invocations.",
    )
    args = parser.parse_args(argv)

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
    diffs = _collect_diff(payload_a, payload_b)
    passed = not diffs

    result = {
        "status": "PASS" if passed else "FAIL",
        "apk_path": str(apk_path),
        "package_name": group.package_name,
        "profile": args.profile,
        "sessions": {"first": session_a, "second": session_b},
        "run_ids": {"first": run_a.run_id, "second": run_b.run_id},
        "started_at_utc": run_started_utc,
        "tool_semver": app_config.APP_VERSION,
        "tool_git_commit": get_git_commit(),
        "allowed_variance": {
            "ignored_fields": [
                "run_id",
                "created_at",
                "updated_at",
                "timestamp fields",
                "filesystem absolute temp paths",
            ],
            "comparison_strategy": "comparison payload excludes volatile fields by construction",
        },
        "comparison": {
            "first": payload_a,
            "second": payload_b,
            "diffs": diffs,
        },
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"status": result["status"], "output": str(output_path), "diff_count": len(diffs)}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
