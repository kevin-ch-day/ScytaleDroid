"""Static session parity and reconciliation helpers for post-run audits."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_utils.package_utils import resolve_package_identity
from scytaledroid.Database.summary_surfaces import (
    STATIC_DYNAMIC_SUMMARY_CACHE,
    STATIC_DYNAMIC_SUMMARY_VIEW,
    refresh_static_dynamic_summary_cache,
    static_dynamic_summary_cache_is_stale,
)
from scytaledroid.StaticAnalysis.cli.flows.session_finalizer import persist_static_session_links

_PACKAGE_COLLATION_TARGETS: tuple[tuple[str, str], ...] = (
    ("runs", "package"),
    ("risk_scores", "package_name"),
    ("static_session_run_links", "package_name"),
    ("static_findings_summary", "package_name"),
    ("static_string_summary", "package_name"),
    ("masvs_control_coverage", "package"),
)


def _count_query(sql: str, params: tuple[object, ...]) -> int:
    row = core_q.run_sql(sql, params, fetch="one")
    if not row or row[0] is None:
        return 0
    return int(row[0])


def _package_query(sql: str, params: tuple[object, ...]) -> set[str]:
    rows = core_q.run_sql(sql, params, fetch="all") or []
    packages: set[str] = set()
    for row in rows:
        if not row:
            continue
        identity = resolve_package_identity(str(row[0] or ""), context="database")
        if identity.normalized_package_name:
            packages.add(identity.normalized_package_name)
    return packages


def _safe_package_query(sql: str, params: tuple[object, ...]) -> set[str]:
    try:
        return _package_query(sql, params)
    except Exception:
        return set()


def _latest_static_session_label() -> str | None:
    row = core_q.run_sql(
        """
        SELECT session_label
        FROM static_analysis_runs
        GROUP BY session_label
        ORDER BY MAX(id) DESC
        LIMIT 1
        """,
        fetch="one",
    )
    if not row:
        return None
    value = str(row[0] or "").strip()
    return value or None


def _session_report_root(session_label: str) -> Path:
    return Path(app_config.DATA_DIR) / "static_analysis" / "reports" / "archive" / session_label


def _collect_report_packages(session_label: str) -> tuple[int, set[str]]:
    root = _session_report_root(session_label)
    if not root.exists():
        return 0, set()
    files = sorted(root.glob("*.json"))
    packages: set[str] = set()
    for path in files:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        metadata = payload.get("metadata") if isinstance(payload, dict) else None
        candidates = []
        if isinstance(payload, dict):
            candidates.extend(
                payload.get(key)
                for key in ("normalized_package_name", "package_name", "manifest_package_name")
            )
        if isinstance(metadata, dict):
            candidates.extend(
                metadata.get(key)
                for key in ("normalized_package_name", "package_name", "manifest_package_name")
            )
        for candidate in candidates:
            identity = resolve_package_identity(str(candidate or ""), context="static_analysis")
            if identity.normalized_package_name:
                packages.add(identity.normalized_package_name)
                break
    return len(files), packages


def _collated_package_match(column_sql: str) -> str:
    return f"CONVERT({column_sql} USING utf8mb4) COLLATE utf8mb4_unicode_ci"


def _package_collation_snapshot() -> dict[str, str]:
    rows = core_q.run_sql(
        """
        SELECT TABLE_NAME, COLUMN_NAME, COLLATION_NAME
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND (
            (TABLE_NAME='runs' AND COLUMN_NAME='package')
            OR (TABLE_NAME='risk_scores' AND COLUMN_NAME='package_name')
            OR (TABLE_NAME='static_session_run_links' AND COLUMN_NAME='package_name')
            OR (TABLE_NAME='static_findings_summary' AND COLUMN_NAME='package_name')
            OR (TABLE_NAME='static_string_summary' AND COLUMN_NAME='package_name')
            OR (TABLE_NAME='masvs_control_coverage' AND COLUMN_NAME='package')
          )
        ORDER BY TABLE_NAME, COLUMN_NAME
        """,
        fetch="all",
    ) or []
    snapshot: dict[str, str] = {}
    for row in rows:
        if not row or len(row) < 3:
            continue
        table = str(row[0] or "").strip()
        column = str(row[1] or "").strip()
        collation = str(row[2] or "").strip() or "<none>"
        if table and column:
            snapshot[f"{table}.{column}"] = collation
    return snapshot


def _collation_risks(snapshot: dict[str, str]) -> list[str]:
    if not snapshot:
        return []
    values = {value for value in snapshot.values() if value and value != "<none>"}
    risks: list[str] = []
    if len(values) > 1:
        risks.append(f"mixed_package_collations={','.join(sorted(values))}")
    non_utf8 = sorted(key for key, value in snapshot.items() if value and not value.startswith("utf8mb4"))
    if non_utf8:
        risks.append(f"non_utf8mb4_package_columns={','.join(non_utf8)}")
    missing = sorted(
        f"{table}.{column}"
        for table, column in _PACKAGE_COLLATION_TARGETS
        if f"{table}.{column}" not in snapshot
    )
    if missing:
        risks.append(f"missing_collation_metadata={','.join(missing)}")
    return risks


@dataclass(slots=True)
class StaticSessionReconcileSummary:
    session_label: str
    total_runs: int
    completed_runs: int
    started_runs: int
    failed_runs: int
    canonical_findings: int
    canonical_permission_matrix: int
    canonical_permission_risk: int
    findings_summary_packages: int
    string_summary_packages: int
    legacy_runs_packages: int
    legacy_risk_packages: int
    secondary_compat_mirror_packages: int
    session_run_links: int
    session_rollups: int
    handoff_paths: int
    report_files: int
    report_packages: int
    completed_packages: set[str]
    failed_packages: set[str]
    missing_session_links: set[str]
    missing_legacy_runs: set[str]
    missing_risk_scores: set[str]
    missing_findings_summary: set[str]
    missing_string_summary: set[str]
    missing_report_packages: set[str]
    stale_report_only_packages: set[str]
    web_view_packages: int
    web_cache_packages: int
    missing_web_view_packages: set[str]
    missing_web_cache_packages: set[str]
    cache_stale: bool | None
    package_collations: dict[str, str]
    collation_risks: list[str]
    missing_secondary_compat_mirror_count: int = 0
    bridge_only_runs: set[str] = field(default_factory=set)
    bridge_only_risk_scores: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, object]:
        return {
            "session_label": self.session_label,
            "counts": {
                "static_analysis_runs": {
                    "total": self.total_runs,
                    "completed": self.completed_runs,
                    "started": self.started_runs,
                    "failed": self.failed_runs,
                },
                "canonical": {
                    "findings": self.canonical_findings,
                    "permission_matrix": self.canonical_permission_matrix,
                    "permission_risk": self.canonical_permission_risk,
                    "findings_summary_packages": self.findings_summary_packages,
                    "string_summary_packages": self.string_summary_packages,
                    "handoff_paths": self.handoff_paths,
                },
                "reports": {
                    "archive_json_files": self.report_files,
                    "report_packages": self.report_packages,
                },
                "web": {
                    "view_packages": self.web_view_packages,
                    "cache_packages": self.web_cache_packages,
                    "cache_stale": self.cache_stale,
                },
                "database": {
                    "package_collations": self.package_collations,
                    "collation_risks": self.collation_risks,
                },
                "parity": {
                    "session_run_links": self.session_run_links,
                    "session_rollups": self.session_rollups,
                    "compat_runs_packages": self.legacy_runs_packages,
                    "compat_risk_packages": self.legacy_risk_packages,
                    "secondary_compat_mirror_packages": self.secondary_compat_mirror_packages,
                },
            },
            "packages": {
                "completed": sorted(self.completed_packages),
                "failed": sorted(self.failed_packages),
                "missing_session_links": sorted(self.missing_session_links),
                "missing_legacy_runs": sorted(self.missing_legacy_runs),
                "missing_risk_scores": sorted(self.missing_risk_scores),
                "missing_secondary_compat_mirror_count": self.missing_secondary_compat_mirror_count,
                "missing_findings_summary": sorted(self.missing_findings_summary),
                "missing_string_summary": sorted(self.missing_string_summary),
                "missing_report_packages": sorted(self.missing_report_packages),
                "stale_report_only_packages": sorted(self.stale_report_only_packages),
                "bridge_only_runs": sorted(self.bridge_only_runs),
                "bridge_only_risk_scores": sorted(self.bridge_only_risk_scores),
                "missing_web_view_packages": sorted(self.missing_web_view_packages),
                "missing_web_cache_packages": sorted(self.missing_web_cache_packages),
            },
        }


def reconcile_static_session(session_label: str | None = None) -> StaticSessionReconcileSummary:
    session = str(session_label or "").strip() or _latest_static_session_label()
    if not session:
        raise RuntimeError("No static session labels found.")

    total = _count_query(
        "SELECT COUNT(*) FROM static_analysis_runs WHERE session_label=%s",
        (session,),
    )
    completed = _count_query(
        "SELECT COUNT(*) FROM static_analysis_runs WHERE session_label=%s AND status='COMPLETED'",
        (session,),
    )
    started = _count_query(
        "SELECT COUNT(*) FROM static_analysis_runs WHERE session_label=%s AND status='STARTED'",
        (session,),
    )
    failed = _count_query(
        "SELECT COUNT(*) FROM static_analysis_runs WHERE session_label=%s AND status='FAILED'",
        (session,),
    )
    canonical_findings = _count_query(
        """
        SELECT COUNT(*)
        FROM static_analysis_findings f
        JOIN static_analysis_runs r ON r.id=f.run_id
        WHERE r.session_label=%s
        """,
        (session,),
    )
    canonical_permission_matrix = _count_query(
        """
        SELECT COUNT(*)
        FROM static_permission_matrix m
        JOIN static_analysis_runs r ON r.id=m.run_id
        WHERE r.session_label=%s
        """,
        (session,),
    )
    canonical_permission_risk = _count_query(
        """
        SELECT COUNT(*)
        FROM static_permission_risk_vnext p
        JOIN static_analysis_runs r ON r.id=p.run_id
        WHERE r.session_label=%s
        """,
        (session,),
    )

    completed_packages = _package_query(
        """
        SELECT a.package_name
        FROM static_analysis_runs sar
        JOIN app_versions av ON av.id=sar.app_version_id
        JOIN apps a ON a.id=av.app_id
        WHERE sar.session_label=%s AND sar.status='COMPLETED'
        """,
        (session,),
    )
    failed_packages = _package_query(
        """
        SELECT a.package_name
        FROM static_analysis_runs sar
        JOIN app_versions av ON av.id=sar.app_version_id
        JOIN apps a ON a.id=av.app_id
        WHERE sar.session_label=%s AND sar.status='FAILED'
        """,
        (session,),
    )

    findings_summary_packages = _package_query(
        "SELECT package_name FROM static_findings_summary WHERE session_stamp=%s",
        (session,),
    )
    string_summary_packages = _package_query(
        "SELECT package_name FROM static_string_summary WHERE session_stamp=%s",
        (session,),
    )
    legacy_run_packages = _package_query(
        "SELECT package FROM runs WHERE session_stamp=%s",
        (session,),
    )
    legacy_risk_packages = _package_query(
        "SELECT package_name FROM risk_scores WHERE session_stamp=%s",
        (session,),
    )
    legacy_findings_packages = _package_query(
        """
        SELECT DISTINCT r.package
        FROM findings f
        JOIN runs r ON r.run_id=f.run_id
        WHERE r.session_stamp=%s
        """,
        (session,),
    )
    legacy_metrics_packages = _package_query(
        """
        SELECT DISTINCT r.package
        FROM metrics m
        JOIN runs r ON r.run_id=m.run_id
        WHERE r.session_stamp=%s
        """,
        (session,),
    )
    legacy_buckets_packages = _package_query(
        """
        SELECT DISTINCT r.package
        FROM buckets b
        JOIN runs r ON r.run_id=b.run_id
        WHERE r.session_stamp=%s
        """,
        (session,),
    )
    legacy_contributors_packages = _package_query(
        """
        SELECT DISTINCT r.package
        FROM contributors c
        JOIN runs r ON r.run_id=c.run_id
        WHERE r.session_stamp=%s
        """,
        (session,),
    )
    session_run_links = _count_query(
        "SELECT COUNT(*) FROM static_session_run_links WHERE session_stamp=%s",
        (session,),
    )
    session_rollups = _count_query(
        "SELECT COUNT(*) FROM static_session_rollups WHERE session_stamp=%s",
        (session,),
    )
    handoff_paths = _count_query(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs
        WHERE session_label=%s
          AND static_handoff_json_path IS NOT NULL
          AND static_handoff_json_path <> ''
        """,
        (session,),
    )
    report_files, report_packages = _collect_report_packages(session)
    web_view_packages = _safe_package_query(
        f"SELECT package_name FROM {STATIC_DYNAMIC_SUMMARY_VIEW} WHERE latest_static_session_stamp=%s",
        (session,),
    )
    web_cache_packages = _safe_package_query(
        f"SELECT package_name FROM {STATIC_DYNAMIC_SUMMARY_CACHE} WHERE latest_static_session_stamp=%s",
        (session,),
    )
    try:
        cache_stale: bool | None = static_dynamic_summary_cache_is_stale()
    except Exception:
        cache_stale = None
    package_collations = _package_collation_snapshot()
    collation_risks = _collation_risks(package_collations)

    missing_session_links = completed_packages - _package_query(
        "SELECT package_name FROM static_session_run_links WHERE session_stamp=%s",
        (session,),
    )
    missing_legacy_runs = completed_packages - legacy_run_packages
    missing_risk_scores = completed_packages - legacy_risk_packages
    missing_legacy_findings = completed_packages - legacy_findings_packages
    missing_legacy_metrics = completed_packages - legacy_metrics_packages
    missing_legacy_buckets = completed_packages - legacy_buckets_packages
    missing_legacy_contributors = completed_packages - legacy_contributors_packages
    missing_findings_summary = completed_packages - findings_summary_packages
    missing_string_summary = completed_packages - string_summary_packages
    missing_report_packages = completed_packages - report_packages
    stale_report_only_packages = report_packages - completed_packages
    bridge_only_runs = legacy_run_packages - completed_packages
    bridge_only_risk_scores = legacy_risk_packages - completed_packages
    missing_web_view_packages = completed_packages - web_view_packages
    missing_web_cache_packages = completed_packages - web_cache_packages
    secondary_compat_mirror_packages = (
        legacy_findings_packages
        | legacy_metrics_packages
        | legacy_buckets_packages
        | legacy_contributors_packages
    )
    missing_secondary_compat_mirror_count = sum(
        len(values)
        for values in (
            missing_legacy_findings,
            missing_legacy_metrics,
            missing_legacy_buckets,
            missing_legacy_contributors,
        )
    )

    return StaticSessionReconcileSummary(
        session_label=session,
        total_runs=total,
        completed_runs=completed,
        started_runs=started,
        failed_runs=failed,
        canonical_findings=canonical_findings,
        canonical_permission_matrix=canonical_permission_matrix,
        canonical_permission_risk=canonical_permission_risk,
        findings_summary_packages=len(findings_summary_packages),
        string_summary_packages=len(string_summary_packages),
        legacy_runs_packages=len(legacy_run_packages),
        legacy_risk_packages=len(legacy_risk_packages),
        secondary_compat_mirror_packages=len(secondary_compat_mirror_packages),
        session_run_links=session_run_links,
        session_rollups=session_rollups,
        handoff_paths=handoff_paths,
        report_files=report_files,
        report_packages=len(report_packages),
        completed_packages=completed_packages,
        failed_packages=failed_packages,
        missing_session_links=missing_session_links,
        missing_legacy_runs=missing_legacy_runs,
        missing_risk_scores=missing_risk_scores,
        missing_secondary_compat_mirror_count=missing_secondary_compat_mirror_count,
        missing_findings_summary=missing_findings_summary,
        missing_string_summary=missing_string_summary,
        missing_report_packages=missing_report_packages,
        stale_report_only_packages=stale_report_only_packages,
        bridge_only_runs=bridge_only_runs,
        bridge_only_risk_scores=bridge_only_risk_scores,
        web_view_packages=len(web_view_packages),
        web_cache_packages=len(web_cache_packages),
        missing_web_view_packages=missing_web_view_packages,
        missing_web_cache_packages=missing_web_cache_packages,
        cache_stale=cache_stale,
        package_collations=package_collations,
        collation_risks=collation_risks,
    )


def write_reconcile_audit(summary: StaticSessionReconcileSummary) -> Path:
    out_dir = Path(app_config.OUTPUT_DIR) / "audit" / "persistence"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{summary.session_label}_reconcile_audit.json"
    payload = {
        "schema_version": "v1",
        "generated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "session_label": summary.session_label,
        "summary": summary.to_dict(),
    }
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return out_path


def repair_session_run_links(session_label: str) -> int:
    rows = core_q.run_sql(
        """
        SELECT a.package_name,
               sar.id AS static_run_id,
               sar.pipeline_version,
               sar.run_signature,
               sar.run_signature_version,
               sar.base_apk_sha256,
               sar.artifact_set_hash,
               sar.identity_valid,
               sar.identity_error_reason
        FROM static_analysis_runs sar
        JOIN app_versions av ON av.id=sar.app_version_id
        JOIN apps a ON a.id=av.app_id
        LEFT JOIN static_session_run_links l
          ON l.session_stamp=sar.session_label
         AND CONVERT(l.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci =
             a.package_name COLLATE utf8mb4_unicode_ci
        WHERE sar.session_label=%s
          AND sar.status='COMPLETED'
          AND l.link_id IS NULL
        ORDER BY a.package_name
        """,
        (session_label,),
        fetch="all_dict",
    ) or []
    run_map = {
        "apps": [
            {
                "package": row["package_name"],
                "static_run_id": int(row["static_run_id"]),
                "run_origin": "reused",
                "origin_session_stamp": session_label,
                "pipeline_version": row.get("pipeline_version"),
                "base_apk_sha256": row.get("base_apk_sha256"),
                "artifact_set_hash": row.get("artifact_set_hash"),
                "run_signature": row.get("run_signature"),
                "run_signature_version": row.get("run_signature_version"),
                "identity_valid": row.get("identity_valid"),
                "identity_error_reason": row.get("identity_error_reason"),
            }
            for row in rows
        ]
    }

    def _run_sql(sql, params=(), **kwargs):
        query_name = kwargs.get("query_name")
        if query_name:
            return core_q.run_sql_write(sql, params, query_name=query_name)
        return core_q.run_sql(sql, params, **kwargs)

    result = persist_static_session_links(
        session_label,
        run_map,
        run_sql=_run_sql,
        get_table_columns=lambda _table: [
            "session_stamp",
            "package_name",
            "static_run_id",
            "run_origin",
            "origin_session_stamp",
            "pipeline_version",
            "base_apk_sha256",
            "artifact_set_hash",
            "run_signature",
            "run_signature_version",
            "identity_valid",
            "identity_error_reason",
            "linked_at_utc",
        ],
        write_query_name="db_utils.static_reconcile.repair_session_run_links",
    )
    return result.links_written


def refresh_summary_cache_and_reconcile(session_label: str) -> tuple[int, StaticSessionReconcileSummary]:
    inserted, _materialized_at = refresh_static_dynamic_summary_cache()
    return inserted, reconcile_static_session(session_label)


__all__ = [
    "StaticSessionReconcileSummary",
    "reconcile_static_session",
    "refresh_summary_cache_and_reconcile",
    "repair_session_run_links",
    "write_reconcile_audit",
]
