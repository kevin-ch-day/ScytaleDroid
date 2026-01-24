"""DB writer for run-level metrics, buckets, correlations, findings, contributors.

Best-effort: functions return None/False if DB not reachable. Schema is
verified only; migrations are handled by the canonical schema tools.
"""

from __future__ import annotations

import json
import math
from typing import Any, Mapping, Optional, Sequence, Union

from functools import lru_cache

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Utils.LoggingUtils import logging_utils as log

_REQUIRED_TABLES = (
    "runs",
    "metrics",
    "buckets",
    "correlations",
    "findings",
    "contributors",
)


def ensure_schema(*, raise_on_error: bool = False) -> bool:
    """Verify required tables exist; schema creation is managed elsewhere."""

    try:
        row = core_q.run_sql(
            """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = DATABASE()
              AND table_name IN ({})
            """.format(",".join(["%s"] * len(_REQUIRED_TABLES))),
            tuple(_REQUIRED_TABLES),
            fetch="all",
        )
        present = {r[0] for r in row or []}
    except Exception as exc:
        message = (
            "Failed to verify persistence schema: "
            f"{exc.__class__.__name__}: {exc}"
        )
        log.error(message, category="static_analysis")
        if raise_on_error:
            raise RuntimeError(message) from exc
        return False

    missing = [name for name in _REQUIRED_TABLES if name not in present]
    if missing:
        message = (
            "Required persistence tables are missing: "
            f"{', '.join(missing)}. "
            "Schema is managed by canonical schema tools; restore the DB snapshot "
            "or run the canonical schema manifest."
        )
        log.error(message, category="static_analysis")
        if raise_on_error:
            raise RuntimeError(message)
        return False
    return True


def create_run(
    *,
    package: str,
    app_label: Optional[str],
    version_code: Optional[int],
    version_name: Optional[str],
    target_sdk: Optional[int],
    schema_version: str = "v1",
    prefs_hash: Optional[str] = None,
    installer: Optional[str] = None,
    confidence: Optional[str] = None,
    session_stamp: Optional[str] = None,
    threat_profile: str = "Unknown",
    env_profile: str = "consumer",
) -> Optional[int]:
    try:
        ensure_schema(raise_on_error=True)
        run_id = core_q.run_sql(
            (
                "INSERT INTO runs (package, app_label, version_code, version_name, target_sdk, schema_version, ts, session_stamp, prefs_hash, installer, confidence, threat_profile, env_profile) "
                "VALUES (%s,%s,%s,%s,%s,%s,CURRENT_TIMESTAMP,%s,%s,%s,%s,%s,%s)"
            ),
            (
                package,
                app_label,
                version_code,
                version_name,
                target_sdk,
                schema_version,
                session_stamp,
                prefs_hash,
                installer,
                confidence,
                threat_profile,
                env_profile,
            ),
            return_lastrowid=True,
        )
        if not run_id:
            raise RuntimeError(
                "INSERT INTO runs returned no identifier; check database permissions or constraints."
            )
        return int(run_id)
    except Exception as exc:
        message = (
            "Failed to create run row for package "
            f"{package}: {exc.__class__.__name__}: {exc}"
        )
        log.error(message, category="static_analysis")
        raise RuntimeError(message) from exc


def write_metrics(
    run_id: int,
    entries: Mapping[str, tuple[Optional[float], Optional[str]]],
    module_id: Optional[str] = None,
    *,
    static_run_id: Optional[int] = None,
) -> bool:
    has_static = _has_column("metrics", "static_run_id")
    try:
        if static_run_id is None and has_static:
            log.warning(
                f"static_run_id missing for metrics; run_id={run_id} will be used without static linkage",
                category="db",
            )
        for key, (num, text) in entries.items():
            if num is not None and not math.isfinite(float(num)):
                log.warning(
                    f"Skipping metric with non-finite value (run_id={run_id}, key={key}, value={num})",
                    category="db",
                )
                continue
            if has_static:
                core_q.run_sql(
                    (
                        "INSERT INTO metrics (run_id, static_run_id, feature_key, value_num, value_text, module_id) "
                        "VALUES (%s,%s,%s,%s,%s,%s) "
                        "ON DUPLICATE KEY UPDATE value_num=VALUES(value_num), value_text=VALUES(value_text), module_id=VALUES(module_id), static_run_id=VALUES(static_run_id)"
                    ),
                    (run_id, static_run_id, key, num, text, module_id),
                )
            else:
                core_q.run_sql(
                    (
                        "INSERT INTO metrics (run_id, feature_key, value_num, value_text, module_id) "
                        "VALUES (%s,%s,%s,%s,%s) "
                        "ON DUPLICATE KEY UPDATE value_num=VALUES(value_num), value_text=VALUES(value_text), module_id=VALUES(module_id)"
                    ),
                    (run_id, key, num, text, module_id),
                )
        return True
    except Exception as exc:
        log.error(
            f"Failed to persist metrics for run_id={run_id} static_run_id={static_run_id}: {exc}",
            category="db",
        )
        return False


def write_buckets(
    run_id: int,
    buckets: Mapping[str, tuple[float, Optional[float]]],
    *,
    static_run_id: Optional[int] = None,
) -> bool:
    has_static = _has_column("buckets", "static_run_id")
    try:
        if static_run_id is None and has_static:
            log.warning(
                f"static_run_id missing for buckets; run_id={run_id} will be used without static linkage",
                category="db",
            )
        for name, (points, cap) in buckets.items():
            if not math.isfinite(points):
                log.warning(
                    f"Skipping bucket with non-finite points (run_id={run_id}, bucket={name}, points={points})",
                    category="db",
                )
                continue
            if cap is not None and not math.isfinite(cap):
                log.warning(
                    f"Skipping bucket with non-finite cap (run_id={run_id}, bucket={name}, cap={cap})",
                    category="db",
                )
                continue
            if has_static:
                core_q.run_sql(
                    (
                        "INSERT INTO buckets (run_id, static_run_id, bucket, points, cap) "
                        "VALUES (%s,%s,%s,%s,%s)"
                    ),
                    (run_id, static_run_id, name, points, cap),
                )
            else:
                core_q.run_sql(
                    "INSERT INTO buckets (run_id, bucket, points, cap) VALUES (%s,%s,%s,%s)",
                    (run_id, name, points, cap),
                )
        return True
    except Exception as exc:
        log.error(
            f"Failed to persist buckets for run_id={run_id} static_run_id={static_run_id}: {exc}",
            category="db",
        )
        return False


def write_correlations(run_id: int, rows: Sequence[tuple[str, float, str]]) -> bool:
    try:
        for rule_id, points, rationale in rows:
            core_q.run_sql(
                "INSERT INTO correlations (run_id, rule_id, points, rationale) VALUES (%s,%s,%s,%s)",
                (run_id, rule_id, points, rationale),
            )
        return True
    except Exception as exc:
        log.warning(
            f"Correlations write failed for run_id={run_id}: {exc}",
            category="db",
        )
        return False


FindingRow = Union[
    tuple[str, str, str, str, Union[str, Mapping[str, Any]]],
    tuple[str, str, str, str, Union[str, Mapping[str, Any]], Optional[str]],
    Mapping[str, Any],
]


def write_findings(run_id: int, rows: Sequence[FindingRow]) -> bool:
    try:
        for row in rows:
            if isinstance(row, Mapping):
                severity = row.get("severity")
                masvs = row.get("masvs")
                cvss = row.get("cvss") or row.get("legacy_cvss")
                kind = row.get("kind")
                module_id = row.get("module_id")
                evidence_payload = row.get("evidence")
            else:
                if len(row) == 6:
                    severity, masvs, cvss, kind, evidence_payload, module_id = row
                else:
                    severity, masvs, cvss, kind, evidence_payload = row[:5]
                    module_id = None
            evidence = _serialise_evidence(evidence_payload)
            if isinstance(evidence, str) and len(evidence) > 512:
                log.warning(
                    f"Truncating evidence payload for run_id={run_id} (len={len(evidence)})",
                    category="db",
                )
                evidence = evidence[:509] + "..."
            core_q.run_sql(
                "INSERT INTO findings (run_id, severity, masvs, cvss, kind, evidence, module_id) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (run_id, severity, masvs, cvss, kind, evidence, module_id),
            )
        return True
    except Exception as exc:
        log.error(
            f"Failed to persist findings for run_id={run_id}: {exc}",
            category="db",
        )
        return False


def _serialise_evidence(payload: Any) -> Optional[str]:
    if payload is None:
        return None
    if isinstance(payload, str):
        return payload
    try:
        return json.dumps(payload, ensure_ascii=False)
    except Exception:
        return json.dumps({}, ensure_ascii=False)


def write_contributors(run_id: int, rows: Sequence[tuple[str, float, str, int]]) -> bool:
    try:
        for feature, points, explanation, rank in rows:
            core_q.run_sql(
                "INSERT INTO contributors (run_id, feature, points, explanation, rank) VALUES (%s,%s,%s,%s,%s)",
                (run_id, feature, points, explanation, rank),
            )
        return True
    except Exception as exc:
        log.error(
            f"Failed to persist contributors for run_id={run_id}: {exc}",
            category="db",
        )
        return False


__all__ = [
    "ensure_schema",
    "create_run",
    "write_metrics",
    "write_buckets",
    "write_correlations",
    "write_findings",
    "write_contributors",
]


@lru_cache(maxsize=None)
def _has_column(table: str, column: str) -> bool:
    try:
        row = core_q.run_sql(
            "SHOW COLUMNS FROM {} LIKE %s".format(table),
            (column,),
            fetch="one",
        )
        return bool(row)
    except Exception:
        return False
