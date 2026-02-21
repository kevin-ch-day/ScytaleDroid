"""Schema bootstrapper for local (SQLite) and MySQL deployments.

Usage:
    python -m scytaledroid.Database.tools.bootstrap
    or call bootstrap_database() from application setup.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from datetime import UTC, datetime

from scytaledroid.Database.db_core.db_config import DB_CONFIG
from scytaledroid.Database.db_core.db_queries import run_sql
from scytaledroid.Database.db_queries import schema_manifest
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def _normalize_sqlite(sql: str) -> str:
    """Translate MySQL-ish DDL to SQLite-friendly syntax."""
    # Drop ENGINE/CHARSET fragments
    sql = re.sub(r"ENGINE=InnoDB[^;]*", "", sql, flags=re.IGNORECASE)
    sql = re.sub(r"DEFAULT CHARSET=\w+", "", sql, flags=re.IGNORECASE)
    sql = sql.replace("AUTO_INCREMENT", "")

    replacements = [
        (r"BIGINT\s+UNSIGNED", "INTEGER"),
        (r"BIGINT", "INTEGER"),
        (r"INT\s+UNSIGNED", "INTEGER"),
        (r"INT\(", "INTEGER("),
        (r"TINYINT\(\d+\)", "INTEGER"),
        (r"SMALLINT\s+UNSIGNED", "INTEGER"),
        (r"SMALLINT", "INTEGER"),
        (r"LONGTEXT", "TEXT"),
        (r"UNSIGNED", ""),
        (r"DOUBLE", "REAL"),
        (r"DECIMAL\([0-9,]+\)", "REAL"),
        (r"JSON", "TEXT"),
        (r"\bDATETIME\b", "TEXT"),
        (r"\bTIMESTAMP\b", "TEXT"),
        (r"ENUM\([^)]*\)", "TEXT"),
    ]
    for pattern, replacement in replacements:
        sql = re.sub(pattern, replacement, sql, flags=re.IGNORECASE)

    # Strip MySQL KEY/CONSTRAINT lines that SQLite won't parse cleanly
    cleaned_lines: list[str] = []
    cleaned_lines: list[str] = []
    for line in sql.splitlines():
        stripped = line.strip()
        upper = stripped.upper()
        if upper.startswith("KEY ") or upper.startswith("UNIQUE KEY") or upper.startswith("CONSTRAINT "):
            continue
        if upper.startswith("FOREIGN KEY"):
            continue
        # DROP ON UPDATE fragments (not supported)
        if "ON UPDATE" in upper or "ON DELETE" in upper:
            continue
        if "REFERENCES" in upper:
            continue
        if upper.startswith("PRIMARY KEY") and cleaned_lines and not cleaned_lines[-1].rstrip().endswith(","):
            cleaned_lines[-1] = cleaned_lines[-1].rstrip() + ","
        cleaned_lines.append(line.rstrip())

    sql = "\n".join(line for line in cleaned_lines if line.strip())
    sql = re.sub(r",\s*\)", "\n)", sql)
    return sql.strip().rstrip(";") + ";"


def _execute_statements(statements: Iterable[str], *, dialect: str) -> None:
    strict = os.environ.get("SCYTALEDROID_DB_BOOTSTRAP_STRICT", "0").strip().lower() in {"1", "true", "yes"}
    for idx, stmt in enumerate(statements, start=1):
        sql = stmt
        if dialect == "sqlite":
            # Skip some MySQL-only ALTERs that SQLite cannot parse even after replacements
            upper = stmt.upper()
            if "ALTER TABLE" in upper:
                continue
            sql = _normalize_sqlite(stmt)
        try:
            run_sql(sql)
        except Exception as exc:  # pragma: no cover - best-effort bootstrap
            if strict:
                log.error(
                    f"Schema statement failed (idx={idx}, dialect={dialect}): {sql[:200]}... error={exc}",
                    category="database",
                )
                raise
            log.warning(f"Schema statement failed ({sql[:60]}...): {exc}", category="database")


def _verify_required_schema(*, dialect: str) -> None:
    """Fail closed when the canonical MariaDB schema is incomplete."""
    if dialect != "mysql":
        return
    # Minimal invariant set. This should only expand over time.
    required_tables = [
        "schema_version",
        "apps",
        "android_app_categories",
        "android_app_profiles",
        "android_app_publishers",
        "android_publisher_prefix_rules",
        "v_static_handoff_v1",
        "dynamic_sessions",
        "app_display_orderings",
        "app_display_aliases",
        "static_persistence_failures",
        # Phase H derived-facts store.
        "analysis_cohorts",
        "analysis_derivation_receipts",
        "analysis_cohort_runs",
        "analysis_ml_app_phase_model_metrics",
        "analysis_signature_deltas",
        "analysis_static_exposure",
        "analysis_risk_regime_summary",
    ]
    missing: list[str] = []
    for t in required_tables:
        try:
            row = run_sql(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s",
                (t,),
                fetch="one",
            )
            ok = bool(row and int(row[0]) > 0)
        except Exception:
            ok = False
        if not ok:
            missing.append(t)
    if missing:
        raise RuntimeError(f"Schema bootstrap incomplete; missing tables: {missing}")

    # Required columns for operator/runtime workflows (kept minimal).
    required_columns: dict[str, list[str]] = {
        "dynamic_sessions": [
            "dynamic_run_id",
            "package_name",
            "profile_key",
            "operator_run_profile",
            "operator_interaction_level",
            "operator_messaging_activity",
            "countable",
            "valid_dataset_run",
            "invalid_reason_code",
            "started_at_utc",
            "ended_at_utc",
        ],
        "apps": ["package_name", "display_name", "profile_key", "publisher_key"],
        "static_analysis_runs": [
            "session_label",
            "base_apk_sha256",
            "identity_mode",
            "identity_conflict_flag",
            "static_handoff_hash",
            "static_handoff_json_path",
            "masvs_mapping_hash",
            "run_class",
            "non_canonical_reasons",
        ],
    }
    for table, cols in required_columns.items():
        try:
            rows = run_sql(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = DATABASE()
                  AND table_name = %s
                """,
                (table,),
                fetch="all",
            ) or []
            present = {str(r[0]).lower() for r in rows if r and r[0]}
        except Exception:
            present = set()
        missing_cols = [c for c in cols if c.lower() not in present]
        if missing_cols:
            raise RuntimeError(f"Schema bootstrap incomplete; {table} missing columns: {missing_cols}")


def bootstrap_database() -> None:
    dialect = str(DB_CONFIG.get("engine", "sqlite")).lower()
    ddl_blocks: list[str] = []

    if dialect == "sqlite":
        log.warning(
            "SQLite bootstrap uses relaxed constraints; MariaDB/MySQL is canonical.",
            category="database",
        )

    # Ordered manifest is the authoritative bootstrap source.
    ddl_blocks = schema_manifest.ordered_schema_statements()

    if not ddl_blocks:
        log.warning("No schema statements discovered during bootstrap.", category="database")
        return

    log.info(f"Bootstrapping schema for {dialect} with {len(ddl_blocks)} statements.", category="database")
    _execute_statements(ddl_blocks, dialect=dialect)
    _verify_required_schema(dialect=dialect)
    # Record schema version after successful bootstrap (append-only, if empty)
    try:
        row = run_sql("SELECT COUNT(*) FROM schema_version", fetch="one")
        if row and int(row[0]) == 0:
            run_sql(
                "INSERT INTO schema_version (version, applied_at_utc) VALUES (%s, %s)",
                (
                    "0.3.0-bootstrap",
                    datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                ),
            )
    except Exception as exc:  # pragma: no cover
        log.warning(f"Failed to record schema_version: {exc}", category="database")
    log.info("Schema bootstrap complete.", category="database")


if __name__ == "__main__":  # pragma: no cover
    bootstrap_database()
