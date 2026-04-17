"""Schema migration and DB operation logging actions for Database Tools."""

from __future__ import annotations

import getpass
import os
import socket
from datetime import UTC, datetime


def ensure_dynamic_tier_column(*, db_config, diagnostics, core_q, prompt_utils, status_messages, prompt_user: bool = True) -> bool:
    """Ensure dynamic_sessions has a tier column (DB migration helper)."""

    cfg = db_config.DB_CONFIG
    backend = str(cfg.get("engine", "disabled"))
    if backend != "mysql":
        print(
            status_messages.status(
                "Tier column migration is only supported for MySQL/MariaDB backends.",
                level="warn",
            )
        )
        return False

    columns = diagnostics.get_table_columns("dynamic_sessions") or []
    if "tier" in {col.lower() for col in columns}:
        print(status_messages.status("dynamic_sessions.tier already present.", level="success"))
        return True

    print(status_messages.status("Missing dynamic_sessions.tier column.", level="warn"))
    if prompt_user and not prompt_utils.prompt_yes_no(
        "Apply migration now? (ALTER TABLE dynamic_sessions ADD COLUMN tier)",
        default=True,
    ):
        return False

    sql = "ALTER TABLE dynamic_sessions ADD COLUMN tier VARCHAR(32) DEFAULT NULL"
    core_q.run_sql_write(sql, query_name="db_utils.dynamic_sessions.add_tier")
    print(status_messages.status("Added dynamic_sessions.tier column.", level="success"))
    return True


def ensure_dynamic_network_quality_column(
    *,
    db_config,
    diagnostics,
    core_q,
    prompt_utils,
    status_messages,
    prompt_user: bool = True,
) -> bool:
    """Ensure dynamic_sessions has a network_signal_quality column (DB migration helper)."""

    cfg = db_config.DB_CONFIG
    backend = str(cfg.get("engine", "disabled"))
    if backend != "mysql":
        print(
            status_messages.status(
                "network_signal_quality migration is only supported for MySQL/MariaDB backends.",
                level="warn",
            )
        )
        return False

    columns = diagnostics.get_table_columns("dynamic_sessions") or []
    if "network_signal_quality" in {col.lower() for col in columns}:
        print(status_messages.status("dynamic_sessions.network_signal_quality already present.", level="success"))
        return True

    print(status_messages.status("Missing dynamic_sessions.network_signal_quality column.", level="warn"))
    if prompt_user and not prompt_utils.prompt_yes_no(
        "Apply migration now? (ALTER TABLE dynamic_sessions ADD COLUMN network_signal_quality)",
        default=True,
    ):
        return False

    sql = "ALTER TABLE dynamic_sessions ADD COLUMN network_signal_quality VARCHAR(32) DEFAULT NULL"
    core_q.run_sql_write(sql, query_name="db_utils.dynamic_sessions.add_network_signal_quality")
    print(status_messages.status("Added dynamic_sessions.network_signal_quality column.", level="success"))
    return True


def ensure_dynamic_pcap_columns(
    *,
    db_config,
    diagnostics,
    core_q,
    prompt_utils,
    status_messages,
    prompt_user: bool = True,
) -> bool:
    """Ensure dynamic_sessions has PCAP metadata columns (DB migration helper)."""

    cfg = db_config.DB_CONFIG
    backend = str(cfg.get("engine", "disabled"))
    if backend != "mysql":
        print(
            status_messages.status(
                "PCAP metadata migrations are only supported for MySQL/MariaDB backends.",
                level="warn",
            )
        )
        return False

    columns = diagnostics.get_table_columns("dynamic_sessions") or []
    column_set = {col.lower() for col in columns}
    needed = {"pcap_relpath", "pcap_bytes", "pcap_sha256", "pcap_valid", "pcap_validated_at_utc"}
    missing = sorted(needed - column_set)
    if not missing:
        print(status_messages.status("dynamic_sessions PCAP columns already present.", level="success"))
        return True

    print(status_messages.status(f"Missing dynamic_sessions columns: {', '.join(missing)}.", level="warn"))
    if prompt_user and not prompt_utils.prompt_yes_no(
        "Apply migration now? (ALTER TABLE dynamic_sessions ADD COLUMN pcap metadata)",
        default=True,
    ):
        return False

    if "pcap_relpath" in missing:
        core_q.run_sql_write(
            "ALTER TABLE dynamic_sessions ADD COLUMN pcap_relpath VARCHAR(512) DEFAULT NULL",
            query_name="db_utils.dynamic_sessions.add_pcap_relpath",
        )
        print(status_messages.status("Added dynamic_sessions.pcap_relpath column.", level="success"))
    if "pcap_bytes" in missing:
        core_q.run_sql_write(
            "ALTER TABLE dynamic_sessions ADD COLUMN pcap_bytes BIGINT DEFAULT NULL",
            query_name="db_utils.dynamic_sessions.add_pcap_bytes",
        )
        print(status_messages.status("Added dynamic_sessions.pcap_bytes column.", level="success"))
    if "pcap_sha256" in missing:
        core_q.run_sql_write(
            "ALTER TABLE dynamic_sessions ADD COLUMN pcap_sha256 CHAR(64) DEFAULT NULL",
            query_name="db_utils.dynamic_sessions.add_pcap_sha256",
        )
        print(status_messages.status("Added dynamic_sessions.pcap_sha256 column.", level="success"))
    if "pcap_valid" in missing:
        core_q.run_sql_write(
            "ALTER TABLE dynamic_sessions ADD COLUMN pcap_valid TINYINT(1) DEFAULT NULL",
            query_name="db_utils.dynamic_sessions.add_pcap_valid",
        )
        print(status_messages.status("Added dynamic_sessions.pcap_valid column.", level="success"))
    if "pcap_validated_at_utc" in missing:
        core_q.run_sql_write(
            "ALTER TABLE dynamic_sessions ADD COLUMN pcap_validated_at_utc DATETIME DEFAULT NULL",
            query_name="db_utils.dynamic_sessions.add_pcap_validated_at",
        )
        print(status_messages.status("Added dynamic_sessions.pcap_validated_at_utc column.", level="success"))
    return True


def ensure_dynamic_netstats_rows_columns(
    *,
    db_config,
    diagnostics,
    core_q,
    prompt_utils,
    status_messages,
    prompt_user: bool = True,
) -> bool:
    """Ensure dynamic_sessions has netstats row counters (DB migration helper)."""

    cfg = db_config.DB_CONFIG
    backend = str(cfg.get("engine", "disabled"))
    if backend != "mysql":
        print(
            status_messages.status(
                "netstats row counter migrations are only supported for MySQL/MariaDB backends.",
                level="warn",
            )
        )
        return False

    columns = diagnostics.get_table_columns("dynamic_sessions") or []
    column_set = {col.lower() for col in columns}
    needed = {"netstats_rows", "netstats_missing_rows"}
    missing = sorted(needed - column_set)
    if not missing:
        print(status_messages.status("dynamic_sessions netstats row columns already present.", level="success"))
        return True

    print(status_messages.status(f"Missing dynamic_sessions columns: {', '.join(missing)}.", level="warn"))
    if prompt_user and not prompt_utils.prompt_yes_no(
        "Apply migration now? (ALTER TABLE dynamic_sessions ADD COLUMN netstats rows)",
        default=True,
    ):
        return False

    if "netstats_rows" in missing:
        core_q.run_sql_write(
            "ALTER TABLE dynamic_sessions ADD COLUMN netstats_rows INT DEFAULT NULL",
            query_name="db_utils.dynamic_sessions.add_netstats_rows",
        )
        print(status_messages.status("Added dynamic_sessions.netstats_rows column.", level="success"))
    if "netstats_missing_rows" in missing:
        core_q.run_sql_write(
            "ALTER TABLE dynamic_sessions ADD COLUMN netstats_missing_rows INT DEFAULT NULL",
            query_name="db_utils.dynamic_sessions.add_netstats_missing_rows",
        )
        print(status_messages.status("Added dynamic_sessions.netstats_missing_rows column.", level="success"))
    return True


def ensure_dynamic_sampling_duration_columns(
    *,
    db_config,
    diagnostics,
    core_q,
    prompt_utils,
    status_messages,
    prompt_user: bool = True,
) -> bool:
    """Ensure dynamic_sessions has sampling duration alignment columns."""

    cfg = db_config.DB_CONFIG
    backend = str(cfg.get("engine", "disabled"))
    if backend != "mysql":
        print(
            status_messages.status(
                "sampling duration migrations are only supported for MySQL/MariaDB backends.",
                level="warn",
            )
        )
        return False

    columns = diagnostics.get_table_columns("dynamic_sessions") or []
    column_set = {col.lower() for col in columns}
    needed = {"sampling_duration_seconds", "clock_alignment_delta_s"}
    missing = sorted(needed - column_set)
    if not missing:
        print(status_messages.status("dynamic_sessions sampling duration columns already present.", level="success"))
        return True

    print(status_messages.status(f"Missing dynamic_sessions columns: {', '.join(missing)}.", level="warn"))
    if prompt_user and not prompt_utils.prompt_yes_no(
        "Apply migration now? (ALTER TABLE dynamic_sessions ADD COLUMN sampling duration)",
        default=True,
    ):
        return False

    if "sampling_duration_seconds" in missing:
        core_q.run_sql_write(
            "ALTER TABLE dynamic_sessions ADD COLUMN sampling_duration_seconds DOUBLE DEFAULT NULL",
            query_name="db_utils.dynamic_sessions.add_sampling_duration_seconds",
        )
        print(status_messages.status("Added dynamic_sessions.sampling_duration_seconds column.", level="success"))
    if "clock_alignment_delta_s" in missing:
        core_q.run_sql_write(
            "ALTER TABLE dynamic_sessions ADD COLUMN clock_alignment_delta_s DOUBLE DEFAULT NULL",
            query_name="db_utils.dynamic_sessions.add_clock_alignment_delta_s",
        )
        print(status_messages.status("Added dynamic_sessions.clock_alignment_delta_s column.", level="success"))
    return True


def ensure_dynamic_gap_columns(
    *,
    db_config,
    diagnostics,
    core_q,
    prompt_utils,
    status_messages,
    prompt_user: bool = True,
) -> bool:
    """Ensure dynamic_sessions has warm-up gap columns."""

    cfg = db_config.DB_CONFIG
    backend = str(cfg.get("engine", "disabled"))
    if backend != "mysql":
        print(
            status_messages.status(
                "gap column migrations are only supported for MySQL/MariaDB backends.",
                level="warn",
            )
        )
        return False

    columns = diagnostics.get_table_columns("dynamic_sessions") or []
    column_set = {col.lower() for col in columns}
    needed = {"sample_first_gap_s", "sample_max_gap_excluding_first_s"}
    missing = sorted(needed - column_set)
    if not missing:
        print(status_messages.status("dynamic_sessions warm-up gap columns already present.", level="success"))
        return True

    print(status_messages.status(f"Missing dynamic_sessions columns: {', '.join(missing)}.", level="warn"))
    if prompt_user and not prompt_utils.prompt_yes_no(
        "Apply migration now? (ALTER TABLE dynamic_sessions ADD COLUMN warm-up gap)",
        default=True,
    ):
        return False

    if "sample_first_gap_s" in missing:
        core_q.run_sql_write(
            "ALTER TABLE dynamic_sessions ADD COLUMN sample_first_gap_s FLOAT DEFAULT NULL",
            query_name="db_utils.dynamic_sessions.add_sample_first_gap_s",
        )
        print(status_messages.status("Added dynamic_sessions.sample_first_gap_s column.", level="success"))
    if "sample_max_gap_excluding_first_s" in missing:
        core_q.run_sql_write(
            "ALTER TABLE dynamic_sessions ADD COLUMN sample_max_gap_excluding_first_s FLOAT DEFAULT NULL",
            query_name="db_utils.dynamic_sessions.add_sample_max_gap_excluding_first_s",
        )
        print(
            status_messages.status(
                "Added dynamic_sessions.sample_max_gap_excluding_first_s column.", level="success"
            )
        )
    return True


def ensure_dynamic_tier_migrations(
    *,
    diagnostics,
    app_config,
    core_q,
    db_config,
    prompt_utils,
    status_messages,
    prompt_user: bool = True,
) -> bool:
    """Apply all Baseline dynamic schema migrations in one step."""

    schema_before = diagnostics.get_schema_version() or "<unknown>"
    backend = str((db_config.DB_CONFIG or {}).get("engine", "disabled"))
    if backend != "mysql":
        print(
            status_messages.status(
                "Tier1 schema migrations are only supported for MySQL/MariaDB backends.",
                level="warn",
            )
        )
        return False

    _ensure_db_ops_log_table(core_q=core_q)
    started_at = datetime.now(UTC)
    success = False
    error_text = None
    try:
        tier_ok = ensure_dynamic_tier_column(
            db_config=db_config,
            diagnostics=diagnostics,
            core_q=core_q,
            prompt_utils=prompt_utils,
            status_messages=status_messages,
            prompt_user=prompt_user,
        )
        quality_ok = ensure_dynamic_network_quality_column(
            db_config=db_config,
            diagnostics=diagnostics,
            core_q=core_q,
            prompt_utils=prompt_utils,
            status_messages=status_messages,
            prompt_user=prompt_user,
        )
        netstats_ok = ensure_dynamic_netstats_rows_columns(
            db_config=db_config,
            diagnostics=diagnostics,
            core_q=core_q,
            prompt_utils=prompt_utils,
            status_messages=status_messages,
            prompt_user=prompt_user,
        )
        pcap_ok = ensure_dynamic_pcap_columns(
            db_config=db_config,
            diagnostics=diagnostics,
            core_q=core_q,
            prompt_utils=prompt_utils,
            status_messages=status_messages,
            prompt_user=prompt_user,
        )
        sampling_ok = ensure_dynamic_sampling_duration_columns(
            db_config=db_config,
            diagnostics=diagnostics,
            core_q=core_q,
            prompt_utils=prompt_utils,
            status_messages=status_messages,
            prompt_user=prompt_user,
        )
        gap_ok = ensure_dynamic_gap_columns(
            db_config=db_config,
            diagnostics=diagnostics,
            core_q=core_q,
            prompt_utils=prompt_utils,
            status_messages=status_messages,
            prompt_user=prompt_user,
        )
        success = tier_ok and quality_ok and netstats_ok and pcap_ok and sampling_ok and gap_ok
        target_version = _tier1_schema_version()
        if success and schema_before != target_version:
            _record_schema_version(core_q=core_q, version=target_version)
        return success
    except Exception as exc:
        error_text = str(exc)
        raise
    finally:
        finished_at = datetime.now(UTC)
        _log_db_op(
            app_config=app_config,
            core_q=core_q,
            operation="tier1_schema_migrations",
            schema_before=schema_before,
            schema_after=_tier1_schema_version() if success else (diagnostics.get_schema_version() or schema_before),
            started_at=started_at,
            finished_at=finished_at,
            success=success,
            error_text=error_text,
        )


def _tier1_schema_version() -> str:
    return "0.2.6"


def _ensure_db_ops_log_table(*, core_q) -> None:
    sql = """
        CREATE TABLE IF NOT EXISTS db_ops_log (
          id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
          operation VARCHAR(64) NOT NULL,
          schema_before VARCHAR(64) DEFAULT NULL,
          schema_after VARCHAR(64) DEFAULT NULL,
          tool_version VARCHAR(32) DEFAULT NULL,
          username VARCHAR(64) DEFAULT NULL,
          hostname VARCHAR(128) DEFAULT NULL,
          pid INT DEFAULT NULL,
          started_at_utc DATETIME DEFAULT NULL,
          finished_at_utc DATETIME DEFAULT NULL,
          success TINYINT(1) DEFAULT NULL,
          error_text TEXT DEFAULT NULL,
          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (id),
          KEY idx_db_ops_operation (operation),
          KEY idx_db_ops_created (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    core_q.run_sql_write(sql, query_name="db_utils.db_ops_log.ensure")


def _record_schema_version(*, core_q, version: str) -> None:
    if not version:
        return
    sql = "INSERT INTO schema_version (version, applied_at_utc) VALUES (%s, %s)"
    core_q.run_sql_write(
        sql,
        (version, datetime.now(UTC)),
        query_name="db_utils.schema_version.insert",
    )


def _log_db_op(
    *,
    app_config,
    core_q,
    operation: str,
    schema_before: str | None,
    schema_after: str | None,
    started_at: datetime,
    finished_at: datetime,
    success: bool,
    error_text: str | None,
) -> None:
    sql = """
        INSERT INTO db_ops_log (
          operation,
          schema_before,
          schema_after,
          tool_version,
          username,
          hostname,
          pid,
          started_at_utc,
          finished_at_utc,
          success,
          error_text
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    core_q.run_sql_write(
        sql,
        (
            operation,
            schema_before,
            schema_after,
            app_config.APP_VERSION,
            getpass.getuser(),
            socket.gethostname(),
            os.getpid(),
            started_at,
            finished_at,
            1 if success else 0,
            error_text,
        ),
        query_name="db_utils.db_ops_log.insert",
    )


def log_db_op(
    *,
    app_config,
    core_q,
    diagnostics,
    operation: str,
    started_at: datetime,
    finished_at: datetime,
    success: bool,
    error_text: str | None,
) -> None:
    """Public wrapper for logging DB operations."""
    _ensure_db_ops_log_table(core_q=core_q)
    _log_db_op(
        app_config=app_config,
        core_q=core_q,
        operation=operation,
        schema_before=diagnostics.get_schema_version() or "<unknown>",
        schema_after=diagnostics.get_schema_version() or "<unknown>",
        started_at=started_at,
        finished_at=finished_at,
        success=success,
        error_text=error_text,
    )


__all__ = [
    "ensure_dynamic_tier_column",
    "ensure_dynamic_network_quality_column",
    "ensure_dynamic_netstats_rows_columns",
    "ensure_dynamic_pcap_columns",
    "ensure_dynamic_sampling_duration_columns",
    "ensure_dynamic_gap_columns",
    "ensure_dynamic_tier_migrations",
    "log_db_op",
]
