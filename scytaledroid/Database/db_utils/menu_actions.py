"""Helper actions for the database utilities menu."""

from __future__ import annotations

import getpass
import os
import socket
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_core.session import database_session
from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.Database.tools.bootstrap import bootstrap_database
from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages


def show_connection_and_config() -> None:
    """Display database configuration details and test connectivity."""

    try:
        cfg = db_config.DB_CONFIG
        backend = str(cfg.get("engine", "sqlite"))
        host = str(cfg.get("host", "<unknown>"))
        port_display = str(cfg.get("port", "<unknown>"))
        database = str(cfg.get("database", "<unknown>"))
        user = str(cfg.get("user", "<unknown>"))
        cfg_source = getattr(db_config, "DB_CONFIG_SOURCE", "default")
    except Exception as exc:
        backend = host = port_display = database = user = "<unknown>"
        cfg_source = "error"
        print(status_messages.status(f"Unable to read DB config: {exc}", level="warn"))

    def _section(title: str) -> None:
        print(title)
        print("-" * len(title))

    _section("Database Configuration")
    print(f"    Backend:    {backend}")
    print(f"    Host:       {host}")
    print(f"    Port:       {port_display}")
    print(f"    Database:   {database}")
    print(f"    Username:   {user}")
    print(f"    Config via: {cfg_source}")
    schema_version = diagnostics.get_schema_version()
    print(f"    Schema ver: {schema_version or '<unknown>'}")
    print()

    _section("Test Database Connection")
    success = diagnostics.check_connection()
    if success:
        print("    Connection established successfully")
    else:
        print("    Connection failed. Check logs for details.")
        if backend == "mysql":
            print("    Verify SCYTALEDROID_DB_URL and ensure schema is bootstrapped.")
    prompt_utils.press_enter_to_continue()


def show_governance_snapshot_status() -> None:
    """Show high-level governance snapshot status and import guidance."""

    def _section(title: str) -> None:
        print(title)
        print("-" * len(title))

    _section("Governance Snapshot Status")
    version = None
    sha = None
    row_count = 0
    try:
        row = core_q.run_sql(
            """
            SELECT s.governance_version, s.snapshot_sha256, COUNT(r.permission_string) AS row_count
            FROM permission_governance_snapshots s
            LEFT JOIN permission_governance_snapshot_rows r
              ON r.governance_version = s.governance_version
            GROUP BY s.governance_version, s.snapshot_sha256
            ORDER BY s.created_at_utc DESC
            LIMIT 1
            """,
            fetch="one",
        )
        if row:
            version = row[0]
            sha = row[1]
            row_count = int(row[2] or 0)
    except Exception as exc:
        print(status_messages.status(f"Unable to read governance snapshot: {exc}", level="warn"))

    if version:
        print(f"    Version : {version}")
        print(f"    SHA-256 : {sha or '<unknown>'}")
        print(f"    Rows    : {row_count}")
    else:
        print("    Status  : missing")
        print("    Rows    : 0")

    print()
    _section("Import (required for paper-grade)")
    print(
        "    python -m scytaledroid.Database.tools.permission_governance_import \\"
    )
    print("      /path/to/governance_snapshot.csv \\")
    print("      --version gov_vYYYYMMDD --source EREBUS")
    print()
    prompt_utils.press_enter_to_continue()


def show_db_status() -> None:
    """Show backend/schema status, config source, and env hints."""

    cfg = db_config.DB_CONFIG
    backend = str(cfg.get("engine", "sqlite"))
    host = str(cfg.get("host", "<unknown>"))
    port_display = str(cfg.get("port", "<unknown>"))
    database = str(cfg.get("database", "<unknown>"))
    user = str(cfg.get("user", "<unknown>"))
    cfg_source = getattr(db_config, "DB_CONFIG_SOURCE", "default")
    schema_version = diagnostics.get_schema_version() or "<unknown>"
    db_url_env = os.environ.get("SCYTALEDROID_DB_URL")

    def _section(title: str) -> None:
        print(title)
        print("-" * len(title))

    _section("DB Status (Quick)")
    print(f"    Backend    : {backend}")
    print(f"    Host       : {host}")
    print(f"    Port       : {port_display}")
    print(f"    Database   : {database}")
    print(f"    Username   : {user}")
    print(f"    Schema ver : {schema_version}")
    print(f"    Config via : {cfg_source}")
    print(f"    SCYTALEDROID_DB_URL set: {bool(db_url_env)}")
    print()
    prompt_utils.press_enter_to_continue()


def ingest_analysis_cohort_from_paper_bundle() -> None:
    """Phase H helper: ingest canonical output/paper artifacts into DB.

    This is tables-only ingestion (no recomputation). Evidence packs remain the ground truth;
    DB stores the cohort index + derived aggregates for queryability.
    """

    from scytaledroid.Database.tools.analysis_ingest import ingest_paper_bundle_to_db

    print()
    print("Ingest Analysis Cohort (Phase H)")
    print("--------------------------------")
    paper_root = prompt_utils.prompt_text("Paper root (default=output/paper)", required=False, show_arrow=False).strip() or "output/paper"
    cohort_id = prompt_utils.prompt_text("cohort_id (required, stable id)", required=True, show_arrow=False).strip()
    name = prompt_utils.prompt_text("name (required)", required=True, show_arrow=False).strip()
    selector_type = (
        prompt_utils.prompt_text("selector_type freeze|query|manual (default=freeze)", required=False, show_arrow=False).strip()
        or "freeze"
    ).lower()
    if selector_type not in {"freeze", "query", "manual"}:
        print(status_messages.status(f"Invalid selector_type: {selector_type!r}", level="fail"))
        prompt_utils.press_enter_to_continue()
        return

    try:
        ingest_paper_bundle_to_db(
            paper_root=Path(paper_root),
            cohort_id=cohort_id,
            name=name,
            selector_type=selector_type,
        )
        print(status_messages.status("Ingest complete.", level="success"))
    except Exception as exc:  # pragma: no cover
        print(status_messages.status(f"Ingest failed: {exc}", level="error"))
    prompt_utils.press_enter_to_continue()


def apply_canonical_schema_bootstrap(*, prompt_user: bool = True) -> bool:
    """Apply canonical schema statements (CREATE/ALTER) for missing tables/columns."""

    _ensure_db_ops_log_table()
    schema_before = diagnostics.get_schema_version() or "<unknown>"
    started_at = datetime.now(UTC)
    success = False
    error_text = None
    snapshot_before = _schema_snapshot()
    try:
        if prompt_user and not prompt_utils.prompt_yes_no(
            "Apply canonical schema bootstrap now? (CREATE/ALTER missing tables/columns)",
            default=True,
        ):
            return False
        # Paper/ops posture: fail-closed if schema statements cannot be applied.
        prev_strict = os.environ.get("SCYTALEDROID_DB_BOOTSTRAP_STRICT")
        os.environ["SCYTALEDROID_DB_BOOTSTRAP_STRICT"] = "1"
        try:
            bootstrap_database()
        finally:
            if prev_strict is None:
                os.environ.pop("SCYTALEDROID_DB_BOOTSTRAP_STRICT", None)
            else:
                os.environ["SCYTALEDROID_DB_BOOTSTRAP_STRICT"] = prev_strict
        _drop_legacy_string_run_id_columns()
        _ensure_canonical_triggers()
        success = True
        _render_schema_bootstrap_summary(schema_before, snapshot_before)
        _render_schema_bootstrap_verification()
        return True
    except Exception as exc:
        error_text = str(exc)
        print(status_messages.status(f"Canonical schema bootstrap failed: {exc}", level="error"))
        return False
    finally:
        finished_at = datetime.now(UTC)
        _log_db_op(
            operation="canonical_schema_bootstrap",
            schema_before=schema_before,
            schema_after=diagnostics.get_schema_version() or schema_before,
            started_at=started_at,
            finished_at=finished_at,
            success=success,
            error_text=error_text,
        )


def _schema_snapshot() -> dict[str, object]:
    tables = diagnostics.list_tables()
    columns = {table: set(diagnostics.get_table_columns(table) or []) for table in tables}
    indexes = {table: _fetch_index_signatures(table) for table in tables}
    return {"tables": set(tables), "columns": columns, "indexes": indexes}


def _drop_legacy_string_run_id_columns() -> None:
    tables = (
        "static_string_summary",
        "static_string_samples",
        "static_string_selected_samples",
        "static_string_sample_sets",
    )
    try:
        with database_session(reuse_connection=False) as engine:
            if getattr(engine, "_dialect", "sqlite") != "mysql":
                return
            for table in tables:
                columns = diagnostics.get_table_columns(table) or []
                if "run_id" not in columns:
                    continue
                # Drop foreign keys referencing run_id if present.
                rows = engine.fetch_all(
                    """
                    SELECT CONSTRAINT_NAME
                    FROM information_schema.KEY_COLUMN_USAGE
                    WHERE table_schema = DATABASE()
                      AND table_name = %s
                      AND column_name = 'run_id'
                      AND REFERENCED_TABLE_NAME IS NOT NULL
                    """,
                    (table,),
                )
                for row in rows or []:
                    fk_name = str(row[0])
                    try:
                        engine.execute(f"ALTER TABLE `{table}` DROP FOREIGN KEY `{fk_name}`;")
                    except Exception:
                        continue
                # Drop indexes on run_id.
                idx_rows = engine.fetch_all(f"SHOW INDEX FROM `{table}`;")
                for row in idx_rows or []:
                    if len(row) < 5:
                        continue
                    index_name = str(row[2])
                    column_name = str(row[4])
                    if column_name == "run_id" and index_name != "PRIMARY":
                        try:
                            engine.execute(f"ALTER TABLE `{table}` DROP INDEX `{index_name}`;")
                        except Exception:
                            continue
                # Drop the legacy column.
                try:
                    engine.execute(f"ALTER TABLE `{table}` DROP COLUMN run_id;")
                except Exception:
                    continue
    except Exception:
        return


def _ensure_canonical_triggers() -> None:
    try:
        with database_session(reuse_connection=False) as engine:
            if getattr(engine, "_dialect", "sqlite") != "mysql":
                return
            for name in ("trg_static_runs_canonical_insert", "trg_static_runs_canonical_update"):
                try:
                    engine.execute(f"DROP TRIGGER IF EXISTS `{name}`;")
                except Exception:
                    pass
            engine.execute(
                """
                CREATE TRIGGER trg_static_runs_canonical_insert
                BEFORE INSERT ON static_analysis_runs
                FOR EACH ROW
                BEGIN
                  IF NEW.is_canonical = 1 THEN
                    IF EXISTS (
                      SELECT 1
                      FROM static_analysis_runs
                      WHERE session_label = NEW.session_label
                        AND is_canonical = 1
                    ) THEN
                      SIGNAL SQLSTATE '45000'
                        SET MESSAGE_TEXT = 'canonical constraint violated (session_label already has canonical)';
                    END IF;
                  END IF;
                END;
                """
            )
            engine.execute(
                """
                CREATE TRIGGER trg_static_runs_canonical_update
                BEFORE UPDATE ON static_analysis_runs
                FOR EACH ROW
                BEGIN
                  IF NEW.is_canonical = 1 THEN
                    IF EXISTS (
                      SELECT 1
                      FROM static_analysis_runs
                      WHERE session_label = NEW.session_label
                        AND is_canonical = 1
                        AND id <> NEW.id
                    ) THEN
                      SIGNAL SQLSTATE '45000'
                        SET MESSAGE_TEXT = 'canonical constraint violated (session_label already has canonical)';
                    END IF;
                  END IF;
                END;
                """
            )
    except Exception:
        return


def _fetch_index_signatures(table: str) -> set[str]:
    signatures: set[str] = set()
    try:
        with database_session(reuse_connection=False) as engine:
            rows = engine.fetch_all(f"SHOW INDEX FROM `{table}`;")
    except Exception:
        return signatures
    if not rows:
        return signatures
    index_map: dict[str, dict[str, object]] = {}
    for row in rows:
        if not row or len(row) < 5:
            continue
        name = str(row[2])
        seq = int(row[3])
        column = str(row[4])
        unique = bool(int(row[1]) == 0)
        entry = index_map.setdefault(name, {"unique": unique, "columns": {}})
        entry["unique"] = entry["unique"] or unique
        entry["columns"][seq] = column
    for name, entry in index_map.items():
        columns = [entry["columns"][idx] for idx in sorted(entry["columns"])]
        unique = "unique" if entry["unique"] else "non_unique"
        signatures.add(f"{name}|{unique}|{','.join(columns)}")
    return signatures


def _render_schema_bootstrap_summary(
    schema_before: str,
    snapshot_before: dict[str, object],
) -> None:
    schema_after = diagnostics.get_schema_version() or schema_before
    snapshot_after = _schema_snapshot()

    before_tables = snapshot_before["tables"]
    after_tables = snapshot_after["tables"]
    created_tables = sorted(after_tables - before_tables)
    removed_tables = sorted(before_tables - after_tables)

    before_columns: dict[str, set[str]] = snapshot_before["columns"]
    after_columns: dict[str, set[str]] = snapshot_after["columns"]
    column_additions: dict[str, list[str]] = {}
    column_removals: dict[str, list[str]] = {}
    for table in sorted(before_tables & after_tables):
        added = sorted(after_columns.get(table, set()) - before_columns.get(table, set()))
        removed = sorted(before_columns.get(table, set()) - after_columns.get(table, set()))
        if added:
            column_additions[table] = added
        if removed:
            column_removals[table] = removed

    before_indexes: dict[str, set[str]] = snapshot_before["indexes"]
    after_indexes: dict[str, set[str]] = snapshot_after["indexes"]
    index_additions: dict[str, list[str]] = {}
    index_removals: dict[str, list[str]] = {}
    for table in sorted(before_tables & after_tables):
        added = sorted(after_indexes.get(table, set()) - before_indexes.get(table, set()))
        removed = sorted(before_indexes.get(table, set()) - after_indexes.get(table, set()))
        if added:
            index_additions[table] = added
        if removed:
            index_removals[table] = removed

    print()
    print("Schema bootstrap summary")
    print("------------------------")
    print(f"Schema version: {schema_before} -> {schema_after}")
    print(f"Tables created: {len(created_tables)}")
    if created_tables:
        for table in created_tables:
            print(f"  + {table}")
    if removed_tables:
        print(f"Tables removed: {len(removed_tables)}")
        for table in removed_tables:
            print(f"  - {table}")

    if column_additions:
        print("Columns added:")
        for table, cols in column_additions.items():
            print(f"  {table}: {', '.join(cols)}")
    if column_removals:
        print("Columns removed:")
        for table, cols in column_removals.items():
            print(f"  {table}: {', '.join(cols)}")

    if index_additions:
        print("Indexes added:")
        for table, idxs in index_additions.items():
            for entry in idxs:
                print(f"  {table}: {entry}")
    if index_removals:
        print("Indexes removed:")
        for table, idxs in index_removals.items():
            for entry in idxs:
                print(f"  {table}: {entry}")

    if not created_tables and not removed_tables and not column_additions and not column_removals and not index_additions and not index_removals:
        print("No schema changes detected.")
    print()


def _render_schema_bootstrap_verification() -> None:
    print("Schema bootstrap verification")
    print("-----------------------------")
    try:
        with database_session(reuse_connection=False) as engine:
            if getattr(engine, "_dialect", "sqlite") == "mysql":
                trigger_rows = engine.fetch_all(
                    """
                    SELECT TRIGGER_NAME, ACTION_TIMING, ACTION_STATEMENT
                    FROM information_schema.TRIGGERS
                    WHERE TRIGGER_SCHEMA = DATABASE()
                      AND EVENT_OBJECT_TABLE = 'static_analysis_runs'
                      AND TRIGGER_NAME IN ('trg_static_runs_canonical_insert', 'trg_static_runs_canonical_update')
                    ORDER BY TRIGGER_NAME
                    """
                )
            else:
                trigger_rows = []
    except Exception:
        trigger_rows = []

    if trigger_rows:
        for row in trigger_rows:
            name = str(row[0]) if row and row[0] is not None else "<unknown>"
            timing = str(row[1]) if row and row[1] is not None else "?"
            body = str(row[2]) if row and row[2] is not None else ""
            has_signal = "SIGNAL" in body.upper()
            print(f"Trigger {name}: timing={timing} signal={'yes' if has_signal else 'no'}")
    else:
        print("Trigger check: not available (non-mysql or no triggers found).")

    try:
        row = core_q.run_sql(
            """
            SELECT COUNT(*)
            FROM (
              SELECT session_label
              FROM static_analysis_runs
              WHERE is_canonical=1
              GROUP BY session_label
              HAVING COUNT(*) > 1
            ) x
            """,
            fetch="one",
        )
        dup_count = int(row[0] or 0) if row else 0
        print(f"Canonical duplicates: {dup_count}")
    except Exception:
        print("Canonical duplicates: <error>")

    try:
        columns = diagnostics.get_table_columns("static_string_summary") or []
        run_id_present = "run_id" in columns
        print(f"static_string_summary.run_id present: {'yes' if run_id_present else 'no'}")
    except Exception:
        print("static_string_summary.run_id present: <error>")

    required_tables = [
        "static_string_sample_sets",
        "static_string_selected_samples",
        "v_base002_candidates",
        "v_provider_exposure",
    ]
    missing_tables = [name for name in required_tables if name not in (diagnostics.list_tables() or [])]
    if missing_tables:
        print(f"Required tables missing: {', '.join(missing_tables)}")
    else:
        print("Required tables present: yes")
    print()


def maybe_clear_screen() -> None:
    """Clear the terminal when UI preferences request it."""

    try:
        from scytaledroid.Utils.DisplayUtils import ui_prefs as _ui

        if _ui.should_clear():
            from scytaledroid.Utils.System.util_actions import clear_screen as _clear

            _clear()
        else:
            print()
    except Exception:
        print()

def seed_paper_dataset_profile() -> None:
    """Create or update the paper dataset profile and assign packages."""

    from scytaledroid.Database.db_func.apps.app_labels import upsert_display_names
    from scytaledroid.Database.db_func.apps.app_ordering import upsert_ordering
    from scytaledroid.DynamicAnalysis.datasets.research_dataset_alpha import (
        CANONICAL_PACKAGES,
        PROFILE_KEY,
    )
    from scytaledroid.Paper.paper_contract_inputs import load_paper_contracts

    profile_key = PROFILE_KEY
    display_name = "Research Dataset Alpha (Paper #2)"
    description = "ScytaleDroid-Dyn-v1 research dataset (12-app frozen cohort; Paper #2)."
    scope_group = "research"
    sort_order = 10
    is_active = 1
    packages = list(CANONICAL_PACKAGES)

    print(status_messages.status("Seeding paper dataset profile (DB).", level="info"))
    print(f"Profile key: {profile_key}")
    print(f"Display name: {display_name}")
    print(f"Packages: {len(packages)}")
    if not prompt_utils.prompt_yes_no("Apply these updates now?", default=True):
        return

    profile_sql = """
        INSERT INTO android_app_profiles (
            profile_key,
            display_name,
            description,
            scope_group,
            sort_order,
            is_active
        ) VALUES (%s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            display_name=VALUES(display_name),
            description=VALUES(description),
            scope_group=VALUES(scope_group),
            sort_order=VALUES(sort_order),
            is_active=VALUES(is_active)
    """
    core_q.run_sql_write(
        profile_sql,
        (
            profile_key,
            display_name,
            description,
            scope_group,
            sort_order,
            is_active,
        ),
        query_name="db_utils.seed_paper_profile",
    )

    app_sql = """
        INSERT INTO apps (package_name, profile_key, publisher_key)
        VALUES (%s, %s, 'UNKNOWN')
        ON DUPLICATE KEY UPDATE profile_key=VALUES(profile_key)
    """
    payload = [(pkg, profile_key) for pkg in packages]
    core_q.run_sql_many(app_sql, payload, query_name="db_utils.seed_paper_profile.apps")

    # Seed canonical display names (best-effort). This helps avoid scattered JSON label maps.
    try:
        contracts = load_paper_contracts(fail_closed=True)
        upsert_display_names(contracts.display_name_by_package, overwrite=True)
        upsert_ordering("paper2", contracts.paper_ordering)
    except Exception:
        pass

    placeholders = ", ".join(["%s"] * len(packages))
    count_sql = f"SELECT COUNT(*) AS matched FROM apps WHERE package_name IN ({placeholders})"
    rows = core_q.run_sql(count_sql, tuple(packages), fetch="one", dictionary=True)
    matched = rows.get("matched") if isinstance(rows, dict) else None
    print(status_messages.status(f"Updated apps: {matched or 0}", level="success"))
    prompt_utils.press_enter_to_continue()


def sync_paper_contracts_to_db() -> None:
    """Sync tracked paper contracts into the DB (display names + ordering).

    This is a post-paper hygiene action to reduce drift from scattered JSON maps.
    It does not change any evidence packs or paper outputs.
    """
    from scytaledroid.Database.db_func.apps.app_labels import upsert_display_names
    from scytaledroid.Database.db_func.apps.app_ordering import upsert_ordering
    from scytaledroid.Paper.paper_contract_inputs import load_paper_contracts

    print(status_messages.status("Syncing paper contracts -> DB (display names + ordering).", level="info"))
    if not prompt_utils.prompt_yes_no("Apply updates now?", default=True):
        return
    try:
        contracts = load_paper_contracts(fail_closed=True)
    except Exception as exc:
        print(status_messages.status(f"Failed to load paper contracts: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    # Display names
    n_names = upsert_display_names(contracts.display_name_by_package, overwrite=True)
    # Ordering
    n_order = upsert_ordering("paper2", contracts.paper_ordering)

    print(status_messages.status(f"Upserted display names: {n_names}", level="success"))
    print(status_messages.status(f"Upserted ordering rows: {n_order}", level="success"))
    prompt_utils.press_enter_to_continue()


def ensure_dynamic_tier_column(*, prompt_user: bool = True) -> bool:
    """Ensure dynamic_sessions has a tier column (DB migration helper)."""

    cfg = db_config.DB_CONFIG
    backend = str(cfg.get("engine", "sqlite"))
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


def ensure_dynamic_network_quality_column(*, prompt_user: bool = True) -> bool:
    """Ensure dynamic_sessions has a network_signal_quality column (DB migration helper)."""

    cfg = db_config.DB_CONFIG
    backend = str(cfg.get("engine", "sqlite"))
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


def ensure_dynamic_pcap_columns(*, prompt_user: bool = True) -> bool:
    """Ensure dynamic_sessions has PCAP metadata columns (DB migration helper)."""

    cfg = db_config.DB_CONFIG
    backend = str(cfg.get("engine", "sqlite"))
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


def ensure_dynamic_netstats_rows_columns(*, prompt_user: bool = True) -> bool:
    """Ensure dynamic_sessions has netstats row counters (DB migration helper)."""

    cfg = db_config.DB_CONFIG
    backend = str(cfg.get("engine", "sqlite"))
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


def ensure_dynamic_sampling_duration_columns(*, prompt_user: bool = True) -> bool:
    """Ensure dynamic_sessions has sampling duration alignment columns."""

    cfg = db_config.DB_CONFIG
    backend = str(cfg.get("engine", "sqlite"))
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


def ensure_dynamic_gap_columns(*, prompt_user: bool = True) -> bool:
    """Ensure dynamic_sessions has warm-up gap columns."""

    cfg = db_config.DB_CONFIG
    backend = str(cfg.get("engine", "sqlite"))
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


def ensure_dynamic_tier_migrations(*, prompt_user: bool = True) -> bool:
    """Apply all Tier-1 dynamic schema migrations in one step."""

    _ensure_db_ops_log_table()
    schema_before = diagnostics.get_schema_version() or "<unknown>"
    started_at = datetime.now(UTC)
    success = False
    error_text = None
    try:
        tier_ok = ensure_dynamic_tier_column(prompt_user=prompt_user)
        quality_ok = ensure_dynamic_network_quality_column(prompt_user=prompt_user)
        netstats_ok = ensure_dynamic_netstats_rows_columns(prompt_user=prompt_user)
        pcap_ok = ensure_dynamic_pcap_columns(prompt_user=prompt_user)
        sampling_ok = ensure_dynamic_sampling_duration_columns(prompt_user=prompt_user)
        gap_ok = ensure_dynamic_gap_columns(prompt_user=prompt_user)
        success = tier_ok and quality_ok and netstats_ok and pcap_ok and sampling_ok and gap_ok
        target_version = _tier1_schema_version()
        if success and schema_before != target_version:
            _record_schema_version(target_version)
        return success
    except Exception as exc:
        error_text = str(exc)
        raise
    finally:
        finished_at = datetime.now(UTC)
        _log_db_op(
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


def _ensure_db_ops_log_table() -> None:
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


def _record_schema_version(version: str) -> None:
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
    operation: str,
    started_at: datetime,
    finished_at: datetime,
    success: bool,
    error_text: str | None,
) -> None:
    """Public wrapper for logging DB operations."""
    _ensure_db_ops_log_table()
    _log_db_op(
        operation=operation,
        schema_before=diagnostics.get_schema_version() or "<unknown>",
        schema_after=diagnostics.get_schema_version() or "<unknown>",
        started_at=started_at,
        finished_at=finished_at,
        success=success,
        error_text=error_text,
    )

__all__ = [
    "maybe_clear_screen",
    "show_connection_and_config",
    "seed_paper_dataset_profile",
    "apply_canonical_schema_bootstrap",
    "ensure_dynamic_tier_column",
    "ensure_dynamic_network_quality_column",
    "ensure_dynamic_netstats_rows_columns",
    "ensure_dynamic_pcap_columns",
    "ensure_dynamic_sampling_duration_columns",
    "ensure_dynamic_gap_columns",
    "ensure_dynamic_tier_migrations",
    "log_db_op",
]
