"""Helper actions for the database utilities menu."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_core.session import database_session
from scytaledroid.Database.db_utils.permission_intel_freeze import (
    freeze_operational_managed_tables,
)
from scytaledroid.Database.db_utils.reset_static import (
    purge_static_session_artifacts,
    reset_static_analysis_data,
)
from scytaledroid.Database.summary_surfaces import (
    STATIC_DYNAMIC_SUMMARY_CACHE,
    refresh_static_dynamic_summary_cache as _refresh_static_dynamic_summary_cache,
)
from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.Database.db_utils import schema_gate
from scytaledroid.Database.tools.bootstrap import bootstrap_database
from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages
from .action_groups.risk_actions import (
    audit_static_risk_coverage as _audit_static_risk_coverage,
    backfill_static_permission_risk_vnext as _backfill_static_permission_risk_vnext,
    show_governance_snapshot_status as _show_governance_snapshot_status,
)
from .action_groups.schema_actions import (
    _ensure_db_ops_log_table as _schema_ensure_db_ops_log_table,
    ensure_dynamic_gap_columns as _ensure_dynamic_gap_columns,
    ensure_dynamic_netstats_rows_columns as _ensure_dynamic_netstats_rows_columns,
    ensure_dynamic_network_quality_column as _ensure_dynamic_network_quality_column,
    ensure_dynamic_pcap_columns as _ensure_dynamic_pcap_columns,
    ensure_dynamic_sampling_duration_columns as _ensure_dynamic_sampling_duration_columns,
    ensure_dynamic_tier_column as _ensure_dynamic_tier_column,
    ensure_dynamic_tier_migrations as _ensure_dynamic_tier_migrations,
    _log_db_op as _schema_log_db_op,
    log_db_op as _grouped_log_db_op,
)
from .action_groups.status_actions import (
    run_inventory_determinism_comparator,
    show_connection_and_config,
    write_db_schema_snapshot_audit,
)
from .static_reconcile import (
    reconcile_static_session,
    refresh_summary_cache_and_reconcile,
    repair_session_run_links,
    write_reconcile_audit,
)


def backfill_static_permission_risk_vnext() -> None:
    _backfill_static_permission_risk_vnext(
        core_q=core_q,
        prompt_utils=prompt_utils,
        status_messages=status_messages,
    )


def audit_static_risk_coverage() -> None:
    _audit_static_risk_coverage(
        core_q=core_q,
        prompt_utils=prompt_utils,
        status_messages=status_messages,
    )


def show_governance_snapshot_status() -> None:
    _show_governance_snapshot_status(
        core_q=core_q,
        prompt_utils=prompt_utils,
        status_messages=status_messages,
    )

def freeze_duplicate_permission_intel_tables(*, prompt_user: bool = True) -> bool:
    """Archive duplicate permission-intel managed tables out of the operational DB."""

    if prompt_user and not prompt_utils.prompt_yes_no(
        "Archive duplicate permission-intel managed tables from the operational DB?",
        default=False,
    ):
        return False
    try:
        outcome = freeze_operational_managed_tables()
    except Exception as exc:
        print(
            status_messages.status(
                f"Permission-intel duplicate freeze failed: {exc}",
                level="error",
            )
        )
        prompt_utils.press_enter_to_continue()
        return False

    print(status_messages.status("Permission-intel duplicate freeze complete.", level="success"))
    for line in outcome.as_lines():
        print(line)
    prompt_utils.press_enter_to_continue()
    return True


def ingest_analysis_cohort_from_publication_bundle() -> None:
    """Ingest canonical output/publication artifacts into DB.

    This is tables-only ingestion (no recomputation). Evidence packs remain the ground truth;
    DB stores the cohort index + derived aggregates for queryability.
    """

    from scytaledroid.Database.tools.analysis_ingest import ingest_publication_bundle_to_db

    print()
    print("Ingest Analysis Cohort")
    print("----------------------")
    # Prefer canonical export location. Legacy output/paper fallback is opt-in only.
    default_root = "output/publication"
    bundle_root = (
        prompt_utils.prompt_text(
            "Bundle root",
            default=default_root,
            required=False,
            show_arrow=False,
        ).strip()
        or default_root
    )
    bundle_root_path = Path(bundle_root)
    if not bundle_root_path.exists():
        print(status_messages.status(f"Bundle root not found: {bundle_root_path}", level="fail"))
        prompt_utils.press_enter_to_continue()
        return
    if bundle_root_path == Path("output/paper"):
        legacy_ok = str(os.environ.get("SCYTALEDROID_ALLOW_LEGACY_OUTPUT_PAPER") or "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        if not legacy_ok:
            print(
                status_messages.status(
                    "Legacy bundle root output/paper is disabled. Use output/publication, or set "
                    "SCYTALEDROID_ALLOW_LEGACY_OUTPUT_PAPER=1 to explicitly allow legacy ingest.",
                    level="fail",
                )
            )
            prompt_utils.press_enter_to_continue()
            return
        print(status_messages.status("Using legacy bundle root fallback: output/paper", level="warn"))

    # Derive stable defaults from bundle provenance when available.
    import json
    import hashlib

    def _sha256_file(path: Path) -> str | None:
        try:
            h = hashlib.sha256()
            with path.open("rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    snapshot_id = None
    selector_hint = None
    summary_path = bundle_root_path / "internal" / "provenance" / "snapshot_summary.json"
    if summary_path.exists():
        try:
            obj = json.loads(summary_path.read_text(encoding="utf-8"))
            if isinstance(obj, dict):
                snapshot_id = str(obj.get("snapshot_id") or "").strip() or None
                selector_hint = str(obj.get("selector_type") or "").strip().lower() or None
        except Exception:
            snapshot_id = None

    # If we can't find a snapshot id, fall back to hashing a stable manifest.
    if snapshot_id is None:
        for candidate in (
            bundle_root_path / "manifests" / "selection_manifest.json",
            bundle_root_path / "manifests" / "dataset_freeze.json",
            bundle_root_path / "manifests" / "freeze_manifest.json",
        ):
            if candidate.exists():
                digest = _sha256_file(candidate)
                if digest:
                    snapshot_id = f"bundle-{digest[:12]}"
                    break

    default_cohort_id = snapshot_id or ""
    default_name = f"Publication bundle {snapshot_id}" if snapshot_id else ""
    default_selector = selector_hint if selector_hint in {"freeze", "query", "manual"} else "freeze"

    cohort_id = prompt_utils.prompt_text(
        "cohort_id",
        default=default_cohort_id or None,
        required=True,
        show_arrow=False,
        error_message="Please provide a stable cohort_id (or press Enter to accept the default).",
    ).strip()
    name = prompt_utils.prompt_text(
        "name",
        default=default_name or None,
        required=True,
        show_arrow=False,
    ).strip()
    selector_type = (
        prompt_utils.prompt_text(
            "selector_type freeze|query|manual",
            default=default_selector,
            required=False,
            show_arrow=False,
        ).strip()
        or default_selector
    ).lower()
    if selector_type not in {"freeze", "query", "manual"}:
        print(status_messages.status(f"Invalid selector_type: {selector_type!r}", level="fail"))
        prompt_utils.press_enter_to_continue()
        return

    try:
        ingest_publication_bundle_to_db(
            bundle_root=Path(bundle_root),
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

    _schema_ensure_db_ops_log_table(core_q=core_q)
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
        _schema_log_db_op(
            app_config=app_config,
            core_q=core_q,
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

def seed_dataset_profile() -> None:
    """Create or update the research dataset profile and assign packages."""

    from scytaledroid.Database.db_func.apps.app_labels import upsert_display_names
    from scytaledroid.Database.db_func.apps.app_ordering import upsert_ordering
    from scytaledroid.DynamicAnalysis.datasets.research_dataset_alpha import (
        CANONICAL_PACKAGES,
        PROFILE_KEY,
    )
    from scytaledroid.Publication.contract_inputs import load_publication_contracts

    profile_key = PROFILE_KEY
    display_name = "Research Dataset Alpha"
    description = "ScytaleDroid dynamic research dataset (12-app frozen cohort)."
    scope_group = "research"
    sort_order = 10
    is_active = 1
    packages = list(CANONICAL_PACKAGES)

    print(status_messages.status("Seeding research dataset profile (DB).", level="info"))
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
        query_name="db_utils.seed_dataset_profile",
    )

    app_sql = """
        INSERT INTO apps (package_name, profile_key, publisher_key)
        VALUES (%s, %s, 'UNKNOWN')
        ON DUPLICATE KEY UPDATE profile_key=VALUES(profile_key)
    """
    payload = [(pkg, profile_key) for pkg in packages]
    core_q.run_sql_many(app_sql, payload, query_name="db_utils.seed_dataset_profile.apps")

    # Seed display names (best-effort).
    # Important: DB canonical display names should remain the full product name.
    # Publication alias shortening is stored separately as an alias set.
    try:
        contracts = load_publication_contracts(fail_closed=True)
        # Do not overwrite existing canonical names.
        upsert_display_names(contracts.display_name_by_package, overwrite=False)
        # Persist publication aliases explicitly under the canonical key.
        try:
            from scytaledroid.Database.db_func.apps.app_labels import upsert_display_aliases
            upsert_display_aliases("publication", contracts.display_name_by_package, overwrite=True)
        except Exception:
            pass
        upsert_ordering("publication", contracts.package_order)
    except Exception:
        pass

    placeholders = ", ".join(["%s"] * len(packages))
    count_sql = f"SELECT COUNT(*) AS matched FROM apps WHERE package_name IN ({placeholders})"
    rows = core_q.run_sql(count_sql, tuple(packages), fetch="one", dictionary=True)
    matched = rows.get("matched") if isinstance(rows, dict) else None
    print(status_messages.status(f"Updated apps: {matched or 0}", level="success"))
    prompt_utils.press_enter_to_continue()


def sync_contracts_to_db() -> None:
    """Sync tracked research contracts into the DB (display names + ordering).

    This is a post-freeze hygiene action to reduce drift from scattered JSON maps.
    It does not change any evidence packs or research outputs.
    """
    from scytaledroid.Database.db_func.apps.app_labels import upsert_display_aliases, upsert_display_names
    from scytaledroid.Database.db_func.apps.app_ordering import upsert_ordering
    from scytaledroid.Publication.contract_inputs import load_publication_contracts

    print(status_messages.status("Syncing contract labels and ordering -> DB.", level="info"))
    if not prompt_utils.prompt_yes_no("Apply updates now?", default=True):
        return
    try:
        contracts = load_publication_contracts(fail_closed=True)
    except Exception as exc:
        print(status_messages.status(f"Failed to load contract inputs: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    # Canonical display names: never clobber full product names with publication abbreviations.
    n_names = upsert_display_names(contracts.display_name_by_package, overwrite=False)
    # Publication aliases (short labels) live in a separate table.
    n_alias = upsert_display_aliases("publication", contracts.display_name_by_package, overwrite=True)
    # Ordering
    n_order = upsert_ordering("publication", contracts.package_order)

    print(status_messages.status(f"Upserted display names: {n_names}", level="success"))
    print(status_messages.status(f"Upserted research aliases: {n_alias}", level="success"))
    print(status_messages.status(f"Upserted ordering rows: {n_order}", level="success"))
    prompt_utils.press_enter_to_continue()

def ensure_dynamic_tier_column(*, prompt_user: bool = True) -> bool:
    return _ensure_dynamic_tier_column(
        db_config=db_config,
        diagnostics=diagnostics,
        core_q=core_q,
        prompt_utils=prompt_utils,
        status_messages=status_messages,
        prompt_user=prompt_user,
    )


def ensure_dynamic_network_quality_column(*, prompt_user: bool = True) -> bool:
    return _ensure_dynamic_network_quality_column(
        db_config=db_config,
        diagnostics=diagnostics,
        core_q=core_q,
        prompt_utils=prompt_utils,
        status_messages=status_messages,
        prompt_user=prompt_user,
    )


def ensure_dynamic_pcap_columns(*, prompt_user: bool = True) -> bool:
    return _ensure_dynamic_pcap_columns(
        db_config=db_config,
        diagnostics=diagnostics,
        core_q=core_q,
        prompt_utils=prompt_utils,
        status_messages=status_messages,
        prompt_user=prompt_user,
    )


def ensure_dynamic_netstats_rows_columns(*, prompt_user: bool = True) -> bool:
    return _ensure_dynamic_netstats_rows_columns(
        db_config=db_config,
        diagnostics=diagnostics,
        core_q=core_q,
        prompt_utils=prompt_utils,
        status_messages=status_messages,
        prompt_user=prompt_user,
    )


def ensure_dynamic_sampling_duration_columns(*, prompt_user: bool = True) -> bool:
    return _ensure_dynamic_sampling_duration_columns(
        db_config=db_config,
        diagnostics=diagnostics,
        core_q=core_q,
        prompt_utils=prompt_utils,
        status_messages=status_messages,
        prompt_user=prompt_user,
    )


def ensure_dynamic_gap_columns(*, prompt_user: bool = True) -> bool:
    return _ensure_dynamic_gap_columns(
        db_config=db_config,
        diagnostics=diagnostics,
        core_q=core_q,
        prompt_utils=prompt_utils,
        status_messages=status_messages,
        prompt_user=prompt_user,
    )


def ensure_dynamic_tier_migrations(*, prompt_user: bool = True) -> bool:
    return _ensure_dynamic_tier_migrations(
        diagnostics=diagnostics,
        app_config=app_config,
        core_q=core_q,
        db_config=db_config,
        prompt_utils=prompt_utils,
        status_messages=status_messages,
        prompt_user=prompt_user,
    )


def backfill_static_run_findings_totals() -> None:
    """Reconcile stale ``static_analysis_runs.findings_total`` rollups."""

    print()
    print("Backfill Static Run Findings Totals")
    print("----------------------------------")
    print("Recomputes static_analysis_runs.findings_total from static_analysis_findings.")
    print("Use this to repair older rows that still carry stale rolled-up finding counts.")
    print()

    mismatch_row = core_q.run_sql(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs sar
        LEFT JOIN (
          SELECT run_id, COUNT(*) AS actual_total
          FROM static_analysis_findings
          GROUP BY run_id
        ) sf ON sf.run_id = sar.id
        WHERE COALESCE(sar.findings_total, 0) <> COALESCE(sf.actual_total, 0)
        """,
        fetch="one",
    )
    mismatch_count = int((mismatch_row or [0])[0] or 0)
    print(f"stale rows detected: {mismatch_count}")
    print()

    if mismatch_count == 0:
        print(status_messages.status("No stale findings_total rows detected.", level="success"))
        prompt_utils.press_enter_to_continue()
        return

    if not prompt_utils.prompt_yes_no("Backfill stale findings_total values now?", default=False):
        print(status_messages.status("Backfill cancelled.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    updated = core_q.run_sql_write(
        """
        UPDATE static_analysis_runs sar
        LEFT JOIN (
          SELECT run_id, COUNT(*) AS actual_total
          FROM static_analysis_findings
          GROUP BY run_id
        ) sf ON sf.run_id = sar.id
        SET sar.findings_total = COALESCE(sf.actual_total, 0)
        WHERE COALESCE(sar.findings_total, 0) <> COALESCE(sf.actual_total, 0)
        """,
        query_name="db_utils.backfill.static_analysis_runs.findings_total",
    )

    remaining_row = core_q.run_sql(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs sar
        LEFT JOIN (
          SELECT run_id, COUNT(*) AS actual_total
          FROM static_analysis_findings
          GROUP BY run_id
        ) sf ON sf.run_id = sar.id
        WHERE COALESCE(sar.findings_total, 0) <> COALESCE(sf.actual_total, 0)
        """,
        fetch="one",
    )
    remaining = int((remaining_row or [0])[0] or 0)

    print(status_messages.status("Backfill complete.", level="success"))
    print(f"rows updated : {int(updated or 0)}")
    print(f"rows remain  : {remaining}")
    prompt_utils.press_enter_to_continue()


def backfill_permission_audit_snapshot_totals() -> None:
    """Recompute ``permission_audit_snapshots.apps_total`` from child rows."""

    print()
    print("Backfill Permission Audit Snapshot Totals")
    print("-----------------------------------------")
    print("Recomputes permission_audit_snapshots.apps_total from permission_audit_apps.")
    print("Use this to repair historical snapshots whose declared app totals drifted from persisted child rows.")
    print()

    mismatch_row = core_q.run_sql(
        """
        SELECT COUNT(*)
        FROM (
          SELECT s.snapshot_id
          FROM permission_audit_snapshots s
          LEFT JOIN permission_audit_apps a ON a.snapshot_id = s.snapshot_id
          GROUP BY s.snapshot_id, s.apps_total
          HAVING COALESCE(s.apps_total, 0) <> COUNT(a.audit_id)
        ) x
        """,
        fetch="one",
    )
    mismatch_count = int((mismatch_row or [0])[0] or 0)
    print(f"stale snapshot rows detected: {mismatch_count}")
    print()

    if mismatch_count == 0:
        print(status_messages.status("No stale permission_audit snapshot totals detected.", level="success"))
        prompt_utils.press_enter_to_continue()
        return

    if not prompt_utils.prompt_yes_no("Backfill stale permission_audit snapshot totals now?", default=False):
        print(status_messages.status("Backfill cancelled.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    updated = core_q.run_sql_write(
        """
        UPDATE permission_audit_snapshots s
        LEFT JOIN (
          SELECT snapshot_id, COUNT(*) AS actual_apps
          FROM permission_audit_apps
          GROUP BY snapshot_id
        ) a ON a.snapshot_id = s.snapshot_id
        SET s.apps_total = COALESCE(a.actual_apps, 0)
        WHERE COALESCE(s.apps_total, 0) <> COALESCE(a.actual_apps, 0)
        """,
        query_name="db_utils.backfill.permission_audit_snapshots.apps_total",
    )

    remaining_row = core_q.run_sql(
        """
        SELECT COUNT(*)
        FROM (
          SELECT s.snapshot_id
          FROM permission_audit_snapshots s
          LEFT JOIN permission_audit_apps a ON a.snapshot_id = s.snapshot_id
          GROUP BY s.snapshot_id, s.apps_total
          HAVING COALESCE(s.apps_total, 0) <> COUNT(a.audit_id)
        ) x
        """,
        fetch="one",
    )
    remaining = int((remaining_row or [0])[0] or 0)

    print(status_messages.status("Backfill complete.", level="success"))
    print(f"rows updated : {int(updated or 0)}")
    print(f"rows remain  : {remaining}")
    prompt_utils.press_enter_to_continue()


def backfill_app_version_target_sdks() -> None:
    """Backfill missing ``app_versions.target_sdk`` from historical run rows."""

    print()
    print("Backfill app_versions targetSdk")
    print("-------------------------------")
    print("Reconciles missing app_versions.target_sdk values from historical legacy run rows.")
    print("Use this to support canonical readers that no longer fall back to runs/package metadata.")
    print()

    mismatch_row = core_q.run_sql(
        """
        SELECT COUNT(*)
        FROM app_versions av
        JOIN apps a ON a.id = av.app_id
        JOIN static_analysis_runs sar ON sar.app_version_id = av.id
        JOIN (
          SELECT package, version_code, MAX(target_sdk) AS target_sdk
          FROM runs
          WHERE target_sdk IS NOT NULL
          GROUP BY package, version_code
        ) legacy
          ON legacy.package COLLATE utf8mb4_unicode_ci = a.package_name COLLATE utf8mb4_unicode_ci
         AND legacy.version_code = av.version_code
        WHERE av.target_sdk IS NULL
          AND legacy.target_sdk IS NOT NULL
        """,
        fetch="one",
    )
    mismatch_count = int((mismatch_row or [0])[0] or 0)
    print(f"backfillable rows detected: {mismatch_count}")
    print()

    if mismatch_count == 0:
        print(status_messages.status("No missing app_versions.target_sdk rows detected.", level="success"))
        prompt_utils.press_enter_to_continue()
        return

    if not prompt_utils.prompt_yes_no("Backfill missing app_versions.target_sdk values now?", default=False):
        print(status_messages.status("Backfill cancelled.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    updated = core_q.run_sql_write(
        """
        UPDATE app_versions av
        JOIN apps a ON a.id = av.app_id
        JOIN (
          SELECT package, version_code, MAX(target_sdk) AS target_sdk
          FROM runs
          WHERE target_sdk IS NOT NULL
          GROUP BY package, version_code
        ) legacy
          ON legacy.package COLLATE utf8mb4_unicode_ci = a.package_name COLLATE utf8mb4_unicode_ci
         AND legacy.version_code = av.version_code
        SET av.target_sdk = legacy.target_sdk
        WHERE av.target_sdk IS NULL
          AND legacy.target_sdk IS NOT NULL
        """,
        query_name="db_utils.backfill.app_versions.target_sdk",
    )

    remaining_row = core_q.run_sql(
        """
        SELECT COUNT(*)
        FROM app_versions av
        JOIN apps a ON a.id = av.app_id
        JOIN static_analysis_runs sar ON sar.app_version_id = av.id
        JOIN (
          SELECT package, version_code, MAX(target_sdk) AS target_sdk
          FROM runs
          WHERE target_sdk IS NOT NULL
          GROUP BY package, version_code
        ) legacy
          ON legacy.package COLLATE utf8mb4_unicode_ci = a.package_name COLLATE utf8mb4_unicode_ci
         AND legacy.version_code = av.version_code
        WHERE av.target_sdk IS NULL
          AND legacy.target_sdk IS NOT NULL
        """,
        fetch="one",
    )
    remaining = int((remaining_row or [0])[0] or 0)

    print(status_messages.status("Backfill complete.", level="success"))
    print(f"rows updated : {int(updated or 0)}")
    print(f"rows remain  : {remaining}")
    prompt_utils.press_enter_to_continue()


def collapse_duplicate_app_versions() -> None:
    """Collapse duplicate ``app_versions`` rows by ``(app_id, version_code)``."""

    print()
    print("Collapse duplicate app_versions")
    print("-------------------------------")
    print("Keeps the richest app/version row per (app_id, version_code), re-links static runs, and deletes weaker duplicates.")
    print("This only affects duplicate version_code groups; unique app_versions rows are untouched.")
    print()

    duplicate_groups = core_q.run_sql(
        """
        SELECT
          a.package_name,
          av.app_id,
          av.version_code,
          COUNT(*) AS row_count
        FROM app_versions av
        JOIN apps a ON a.id = av.app_id
        WHERE av.version_code IS NOT NULL
        GROUP BY a.package_name, av.app_id, av.version_code
        HAVING COUNT(*) > 1
        ORDER BY a.package_name, av.version_code
        """,
        fetch="all",
        dictionary=True,
    ) or []

    print(f"duplicate groups detected: {len(duplicate_groups)}")
    if duplicate_groups:
        for row in duplicate_groups[:10]:
            print(
                f"  - {row.get('package_name')} version_code={row.get('version_code')} rows={row.get('row_count')}"
            )
    print()

    if not duplicate_groups:
        print(status_messages.status("No duplicate app_versions groups detected.", level="success"))
        prompt_utils.press_enter_to_continue()
        return

    if not prompt_utils.prompt_yes_no("Collapse duplicate app_versions rows now?", default=False):
        print(status_messages.status("Collapse cancelled.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    relinked_runs = 0
    deleted_rows = 0
    collapsed_groups = 0

    for group in duplicate_groups:
        app_id = int(group.get("app_id") or 0)
        version_code = int(group.get("version_code") or 0)
        rows = core_q.run_sql(
            """
            SELECT
              av.id,
              av.version_name,
              av.min_sdk,
              av.target_sdk,
              COALESCE(refs.ref_count, 0) AS ref_count
            FROM app_versions av
            LEFT JOIN (
              SELECT app_version_id, COUNT(*) AS ref_count
              FROM static_analysis_runs
              GROUP BY app_version_id
            ) refs ON refs.app_version_id = av.id
            WHERE av.app_id = %s
              AND av.version_code = %s
            ORDER BY
              COALESCE(refs.ref_count, 0) DESC,
              CASE
                WHEN av.version_name IS NULL OR TRIM(av.version_name) IN ('', '-', '—') THEN 1
                ELSE 0
              END ASC,
              CASE WHEN av.target_sdk IS NULL THEN 1 ELSE 0 END ASC,
              CASE WHEN av.min_sdk IS NULL THEN 1 ELSE 0 END ASC,
              CHAR_LENGTH(COALESCE(av.version_name, '')) DESC,
              av.id DESC
            """,
            (app_id, version_code),
            fetch="all",
            dictionary=True,
        ) or []
        if len(rows) <= 1:
            continue

        keep = rows[0]
        drop = rows[1:]
        keep_id = int(keep.get("id") or 0)
        keep_name = keep.get("version_name")
        keep_min = keep.get("min_sdk")
        keep_target = keep.get("target_sdk")
        for row in drop:
            drop_id = int(row.get("id") or 0)
            drop_name = row.get("version_name")
            drop_min = row.get("min_sdk")
            drop_target = row.get("target_sdk")

            if ((keep_name is None or str(keep_name).strip() in {"", "-", "—"}) and drop_name not in (None, "", "-", "—")) or (
                keep_min is None and drop_min is not None
            ) or (keep_target is None and drop_target is not None):
                core_q.run_sql_write(
                    """
                    UPDATE app_versions
                    SET version_name = CASE
                          WHEN version_name IS NULL OR TRIM(version_name) IN ('', '-', '—')
                          THEN COALESCE(%s, version_name)
                          ELSE version_name
                        END,
                        min_sdk = COALESCE(min_sdk, %s),
                        target_sdk = COALESCE(target_sdk, %s)
                    WHERE id = %s
                    """,
                    (drop_name, drop_min, drop_target, keep_id),
                    query_name="db_utils.dedupe.app_versions.enrich",
                )
                keep_name = drop_name or keep_name
                keep_min = drop_min if keep_min is None else keep_min
                keep_target = drop_target if keep_target is None else keep_target

            relinked_runs += int(
                core_q.run_sql_write(
                    "UPDATE static_analysis_runs SET app_version_id = %s WHERE app_version_id = %s",
                    (keep_id, drop_id),
                    query_name="db_utils.dedupe.app_versions.relink_static_runs",
                )
                or 0
            )
            deleted_rows += int(
                core_q.run_sql_write(
                    "DELETE FROM app_versions WHERE id = %s",
                    (drop_id,),
                    query_name="db_utils.dedupe.app_versions.delete_row",
                )
                or 0
            )
        collapsed_groups += 1

    remaining = core_q.run_sql(
        """
        SELECT COUNT(*)
        FROM (
          SELECT app_id, version_code
          FROM app_versions
          WHERE version_code IS NOT NULL
          GROUP BY app_id, version_code
          HAVING COUNT(*) > 1
        ) x
        """,
        fetch="one",
    )
    remaining_groups = int((remaining or [0])[0] or 0)

    print(status_messages.status("Duplicate collapse complete.", level="success"))
    print(f"groups collapsed : {collapsed_groups}")
    print(f"runs relinked    : {relinked_runs}")
    print(f"rows deleted     : {deleted_rows}")
    print(f"groups remaining : {remaining_groups}")
    prompt_utils.press_enter_to_continue()


def refresh_static_dynamic_summary_cache() -> None:
    """Rebuild the materialized latest-package static/dynamic summary cache."""

    print()
    print("Refresh Static/Dynamic Summary Cache")
    print("------------------------------------")
    print("Materializes the latest-package static/dynamic summary surface into a cache table.")
    print("Use this to speed up reporting and DB health reads that otherwise scan the live summary view.")
    print()

    try:
        existing_row = core_q.run_sql(
            f"SELECT COUNT(*), MAX(materialized_at_utc) FROM {STATIC_DYNAMIC_SUMMARY_CACHE}",
            fetch="one",
            query_name="db_utils.summary_cache.precheck",
        )
    except Exception:
        existing_row = (0, None)
    existing_count = int((existing_row or [0, None])[0] or 0)
    existing_ts = (existing_row or [0, None])[1] if existing_row else None
    print(f"current rows      : {existing_count}")
    print(f"last materialized : {existing_ts or '—'}")
    print()

    if not prompt_utils.prompt_yes_no("Refresh summary cache now?", default=False):
        print(status_messages.status("Refresh cancelled.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    inserted, materialized_at = _refresh_static_dynamic_summary_cache()

    refreshed_row = core_q.run_sql(
        f"SELECT COUNT(*), MAX(materialized_at_utc) FROM {STATIC_DYNAMIC_SUMMARY_CACHE}",
        fetch="one",
        query_name="db_utils.summary_cache.postcheck",
    )
    refreshed_count = int((refreshed_row or [0, None])[0] or 0)
    refreshed_ts = (refreshed_row or [0, None])[1] if refreshed_row else None
    print(status_messages.status("Summary cache refreshed.", level="success"))
    print(f"rows inserted    : {int(inserted or 0)}")
    print(f"cached rows      : {refreshed_count}")
    print(f"materialized at  : {refreshed_ts or '—'}")
    prompt_utils.press_enter_to_continue()


def log_db_op(
    *,
    operation: str,
    started_at: datetime,
    finished_at: datetime,
    success: bool,
    error_text: str | None,
) -> None:
    _grouped_log_db_op(
        app_config=app_config,
        core_q=core_q,
        diagnostics=diagnostics,
        operation=operation,
        started_at=started_at,
        finished_at=finished_at,
        success=success,
        error_text=error_text,
    )


def reconcile_static_session_artifacts() -> None:
    """Audit one static session across canonical rows and parity surfaces."""

    print()
    print("Reconcile Static Session")
    print("------------------------")
    print("Audits one static session across archive reports, canonical rows, parity surfaces, and session linkage.")
    print("Use this after a large static run or after a partial persistence failure.")
    print()

    latest_row = core_q.run_sql(
        """
        SELECT session_label
        FROM static_analysis_runs
        GROUP BY session_label
        ORDER BY MAX(id) DESC
        LIMIT 1
        """,
        fetch="one",
    )
    default_session = str((latest_row or [None])[0] or "").strip() or None
    session_label = prompt_utils.prompt_text(
        "Session label",
        default=default_session,
        required=True,
        show_arrow=False,
    ).strip()
    if not session_label:
        print(status_messages.status("Session reconcile cancelled.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    try:
        summary = reconcile_static_session(session_label)
    except Exception as exc:
        print(status_messages.status(f"Reconcile failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    audit_path = write_reconcile_audit(summary)

    print(f"Session               : {summary.session_label}")
    print(
        f"Static runs           : total={summary.total_runs} completed={summary.completed_runs} "
        f"started={summary.started_runs} failed={summary.failed_runs}"
    )
    print(
        f"Canonical             : findings={summary.canonical_findings} "
        f"perm_matrix={summary.canonical_permission_matrix} perm_risk={summary.canonical_permission_risk}"
    )
    print(
        f"Summaries             : findings={summary.findings_summary_packages} "
        f"strings={summary.string_summary_packages} handoff_paths={summary.handoff_paths}"
    )
    print(f"Session linkage       : links={summary.session_run_links} rollups={summary.session_rollups}")
    print(f"Archive reports       : files={summary.report_files} packages={summary.report_packages}")
    print(
        f"Web surfaces          : view={summary.web_view_packages} cache={summary.web_cache_packages} "
        f"cache_stale={summary.cache_stale if summary.cache_stale is not None else 'unknown'}"
    )
    print(f"Audit artifact        : {audit_path}")
    if summary.package_collations:
        collation_preview = format_collation_preview(summary.package_collations, limit=4)
        print(f"Package collations    : {collation_preview}")
    print()

    print_warning_preview("Failed packages", summary.failed_packages)
    print_warning_preview("Missing session links", summary.missing_session_links)
    print_warning_preview("Missing compat runs", summary.missing_legacy_runs)
    print_warning_preview("Missing compat risk", summary.missing_risk_scores)
    secondary_compat_gap_count = summary.missing_secondary_compat_mirror_count
    if secondary_compat_gap_count:
        print(
            status_messages.status(
                "Secondary compat mirror gaps recorded in reconcile audit "
                f"(total={secondary_compat_gap_count})",
                level="info",
            )
        )
    print_warning_preview("Missing findings summary", summary.missing_findings_summary)
    print_warning_preview("Missing string summary", summary.missing_string_summary)
    print_warning_preview("Missing report packages", summary.missing_report_packages)
    print_warning_preview("Stale report-only packages", summary.stale_report_only_packages)
    print_warning_preview("Missing web view packages", summary.missing_web_view_packages)
    print_warning_preview("Missing web cache packages", summary.missing_web_cache_packages)
    for risk in summary.collation_risks:
        print(status_messages.status(f"Collation risk: {risk}", level="warn"))

    if summary.missing_session_links:
        print()
        print("Safe repair option")
        print("------------------")
        print("This can rebuild missing static_session_run_links rows from completed canonical runs only.")
        if prompt_utils.prompt_yes_no("Repair missing static_session_run_links now?", default=False):
            try:
                inserted = repair_session_run_links(summary.session_label)
                refreshed = reconcile_static_session(summary.session_label)
                write_reconcile_audit(refreshed)
                print(status_messages.status("Static session link repair complete.", level="success"))
                print(f"rows inserted/updated : {inserted}")
                print(f"links now present     : {refreshed.session_run_links}")
                if refreshed.missing_session_links:
                    print_warning_preview("Links still missing", refreshed.missing_session_links)
            except Exception as exc:
                print(status_messages.status(f"Static session link repair failed: {exc}", level="error"))

    if summary.missing_web_cache_packages or summary.cache_stale:
        print()
        print("Web/cache refresh option")
        print("------------------------")
        print("This rebuilds the latest-package static/dynamic summary cache after static repairs.")
        if prompt_utils.prompt_yes_no("Refresh summary cache and re-check this session now?", default=False):
            try:
                refreshed_rows, refreshed = refresh_summary_cache_and_reconcile(summary.session_label)
                write_reconcile_audit(refreshed)
                print(status_messages.status("Summary cache refresh complete.", level="success"))
                print(f"cache rows rebuilt     : {refreshed_rows}")
                print(f"web cache packages     : {refreshed.web_cache_packages}")
                if refreshed.missing_web_cache_packages:
                    print_warning_preview("Web cache still missing", refreshed.missing_web_cache_packages)
            except Exception as exc:
                print(status_messages.status(f"Summary cache refresh failed: {exc}", level="error"))

    prompt_utils.press_enter_to_continue()


def purge_static_session_for_rerun() -> None:
    """Delete stale static session DB rows and artifacts so the session can be re-run cleanly."""

    print()
    print("Purge Static Session For Re-run")
    print("-------------------------------")
    print("Deletes one static session's DB rows and session-scoped static artifacts.")
    print("Use this for stale pre-fix or partial-failure sessions you plan to re-run on current code.")
    print()

    latest_row = core_q.run_sql(
        """
        SELECT session_label
        FROM static_analysis_runs
        GROUP BY session_label
        ORDER BY MAX(id) DESC
        LIMIT 1
        """,
        fetch="one",
    )
    default_session = str((latest_row or [None])[0] or "").strip() or None
    session_label = prompt_utils.prompt_text(
        "Session label",
        default=default_session,
        required=True,
        show_arrow=False,
    ).strip()
    if not session_label:
        print(status_messages.status("Static session purge cancelled.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    try:
        summary = reconcile_static_session(session_label)
    except Exception as exc:
        print(status_messages.status(f"Session audit failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    print(f"Session               : {summary.session_label}")
    print(
        f"Static runs           : total={summary.total_runs} completed={summary.completed_runs} "
        f"started={summary.started_runs} failed={summary.failed_runs}"
    )
    print(
        f"Canonical             : findings={summary.canonical_findings} "
        f"perm_matrix={summary.canonical_permission_matrix} perm_risk={summary.canonical_permission_risk}"
    )
    print(f"Archive reports       : files={summary.report_files} packages={summary.report_packages}")
    print()
    print(status_messages.status("This deletes stale session rows and archived evidence for this label only.", level="warn"))
    print(status_messages.status("Harvested APKs and other session labels are preserved.", level="info"))
    print()

    if not prompt_utils.prompt_yes_no("Purge this static session now?", default=False):
        print(status_messages.status("Static session purge cancelled.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    reset_outcome = reset_static_analysis_data(session_label=session_label, include_harvest=False)
    artifact_outcome = purge_static_session_artifacts(session_label)
    try:
        rebuilt, _materialized_at = _refresh_static_dynamic_summary_cache()
    except Exception as exc:
        rebuilt = None
        print(status_messages.status(f"Summary cache refresh after purge failed: {exc}", level="error"))

    print(status_messages.status("Static session purge complete.", level="success"))
    for line in reset_outcome.as_lines():
        print(line)
    for line in artifact_outcome.as_lines():
        print(line)
    if rebuilt is not None:
        print(f"summary cache rows rebuilt: {rebuilt}")
    prompt_utils.press_enter_to_continue()

__all__ = [
    "maybe_clear_screen",
    "show_connection_and_config",
    "freeze_duplicate_permission_intel_tables",
    "run_inventory_determinism_comparator",
    "backfill_static_permission_risk_vnext",
    "audit_static_risk_coverage",
    "seed_dataset_profile",
    "sync_contracts_to_db",
    "apply_canonical_schema_bootstrap",
    "ensure_dynamic_tier_column",
    "ensure_dynamic_network_quality_column",
    "ensure_dynamic_netstats_rows_columns",
    "ensure_dynamic_pcap_columns",
    "ensure_dynamic_sampling_duration_columns",
    "ensure_dynamic_gap_columns",
    "ensure_dynamic_tier_migrations",
    "backfill_static_run_findings_totals",
    "backfill_permission_audit_snapshot_totals",
    "backfill_app_version_target_sdks",
    "collapse_duplicate_app_versions",
    "refresh_static_dynamic_summary_cache",
    "reconcile_static_session_artifacts",
    "purge_static_session_for_rerun",
    "log_db_op",
]
