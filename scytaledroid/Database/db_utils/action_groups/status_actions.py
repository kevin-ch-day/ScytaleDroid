"""Status, schema, and comparator actions for Database Tools."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_core import permission_intel as intel_db
from scytaledroid.Database.db_utils import diagnostics, schema_gate
from scytaledroid.Database.db_utils.bridge_posture import (
    bridge_posture_summary,
    list_bridge_postures,
)
from scytaledroid.Database.db_utils.legacy_static_mirror_diagnostics import (
    LEGACY_MIRROR_TABLES_SNAPSHOT,
)
from scytaledroid.Database.db_utils.permission_intel_freeze import (
    list_operational_managed_tables,
)
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.version_utils import get_git_commit

_DUPLICATE_SCAN_FAILED_USER_HINT = "Operational duplicate scan failed; see debug logs."
_PI_TARGET_SNAPSHOT_FAILED_DETAIL = "Permission Intel target inspection failed; see debug logs."

# --- DB schema snapshot (write_db_schema_snapshot_audit) table policy -----------------
# ``required_tables.static`` in the snapshot JSON: canonical static surfaces expected to exist
# for a healthy analyst catalog. Includes every base table/view from ``schema_gate.static_schema_gate``
# plus ``risk_scores`` (run-level scoring; used operationally but not part of that gate's table list).
# Legacy base table ``findings`` is part of ``LEGACY_MIRROR_TABLES_SNAPSHOT`` (``DB_SNAPSHOT_LEGACY_MIRROR_TABLES``).
DB_SNAPSHOT_REQUIRED_STATIC_TABLES: tuple[str, ...] = (
    "static_analysis_runs",
    "static_analysis_findings",
    "static_permission_matrix",
    "static_string_summary",
    "static_string_samples",
    "static_session_run_links",
    "static_session_rollups",
    "v_static_handoff_v1",
    "risk_scores",
)

# Legacy mirror / compatibility five — information_schema presence only; not required for health.
DB_SNAPSHOT_LEGACY_MIRROR_TABLES: tuple[str, ...] = LEGACY_MIRROR_TABLES_SNAPSHOT

DB_SCHEMA_SNAPSHOT_LEGACY_MIRROR_META: dict[str, str] = {
    "role": "legacy_mirror_compatibility_optional",
    "interpretation": (
        "Presence flags only (information_schema). These objects are legacy mirror / compatibility "
        "tables, not canonical static truth. Missing tables are normal for canonical-only deployments. "
        "Judge static health using gates.static_schema_gate and required_tables.static, not "
        "legacy_mirror_table_presence."
    ),
}


def _snapshot_subcheck_short_reason(exc: BaseException, *, max_len: int = 200) -> str:
    text = f"{type(exc).__name__}: {exc}"
    return text if len(text) <= max_len else f"{text[: max_len - 3]}..."


def _bridge_posture_snapshot_block() -> tuple[dict[str, object], str | None]:
    """Collect bridge posture for schema snapshot; never raises."""

    try:
        summary = bridge_posture_summary()
        tables = [
            {
                "table": row.table,
                "posture": row.posture,
                "owner": row.owner,
                "rationale": row.rationale,
                "current_writers": list(row.current_writers),
                "current_readers": list(row.current_readers),
            }
            for row in list_bridge_postures()
        ]
        return {"summary": summary, "tables": tables}, None
    except Exception as exc:
        log.debug(
            f"DB schema snapshot sub-check failed (bridge_posture): "
            f"{type(exc).__name__}: {exc}",
            category="db",
        )
        return {"summary": {}, "tables": []}, _snapshot_subcheck_short_reason(exc)


def _snapshot_operational_duplicates() -> tuple[list[dict[str, object]], str | None]:
    """Return duplicate-table rows for JSON snapshot; never raises."""

    try:
        return list_operational_managed_tables(), None
    except Exception as exc:
        log.debug(
            f"DB schema snapshot sub-check failed (operational_duplicate_scan): "
            f"{type(exc).__name__}: {exc}",
            category="db",
        )
        return [], _DUPLICATE_SCAN_FAILED_USER_HINT


def _fetch_operational_inventory_for_menu() -> tuple[list[dict[str, object]] | None, BaseException | None]:
    """Load duplicate-table inventory for Database Configuration menu; returns (rows, error)."""

    try:
        return list_operational_managed_tables(), None
    except Exception as exc:
        log.debug(
            f"show_connection_and_config operational_duplicate_scan failed: "
            f"{type(exc).__name__}: {exc}",
            category="db",
        )
        return None, exc


def _permission_intel_snapshot_block() -> dict[str, object]:
    """Build the permission_intel section for schema snapshots without crashing when PI is unset."""

    if not intel_db.is_permission_intel_configured():
        dups, dup_warn = _snapshot_operational_duplicates()
        block: dict[str, object] = {
            "configured": False,
            "target": None,
            "detail": "Permission Intel DSN not configured; PI target and governance checks skipped.",
            "operational_duplicates": dups,
        }
        if dup_warn:
            block["operational_duplicate_scan_warning"] = dup_warn
        return block

    try:
        target = intel_db.describe_target()
    except Exception as exc:
        log.debug(
            f"DB schema snapshot sub-check failed (permission_intel_target): "
            f"{type(exc).__name__}: {exc}",
            category="db",
        )
        dups, dup_warn = _snapshot_operational_duplicates()
        err_block: dict[str, object] = {
            "configured": True,
            "target": None,
            "status": "error",
            "detail": _PI_TARGET_SNAPSHOT_FAILED_DETAIL,
            "operational_duplicates": dups,
        }
        if dup_warn:
            err_block["operational_duplicate_scan_warning"] = dup_warn
        return err_block

    dups, dup_warn = _snapshot_operational_duplicates()
    out: dict[str, object] = {
        "target": target,
        "operational_duplicates": dups,
    }
    if dup_warn:
        out["operational_duplicate_scan_warning"] = dup_warn
    return out


def _print_operational_duplicate_menu_section(
    inventory: list[dict[str, object]] | None,
    *,
    inventory_error: BaseException | None,
) -> None:
    """Print duplicate-managed-table metrics or a single operator hint."""

    if inventory is not None:
        duplicate_present = [row for row in inventory if row["exists"]]
        duplicate_rows = sum(int(row["row_count"] or 0) for row in duplicate_present)
        menu_utils.print_metrics(
            [
                ("Dup tables in main DB", len(duplicate_present)),
                ("Dup rows in main DB", duplicate_rows),
            ]
        )
        if duplicate_present:
            print(
                "Duplicate tables: "
                + ", ".join(f"{row['table']}={row['row_count']}" for row in duplicate_present[:6])
                + (" ..." if len(duplicate_present) > 6 else "")
            )
        return

    detail = (
        f"{type(inventory_error).__name__}: {inventory_error}"
        if inventory_error is not None
        else "unknown error"
    )
    print(
        status_messages.status(
            f"Operational duplicate scan unavailable (core DB): {detail}",
            level="warn",
        )
    )


def show_connection_and_config() -> None:
    """Display database configuration details and test connectivity."""

    try:
        cfg = db_config.DB_CONFIG
        backend = str(cfg.get("engine", "disabled"))
        host = str(cfg.get("host", "<unknown>"))
        port_display = str(cfg.get("port", "<unknown>"))
        database = str(cfg.get("database", "<unknown>"))
        user = str(cfg.get("user", "<unknown>"))
        cfg_source = getattr(db_config, "DB_CONFIG_SOURCE", "default")
    except Exception as exc:
        backend = host = port_display = database = user = "<unknown>"
        cfg_source = "error"
        print(status_messages.status(f"Unable to read DB config: {exc}", level="warn"))

    print()
    menu_utils.print_header("Database Configuration")
    menu_utils.print_metrics(
        [
            ("Backend", backend),
            ("Host", host),
            ("Port", port_display),
            ("Database", database),
            ("Username", user),
            ("Config via", cfg_source),
        ]
    )
    schema_version = diagnostics.get_schema_version()
    print(f"Schema ver : {schema_version or '<unknown>'}")
    print()

    menu_utils.print_section("Permission-intel target")
    inventory, inventory_error = _fetch_operational_inventory_for_menu()

    if not intel_db.is_permission_intel_configured():
        print("Permission Intel        : SKIPPED — DSN not configured")
        _print_operational_duplicate_menu_section(inventory, inventory_error=inventory_error)
    else:
        target: dict[str, object] | None = None
        try:
            target = intel_db.describe_target()
        except Exception as exc:
            log.debug(
                f"show_connection_and_config permission_intel_target failed: "
                f"{type(exc).__name__}: {exc}",
                category="db",
            )
            print("Permission Intel        : ERROR — unable to inspect target")

        if target is not None:
            menu_utils.print_metrics(
                [
                    ("Compat mode", "YES" if target["compatibility_mode"] else "NO"),
                    ("Target DB", str(target.get("database") or "<unknown>")),
                    ("Target host", str(target.get("host") or "<unknown>")),
                    ("Config via", str(target.get("source") or "<unknown>")),
                ]
            )
            _print_operational_duplicate_menu_section(inventory, inventory_error=inventory_error)
        else:
            _print_operational_duplicate_menu_section(inventory, inventory_error=inventory_error)
    print()

    menu_utils.print_section("Bridge posture")
    try:
        posture_counts = bridge_posture_summary()
        menu_utils.print_metrics(
            [
                ("Compat-only keep", posture_counts.get("compat_only_keep", 0)),
                ("Compat mirror review", posture_counts.get("compat_mirror_review", 0)),
                ("Derived review", posture_counts.get("derived_review", 0)),
                ("Freeze candidate", posture_counts.get("freeze_candidate", 0)),
            ]
        )
        rows = list_bridge_postures()
        preview = ", ".join(f"{row.table}={row.posture}" for row in rows)
        print(f"Tables     : {preview}")
    except Exception as exc:
        print(status_messages.status(f"Unable to inspect bridge posture: {exc}", level="warn"))
    print()

    menu_utils.print_section("Connection test")
    success = diagnostics.check_connection()
    if success:
        print("Connection established successfully")
    else:
        print("Connection failed. Check logs for details.")
        if backend == "mysql":
            print("Verify SCYTALEDROID_DB_URL and ensure schema is bootstrapped.")
    prompt_utils.press_enter_to_continue()


def write_db_schema_snapshot_audit() -> None:
    """Write a read-only DB schema snapshot under output/audit/db/."""

    if not db_config.db_enabled():
        print(
            status_messages.status(
                "DB is disabled (no mysql/mariadb config). Schema snapshot skipped.",
                level="info",
            )
        )
        prompt_utils.press_enter_to_continue()
        return

    out_dir = Path(app_config.OUTPUT_DIR) / "audit" / "db"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%SZ")
    out_path = out_dir / f"db_schema_snapshot_{stamp}.json"
    latest_path = out_dir / "latest.json"

    cfg = dict(db_config.DB_CONFIG)
    if "password" in cfg:
        cfg["password"] = "***"

    snapshot: dict[str, object] = {
        "generated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "db_enabled": True,
        "db_config_source": getattr(db_config, "DB_CONFIG_SOURCE", "unknown"),
        "db_config": cfg,
        "server_info": diagnostics.get_server_info(),
        "schema_version": diagnostics.get_schema_version(),
        "required_tables": {
            "base": diagnostics.check_required_tables(["schema_version", "apps"]),
            "inventory": diagnostics.check_required_tables(
                [
                    "device_inventory_snapshots",
                    "device_inventory",
                    "apps",
                    "android_apk_repository",
                    "apk_split_groups",
                    "harvest_artifact_paths",
                    "harvest_source_paths",
                    "harvest_storage_roots",
                ]
            ),
            "static": diagnostics.check_required_tables(list(DB_SNAPSHOT_REQUIRED_STATIC_TABLES)),
            "dynamic": diagnostics.check_required_tables(
                [
                    "dynamic_sessions",
                    "dynamic_session_issues",
                    "dynamic_telemetry_process",
                    "dynamic_telemetry_network",
                ]
            ),
        },
        "legacy_mirror_table_presence": diagnostics.check_required_tables(
            list(DB_SNAPSHOT_LEGACY_MIRROR_TABLES)
        ),
        "legacy_mirror_table_presence_meta": dict(DB_SCHEMA_SNAPSHOT_LEGACY_MIRROR_META),
        "gates": {
            "base_schema_gate": schema_gate.check_base_schema(),
            "inventory_schema_gate": schema_gate.inventory_schema_gate(),
            "static_schema_gate": schema_gate.static_schema_gate(),
            "dynamic_schema_gate": schema_gate.dynamic_schema_gate(),
            "permissions_schema_gate": schema_gate.permissions_schema_gate(),
        },
        "permission_intel": _permission_intel_snapshot_block(),
        "tables": {},
        "tables_error": None,
    }
    bridge_body, bridge_err = _bridge_posture_snapshot_block()
    snapshot["bridge_posture"] = bridge_body
    if bridge_err:
        snapshot["bridge_posture_error"] = bridge_err

    try:
        use_exact = str(
            os.environ.get("SCYTALEDROID_DB_SCHEMA_SNAPSHOT_EXACT_TABLE_COUNTS") or ""
        ).strip().lower() in {"1", "true", "yes", "on"}
        if use_exact:
            table_names = diagnostics.list_tables()
            counts = diagnostics.table_counts(table_names)
            snapshot["tables"] = {
                name: {"row_count": counts.get(name)} for name in table_names
            }
            snapshot["tables_row_count_note"] = (
                "exact: SELECT COUNT(*) per table (SCYTALEDROID_DB_SCHEMA_SNAPSHOT_EXACT_TABLE_COUNTS=1)."
            )
        else:
            approx = diagnostics.approximate_table_row_counts()
            if approx:
                snapshot["tables"] = {
                    name: {"row_count": approx.get(name)} for name in sorted(approx.keys())
                }
                snapshot["tables_row_count_note"] = (
                    "approximate: information_schema.tables.TABLE_ROWS (InnoDB estimate; NULL for many "
                    "VIEW rows). Set SCYTALEDROID_DB_SCHEMA_SNAPSHOT_EXACT_TABLE_COUNTS=1 for exact "
                    "COUNT(*) per table."
                )
            else:
                table_names = diagnostics.list_tables()
                counts = diagnostics.table_counts(table_names)
                snapshot["tables"] = {
                    name: {"row_count": counts.get(name)} for name in table_names
                }
                snapshot["tables_row_count_note"] = (
                    "exact: SELECT COUNT(*) per table (fallback when information_schema estimate "
                    "read returned no rows or failed)."
                )
        try:
            rows = core_q.run_sql(
                "SELECT version, applied_at_utc, note FROM schema_version ORDER BY applied_at_utc ASC",
                fetch="all_dict",
            ) or []
            snapshot["schema_version_history"] = [dict(r) for r in rows]
        except Exception as exc:
            snapshot["schema_version_history"] = []
            snapshot["schema_version_history_error"] = f"{type(exc).__name__}: {exc}"
    except Exception as exc:
        snapshot["tables_error"] = f"{type(exc).__name__}: {exc}"

    content = json.dumps(snapshot, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    out_path.write_text(content, encoding="utf-8")
    latest_path.write_text(content, encoding="utf-8")

    print(status_messages.status("DB schema snapshot written.", level="success"))
    print(f"  {out_path}")
    print(
        status_messages.status(
            "legacy_mirror_table_presence (JSON): optional legacy five — missing is normal for "
            "canonical-only catalogs; see legacy_mirror_table_presence_meta.",
            level="info",
        )
    )
    prompt_utils.press_enter_to_continue()


def run_inventory_determinism_comparator() -> None:
    """Run strict inventory comparator on two snapshots for one device serial."""

    from scytaledroid.DeviceAnalysis.inventory.determinism import (
        build_snapshot_payload,
        compare_inventory_payloads,
    )

    def _latest_serial() -> str | None:
        row = core_q.run_sql(
            """
            SELECT device_serial
            FROM device_inventory_snapshots
            ORDER BY snapshot_id DESC
            LIMIT 1
            """,
            fetch="one",
        )
        if not row:
            return None
        return str(row[0] or "").strip() or None

    def _latest_two_snapshot_ids(device_serial: str) -> tuple[int, int] | None:
        rows = core_q.run_sql(
            """
            SELECT snapshot_id
            FROM device_inventory_snapshots
            WHERE device_serial=%s
            ORDER BY snapshot_id DESC
            LIMIT 2
            """,
            (device_serial,),
            fetch="all",
        ) or []
        if len(rows) < 2:
            return None
        left = int(rows[1][0])
        right = int(rows[0][0])
        return left, right

    def _load_snapshot(snapshot_id: int) -> dict[str, object] | None:
        row = core_q.run_sql(
            """
            SELECT
              snapshot_id,
              device_serial,
              package_count,
              package_list_hash,
              package_signature_hash,
              scope_hash,
              captured_at
            FROM device_inventory_snapshots
            WHERE snapshot_id = %s
            """,
            (snapshot_id,),
            fetch="one_dict",
        )
        return dict(row) if row else None

    def _load_rows(snapshot_id: int) -> list[dict[str, object]]:
        rows = core_q.run_sql(
            """
            SELECT
              package_name,
              version_code,
              app_label,
              version_name,
              installer,
              primary_path,
              split_count,
              extras,
              apk_paths
            FROM device_inventory
            WHERE snapshot_id = %s
            ORDER BY package_name ASC
            """,
            (snapshot_id,),
            fetch="all_dict",
        ) or []
        return [dict(row) for row in rows]

    print()
    print("Inventory Determinism Comparator (Strict)")
    print("----------------------------------------")
    print("Mode: strict (missing/duplicate keys fail; only timestamp/run_id diffs allowed)")
    print()

    default_serial = _latest_serial()
    if not default_serial:
        print(status_messages.status("No inventory snapshots found in DB.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    device_serial = (
        prompt_utils.prompt_text(
            "Device serial",
            default=default_serial,
            required=True,
            show_arrow=False,
        ).strip()
        or default_serial
    )
    pair = _latest_two_snapshot_ids(device_serial)
    if not pair:
        print(status_messages.status(f"Need at least two snapshots for {device_serial}.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return
    left_id, right_id = pair

    left_snapshot = _load_snapshot(left_id)
    right_snapshot = _load_snapshot(right_id)
    if not left_snapshot or not right_snapshot:
        print(status_messages.status("Failed to load snapshot metadata.", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    left_rows = _load_rows(left_id)
    right_rows = _load_rows(right_id)
    left_payload = build_snapshot_payload(snapshot=left_snapshot, rows=left_rows)
    right_payload = build_snapshot_payload(snapshot=right_snapshot, rows=right_rows)
    compare = compare_inventory_payloads(
        left_payload=left_payload,
        right_payload=right_payload,
        left_meta={
            "run_id": left_id,
            "source": "db:device_inventory",
            "timestamp_utc": str(left_snapshot.get("captured_at") or ""),
        },
        right_meta={
            "run_id": right_id,
            "source": "db:device_inventory",
            "timestamp_utc": str(right_snapshot.get("captured_at") or ""),
        },
        tool_semver=app_config.APP_VERSION,
        git_commit=get_git_commit(),
        compare_type="inventory_guard",
    )
    stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%SZ")
    output_path = Path("output") / "audit" / "comparators" / "inventory_guard" / stamp / "diff.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(compare.payload, indent=2, sort_keys=True, ensure_ascii=True),
        encoding="utf-8",
    )
    passed = bool(compare.passed)
    diff_count = int(compare.payload.get("result", {}).get("diff_counts", {}).get("disallowed", 0))
    print()
    if passed:
        print(status_messages.status("PASS: no disallowed diffs.", level="success"))
    else:
        print(status_messages.status(f"FAIL: {diff_count} disallowed diffs.", level="error"))
    print(f"Left snapshot : {left_id}")
    print(f"Right snapshot: {right_id}")
    print(f"Artifact      : {output_path}")
    prompt_utils.press_enter_to_continue()


__all__ = [
    "run_inventory_determinism_comparator",
    "show_connection_and_config",
    "write_db_schema_snapshot_audit",
]
