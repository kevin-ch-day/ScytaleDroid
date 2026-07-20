"""Dynamic Tier 1 export/status actions for the reporting menu."""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_utils.menus import health_checks
from scytaledroid.DynamicAnalysis.exports.dataset_export import export_tier1_pack
from scytaledroid.DynamicAnalysis.storage.index_from_evidence import (
    index_dynamic_evidence_packs_to_db,
)
from scytaledroid.DynamicAnalysis.utils.path_utils import (
    dynamic_evidence_root,
    dynamic_evidence_roots,
)
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def handle_tier1_export_pack() -> None:
    """Export the Baseline dataset pack (manifest + telemetry + summary)."""

    from scytaledroid.Database.db_utils import schema_gate

    ok, message, detail = schema_gate.dynamic_schema_gate()
    if not ok:
        status_messages.print_status(f"[ERROR] {message}", level="error")
        if detail:
            status_messages.print_status(detail, level="error")
        status_messages.print_status(
            "Fix: Database Tools → Apply Baseline schema migrations (or import canonical DB export), then retry.",
            level="error",
        )
        return

    default_dir = Path(app_config.OUTPUT_DIR) / "exports" / "scytaledroid_dyn_v1"
    print(status_messages.status(f"Export directory: {default_dir}", level="info"))
    if not prompt_utils.prompt_yes_no("Generate Baseline export pack now?", default=True):
        return
    outputs = export_tier1_pack(default_dir)
    print(status_messages.status(f"Manifest written: {outputs['manifest']}", level="success"))
    print(status_messages.status(f"Summary written: {outputs['summary']}", level="success"))
    print(status_messages.status(f"Rollup written: {outputs['rollup']}", level="success"))
    print(status_messages.status(f"Telemetry dir: {outputs['telemetry_dir']}", level="success"))
    feature_health = outputs.get("feature_health") or {}
    if feature_health:
        print(
            status_messages.status(
                f"Feature health ({feature_health.get('status')}): {feature_health.get('json_path')}",
                level="success",
            )
        )
    _print_export_validation(outputs)
    prompt_utils.press_enter_to_continue()


def _print_export_validation(outputs: dict) -> None:
    manifest_path = outputs.get("manifest")
    telemetry_dir = outputs.get("telemetry_dir")
    if not manifest_path:
        return
    total_rows = 0
    included_rows = 0
    net_included = 0
    try:
        with open(manifest_path, newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                total_rows += 1
                inclusion = (row.get("inclusion_status") or "").strip().lower()
                if inclusion == "include":
                    included_rows += 1
                net_status = (row.get("network_inclusion_status") or "").strip().lower()
                if net_status in {"netstats_ok", "netstats_partial"}:
                    net_included += 1
    except OSError:
        return

    network_files = 0
    if telemetry_dir:
        try:
            network_files = sum(1 for _ in Path(telemetry_dir).glob("*-network.csv"))
        except OSError:
            network_files = 0

    print(
        status_messages.status(
            f"Export validation: runs={total_rows}, included={included_rows}, "
            f"network_eligible={net_included}, network_files={network_files}",
            level="info",
        )
    )


def handle_tier1_audit_report() -> None:
    """Run Baseline dataset readiness audit."""

    health_checks.run_tier1_audit_report()


def _rebuild_dynamic_db_index_from_evidence(root: Path) -> dict[str, object]:
    """Return indexer results for a dynamic evidence-pack root."""

    result = index_dynamic_evidence_packs_to_db(root)
    return {
        "raw": result,
        "scanned": int(result.get("scanned") or 0),
        "ok": int(result.get("ok") or 0),
        "network_features_upserted": int(result.get("network_features_upserted") or 0),
        "indicators_indexed": int(result.get("indicators_indexed") or 0),
        "errors": result.get("errors") or [],
    }


def handle_tier1_quick_fix() -> None:
    """One-shot helper: rebuild DB index from evidence packs and rerun Baseline checks."""

    root = dynamic_evidence_root()
    if not root.exists():
        print(status_messages.status("Dynamic evidence root not found.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_header("Baseline quick fix")
    print(status_messages.status("This does not modify evidence packs; it rebuilds derived DB tables.", level="info"))
    print(status_messages.status(f"Root: {root}", level="info"))
    if not prompt_utils.prompt_yes_no("Rebuild DB index now?", default=True):
        return

    outcome = _rebuild_dynamic_db_index_from_evidence(root)
    scanned = int(outcome.get("scanned") or 0)
    ok = int(outcome.get("ok") or 0)
    features = int(outcome.get("network_features_upserted") or 0)
    indexed = int(outcome.get("indicators_indexed") or 0)
    errors = outcome.get("errors") or []
    print(
        status_messages.status(
            f"Reindex complete: scanned={scanned} ok={ok} network_features_upserted={features} indicators_indexed={indexed}",
            level="success" if scanned and scanned == ok else "warn",
        )
    )
    if errors:
        print(status_messages.status(f"Errors (sample): {', '.join(str(e) for e in errors[:5])}", level="warn"))

    print()
    if prompt_utils.prompt_yes_no("Run Baseline audit report now?", default=True):
        health_checks.run_tier1_audit_report()

    print()
    if prompt_utils.prompt_yes_no(
        "Generate Baseline export pack now? (populates Feature Health)", default=False
    ):
        handle_tier1_export_pack()

    prompt_utils.press_enter_to_continue()


def handle_tier1_end_to_end() -> None:
    """One-button Baseline run: rebuild DB index + audit + export."""

    from scytaledroid.Database.db_utils import schema_gate

    ok, message, detail = schema_gate.dynamic_schema_gate()
    if not ok:
        status_messages.print_status(f"[ERROR] {message}", level="error")
        if detail:
            status_messages.print_status(detail, level="error")
        status_messages.print_status(
            "Fix: Database Tools → Apply Baseline schema migrations (or import canonical DB export), then retry.",
            level="error",
        )
        return

    root = dynamic_evidence_root()
    if not root.exists():
        print(status_messages.status("Dynamic evidence root not found.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_header("Baseline end-to-end")
    print(status_messages.status("Rebuild DB index from evidence packs → audit → export pack.", level="info"))
    result = index_dynamic_evidence_packs_to_db(root)
    scanned = int(result.get("scanned") or 0)
    ok_n = int(result.get("ok") or 0)
    print(
        status_messages.status(
            f"Reindex: scanned={scanned} ok={ok_n}",
            level="success" if scanned and scanned == ok_n else "warn",
        )
    )
    health_checks.run_tier1_audit_report()
    default_dir = Path(app_config.OUTPUT_DIR) / "exports" / "scytaledroid_dyn_v1"
    outputs = export_tier1_pack(default_dir)
    print(status_messages.status(f"Export written: {outputs.get('manifest')}", level="success"))
    prompt_utils.press_enter_to_continue()


def fetch_tier1_status() -> dict[str, object]:
    """Return a compact Baseline readiness snapshot for the reporting menu."""

    from scytaledroid.Database.db_utils.schema_migration_registry import (
        latest_registered_schema_version,
    )

    status: dict[str, object] = {
        "schema_version": None,
        "expected_schema": latest_registered_schema_version() or "0.2.6",
        "tier1_ready_runs": 0,
        "last_export_path": None,
        "last_export_at": None,
        "pcap_valid_runs": 0,
        "pcap_total_runs": 0,
        "db_dynamic_sessions_total": 0,
        "db_dynamic_sessions_dataset_tier": 0,
        "db_dynamic_sessions_dataset": 0,
        "evidence_packs_total": 0,
        "evidence_quota_eligible_packs": 0,
        "evidence_quota_valid_packs": 0,
        "evidence_dataset_packs": 0,
        "evidence_dataset_valid": 0,
        "feature_health_status": None,
        "feature_health_at": None,
    }
    try:
        row = core_q.run_sql(
            "SELECT version FROM schema_version ORDER BY applied_at_utc DESC LIMIT 1",
            fetch="one",
            dictionary=True,
        )
        if row:
            status["schema_version"] = row.get("version")
    except Exception:
        status["schema_version"] = None

    try:
        row = core_q.run_sql(
            "SELECT COUNT(*) AS cnt FROM dynamic_sessions",
            fetch="one",
            dictionary=True,
        )
        if row:
            status["db_dynamic_sessions_total"] = int(row.get("cnt") or 0)
    except Exception:
        status["db_dynamic_sessions_total"] = 0

    try:
        row = core_q.run_sql(
            "SELECT COUNT(*) AS cnt FROM dynamic_sessions WHERE tier='dataset'",
            fetch="one",
            dictionary=True,
        )
        if row:
            status["db_dynamic_sessions_dataset_tier"] = int(row.get("cnt") or 0)
            status["db_dynamic_sessions_dataset"] = status["db_dynamic_sessions_dataset_tier"]
    except Exception:
        status["db_dynamic_sessions_dataset_tier"] = 0
        status["db_dynamic_sessions_dataset"] = 0

    try:
        row = core_q.run_sql(
            """
            SELECT COUNT(*) AS cnt
            FROM dynamic_sessions ds
            WHERE ds.tier='dataset'
              AND ds.status='success'
              AND ds.captured_samples / NULLIF(ds.expected_samples,0) >= 0.90
              AND ds.sample_max_gap_s <= (ds.sampling_rate_s * 2)
              AND NOT EXISTS (
                SELECT 1
                FROM dynamic_session_issues i
                WHERE i.dynamic_run_id = ds.dynamic_run_id
                  AND i.issue_code = 'telemetry_partial_samples'
              )
            """,
            fetch="one",
            dictionary=True,
        )
        if row:
            status["tier1_ready_runs"] = int(row.get("cnt") or 0)
    except Exception:
        status["tier1_ready_runs"] = 0

    try:
        row = core_q.run_sql(
            """
            SELECT
              SUM(CASE WHEN pcap_valid = 1 THEN 1 ELSE 0 END) AS valid_count,
              SUM(CASE WHEN pcap_relpath IS NOT NULL THEN 1 ELSE 0 END) AS linked_count
            FROM dynamic_sessions
            WHERE tier='dataset'
            """,
            fetch="one",
            dictionary=True,
        )
        if row:
            status["pcap_valid_runs"] = int(row.get("valid_count") or 0)
            status["pcap_total_runs"] = int(row.get("linked_count") or 0)
    except Exception:
        status["pcap_valid_runs"] = 0
        status["pcap_total_runs"] = 0

    try:
        total = quota_eligible_total = quota_valid_total = 0
        seen_manifests: set[Path] = set()
        for root in dynamic_evidence_roots(include_legacy=True):
            if not root.exists():
                continue
            for mf in root.glob("*/run_manifest.json"):
                resolved_mf = mf.resolve()
                if resolved_mf in seen_manifests:
                    continue
                seen_manifests.add(resolved_mf)
                total += 1
                try:
                    payload = json.loads(mf.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if not isinstance(payload, dict):
                    continue
                ds = payload.get("dataset") if isinstance(payload.get("dataset"), dict) else {}
                tier = ds.get("tier")
                if str(tier or "").lower() != "dataset":
                    continue
                if ds.get("countable") is False:
                    continue
                quota_eligible_total += 1
                if ds.get("valid_dataset_run") is True:
                    quota_valid_total += 1
        status["evidence_packs_total"] = total
        status["evidence_quota_eligible_packs"] = quota_eligible_total
        status["evidence_quota_valid_packs"] = quota_valid_total
        status["evidence_dataset_packs"] = quota_eligible_total
        status["evidence_dataset_valid"] = quota_valid_total
    except Exception:
        status["evidence_packs_total"] = 0
        status["evidence_quota_eligible_packs"] = 0
        status["evidence_quota_valid_packs"] = 0
        status["evidence_dataset_packs"] = 0
        status["evidence_dataset_valid"] = 0

    try:
        export_dir = Path(app_config.OUTPUT_DIR) / "exports" / "scytaledroid_dyn_v1"
        manifest_path = export_dir / "scytaledroid_dyn_v1_manifest.csv"
        if manifest_path.exists():
            status["last_export_path"] = _relative_path(manifest_path)
            status["last_export_at"] = datetime.fromtimestamp(
                manifest_path.stat().st_mtime
            ).strftime("%Y-%m-%d %H:%M")
    except Exception:
        status["last_export_path"] = None
        status["last_export_at"] = None

    try:
        export_analysis_dir = Path(app_config.OUTPUT_DIR) / "exports" / "scytaledroid_dyn_v1" / "analysis"
        fh_path = export_analysis_dir / "feature_health.json"
        if fh_path.exists():
            payload = json.loads(fh_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                status["feature_health_status"] = payload.get("status")
            status["feature_health_at"] = datetime.fromtimestamp(fh_path.stat().st_mtime).strftime(
                "%Y-%m-%d %H:%M"
            )
    except Exception:
        status["feature_health_status"] = None
        status["feature_health_at"] = None

    return status


def _relative_path(path: Path) -> Path:
    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd())
    except ValueError:
        return resolved


__all__ = [
    "fetch_tier1_status",
    "handle_tier1_audit_report",
    "handle_tier1_end_to_end",
    "handle_tier1_export_pack",
    "handle_tier1_quick_fix",
]
