"""Action handlers triggered by the reporting menu."""

from __future__ import annotations

import csv
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_utils.menus import health_checks
from scytaledroid.DeviceAnalysis.adb import devices as adb_devices
from scytaledroid.DeviceAnalysis import device_manager
from scytaledroid.DeviceAnalysis.report import generate_device_report
from scytaledroid.DynamicAnalysis.exports.dataset_export import export_tier1_pack
from scytaledroid.Reporting.generator import export_static_analysis_markdown
from scytaledroid.StaticAnalysis.persistence import list_reports
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def handle_dataset_readiness_dashboard() -> None:
    """Print a compact dataset readiness dashboard for RESEARCH_DATASET_ALPHA."""

    rows = core_q.run_sql(
        """
        WITH latest_snap AS (
          SELECT snapshot_id
          FROM device_inventory_snapshots
          ORDER BY captured_at DESC
          LIMIT 1
        ),
        repo_latest AS (
          SELECT package_name,
                 MAX(CAST(version_code AS UNSIGNED)) AS repo_version,
                 MAX(harvested_at) AS harvested_at
          FROM android_apk_repository
          GROUP BY package_name
        ),
        static_latest AS (
          SELECT a.package_name, MAX(sar.id) AS static_run_id
          FROM static_analysis_runs sar
          JOIN app_versions av ON av.id = sar.app_version_id
          JOIN apps a ON a.id = av.app_id
          GROUP BY a.package_name
        ),
        dyn_counts AS (
          SELECT package_name,
                 COUNT(*) AS total_runs,
                 SUM(CASE WHEN grade = 'PAPER_GRADE' THEN 1 ELSE 0 END) AS paper_runs,
                 MAX(CASE WHEN pcap_valid = 1 THEN 1 ELSE 0 END) AS pcap_valid
          FROM dynamic_sessions
          GROUP BY package_name
        )
        SELECT
          a.display_name,
          a.package_name,
          CASE WHEN i.package_name IS NULL THEN 'N' ELSE 'Y' END AS installed,
          i.version_code,
          CASE WHEN r.package_name IS NULL THEN 'N' ELSE 'Y' END AS harvested,
          r.repo_version,
          r.harvested_at,
          CASE WHEN s.static_run_id IS NULL THEN 'N' ELSE 'Y' END AS static_ready,
          COALESCE(d.total_runs, 0) AS dyn_runs,
          COALESCE(d.paper_runs, 0) AS paper_runs,
          CASE
            WHEN d.pcap_valid IS NULL THEN 'N/A'
            WHEN d.pcap_valid = 1 THEN 'Y'
            ELSE 'N'
          END AS pcap_valid
        FROM apps a
        LEFT JOIN latest_snap ls ON 1=1
        LEFT JOIN device_inventory i
          ON LOWER(a.package_name) COLLATE utf8mb4_general_ci =
             LOWER(i.package_name) COLLATE utf8mb4_general_ci
         AND i.snapshot_id = ls.snapshot_id
        LEFT JOIN repo_latest r
          ON LOWER(r.package_name) COLLATE utf8mb4_general_ci =
             LOWER(a.package_name) COLLATE utf8mb4_general_ci
        LEFT JOIN static_latest s
          ON LOWER(s.package_name) COLLATE utf8mb4_general_ci =
             LOWER(a.package_name) COLLATE utf8mb4_general_ci
        LEFT JOIN dyn_counts d
          ON LOWER(d.package_name) COLLATE utf8mb4_general_ci =
             LOWER(a.package_name) COLLATE utf8mb4_general_ci
        WHERE a.profile_key = 'RESEARCH_DATASET_ALPHA'
        ORDER BY a.display_name
        """,
        fetch="all",
    ) or []

    print()
    menu_utils.print_header("Dataset readiness dashboard")
    headers = [
        "App",
        "Package",
        "Installed",
        "Inst Ver",
        "Harvested",
        "Repo Ver",
        "Static",
        "Dyn Runs",
        "Paper",
        "PCAP",
        "Status",
    ]
    table_rows: list[list[str]] = []
    for row in rows:
        (
            display_name,
            package_name,
            installed,
            inst_ver,
            harvested,
            repo_ver,
            harvested_at,
            static_ready,
            dyn_runs,
            paper_runs,
            pcap_valid,
        ) = row
        status = "DATASET_READY"
        if installed == "N":
            status = "BLOCKED_NOT_INSTALLED"
        elif harvested == "N":
            status = "NEEDS_HARVEST"
        elif static_ready == "N":
            status = "NEEDS_STATIC"
        elif int(paper_runs or 0) == 0:
            status = "NEEDS_DYNAMIC"
        table_rows.append(
            [
                str(display_name or "—"),
                str(package_name or "—"),
                str(installed),
                str(inst_ver or "—"),
                str(harvested),
                str(repo_ver or "—"),
                str(static_ready),
                str(dyn_runs),
                str(paper_runs),
                str(pcap_valid),
                status,
            ]
        )
    table_utils.render_table(headers, table_rows)
    print()
    prompt_utils.press_enter_to_continue()


def handle_device_report() -> None:
    """Generate a device report for the active or selected device."""

    active_serial = device_manager.get_active_serial()
    if active_serial:
        label = device_manager.describe_active_device()
        if prompt_utils.prompt_yes_no(
            f"Generate report for active device {label}?",
            default=True,
        ):
            generate_device_report(active_serial)
            return

    serial = _select_device_serial()
    if serial:
        log.info(f"Generating device report for {serial}", category="reporting")
        generate_device_report(serial)


def handle_static_report() -> None:
    """Export a stored static analysis run to markdown."""

    stored = list_reports()
    if not stored:
        print(status_messages.status("No static analysis reports found.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_header("Static analysis reports", "Select a report to export")

    rows: list[list[str]] = []
    for index, entry in enumerate(stored, start=1):
        manifest = entry.report.manifest
        package = (
            manifest.package_name
            or entry.report.metadata.get("package_name")
            or "Unknown"
        )
        version = (
            manifest.version_name
            or entry.report.metadata.get("version_name")
            or manifest.version_code
            or entry.report.metadata.get("version_code")
            or "Unknown"
        )
        generated = format_timestamp(entry.report.generated_at)
        severity = summarise_severity(entry.report.findings)
        rows.append([str(index), package, version, generated, severity])

    table_utils.render_table(["#", "Package", "Version", "Captured", "Findings"], rows)

    print()
    choice = prompt_utils.get_choice(
        [str(index) for index in range(1, len(stored) + 1)] + ["0"],
        prompt="Select report #: ",
        default="0",
    )
    if choice == "0":
        return

    selected = stored[int(choice) - 1]
    try:
        output_path = export_static_analysis_markdown(
            selected.report,
            source_path=selected.path,
        )
    except OSError as exc:  # pragma: no cover - filesystem errors
        print(status_messages.status(f"Failed to write report: {exc}", level="fail"))
        prompt_utils.press_enter_to_continue()
        return

    resolved = relative_path(output_path)
    print(status_messages.status(f"Markdown report saved to {resolved}", level="success"))
    log.info(f"Static analysis markdown exported to {output_path}", category="reporting")
    prompt_utils.press_enter_to_continue()


def view_saved_reports() -> None:
    """Browse and preview generated markdown reports."""

    base_dir = Path(app_config.OUTPUT_DIR) / "reports"
    if not base_dir.exists():
        print(status_messages.status("No reports have been generated yet.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    files = sorted(base_dir.rglob("*.md"), key=lambda path: path.stat().st_mtime, reverse=True)
    if not files:
        print(status_messages.status("No markdown reports found in the output directory.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    visible = files[:20]
    print()
    menu_utils.print_header("Saved reports", f"Showing {len(visible)} of {len(files)}")

    rows: list[list[str]] = []
    for index, path in enumerate(visible, start=1):
        report_type = classify_report(path, base_dir)
        modified = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        rows.append([str(index), report_type, path.name, modified])

    table_utils.render_table(["#", "Type", "File", "Modified"], rows)
    if len(files) > len(visible):
        remaining = len(files) - len(visible)
        print(status_messages.status(f"+ {remaining} more report(s) available.", level="info"))

    print()
    choice = prompt_utils.get_choice(
        [str(index) for index in range(1, len(visible) + 1)] + ["0"],
        prompt="Preview report #: ",
        default="0",
    )
    if choice == "0":
        return

    selected = visible[int(choice) - 1]
    preview_report_file(selected)


def summarise_severity(findings: Iterable[object]) -> str:
    """Summarise static-analysis findings by severity level."""

    from scytaledroid.StaticAnalysis.core import Finding, SeverityLevel

    counts = {level: 0 for level in (SeverityLevel.P0, SeverityLevel.P1, SeverityLevel.P2)}
    total_notes = 0
    for entry in findings:
        if isinstance(entry, Finding):
            if entry.severity_gate in counts:
                counts[entry.severity_gate] += 1
            else:
                total_notes += 1

    parts = [f"{level.value}:{count}" for level, count in counts.items() if count]
    if total_notes:
        parts.append(f"NOTE:{total_notes}")
    return ", ".join(parts) if parts else "None"


def classify_report(path: Path, base_dir: Path) -> str:
    """Classify a report based on its location and name."""

    try:
        relative = path.relative_to(base_dir)
    except ValueError:  # pragma: no cover - defensive
        return "Report"

    parts = list(relative.parts)
    if parts and parts[0] == "static_analysis":
        return "Static analysis"
    if path.name.startswith("device_report_"):
        return "Device"
    return "Report"


def preview_report_file(path: Path) -> None:
    """Display a short preview of a markdown report."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:  # pragma: no cover - filesystem errors
        print(status_messages.status(f"Unable to read {path.name}: {exc}", level="fail"))
        prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_header("Report preview", path.name)
    preview_limit = 40
    for line in lines[:preview_limit]:
        print(line)
    if len(lines) > preview_limit:
        print(f"... (+{len(lines) - preview_limit} more lines)")

    print()
    resolved = relative_path(path)
    print(status_messages.status(f"Full report available at {resolved}", level="info"))
    prompt_utils.press_enter_to_continue()


def handle_tier1_export_pack() -> None:
    """Export the Tier-1 dataset pack (manifest + telemetry + summary)."""

    from scytaledroid.Database.db_utils import schema_gate

    ok, message, detail = schema_gate.dynamic_schema_gate()
    if not ok:
        status_messages.print_status(f"[ERROR] {message}", level="error")
        if detail:
            status_messages.print_status(detail, level="error")
        status_messages.print_status(
            "Fix: Database Tools → Apply Tier-1 schema migrations (or import canonical DB export), then retry.",
            level="error",
        )
        return

    default_dir = Path(app_config.OUTPUT_DIR) / "exports" / "scytaledroid_dyn_v1"
    print(status_messages.status(f"Export directory: {default_dir}", level="info"))
    if not prompt_utils.prompt_yes_no("Generate Tier-1 export pack now?", default=True):
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
    """Run Tier-1 dataset readiness audit."""

    health_checks.run_tier1_audit_report()


def handle_tier1_qa_failures_report() -> None:
    """Show the most recent Tier-1 QA failures with reasons."""

    print()
    menu_utils.print_header("Tier-1 QA Failures (last 10 runs)")
    rows = _fetch_recent_tier1_candidates(limit=10)
    if not rows:
        print(status_messages.status("No dynamic runs found.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    table_rows = []
    for row in rows:
        failures = _evaluate_tier1_qa_failures(row)
        table_rows.append(
            [
                row.get("dynamic_run_id") or "",
                row.get("package_name") or "",
                row.get("tier") or "",
                row.get("status") or "",
                _fmt_ratio(row.get("captured_samples"), row.get("expected_samples")),
                _fmt_gap(row.get("sample_max_gap_s")),
                "yes" if row.get("telemetry_partial") else "no",
                ", ".join(failures) if failures else "ok",
            ]
        )

    table_utils.render_table(
        [
            "run_id",
            "package",
            "tier",
            "status",
            "capture_ratio",
            "max_gap_s",
            "partial_samples",
            "failed_checks",
        ],
        table_rows,
        compact=True,
    )
    print()
    prompt_utils.press_enter_to_continue()


def fetch_tier1_status() -> dict[str, object]:
    """Return a compact Tier-1 readiness snapshot for the reporting menu."""

    status: dict[str, object] = {
        "schema_version": None,
        "expected_schema": "0.2.6",
        "tier1_ready_runs": 0,
        "last_export_path": None,
        "last_export_at": None,
        "pcap_valid_runs": 0,
        "pcap_total_runs": 0,
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
        export_dir = Path(app_config.OUTPUT_DIR) / "exports" / "scytaledroid_dyn_v1"
        manifest_path = export_dir / "scytaledroid_dyn_v1_manifest.csv"
        if manifest_path.exists():
            status["last_export_path"] = relative_path(manifest_path)
            status["last_export_at"] = datetime.fromtimestamp(
                manifest_path.stat().st_mtime
            ).strftime("%Y-%m-%d %H:%M")
    except Exception:
        status["last_export_path"] = None
        status["last_export_at"] = None

    return status


def _fetch_recent_tier1_candidates(limit: int = 10) -> list[dict[str, object]]:
    sql = """
        SELECT
          ds.dynamic_run_id,
          ds.package_name,
          ds.tier,
          ds.status,
          ds.sampling_rate_s,
          ds.expected_samples,
          ds.captured_samples,
          ds.sample_max_gap_s,
          MAX(CASE WHEN i.issue_code = 'telemetry_partial_samples' THEN 1 ELSE 0 END) AS telemetry_partial
        FROM dynamic_sessions ds
        LEFT JOIN dynamic_session_issues i
          ON i.dynamic_run_id = ds.dynamic_run_id
        GROUP BY ds.dynamic_run_id, ds.package_name, ds.tier, ds.status,
                 ds.sampling_rate_s, ds.expected_samples, ds.captured_samples, ds.sample_max_gap_s
        ORDER BY ds.started_at_utc DESC
        LIMIT %s
    """
    rows = core_q.run_sql(sql, (limit,), fetch="all", dictionary=True) or []
    return [dict(row) for row in rows]


def _evaluate_tier1_qa_failures(row: dict[str, object]) -> list[str]:
    failures: list[str] = []
    tier = row.get("tier")
    status = row.get("status")
    sampling_rate = row.get("sampling_rate_s")
    expected = row.get("expected_samples")
    captured = row.get("captured_samples")
    max_gap = row.get("sample_max_gap_s")
    partial = row.get("telemetry_partial")

    if tier != "dataset":
        failures.append("tier_not_dataset")
    if status != "success":
        failures.append("status_not_success")
    ratio = _safe_ratio(captured, expected)
    if ratio is None:
        failures.append("missing_capture_ratio")
    elif ratio < 0.90:
        failures.append("low_capture_ratio")
    if sampling_rate is None or max_gap is None:
        failures.append("missing_gap_stats")
    else:
        try:
            if float(max_gap) > (float(sampling_rate) * 2):
                failures.append("max_gap_exceeded")
        except (TypeError, ValueError):
            failures.append("invalid_gap_stats")
    if partial:
        failures.append("telemetry_partial_samples")
    return failures


def _safe_ratio(captured: object, expected: object) -> float | None:
    try:
        cap = float(captured)
        exp = float(expected)
    except (TypeError, ValueError):
        return None
    if exp == 0:
        return None
    return cap / exp


def _fmt_ratio(captured: object, expected: object) -> str:
    ratio = _safe_ratio(captured, expected)
    if ratio is None:
        return "n/a"
    return f"{ratio:.3f}"


def _fmt_gap(value: object) -> str:
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return "n/a"




def relative_path(path: Path) -> Path:
    """Return the path relative to the current working directory if possible."""

    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd())
    except ValueError:
        return resolved


def format_timestamp(value: str) -> str:
    """Normalise ISO timestamps for display."""

    try:
        normalised = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalised)
    except Exception:  # pragma: no cover - fallback path
        return value
    return parsed.strftime("%Y-%m-%d %H:%M UTC")


def _select_device_serial() -> str | None:
    devices, warnings = adb_devices.scan_devices()
    for message in warnings:
        print(status_messages.status(message, level="warn"))

    if not devices:
        print(status_messages.status("No Android devices detected.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return None

    print()
    menu_utils.print_header("Device selection", "Choose a connected device")
    rows: list[list[str]] = []
    for index, device in enumerate(devices, start=1):
        serial = device.get("serial") or "?"
        model = device.get("model") or device.get("device") or "Unknown"
        state = device.get("state") or "unknown"
        rows.append([str(index), serial, model, state.upper()])
    table_utils.render_table(["#", "Serial", "Model", "State"], rows)

    print()
    choice = prompt_utils.get_choice(
        [str(index) for index in range(1, len(devices) + 1)] + ["0"],
        prompt="Select device #: ",
        default="0",
    )
    if choice == "0":
        return None

    return devices[int(choice) - 1].get("serial")


def handle_recent_static_runs() -> None:
    """List recent static-analysis runs with metadata for quick review."""

    try:
        rows = core_q.run_sql(
            (
                "SELECT id, COALESCE(run_started_utc, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s')) AS started_utc, "
                "scope_label, findings_total, pipeline_version, catalog_versions, config_hash, study_tag "
                "FROM static_analysis_runs "
                "ORDER BY created_at DESC LIMIT 20"
            ),
            fetch="all",
        )
    except Exception as exc:  # pragma: no cover - DB connectivity guard
        print(status_messages.status(f"Unable to query static analysis runs: {exc}", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    if not rows:
        print(status_messages.status("No static-analysis runs found in the database.", level="info"))
        prompt_utils.press_enter_to_continue()
        return

    headers = ["ID", "Started (UTC)", "Scope", "Findings", "Pipeline", "Catalogs", "Config", "Study"]
    table_rows: list[list[str]] = []
    for row in rows:
        (
            run_id,
            started,
            scope_label,
            findings_total,
            pipeline_version,
            catalog_versions,
            config_hash,
            study_tag,
        ) = row
        table_rows.append(
            [
                str(run_id),
                str(started or "—"),
                str(scope_label or "—"),
                str(findings_total or 0),
                str(pipeline_version or "—"),
                str(catalog_versions or "—"),
                str(config_hash or "—"),
                str(study_tag or "—"),
            ]
        )

    print()
    menu_utils.print_header("Recent static analysis runs", subtitle=f"Showing {len(table_rows)} most recent")
    table_utils.render_table(headers, table_rows)
    prompt_utils.press_enter_to_continue()


__all__ = [
    "classify_report",
    "format_timestamp",
    "handle_device_report",
    "handle_static_report",
    "handle_recent_static_runs",
    "preview_report_file",
    "relative_path",
    "summarise_severity",
    "view_saved_reports",
]
