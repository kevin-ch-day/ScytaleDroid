"""Paper-grade inputs dashboard helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Utils.DisplayUtils import colors, menu_utils, prompt_utils


def _ensure_workspace() -> Path:
    base = Path("data")
    subdirs = (
        base / "governance",
        base / "imports",
        base / "exports",
        base / "tmp",
    )
    base.mkdir(parents=True, exist_ok=True)
    for path in subdirs:
        path.mkdir(parents=True, exist_ok=True)
    return base


def _latest_governance_status() -> tuple[str, str | None, str | None, int, str | None]:
    try:
        row = core_q.run_sql(
            """
            SELECT
              s.governance_version,
              s.snapshot_sha256,
              COUNT(r.permission_string) AS row_count,
              s.loaded_at_utc
            FROM permission_governance_snapshots s
            LEFT JOIN permission_governance_snapshot_rows r
              ON r.governance_version = s.governance_version
            GROUP BY s.governance_version, s.snapshot_sha256, s.loaded_at_utc
            ORDER BY s.created_at_utc DESC
            LIMIT 1
            """,
            fetch="one",
        )
        if row:
            version, sha, rows, loaded_at = row
            return "present", str(version), str(sha or ""), int(rows or 0), str(loaded_at or "")
        return "missing", None, None, 0, None
    except Exception:
        return "unknown", None, None, 0, None


def render_dataset_readiness_line() -> None:
    status, _, _, rows, _ = _latest_governance_status()
    status_label = (
        "✅ present" if status == "present" else
        "❌ missing" if status == "missing" else
        "unknown"
    )
    print(f"• Governance snapshot: {status_label}")
    print(f"• Data workspace: {Path('data').resolve()}")


def _render_header(base: Path, palette) -> None:
    print()
    menu_utils.print_header("Governance Inputs & Readiness")
    print(f"Workspace: {colors.apply(str(base.resolve()), palette.text)}")
    print(f"Snapshot drop path: {colors.apply(str((base / 'governance').resolve()), palette.muted)}")
    print("Governance snapshot (v1)")
    print("------------------------")
    print("  Bundle name : erebus_gov_v0_YYYYMMDD_NN/")
    print("  Required    : permission_governance_snapshot.csv (one row per permission)")
    print("  Optional    : snapshot_meta.json, qa_report.json, checksums.sha256, source_query.sql")
    print("  Rule        : exactly one CSV per snapshot; extras are audit-only")
    print()


def _render_checklist() -> None:
    print("Operator checklist")
    print("------------------")
    print("  1) Place bundle under data/governance/")
    print("  2) Verify required CSV exists")
    print("  3) (Optional) Run validate-only to confirm counts")
    print("  4) Run importer to load snapshot")
    print("  5) Confirm status below (Status: present, Rows > 0)")
    print("  6) Run a paper-grade static scan")


def _render_status(palette) -> None:
    print("Current governance status")
    print("-------------------------")
    status, version, sha, rows, loaded_at = _latest_governance_status()
    if status == "present":
        sha_display = sha
        if sha and len(sha) > 12:
            sha_display = f"{sha[:12]}…"
        status_text = colors.apply("✅ present", palette.success)
        print(f"  Status  : {status_text}")
        print(f"  Version : {colors.apply(str(version), palette.text)}")
        print(f"  SHA-256 : {colors.apply(sha_display or '<unknown>', palette.muted)}")
        print(f"  Rows    : {colors.apply(str(rows), palette.text)}")
        if loaded_at:
            print(f"  Last imported : {colors.apply(loaded_at, palette.muted)}")
    elif status == "missing":
        status_text = colors.apply("❌ missing", palette.error)
        print(f"  Status  : {status_text}")
        print(f"  Rows    : {colors.apply('0', palette.muted)}")
        print("  Version : —")
        print("  SHA-256 : —")
        print("  Last imported : —")
    else:
        print("  Status  : unknown (database query failed)")
    print()
    if status == "present":
        print(colors.apply("Paper-grade runs: ENABLED", palette.success))
    elif status == "missing":
        print(colors.apply("Paper-grade runs: BLOCKED (missing governance snapshot)", palette.error))
        print(colors.apply("Next step: import a snapshot CSV into governance tables.", palette.muted))
    else:
        print("Paper-grade runs: UNKNOWN (governance status unavailable)")
    print()


def _scan_governance_folder(base: Path) -> None:
    gov_root = base / "governance"
    print("Governance bundle scan")
    print("----------------------")
    if not gov_root.exists():
        print("  Status : missing folder")
        return
    bundles = [p for p in gov_root.iterdir() if p.is_dir()]
    if not bundles:
        print("  Status : no bundles found")
        return
    for bundle in sorted(bundles):
        csv_path = bundle / "permission_governance_snapshot.csv"
        marker = "✅" if csv_path.exists() else "❌"
        print(f"  {marker} {bundle.name} ({'csv present' if csv_path.exists() else 'missing csv'})")


def _show_latest_bundle(base: Path) -> None:
    gov_root = base / "governance"
    print("Latest bundle status")
    print("--------------------")
    if not gov_root.exists():
        print("  Status : missing folder")
        return
    bundles = [p for p in gov_root.iterdir() if p.is_dir()]
    if not bundles:
        print("  Status : no bundles found")
        return
    latest = max(bundles, key=lambda p: p.stat().st_mtime)
    csv_path = latest / "permission_governance_snapshot.csv"
    print(f"  Bundle : {latest.name}")
    print(f"  CSV    : {'present' if csv_path.exists() else 'missing'}")
    if csv_path.exists():
        print(f"  Size   : {csv_path.stat().st_size} bytes")


def _bundle_health_summary(base: Path) -> None:
    gov_root = base / "governance"
    print("Bundle health summary")
    print("---------------------")
    if not gov_root.exists():
        print("  Bundles : 0 (governance folder missing)")
        return
    bundles = [p for p in gov_root.iterdir() if p.is_dir()]
    total = len(bundles)
    if total == 0:
        print("  Bundles : 0")
        return
    with_csv = sum(1 for b in bundles if (b / "permission_governance_snapshot.csv").exists())
    newest = max(bundles, key=lambda p: p.stat().st_mtime)
    print(f"  Bundles : {total}")
    print(f"  With CSV: {with_csv}")
    print(f"  Newest  : {newest.name}")


def _missing_file_diagnostics(base: Path) -> None:
    gov_root = base / "governance"
    print("Missing-file diagnostics")
    print("------------------------")
    if not gov_root.exists():
        print("  Status : governance folder missing")
        return
    bundles = [p for p in gov_root.iterdir() if p.is_dir()]
    if not bundles:
        print("  Status : no bundles found")
        return
    for bundle in sorted(bundles):
        missing = []
        if not (bundle / "permission_governance_snapshot.csv").exists():
            missing.append("CSV")
        optional = [
            "snapshot_meta.json",
            "qa_report.json",
            "checksums.sha256",
            "source_query.sql",
        ]
        missing_optional = [name for name in optional if not (bundle / name).exists()]
        note = "missing optional: " + ", ".join(missing_optional) if missing_optional else "optional ok"
        if missing:
            print(f"  ❌ {bundle.name}: missing {', '.join(missing)} ({note})")
        else:
            print(f"  ✅ {bundle.name}: CSV present ({note})")


def _verify_checksums(base: Path) -> None:
    gov_root = base / "governance"
    print("Checksum verification")
    print("---------------------")
    if not gov_root.exists():
        print("  Status : governance folder missing")
        return
    bundles = [p for p in gov_root.iterdir() if p.is_dir()]
    if not bundles:
        print("  Status : no bundles found")
        return
    for bundle in sorted(bundles):
        checksum_file = bundle / "checksums.sha256"
        csv_path = bundle / "permission_governance_snapshot.csv"
        if not checksum_file.exists():
            print(f"  ⚠️  {bundle.name}: checksums.sha256 missing")
            continue
        if not csv_path.exists():
            print(f"  ❌ {bundle.name}: CSV missing, cannot verify")
            continue
        expected = None
        for line in checksum_file.read_text(encoding="utf-8").splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[-1].endswith("permission_governance_snapshot.csv"):
                expected = parts[0]
                break
        if not expected:
            print(f"  ⚠️  {bundle.name}: CSV hash not listed in checksums file")
            continue
        h = hashlib.sha256(csv_path.read_bytes()).hexdigest()
        if h == expected:
            print(f"  ✅ {bundle.name}: checksum OK")
        else:
            print(f"  ❌ {bundle.name}: checksum FAIL")


def _show_active_vs_latest(base: Path) -> None:
    gov_root = base / "governance"
    print("Active snapshot vs latest bundle")
    print("-------------------------------")
    status, version, sha, rows, loaded_at = _latest_governance_status()
    if status == "present":
        print(f"  Active : {version} (rows={rows})")
    else:
        print("  Active : none")
    if not gov_root.exists():
        print("  Latest : governance folder missing")
        return
    bundles = [p for p in gov_root.iterdir() if p.is_dir()]
    if not bundles:
        print("  Latest : no bundles found")
        return
    latest = max(bundles, key=lambda p: p.stat().st_mtime)
    print(f"  Latest : {latest.name}")
    if status == "present" and version != latest.name:
        print("  Note   : active snapshot differs from latest bundle")


def _export_status_report(base: Path) -> None:
    export_dir = base / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    status, version, sha, rows, loaded_at = _latest_governance_status()
    report = {
        "status": status,
        "version": version,
        "sha256": sha,
        "rows": rows,
        "last_imported": loaded_at,
    }
    path = export_dir / "governance_status.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True))
    print(f"Status report written: {path}")


def render_paper_grade_inputs() -> None:
    base = _ensure_workspace()
    palette = colors.get_palette()
    while True:
        _render_header(base, palette)
        _render_checklist()
        print()
        _render_status(palette)
        print("Options")
        print("-------")
        print("  1) Scan governance folder (read-only)")
        print("  2) Show latest bundle status")
        print("  3) Refresh database status")
        print("  4) Bundle health summary")
        print("  5) Missing-file diagnostics")
        print("  6) Verify checksums (if present)")
        print("  7) Active vs latest bundle")
        print("  0) Return to Main Menu")
        choice = prompt_utils.get_choice(
            valid=["1", "2", "3", "4", "5", "6", "7", "0"],
            default="0",
        )
        print()
        if choice == "0":
            break
        if choice == "1":
            _scan_governance_folder(base)
            prompt_utils.press_any_key("Press any key to return")
            continue
        if choice == "2":
            _show_latest_bundle(base)
            prompt_utils.press_any_key("Press any key to return")
            continue
        if choice == "3":
            _render_status(palette)
            prompt_utils.press_any_key("Press any key to return")
            continue
        if choice == "4":
            _bundle_health_summary(base)
            prompt_utils.press_any_key("Press any key to return")
            continue
        if choice == "5":
            _missing_file_diagnostics(base)
            prompt_utils.press_any_key("Press any key to return")
            continue
        if choice == "6":
            _verify_checksums(base)
            prompt_utils.press_any_key("Press any key to return")
            continue
        if choice == "7":
            _show_active_vs_latest(base)
            prompt_utils.press_any_key("Press any key to return")
            continue


__all__ = ["render_dataset_readiness_line", "render_paper_grade_inputs"]
