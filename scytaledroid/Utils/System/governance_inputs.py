"""Governance inputs & readiness dashboard helpers.

This is operator-facing UI for managing governance snapshot inputs and verifying
readiness. It is filesystem-canonical; the DB is a mirror/query layer.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Utils.DisplayUtils import colors, menu_utils, prompt_utils, status_messages


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
    if status == "present":
        status_label = "present"
    elif status == "missing":
        status_label = "missing"
    else:
        status_label = "unknown"
    print(status_messages.status(f"Governance snapshot: {status_label}", level="info"))
    print(status_messages.status(f"Data workspace: {Path('data').resolve()}", level="info"))


def _render_header(base: Path, palette) -> None:
    print()
    menu_utils.print_header("Governance & Readiness")
    menu_utils.print_hint(
        "Manage filesystem-canonical governance bundles and confirm research readiness before persisted static runs."
    )
    menu_utils.print_section("Workspace")
    menu_utils.print_metrics(
        [
            ("Workspace", str(base.resolve())),
            ("Snapshot drop path", str((base / "governance").resolve())),
        ]
    )
    menu_utils.print_section("Governance Snapshot Bundle")
    menu_utils.print_metrics(
        [
            ("Bundle name", "erebus_gov_v0_YYYYMMDD_NN/"),
            ("Required", "permission_governance_snapshot.csv"),
            ("Optional", "snapshot_meta.json, qa_report.json, checksums.sha256, source_query.sql"),
            ("Rule", "exactly one CSV per snapshot; extras are audit-only"),
        ]
    )


def _render_checklist() -> None:
    menu_utils.print_section("Operator Checklist")
    print("  1) Place bundle under data/governance/")
    print("  2) Verify required CSV exists")
    print("  3) (Optional) Run validate-only to confirm counts")
    print("  4) Run importer to load snapshot")
    print("  5) Confirm status below (Status: present, Rows > 0)")
    print("  6) Run a research-grade static scan")


def _render_status(palette) -> None:
    menu_utils.print_section("Current Governance Status")
    status, version, sha, rows, loaded_at = _latest_governance_status()
    if status == "present":
        sha_display = sha
        if sha and len(sha) > 12:
            sha_display = f"{sha[:12]}…"
        status_text = colors.apply("present", palette.success)
        print(f"  Status  : {status_text}")
        print(f"  Version : {colors.apply(str(version), palette.text)}")
        print(f"  SHA-256 : {colors.apply(sha_display or '<unknown>', palette.muted)}")
        print(f"  Rows    : {colors.apply(str(rows), palette.text)}")
        if loaded_at:
            print(f"  Last imported : {colors.apply(loaded_at, palette.muted)}")
    elif status == "missing":
        status_text = colors.apply("missing", palette.warning)
        print(f"  Status  : {status_text}")
        print(f"  Rows    : {colors.apply('0', palette.muted)}")
        print("  Version : —")
        print("  SHA-256 : —")
        print("  Last imported : —")
    else:
        print("  Status  : unknown (database query failed)")
    print()
    if status == "present":
        print(status_messages.status("Research-grade runs: enabled", level="success"))
    elif status == "missing":
        print(status_messages.status("Research-grade runs: blocked (missing governance snapshot)", level="blocked"))
        print(status_messages.status("Next step: import a snapshot CSV into governance tables.", level="info"))
    else:
        print(status_messages.status("Research-grade runs: unknown (governance status unavailable)", level="info"))
    print()


def _scan_governance_folder(base: Path) -> None:
    gov_root = base / "governance"
    menu_utils.print_section("Governance Bundle Scan")
    if not gov_root.exists():
        print("  Status : missing folder")
        return
    bundles = [p for p in gov_root.iterdir() if p.is_dir()]
    if not bundles:
        print("  Status : no bundles found")
        return
    for bundle in sorted(bundles):
        csv_path = bundle / "permission_governance_snapshot.csv"
        status_line = f"{bundle.name} ({'csv present' if csv_path.exists() else 'missing csv'})"
        print(
            status_messages.status(
                status_line,
                level="success" if csv_path.exists() else "warn",
            )
        )


def _show_latest_bundle(base: Path) -> None:
    gov_root = base / "governance"
    menu_utils.print_section("Latest Bundle Status")
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
    menu_utils.print_section("Bundle Health Summary")
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
    menu_utils.print_section("Missing-File Diagnostics")
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
        if missing or missing_optional:
            msg = f"  {bundle.name}: missing={'/'.join(missing) if missing else 'none'}"
            if missing_optional:
                msg += f" optional_missing={','.join(missing_optional[:3])}" + ("…" if len(missing_optional) > 3 else "")
            print(msg)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_checksums(base: Path) -> None:
    gov_root = base / "governance"
    menu_utils.print_section("Bundle Checksum Verification")
    if not gov_root.exists():
        print("  Status : governance folder missing")
        return
    bundles = [p for p in gov_root.iterdir() if p.is_dir()]
    if not bundles:
        print("  Status : no bundles found")
        return
    for bundle in sorted(bundles):
        checksums = bundle / "checksums.sha256"
        if not checksums.exists():
            print(f"  ⚠ {bundle.name}: no checksums.sha256")
            continue
        ok = True
        for line in checksums.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) < 2:
                continue
            expected = parts[0].strip()
            rel = parts[-1].strip().lstrip("*")
            target = bundle / rel
            if not target.exists():
                ok = False
                break
            if _sha256_file(target) != expected:
                ok = False
                break
        print(
            status_messages.status(
                f"{bundle.name}: checksum {'OK' if ok else 'FAIL'}",
                level="success" if ok else "error",
            )
        )


def _show_active_vs_latest(base: Path) -> None:
    gov_root = base / "governance"
    menu_utils.print_section("Active Snapshot vs Latest Bundle")
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
    csv_path = latest / "permission_governance_snapshot.csv"
    print(f"  Latest : {latest.name}")
    print(f"  CSV    : {'present' if csv_path.exists() else 'missing'}")
    if status == "present" and version != latest.name:
        print("  Note   : active snapshot differs from latest bundle")


def render_governance_inputs() -> None:
    base = _ensure_workspace()
    palette = colors.get_palette()
    options = [
        menu_utils.MenuOption("1", "Scan governance folder (read-only)"),
        menu_utils.MenuOption("2", "Show latest bundle status"),
        menu_utils.MenuOption("3", "Refresh database status"),
        menu_utils.MenuOption("4", "Bundle health summary"),
        menu_utils.MenuOption("5", "Missing-file diagnostics"),
        menu_utils.MenuOption("6", "Verify checksums (if present)"),
        menu_utils.MenuOption("7", "Active vs latest bundle"),
    ]
    while True:
        _render_header(base, palette)
        _render_checklist()
        print()
        _render_status(palette)
        menu_utils.print_section("Actions")
        menu_utils.render_menu(
            menu_utils.MenuSpec(
                items=options,
                exit_label="Back",
                show_exit=True,
                show_descriptions=False,
                compact=True,
            )
        )
        choice = prompt_utils.get_choice(
            valid=menu_utils.selectable_keys(options, include_exit=True),
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


__all__ = ["render_dataset_readiness_line", "render_governance_inputs"]
