#!/usr/bin/env python3
"""Read-only cleanup classifier for the ScytaleDroid output workspace."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@dataclass(frozen=True)
class WorkspaceEntry:
    path: str
    exists: bool
    kind: str
    cleanup_class: str
    recommendation: str
    reason: str
    size_bytes: int
    file_count: int
    dir_count: int
    symlink_count: int
    broken_symlink_count: int


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=REPO_ROOT / "output",
        help="Output workspace root to inspect. Default: output.",
    )
    parser.add_argument("--json", action="store_true", help="Print full JSON instead of the text summary.")
    return parser


def _rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT.resolve()))
    except ValueError:
        return str(path)


def _scan_tree(path: Path) -> tuple[int, int, int, int, int]:
    size_bytes = 0
    file_count = 0
    dir_count = 0
    symlink_count = 0
    broken_symlink_count = 0
    if not path.exists() and not path.is_symlink():
        return 0, 0, 0, 0, 0
    if path.is_file() or path.is_symlink():
        try:
            size_bytes += path.lstat().st_size
        except OSError:
            pass
        file_count += int(path.is_file())
        symlink_count += int(path.is_symlink())
        if path.is_symlink() and not path.exists():
            broken_symlink_count += 1
        return size_bytes, file_count, dir_count, symlink_count, broken_symlink_count

    for root, dirs, files in os.walk(path, followlinks=False):
        root_path = Path(root)
        dir_count += len(dirs)
        for name in dirs:
            child = root_path / name
            if child.is_symlink():
                symlink_count += 1
                if not child.exists():
                    broken_symlink_count += 1
                try:
                    size_bytes += child.lstat().st_size
                except OSError:
                    pass
        for name in files:
            child = root_path / name
            file_count += 1
            if child.is_symlink():
                symlink_count += 1
                if not child.exists():
                    broken_symlink_count += 1
            try:
                size_bytes += child.lstat().st_size
            except OSError:
                pass
    return size_bytes, file_count, dir_count, symlink_count, broken_symlink_count


def _classify_output_child(path: Path) -> tuple[str, str, str, str]:
    name = path.name
    if name == "reports":
        return (
            "generated_report_bundles",
            "safe_to_prune_after_review",
            "Report bundles are derived outputs; keep the latest paper/report runs you still need.",
            "Generated report output, not canonical evidence storage.",
        )
    if name == "paper":
        return (
            "legacy_publication_workspace",
            "review_before_delete",
            "Do not delete until final cutoff/workspace files are copied into the active paper or publication workspace.",
            "Legacy paper-writing outputs still contain cutoff and draft artifacts.",
        )
    if name == "evidence":
        return (
            "compatibility_evidence_links",
            "keep_or_recreate_only",
            "Keep unless all legacy dynamic path consumers have been migrated; contents should be symlinks, not primary evidence.",
            "Dynamic evidence bytes belong under data/evidence/dynamic.",
        )
    if name == "audit":
        return (
            "audit_receipts",
            "age_gate_and_review",
            "Prune only with a staged audit/receipt policy; these explain previous repairs and cleanup decisions.",
            "Audit outputs are derived but often needed for provenance.",
        )
    if name in {"tmp", "cache"}:
        return (
            "temporary_output",
            "safe_to_clean",
            "Safe cleanup candidate when no active process is using it.",
            "Temporary derived workspace.",
        )
    if name == "quarantine":
        return (
            "quarantine_workspace",
            "review_before_delete",
            "Review contents before deletion; quarantine may hold evidence about rejected or unsafe artifacts.",
            "Quarantine output is intentionally separated for review.",
        )
    if name == "tables":
        return (
            "legacy_generated_tables",
            "review_before_delete",
            "Likely superseded by output/reports table exports, but review before deleting.",
            "Older generated table location.",
        )
    return (
        "unclassified_output",
        "review_before_delete",
        "Unknown output child; inspect before deleting.",
        "No built-in cleanup policy for this directory.",
    )


def inspect_output_workspace(output_root: Path) -> dict[str, Any]:
    output_root = output_root.resolve()
    entries: list[WorkspaceEntry] = []
    if not output_root.exists():
        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "output_root": str(output_root),
            "exists": False,
            "entries": [],
            "summary": {},
        }

    for child in sorted(output_root.iterdir(), key=lambda p: p.name):
        cleanup_class, recommendation, rec_text, reason = _classify_output_child(child)
        size, files, dirs, symlinks, broken = _scan_tree(child)
        if child.name in {"quarantine", "tmp"} and size == 0 and files == 0 and dirs == 0 and symlinks == 0:
            cleanup_class = "empty_output_placeholder"
            recommendation = "safe_to_remove_empty_dir"
            rec_text = "Directory is empty; supported workflows recreate subdirectories when needed."
            reason = "No files, subdirectories, or symlinks are present."
        if child.is_symlink():
            kind = "symlink_dir" if child.is_dir() else "symlink_file"
        elif child.is_dir():
            kind = "directory"
        elif child.is_file():
            kind = "file"
        else:
            kind = "other"
        entries.append(
            WorkspaceEntry(
                path=_rel(child),
                exists=child.exists() or child.is_symlink(),
                kind=kind,
                cleanup_class=cleanup_class,
                recommendation=recommendation,
                reason=f"{reason} {rec_text}",
                size_bytes=size,
                file_count=files,
                dir_count=dirs,
                symlink_count=symlinks,
                broken_symlink_count=broken,
            )
        )

    by_recommendation: dict[str, int] = {}
    broken_symlinks = 0
    total_bytes = 0
    for entry in entries:
        by_recommendation[entry.recommendation] = by_recommendation.get(entry.recommendation, 0) + 1
        broken_symlinks += entry.broken_symlink_count
        total_bytes += entry.size_bytes
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "output_root": _rel(output_root),
        "exists": True,
        "summary": {
            "entry_count": len(entries),
            "total_size_bytes_lstat": total_bytes,
            "broken_symlink_count": broken_symlinks,
            "recommendations": by_recommendation,
        },
        "entries": [asdict(entry) for entry in entries],
        "report_families": _inspect_report_families(output_root / "reports"),
        "audit_families": _inspect_audit_families(output_root / "audit"),
    }


def _inspect_audit_families(audit_root: Path) -> list[dict[str, Any]]:
    if not audit_root.exists():
        return []
    families: list[dict[str, Any]] = []
    for child in sorted((path for path in audit_root.iterdir() if path.is_dir()), key=lambda p: p.name):
        size, files, dirs, symlinks, broken = _scan_tree(child)
        latest_mtime = 0.0
        for path in child.rglob("*"):
            try:
                latest_mtime = max(latest_mtime, path.stat().st_mtime)
            except OSError:
                continue
        if latest_mtime == 0.0:
            try:
                latest_mtime = child.stat().st_mtime
            except OSError:
                latest_mtime = 0.0
        families.append(
            {
                "path": _rel(child),
                "family": child.name,
                "size_bytes_lstat": size,
                "file_count": files,
                "dir_count": dirs,
                "symlink_count": symlinks,
                "broken_symlink_count": broken,
                "latest_modified_utc": datetime.fromtimestamp(latest_mtime, UTC).isoformat() if latest_mtime else "",
                "recommendation": "review_large_audit_family" if size >= 1024 * 1024 else "retain_or_age_gate",
            }
        )
    families.sort(key=lambda row: int(row["size_bytes_lstat"]), reverse=True)
    return families


def _is_legacy_noise_file(path: Path, bundle_root: Path) -> bool:
    rel = path.relative_to(bundle_root)
    if "latex" in rel.parts:
        return True
    name = path.name
    if name.endswith("_caption.txt"):
        return True
    if path.suffix in {".pdf", ".svg", ".aux", ".fls", ".fdb_latexmk"}:
        return True
    if name.startswith("layout_fit_") or name.startswith("ieee_artifact_fit_smoke"):
        return True
    return False


def _inspect_report_families(reports_root: Path) -> list[dict[str, Any]]:
    if not reports_root.exists():
        return []
    families: list[dict[str, Any]] = []
    for family_dir in sorted((path for path in reports_root.iterdir() if path.is_dir()), key=lambda p: p.name):
        bundles = sorted((path for path in family_dir.iterdir() if path.is_dir()), key=lambda p: p.stat().st_mtime)
        noisy_files = 0
        bundles_with_noise = 0
        incomplete_bundles = 0
        zero_row_bundles = 0
        noisy_bundle_paths: list[str] = []
        incomplete_bundle_paths: list[str] = []
        zero_row_bundle_paths: list[str] = []
        latest_bundle = bundles[-1] if bundles else None
        latest_noise = 0
        latest_complete = False
        latest_zero_row = False
        for bundle in bundles:
            bundle_noise = sum(1 for path in bundle.rglob("*") if path.is_file() and _is_legacy_noise_file(path, bundle))
            noisy_files += bundle_noise
            if bundle_noise > 0:
                bundles_with_noise += 1
                noisy_bundle_paths.append(_rel(bundle))
            manifest_path = bundle / "manifest" / "report_manifest.json"
            is_complete = manifest_path.is_file()
            is_zero_row = False
            if is_complete:
                is_zero_row = _manifest_is_zero_row(manifest_path)
                if is_zero_row:
                    zero_row_bundles += 1
                    zero_row_bundle_paths.append(_rel(bundle))
            if not is_complete:
                incomplete_bundles += 1
                incomplete_bundle_paths.append(_rel(bundle))
            if latest_bundle is not None and bundle == latest_bundle:
                latest_noise = bundle_noise
                latest_complete = is_complete
                latest_zero_row = is_zero_row
        families.append(
            {
                "family": family_dir.name,
                "path": _rel(family_dir),
                "bundle_count": len(bundles),
                "latest_bundle": _rel(latest_bundle) if latest_bundle else "",
                "incomplete_bundle_count": incomplete_bundles,
                "incomplete_bundle_paths": incomplete_bundle_paths,
                "zero_row_bundle_count": zero_row_bundles,
                "zero_row_bundle_paths": zero_row_bundle_paths,
                "latest_bundle_complete": latest_complete,
                "latest_bundle_zero_row": latest_zero_row,
                "legacy_noise_file_count": noisy_files,
                "bundles_with_legacy_noise": bundles_with_noise,
                "bundles_with_legacy_noise_paths": noisy_bundle_paths,
                "latest_bundle_legacy_noise_file_count": latest_noise,
                "recommendation": (
                    "latest_bundle_incomplete_review_before_pruning"
                    if latest_bundle is not None and not latest_complete
                    else
                    "latest_bundle_zero_row_review_before_pruning"
                    if latest_zero_row
                    else
                    "regenerate_latest_with_current_defaults_before_pruning"
                    if latest_noise
                    else "latest_bundle_matches_cleaner_defaults_or_has_no_detected_legacy_noise"
                ),
            }
        )
    return families


def _format_bytes(value: int) -> str:
    units = ("B", "K", "M", "G", "T")
    amount = float(value)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.1f}{unit}" if unit != "B" else f"{int(amount)}B"
        amount /= 1024
    return f"{value}B"


def _print_text(payload: dict[str, Any]) -> None:
    print("Output workspace audit")
    print(f"Root: {payload.get('output_root')}")
    print(f"Exists: {'yes' if payload.get('exists') else 'no'}")
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    print(f"Entries: {summary.get('entry_count', 0)}")
    print(f"Broken symlinks: {summary.get('broken_symlink_count', 0)}")
    print()
    print("Path | Size | Class | Recommendation | Broken links")
    print("-----|------|-------|----------------|-------------")
    for entry in payload.get("entries") or []:
        print(
            f"{entry['path']} | {_format_bytes(int(entry['size_bytes']))} | "
            f"{entry['cleanup_class']} | {entry['recommendation']} | "
            f"{entry['broken_symlink_count']}"
        )
    families = list(payload.get("report_families") or [])
    if families:
        print()
        print("Report family details")
        print("Family | Bundles | Incomplete | Zero-row | Legacy-noise files | Latest bundle noise | Recommendation")
        print("-------|---------|------------|----------|--------------------|---------------------|---------------")
        for family in families:
            print(
                f"{family['family']} | {family['bundle_count']} | "
                f"{family['incomplete_bundle_count']} | "
                f"{family['zero_row_bundle_count']} | "
                f"{family['legacy_noise_file_count']} | "
                f"{family['latest_bundle_legacy_noise_file_count']} | "
                f"{family['recommendation']}"
            )
            for path in family.get("incomplete_bundle_paths") or []:
                print(f"  incomplete: {path}")
            for path in family.get("zero_row_bundle_paths") or []:
                print(f"  zero-row: {path}")
            for path in family.get("bundles_with_legacy_noise_paths") or []:
                print(f"  legacy-noise: {path}")
    audit_families = list(payload.get("audit_families") or [])
    if audit_families:
        print()
        print("Largest audit families")
        print("Family | Size | Files | Dirs | Latest modified | Recommendation")
        print("-------|------|-------|------|-----------------|---------------")
        for family in audit_families[:15]:
            print(
                f"{family['family']} | {_format_bytes(int(family['size_bytes_lstat']))} | "
                f"{family['file_count']} | {family['dir_count']} | "
                f"{family['latest_modified_utc']} | {family['recommendation']}"
            )


def _manifest_is_zero_row(path: Path) -> bool:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    row_counts = payload.get("row_counts") if isinstance(payload, dict) else None
    if not isinstance(row_counts, dict):
        return False
    selected = row_counts.get("selected_static_runs")
    applications = row_counts.get("applications")
    builds = row_counts.get("application_builds")
    if selected is not None:
        try:
            return int(selected or 0) == 0
        except (TypeError, ValueError):
            return False
    try:
        return int(applications or 0) == 0 and int(builds or 0) == 0
    except (TypeError, ValueError):
        return False


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    payload = inspect_output_workspace(args.output_root)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_text(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
