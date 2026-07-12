#!/usr/bin/env python3
"""Dry-run-first cleanup for generated report bundles."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.reporting.audit_output_workspace import _is_legacy_noise_file, _manifest_is_zero_row  # noqa: E402


@dataclass(frozen=True)
class PruneCandidate:
    path: str
    family: str
    reason: str
    file_count: int
    dir_count: int
    size_bytes_lstat: int
    action: str
    status: str


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reports-root",
        type=Path,
        default=REPO_ROOT / "output" / "reports",
        help="Generated reports root. Default: output/reports.",
    )
    parser.add_argument("--family", default=None, help="Optional report family, such as static_exposure_privacy.")
    parser.add_argument(
        "--include-legacy-noise",
        action="store_true",
        help="Also prune older bundles that only contain legacy generated noise files.",
    )
    parser.add_argument(
        "--receipt-dir",
        type=Path,
        default=REPO_ROOT / "output" / "audit" / "report_bundle_prune",
        help="Receipt directory used only with --apply.",
    )
    parser.add_argument("--apply", action="store_true", help="Delete selected generated report bundle directories.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of text summary.")
    return parser


def _rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT.resolve()))
    except ValueError:
        return str(path)


def _tree_counts(path: Path) -> tuple[int, int, int]:
    files = 0
    dirs = 0
    size = 0
    for child in path.rglob("*"):
        try:
            size += child.lstat().st_size
        except OSError:
            pass
        if child.is_dir():
            dirs += 1
        elif child.is_file() or child.is_symlink():
            files += 1
    return files, dirs, size


def _bundle_reason(bundle: Path, *, latest_bundle: Path | None, include_legacy_noise: bool) -> str | None:
    manifest = bundle / "manifest" / "report_manifest.json"
    if not manifest.is_file():
        return "incomplete_missing_report_manifest"
    if _manifest_is_zero_row(manifest):
        return "zero_row_report"
    if include_legacy_noise and latest_bundle is not None and bundle != latest_bundle:
        noise = sum(1 for path in bundle.rglob("*") if path.is_file() and _is_legacy_noise_file(path, bundle))
        if noise > 0:
            return "legacy_generated_noise"
    return None


def collect_candidates(
    *,
    reports_root: Path,
    family: str | None = None,
    include_legacy_noise: bool = False,
) -> list[PruneCandidate]:
    root = reports_root.resolve()
    if not root.exists():
        return []
    families = [root / family] if family else sorted(path for path in root.iterdir() if path.is_dir())
    candidates: list[PruneCandidate] = []
    for family_dir in families:
        if not family_dir.is_dir():
            continue
        bundles = sorted((path for path in family_dir.iterdir() if path.is_dir()), key=lambda p: p.name)
        latest_bundle = bundles[-1] if bundles else None
        for bundle in bundles:
            reason = _bundle_reason(bundle, latest_bundle=latest_bundle, include_legacy_noise=include_legacy_noise)
            if reason is None:
                continue
            files, dirs, size = _tree_counts(bundle)
            candidates.append(
                PruneCandidate(
                    path=_rel(bundle),
                    family=family_dir.name,
                    reason=reason,
                    file_count=files,
                    dir_count=dirs,
                    size_bytes_lstat=size,
                    action="delete_report_bundle_dir",
                    status="planned",
                )
            )
    return candidates


def _candidate_path(candidate: PruneCandidate) -> Path:
    path = Path(candidate.path)
    if path.is_absolute():
        return path
    return REPO_ROOT / path


def _write_receipt(receipt_dir: Path, payload: dict[str, object]) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    receipt_dir.mkdir(parents=True, exist_ok=True)
    path = receipt_dir / f"report_bundle_prune_{stamp}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _payload(args: argparse.Namespace, candidates: list[PruneCandidate]) -> dict[str, object]:
    return {
        "mode": "apply" if args.apply else "dry_run",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "reports_root": _rel(args.reports_root),
        "family": args.family or "",
        "include_legacy_noise": bool(args.include_legacy_noise),
        "candidate_count": len(candidates),
        "candidates": [asdict(candidate) for candidate in candidates],
    }


def _print_text(payload: dict[str, object]) -> None:
    print("Generated report bundle prune")
    print(f"Mode: {payload['mode']}")
    print(f"Candidates: {payload['candidate_count']}")
    for row in payload.get("candidates") or []:
        if not isinstance(row, dict):
            continue
        print(f"- {row.get('path')} [{row.get('reason')}] files={row.get('file_count')} dirs={row.get('dir_count')}")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    candidates = collect_candidates(
        reports_root=args.reports_root,
        family=args.family,
        include_legacy_noise=bool(args.include_legacy_noise),
    )
    payload = _payload(args, candidates)
    if args.apply:
        applied: list[dict[str, object]] = []
        for candidate in candidates:
            target = _candidate_path(candidate)
            row = asdict(candidate)
            try:
                if target.exists() and target.is_dir():
                    shutil.rmtree(target)
                    row["status"] = "deleted"
                else:
                    row["status"] = "missing"
            except OSError as exc:
                row["status"] = "error"
                row["error"] = str(exc)
            applied.append(row)
        payload["candidates"] = applied
        payload["deleted_count"] = sum(1 for row in applied if row.get("status") == "deleted")
        receipt = _write_receipt(args.receipt_dir, payload)
        payload["receipt_path"] = _rel(receipt)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_text(payload)
        if payload.get("receipt_path"):
            print(f"Receipt: {payload['receipt_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
