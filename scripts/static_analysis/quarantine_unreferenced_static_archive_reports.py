#!/usr/bin/env python3
"""Stage or quarantine unreferenced static archive JSON reports."""

from __future__ import annotations

import argparse
import json
import shutil
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", required=True, help="Static session stamp.")
    parser.add_argument(
        "--artifact-map",
        default=None,
        help="Artifact-map JSON report. Defaults to output/audit/run_artifacts/<session>-postrun.json.",
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root. Defaults to the current working directory.",
    )
    parser.add_argument(
        "--quarantine-root",
        default="output/quarantine/static_archive_unreferenced",
        help="Quarantine root, relative to repo root unless absolute.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Move candidate archive/latest JSON files into quarantine. Omit for dry-run.",
    )
    return parser


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )


def _rel(repo_root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def _candidate_archive_paths(
    *,
    repo_root: Path,
    artifact_map_path: Path,
) -> list[Path]:
    report = _read_json(artifact_map_path)
    if not report:
        return []
    alignment = (
        report.get("evidence_vs_log_stream", {})
        .get("evidence_path_alignment", {})
    )
    paths = alignment.get("archive_paths_on_disk_not_in_log_events")
    if not isinstance(paths, list):
        return []
    candidates: list[Path] = []
    for raw in paths:
        if not isinstance(raw, str) or not raw.strip():
            continue
        path = Path(raw.strip())
        if not path.is_absolute():
            path = repo_root / path
        if path.suffix.lower() == ".json":
            candidates.append(path)
    return candidates


def _latest_peer(repo_root: Path, archive_path: Path) -> Path:
    return repo_root / "data/static_analysis/reports/latest" / archive_path.name


def _move_file(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))


def quarantine_session(
    *,
    repo_root: Path,
    session: str,
    artifact_map_path: Path,
    quarantine_root: Path,
    apply: bool,
) -> dict[str, Any]:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    destination_root = quarantine_root / session / timestamp
    archive_candidates = _candidate_archive_paths(
        repo_root=repo_root,
        artifact_map_path=artifact_map_path,
    )
    rows: list[dict[str, Any]] = []
    files_to_move: list[tuple[Path, Path]] = []
    for archive_path in archive_candidates:
        row: dict[str, Any] = {
            "archive_path": _rel(repo_root, archive_path),
            "archive_exists": archive_path.exists(),
        }
        latest_path = _latest_peer(repo_root, archive_path)
        row["latest_path"] = _rel(repo_root, latest_path)
        row["latest_exists"] = latest_path.exists()
        payload = _read_json(archive_path) if archive_path.exists() else None
        if payload:
            metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
            manifest = payload.get("manifest") if isinstance(payload.get("manifest"), dict) else {}
            row["package_name"] = manifest.get("package_name") or metadata.get("package_name")
            row["generated_at"] = payload.get("generated_at") or metadata.get("generated_at")
            row["session_stamp"] = metadata.get("session_stamp")
            row["execution_id"] = metadata.get("execution_id")
        if archive_path.exists():
            files_to_move.append(
                (
                    archive_path,
                    destination_root / "archive" / archive_path.name,
                )
            )
        if latest_path.exists():
            files_to_move.append(
                (
                    latest_path,
                    destination_root / "latest" / latest_path.name,
                )
            )
        rows.append(row)

    receipt = {
        "mode": "apply" if apply else "dry_run",
        "session": session,
        "artifact_map": _rel(repo_root, artifact_map_path),
        "quarantine_root": _rel(repo_root, destination_root),
        "candidate_archive_count": len(archive_candidates),
        "files_to_move_count": len(files_to_move),
        "candidates": rows,
    }
    if apply:
        for src, dst in files_to_move:
            if src.exists():
                _move_file(src, dst)
        receipt["receipt_path"] = _rel(repo_root, destination_root / "receipt.json")
        _write_json(destination_root / "receipt.json", receipt)
    return receipt


def main() -> int:
    args = _build_parser().parse_args()
    repo_root = Path(args.repo_root).resolve()
    artifact_map_path = (
        Path(args.artifact_map)
        if args.artifact_map
        else repo_root / "output/audit/run_artifacts" / f"{args.session}-postrun.json"
    )
    if not artifact_map_path.is_absolute():
        artifact_map_path = repo_root / artifact_map_path
    quarantine_root = Path(args.quarantine_root)
    if not quarantine_root.is_absolute():
        quarantine_root = repo_root / quarantine_root
    receipt = quarantine_session(
        repo_root=repo_root,
        session=args.session,
        artifact_map_path=artifact_map_path,
        quarantine_root=quarantine_root,
        apply=bool(args.apply),
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
