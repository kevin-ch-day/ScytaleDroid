#!/usr/bin/env python3
"""Repair static report JSON execution context from report.saved log events."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", required=True, help="Static session stamp to repair.")
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root. Defaults to the current working directory.",
    )
    parser.add_argument(
        "--jsonl",
        default="logs/static_analysis.jsonl",
        help="Static JSONL log path, relative to repo root unless absolute.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write repaired report JSON files. Omit for dry-run.",
    )
    return parser


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )


def _resolve_path(repo_root: Path, value: object) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    path = Path(value.strip())
    return path if path.is_absolute() else repo_root / path


def _rel(repo_root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def _latest_peer(repo_root: Path, archive_path: Path) -> Path:
    return repo_root / "data/static_analysis/reports/latest" / archive_path.name


def _collect_report_saved_context(
    *,
    repo_root: Path,
    jsonl_path: Path,
    session: str,
) -> dict[Path, dict[str, Any]]:
    events: dict[Path, dict[str, Any]] = {}
    if not jsonl_path.exists():
        return events
    with jsonl_path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            if event.get("event") != "report.saved":
                continue
            if str(event.get("session_stamp") or "") != session:
                continue
            archive_path = _resolve_path(repo_root, event.get("archive_path"))
            if archive_path is None:
                continue
            context = {
                "execution_id": event.get("execution_id"),
                "session_stamp": event.get("session_stamp"),
                "report_saved_at_utc": event.get("ts"),
                "report_sha256": event.get("report_sha256"),
                "package_name": event.get("package_name"),
                "normalized_package_name": event.get("normalized_package_name"),
                "manifest_package_name": event.get("manifest_package_name"),
            }
            events[archive_path.resolve()] = {
                key: value for key, value in context.items() if value is not None
            }
    return events


def _patch_payload(payload: dict[str, Any], context: Mapping[str, Any]) -> bool:
    metadata = payload.setdefault("metadata", {})
    if not isinstance(metadata, dict):
        return False
    changed = False
    for key in (
        "execution_id",
        "session_stamp",
        "report_saved_at_utc",
        "report_sha256",
        "package_name",
        "normalized_package_name",
        "manifest_package_name",
    ):
        value = context.get(key)
        if value is None:
            continue
        if metadata.get(key) != value:
            metadata[key] = value
            changed = True
    return changed


def repair_session(
    *,
    repo_root: Path,
    session: str,
    jsonl_path: Path,
    apply: bool,
) -> dict[str, Any]:
    contexts = _collect_report_saved_context(
        repo_root=repo_root,
        jsonl_path=jsonl_path,
        session=session,
    )
    patched_paths: list[str] = []
    missing_archive_paths: list[str] = []

    for archive_path, context in sorted(contexts.items(), key=lambda item: str(item[0])):
        if not archive_path.exists():
            missing_archive_paths.append(_rel(repo_root, archive_path))
            continue
        candidate_paths = [archive_path]
        latest_path = _latest_peer(repo_root, archive_path)
        if latest_path.exists():
            candidate_paths.append(latest_path)
        for path in candidate_paths:
            payload = _read_json(path)
            if not payload:
                continue
            if _patch_payload(payload, context):
                patched_paths.append(_rel(repo_root, path))
                if apply:
                    _write_json(path, payload)

    return {
        "mode": "apply" if apply else "dry_run",
        "session": session,
        "jsonl_path": _rel(repo_root, jsonl_path),
        "report_saved_archive_paths": len(contexts),
        "missing_archive_path_count": len(missing_archive_paths),
        "missing_archive_path_sample": missing_archive_paths[:20],
        "report_files_needing_update": len(patched_paths),
        "report_file_sample": patched_paths[:20],
    }


def main() -> int:
    args = _build_parser().parse_args()
    repo_root = Path(args.repo_root).resolve()
    jsonl_path = Path(args.jsonl)
    if not jsonl_path.is_absolute():
        jsonl_path = repo_root / jsonl_path
    summary = repair_session(
        repo_root=repo_root,
        session=args.session,
        jsonl_path=jsonl_path,
        apply=bool(args.apply),
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
