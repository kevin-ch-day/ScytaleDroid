#!/usr/bin/env python3
"""Repair static report metadata for captured resource-bound parser warnings."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping

from scytaledroid.StaticAnalysis.engine.strings_capture import (
    _classify_resource_parse_state,
    _summarize_bounds_warnings,
)

_SHA_RE = re.compile(r"([0-9a-fA-F]{64})\.apk$")


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
        "--archive-dir",
        default=None,
        help="Session archive directory. Defaults to data/static_analysis/reports/archive/<session>.",
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


def _extract_apk_sha(apk_path: object) -> str | None:
    if not isinstance(apk_path, str):
        return None
    match = _SHA_RE.search(apk_path.strip())
    return match.group(1).lower() if match else None


def _warning_lines(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    lines: list[str] = []
    for item in value:
        text = str(item).strip()
        if text and text not in lines:
            lines.append(text)
    return lines


def _collect_warning_lines(jsonl_path: Path) -> dict[str, list[str]]:
    warnings_by_sha: dict[str, list[str]] = defaultdict(list)
    if not jsonl_path.exists():
        return {}
    with jsonl_path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            if event.get("event") != "strings.resource_bounds_warning":
                continue
            apk_sha = _extract_apk_sha(event.get("apk_path"))
            if not apk_sha:
                continue
            for line in _warning_lines(event.get("warning_lines")):
                if line not in warnings_by_sha[apk_sha]:
                    warnings_by_sha[apk_sha].append(line)
    return dict(warnings_by_sha)


def _report_sha(payload: Mapping[str, Any]) -> str | None:
    hashes = payload.get("hashes")
    if isinstance(hashes, Mapping):
        value = hashes.get("sha256")
        if isinstance(value, str) and len(value.strip()) == 64:
            return value.strip().lower()
    metadata = payload.get("metadata")
    if isinstance(metadata, Mapping):
        value = metadata.get("sha256")
        if isinstance(value, str) and len(value.strip()) == 64:
            return value.strip().lower()
    return None


def _load_archive_reports(archive_dir: Path) -> dict[str, list[Path]]:
    paths_by_sha: dict[str, list[Path]] = defaultdict(list)
    for path in sorted(archive_dir.glob("*.json")):
        payload = _read_json(path)
        if not payload:
            continue
        sha = _report_sha(payload)
        if sha:
            paths_by_sha[sha].append(path)
    return dict(paths_by_sha)


def _merge_lines(existing: object, repair_lines: list[str]) -> list[str]:
    merged = _warning_lines(existing)
    for line in repair_lines:
        if line not in merged:
            merged.append(line)
    return merged


def _patch_payload(payload: dict[str, Any], repair_lines: list[str]) -> bool:
    metadata = payload.setdefault("metadata", {})
    if not isinstance(metadata, dict):
        return False
    merged = _merge_lines(metadata.get("resource_bounds_warnings"), repair_lines)
    if not merged:
        return False

    changed = metadata.get("resource_bounds_warnings") != merged
    metadata["resource_bounds_warnings"] = merged

    parser = metadata.setdefault("parser_provenance", {})
    if isinstance(parser, dict):
        summary = _summarize_bounds_warnings(merged)
        parse_state = _classify_resource_parse_state(
            merged,
            resource_string_count=int(metadata.get("string_index_resource_strings") or 0),
            parse_error_resources=bool(metadata.get("parse_error_resources")),
            resource_fallback_used=bool(metadata.get("resource_fallback_used")),
        )
        if parser.get("resource_bounds_warning_count") != len(merged):
            parser["resource_bounds_warning_count"] = len(merged)
            changed = True
        if parser.get("resource_bounds_warning_severity") != summary.get("severity"):
            parser["resource_bounds_warning_severity"] = summary.get("severity")
            changed = True
        if parser.get("resource_bounds_warning_kind") != summary.get("warning_kind"):
            parser["resource_bounds_warning_kind"] = summary.get("warning_kind")
            changed = True
        if parser.get("resource_parse_state") != parse_state.get("parse_state"):
            parser["resource_parse_state"] = parse_state.get("parse_state")
            changed = True
        if bool(parser.get("resource_parse_partial")) != bool(parse_state.get("parse_partial")):
            parser["resource_parse_partial"] = bool(parse_state.get("parse_partial"))
            changed = True
        if bool(parser.get("resource_reparse_candidate")) != bool(parse_state.get("reparse_candidate")):
            parser["resource_reparse_candidate"] = bool(parse_state.get("reparse_candidate"))
            changed = True

    payload_obj = metadata.get("post_run_string_payload")
    if isinstance(payload_obj, dict):
        payload_warnings = _merge_lines(payload_obj.get("warnings"), merged)
        if payload_obj.get("warnings") != payload_warnings:
            payload_obj["warnings"] = payload_warnings
            changed = True
    return changed


def _latest_peer(repo_root: Path, archive_path: Path) -> Path:
    return repo_root / "data/static_analysis/reports/latest" / archive_path.name


def repair_session(
    *,
    repo_root: Path,
    session: str,
    jsonl_path: Path,
    archive_dir: Path,
    apply: bool,
) -> dict[str, Any]:
    warnings_by_sha = _collect_warning_lines(jsonl_path)
    reports_by_sha = _load_archive_reports(archive_dir)
    patched_paths: list[str] = []
    matching_warning_shas = 0
    missing_report_shas: list[str] = []

    for sha, lines in sorted(warnings_by_sha.items()):
        archive_paths = reports_by_sha.get(sha) or []
        if not archive_paths:
            missing_report_shas.append(sha)
            continue
        matching_warning_shas += 1
        for archive_path in archive_paths:
            candidate_paths = [archive_path]
            latest_path = _latest_peer(repo_root, archive_path)
            if latest_path.exists():
                candidate_paths.append(latest_path)
            for path in candidate_paths:
                payload = _read_json(path)
                if not payload:
                    continue
                if _patch_payload(payload, lines):
                    patched_paths.append(str(path.relative_to(repo_root)))
                    if apply:
                        _write_json(path, payload)

    return {
        "mode": "apply" if apply else "dry_run",
        "session": session,
        "jsonl_path": str(jsonl_path.relative_to(repo_root) if jsonl_path.is_relative_to(repo_root) else jsonl_path),
        "archive_dir": str(archive_dir.relative_to(repo_root) if archive_dir.is_relative_to(repo_root) else archive_dir),
        "warning_apk_sha_count": len(warnings_by_sha),
        "matching_warning_sha_count": matching_warning_shas,
        "missing_report_sha_count": len(missing_report_shas),
        "missing_report_sha_sample": missing_report_shas[:20],
        "report_files_needing_update": len(patched_paths),
        "report_file_sample": patched_paths[:20],
    }


def main() -> int:
    args = _build_parser().parse_args()
    repo_root = Path(args.repo_root).resolve()
    jsonl_path = Path(args.jsonl)
    if not jsonl_path.is_absolute():
        jsonl_path = repo_root / jsonl_path
    archive_dir = Path(args.archive_dir) if args.archive_dir else (
        repo_root / "data/static_analysis/reports/archive" / args.session
    )
    if not archive_dir.is_absolute():
        archive_dir = repo_root / archive_dir

    summary = repair_session(
        repo_root=repo_root,
        session=args.session,
        jsonl_path=jsonl_path,
        archive_dir=archive_dir,
        apply=bool(args.apply),
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
