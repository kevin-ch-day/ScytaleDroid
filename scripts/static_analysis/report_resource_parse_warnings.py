#!/usr/bin/env python3
"""Report static APK artifacts with resource parser coverage warnings."""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

_COUNT_RE = re.compile(r"Count:\s*(\d+)")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", help="Static session stamp, e.g. 20260709-all-full.")
    parser.add_argument(
        "--archive-dir",
        help="Static report archive directory. Defaults to data/static_analysis/reports/archive/<session>.",
    )
    parser.add_argument("--repo-root", default=".", help="Repository root. Defaults to the current working directory.")
    parser.add_argument("--json", dest="json_path", help="Optional path to write the full JSON report.")
    parser.add_argument("--csv", dest="csv_path", help="Optional path to write artifact rows as CSV.")
    parser.add_argument(
        "--paper-freeze-manifest",
        help="Optional paper_freeze_manifest.csv used to mark selected paper APK hashes/packages.",
    )
    parser.add_argument(
        "--check-aapt2-recovery",
        action="store_true",
        help="Read affected APKs and count default/English resource strings recoverable via aapt2.",
    )
    parser.add_argument("--aapt2-timeout", type=int, default=45, help="Per-APK aapt2 timeout in seconds.")
    parser.add_argument("--top", type=int, default=25, help="Number of package summary rows to print. Default: 25.")
    parser.add_argument("--stdout-json", action="store_true", help="Print the full JSON report to stdout.")
    return parser


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _safe_int(value: Any) -> int:
    try:
        if value in (None, ""):
            return 0
        return int(value)
    except (TypeError, ValueError):
        return 0


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _metadata(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    value = payload.get("metadata")
    return value if isinstance(value, Mapping) else {}


def _parser_provenance(metadata: Mapping[str, Any]) -> Mapping[str, Any]:
    value = metadata.get("parser_provenance")
    return value if isinstance(value, Mapping) else {}


def _hash(payload: Mapping[str, Any], metadata: Mapping[str, Any]) -> str:
    hashes = payload.get("hashes")
    if isinstance(hashes, Mapping):
        value = _norm_text(hashes.get("sha256")).lower()
        if len(value) == 64:
            return value
    value = _norm_text(metadata.get("sha256")).lower()
    return value if len(value) == 64 else ""


def _warning_lines(metadata: Mapping[str, Any]) -> list[str]:
    lines = metadata.get("resource_bounds_warnings")
    if not isinstance(lines, list):
        return []
    out: list[str] = []
    for line in lines:
        text = _norm_text(line)
        if text:
            out.append(text)
    return out


def _count_values(lines: list[str]) -> list[int]:
    values: set[int] = set()
    for line in lines:
        for match in _COUNT_RE.finditer(line):
            try:
                values.add(int(match.group(1)))
            except ValueError:
                continue
    return sorted(values)


def _keep_recovery_locale(locale: str) -> bool:
    normalized = str(locale or "").strip().lower()
    return not normalized or normalized == "default" or normalized.startswith("en")


def _artifact_row(path: Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    metadata = _metadata(payload)
    parser = _parser_provenance(metadata)
    lines = _warning_lines(metadata)
    counts = _count_values(lines)
    package_name = (
        _norm_text(metadata.get("package_name"))
        or _norm_text(metadata.get("normalized_package_name"))
        or _norm_text(metadata.get("manifest_package_name"))
        or _norm_text(payload.get("package_name"))
        or "unknown"
    )
    return {
        "report_path": str(path),
        "sha256": _hash(payload, metadata),
        "package_name": package_name,
        "app_label": _norm_text(metadata.get("app_label")) or package_name,
        "version_code": _norm_text(metadata.get("version_code")),
        "version_name": _norm_text(metadata.get("version_name")),
        "artifact": _norm_text(metadata.get("artifact")) or _norm_text(payload.get("file_name")),
        "canonical_store_path": _norm_text(metadata.get("canonical_store_path")),
        "resource_bounds_warning_count": _safe_int(
            parser.get("resource_bounds_warning_count")
            if parser
            else len(lines)
        )
        or len(lines),
        "resource_bounds_warning_severity": _norm_text(parser.get("resource_bounds_warning_severity")) or "none",
        "resource_bounds_warning_kind": _norm_text(parser.get("resource_bounds_warning_kind")) or "none",
        "resource_parse_state": _norm_text(parser.get("resource_parse_state")) or "none",
        "resource_parse_partial": bool(parser.get("resource_parse_partial") or metadata.get("resource_parse_partial")),
        "resource_reparse_candidate": bool(
            parser.get("resource_reparse_candidate") or metadata.get("resource_reparse_candidate")
        ),
        "resource_fallback_used": bool(parser.get("resource_fallback_used") or metadata.get("resource_fallback_used")),
        "resource_string_fallback_used": bool(
            parser.get("resource_string_fallback_used") or metadata.get("resource_string_fallback_used")
        ),
        "resource_string_fallback_count": _safe_int(
            parser.get("resource_string_fallback_count") or metadata.get("resource_string_fallback_count")
        ),
        "string_index_resource_strings": _safe_int(metadata.get("string_index_resource_strings")),
        "string_index_total_strings": _safe_int(metadata.get("string_index_total_strings")),
        "count_values": ",".join(str(value) for value in counts),
        "warning_lines": " | ".join(lines),
        "paper_package": False,
        "paper_selected_base_apk": False,
        "paper_selected_version_code": "",
        "paper_selected_version_name": "",
        "paper_selected_static_run_ids": "",
        "reanalysis_priority": "LIBRARY_ONLY",
        "aapt2_recovery_status": "not_checked",
        "aapt2_resource_string_count": 0,
    }


def _load_paper_manifest(path: Path | None) -> dict[str, dict[str, str]]:
    if path is None:
        return {}
    try:
        handle = path.open(newline="", encoding="utf-8")
    except OSError:
        return {}
    with handle:
        rows: dict[str, dict[str, str]] = {}
        for row in csv.DictReader(handle):
            package = _norm_text(row.get("package_name"))
            if package:
                rows[package] = {str(key): str(value or "") for key, value in row.items()}
        return rows


def _apply_paper_context(rows: list[dict[str, Any]], manifest_rows: Mapping[str, Mapping[str, str]]) -> None:
    for row in rows:
        manifest = manifest_rows.get(str(row.get("package_name") or ""))
        if not manifest:
            continue
        selected_hash = _norm_text(manifest.get("selected_base_apk_sha256")).lower()
        warning_hash = _norm_text(row.get("sha256")).lower()
        selected_base = bool(selected_hash and selected_hash == warning_hash)
        row["paper_package"] = True
        row["paper_selected_base_apk"] = selected_base
        row["paper_selected_version_code"] = _norm_text(manifest.get("selected_version_code"))
        row["paper_selected_version_name"] = _norm_text(manifest.get("selected_version_name"))
        row["paper_selected_static_run_ids"] = _norm_text(manifest.get("selected_static_run_ids"))
        row["reanalysis_priority"] = "PAPER_SELECTED_BASE" if selected_base else "PAPER_PACKAGE_OTHER_BUILD"


def _apply_aapt2_recovery_check(rows: list[dict[str, Any]], *, timeout: int) -> None:
    from scytaledroid.StaticAnalysis.engine import aapt2_fallback

    for row in rows:
        path = Path(str(row.get("canonical_store_path") or ""))
        if not path.exists():
            row["aapt2_recovery_status"] = "missing_apk"
            continue
        try:
            raw_rows = aapt2_fallback.extract_resource_strings(str(path), timeout=timeout)
        except Exception:
            row["aapt2_recovery_status"] = "error"
            continue
        seen_values: set[str] = set()
        for item in raw_rows:
            value = _norm_text(item.get("value") if isinstance(item, Mapping) else "")
            locale = _norm_text(item.get("locale") if isinstance(item, Mapping) else "")
            if not value or not _keep_recovery_locale(locale):
                continue
            seen_values.add(value)
        row["aapt2_resource_string_count"] = len(seen_values)
        row["aapt2_recovery_status"] = "ok" if seen_values else "empty"


def build_report(
    archive_dir: Path,
    *,
    session: str = "",
    paper_freeze_manifest: Path | None = None,
    check_aapt2_recovery: bool = False,
    aapt2_timeout: int = 45,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    invalid_json = 0
    reports_scanned = 0
    for path in sorted(archive_dir.glob("*.json")):
        reports_scanned += 1
        payload = _read_json(path)
        if payload is None:
            invalid_json += 1
            continue
        row = _artifact_row(path, payload)
        if row["resource_bounds_warning_count"] > 0 or row["resource_parse_partial"]:
            rows.append(row)

    manifest_rows = _load_paper_manifest(paper_freeze_manifest)
    if manifest_rows:
        _apply_paper_context(rows, manifest_rows)
    if check_aapt2_recovery:
        _apply_aapt2_recovery_check(rows, timeout=max(1, int(aapt2_timeout)))

    package_counter = Counter(str(row["package_name"]) for row in rows)
    partial_counter = Counter(str(row["package_name"]) for row in rows if row["resource_parse_partial"])
    reparse_counter = Counter(str(row["package_name"]) for row in rows if row["resource_reparse_candidate"])
    package_summary = [
        {
            "package_name": package,
            "warning_artifacts": count,
            "partial_artifacts": partial_counter.get(package, 0),
            "reparse_candidate_artifacts": reparse_counter.get(package, 0),
        }
        for package, count in package_counter.most_common()
    ]
    return {
        "session": session,
        "archive_dir": str(archive_dir),
        "summary": {
            "reports_scanned": reports_scanned,
            "invalid_json_reports": invalid_json,
            "resource_warning_artifacts": len(rows),
            "resource_parse_partial_artifacts": sum(1 for row in rows if row["resource_parse_partial"]),
            "resource_reparse_candidate_artifacts": sum(1 for row in rows if row["resource_reparse_candidate"]),
            "packages_with_resource_warnings": len(package_counter),
            "paper_packages_with_resource_warnings": len({row["package_name"] for row in rows if row["paper_package"]}),
            "paper_selected_base_warning_artifacts": sum(1 for row in rows if row["paper_selected_base_apk"]),
            "aapt2_recovery_checked_artifacts": sum(
                1 for row in rows if row["aapt2_recovery_status"] != "not_checked"
            ),
            "aapt2_recovery_ok_artifacts": sum(1 for row in rows if row["aapt2_recovery_status"] == "ok"),
            "aapt2_recovery_empty_artifacts": sum(1 for row in rows if row["aapt2_recovery_status"] == "empty"),
            "aapt2_recovery_missing_artifacts": sum(1 for row in rows if row["aapt2_recovery_status"] == "missing_apk"),
        },
        "package_summary": package_summary,
        "rows": rows,
    }


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "package_name",
        "app_label",
        "version_code",
        "version_name",
        "artifact",
        "sha256",
        "canonical_store_path",
        "resource_bounds_warning_count",
        "resource_bounds_warning_severity",
        "resource_bounds_warning_kind",
        "resource_parse_state",
        "resource_parse_partial",
        "resource_reparse_candidate",
        "resource_fallback_used",
        "resource_string_fallback_used",
        "resource_string_fallback_count",
        "string_index_resource_strings",
        "string_index_total_strings",
        "count_values",
        "report_path",
        "warning_lines",
        "paper_package",
        "paper_selected_base_apk",
        "paper_selected_version_code",
        "paper_selected_version_name",
        "paper_selected_static_run_ids",
        "reanalysis_priority",
        "aapt2_recovery_status",
        "aapt2_resource_string_count",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _archive_dir(args: argparse.Namespace) -> Path:
    repo_root = Path(args.repo_root).resolve()
    if args.archive_dir:
        path = Path(args.archive_dir)
        return path if path.is_absolute() else repo_root / path
    if not args.session:
        raise SystemExit("--session is required when --archive-dir is not provided")
    return repo_root / "data" / "static_analysis" / "reports" / "archive" / args.session


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    archive_dir = _archive_dir(args)
    paper_manifest = Path(args.paper_freeze_manifest).resolve() if args.paper_freeze_manifest else None
    report = build_report(
        archive_dir,
        session=_norm_text(args.session),
        paper_freeze_manifest=paper_manifest,
        check_aapt2_recovery=bool(args.check_aapt2_recovery),
        aapt2_timeout=int(args.aapt2_timeout),
    )

    if args.json_path:
        _write_json(Path(args.json_path), report)
    if args.csv_path:
        _write_csv(Path(args.csv_path), list(report["rows"]))

    if args.stdout_json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    summary = report["summary"]
    print(f"session: {report['session'] or '—'}")
    print(f"archive_dir: {report['archive_dir']}")
    print(f"reports_scanned: {summary['reports_scanned']}")
    print(f"resource_warning_artifacts: {summary['resource_warning_artifacts']}")
    print(f"resource_parse_partial_artifacts: {summary['resource_parse_partial_artifacts']}")
    print(f"resource_reparse_candidate_artifacts: {summary['resource_reparse_candidate_artifacts']}")
    print(f"packages_with_resource_warnings: {summary['packages_with_resource_warnings']}")
    print(f"paper_packages_with_resource_warnings: {summary['paper_packages_with_resource_warnings']}")
    print(f"paper_selected_base_warning_artifacts: {summary['paper_selected_base_warning_artifacts']}")
    if summary["aapt2_recovery_checked_artifacts"]:
        print(f"aapt2_recovery_checked_artifacts: {summary['aapt2_recovery_checked_artifacts']}")
        print(f"aapt2_recovery_ok_artifacts: {summary['aapt2_recovery_ok_artifacts']}")
        print(f"aapt2_recovery_empty_artifacts: {summary['aapt2_recovery_empty_artifacts']}")
        print(f"aapt2_recovery_missing_artifacts: {summary['aapt2_recovery_missing_artifacts']}")
    top = max(0, int(args.top))
    if top and report["package_summary"]:
        print()
        print("top_packages:")
        for row in report["package_summary"][:top]:
            print(
                f"- {row['package_name']}: warnings={row['warning_artifacts']} "
                f"partial={row['partial_artifacts']} reparse={row['reparse_candidate_artifacts']}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
