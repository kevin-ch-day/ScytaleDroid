#!/usr/bin/env python3
"""Repair APK library artifact canonical paths to logical repo-facing paths.

This metadata-only repair rewrites ``artifacts[].canonical_path`` values such
as ``/mnt/MERCURY_DATA_V2/.../data/store/apk/sha256/<prefix>/<sha>.apk`` to
``data/store/apk/sha256/<prefix>/<sha>.apk`` when both paths resolve to the
same canonical APK blob. It does not move APK bytes, touch legacy run folders,
or update database rows.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scytaledroid.Utils.IO.atomic_write import atomic_write_text  # noqa: E402


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=Path("data"))
    parser.add_argument("--output-root", type=Path, default=None)
    parser.add_argument("--stamp", default=None)
    parser.add_argument("--apply", action="store_true", help="Rewrite eligible manifest canonical_path values.")
    parser.add_argument("--json", action="store_true", help="Print summary JSON.")
    return parser


def build_actions(*, data_root: Path) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for manifest in _iter_manifests(data_root):
        payload = _read_json(manifest)
        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, list):
            artifact = payload.get("artifact") if isinstance(payload.get("artifact"), dict) else None
            artifacts = [artifact] if artifact is not None else []
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict):
                continue
            actions.append(
                _classify_artifact(
                    data_root=data_root,
                    source_path=manifest,
                    source_kind="json_manifest",
                    index=index,
                    artifact=artifact,
                )
            )
    for csv_path in _iter_artifacts_csv(data_root):
        with csv_path.open("r", encoding="utf-8", newline="") as handle:
            for index, row in enumerate(csv.DictReader(handle)):
                actions.append(
                    _classify_artifact(
                        data_root=data_root,
                        source_path=csv_path,
                        source_kind="artifacts_csv",
                        index=index,
                        artifact=row,
                    )
                )
    return actions


def apply_actions(actions: list[dict[str, Any]]) -> None:
    by_source: dict[Path, list[dict[str, Any]]] = {}
    for action in actions:
        if action["status"] == "eligible":
            by_source.setdefault(Path(action["source_path"]), []).append(action)
    for source_path, rows in by_source.items():
        if rows[0]["source_kind"] == "artifacts_csv":
            _apply_csv_actions(source_path, rows)
        else:
            _apply_json_actions(source_path, rows)
        for row in rows:
            row["status"] = "applied"


def _apply_json_actions(manifest: Path, rows: list[dict[str, Any]]) -> None:
    payload = _read_json(manifest)
    if "artifacts" in payload and isinstance(payload.get("artifacts"), list):
        artifacts = payload["artifacts"]
        for row in rows:
            artifacts[int(row["artifact_index"])]["canonical_path"] = row["logical_canonical_path"]
    elif isinstance(payload.get("artifact"), dict):
        payload["artifact"]["canonical_path"] = rows[0]["logical_canonical_path"]
    else:
        return
    atomic_write_text(manifest, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _apply_csv_actions(csv_path: Path, rows: list[dict[str, Any]]) -> None:
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        csv_rows = list(reader)
    if "canonical_path" not in fieldnames:
        return
    for row in rows:
        csv_rows[int(row["artifact_index"])]["canonical_path"] = row["logical_canonical_path"]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(csv_rows)
    atomic_write_text(csv_path, buffer.getvalue())


def build_report(
    *,
    data_root: Path,
    output_root: Path | None = None,
    stamp: str | None = None,
    apply: bool = False,
    write_outputs: bool = True,
) -> dict[str, Any]:
    data_root = data_root.expanduser()
    repo_root = data_root.parent
    stamp = stamp or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output_root = output_root or repo_root / "output" / "audit" / "apk_library_logical_path_repair" / stamp

    actions = build_actions(data_root=data_root)
    if apply:
        apply_actions(actions)
    counts = Counter(row["status"] for row in actions)
    summary = {
        "schema_version": "apk_library_logical_path_repair_v1",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "data_root": data_root.as_posix(),
        "apply": bool(apply),
        "status": "BLOCKED" if counts["blocked"] else "OK",
        "artifact_rows_scanned": len(actions),
        "json_manifest_rows_scanned": sum(1 for row in actions if row["source_kind"] == "json_manifest"),
        "artifacts_csv_rows_scanned": sum(1 for row in actions if row["source_kind"] == "artifacts_csv"),
        "eligible_count": counts["eligible"],
        "applied_count": counts["applied"],
        "already_logical_count": counts["already_logical"],
        "blocked_count": counts["blocked"],
        "ignored_count": counts["ignored"],
    }
    outputs = {
        "summary_json": output_root / "summary.json",
        "actions_csv": output_root / "actions.csv",
        "blocked_csv": output_root / "blocked.csv",
    }
    if write_outputs:
        output_root.mkdir(parents=True, exist_ok=True)
        outputs["summary_json"].write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        _write_csv(outputs["actions_csv"], actions)
        _write_csv(outputs["blocked_csv"], [row for row in actions if row["status"] == "blocked"])
    return {
        "summary": summary,
        "outputs": {key: value.as_posix() for key, value in outputs.items()},
        "actions": actions,
    }


def _iter_manifests(data_root: Path) -> Iterable[Path]:
    packages = data_root / "android_apks" / "packages"
    yield from sorted(packages.glob("*/*/split_sets/*/package_manifest.json"))
    yield from sorted(packages.glob("*/*/split_sets/*/content_variants/*/package_manifest.json"))
    yield from sorted((data_root / "android_apks" / "partial_artifacts").glob("*/*/*/artifact_manifest.json"))


def _iter_artifacts_csv(data_root: Path) -> Iterable[Path]:
    packages = data_root / "android_apks" / "packages"
    yield from sorted(packages.glob("*/*/split_sets/*/artifacts.csv"))
    yield from sorted(packages.glob("*/*/split_sets/*/content_variants/*/artifacts.csv"))


def _classify_artifact(
    *,
    data_root: Path,
    source_path: Path,
    source_kind: str,
    index: int,
    artifact: Mapping[str, Any],
) -> dict[str, Any]:
    sha = str(artifact.get("sha256") or "").strip().lower()
    current = str(artifact.get("canonical_path") or "").strip()
    logical = f"data/store/apk/sha256/{sha[:2]}/{sha}.apk" if len(sha) == 64 else ""
    base = {
        "source_path": source_path.as_posix(),
        "source_kind": source_kind,
        "artifact_index": index,
        "package_name": _source_package_name(source_path),
        "sha256": sha,
        "current_canonical_path": current,
        "logical_canonical_path": logical,
        "status": "ignored",
        "reason": "",
    }
    if len(sha) != 64:
        return {**base, "status": "blocked", "reason": "invalid_sha256"}
    if not current:
        return {**base, "status": "blocked", "reason": "missing_canonical_path"}
    if current == logical:
        return {**base, "status": "already_logical", "reason": "already_logical"}
    current_path = _resolve_repo_path(data_root, current)
    logical_path = _resolve_repo_path(data_root, logical)
    try:
        current_resolved = current_path.resolve(strict=True)
        logical_resolved = logical_path.resolve(strict=True)
    except FileNotFoundError:
        return {**base, "status": "blocked", "reason": "canonical_path_missing"}
    if current_resolved != logical_resolved:
        return {**base, "status": "blocked", "reason": "canonical_paths_resolve_differently"}
    return {**base, "status": "eligible", "reason": "absolute_path_matches_logical_blob"}


def _source_package_name(path: Path) -> str:
    try:
        if "packages" in path.parts:
            index = path.parts.index("packages")
            return path.parts[index + 1]
        if "partial_artifacts" in path.parts:
            index = path.parts.index("partial_artifacts")
            return path.parts[index + 1]
    except IndexError:
        return ""
    return ""


def _resolve_repo_path(data_root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else data_root.parent / path


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_csv(path: Path, rows: list[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row.keys()})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    report = build_report(
        data_root=args.data_root,
        output_root=args.output_root,
        stamp=args.stamp,
        apply=args.apply,
    )
    if args.json:
        print(json.dumps({"summary": report["summary"], "outputs": report["outputs"]}, indent=2, sort_keys=True))
    else:
        print("APK library logical-path repair")
        print(f"  Mode    : {'apply' if args.apply else 'dry-run'}")
        print(f"  Status  : {report['summary']['status']}")
        print(f"  Output  : {report['outputs']['summary_json']}")
        print(f"  Eligible: {report['summary']['eligible_count']}")
        print(f"  Applied : {report['summary']['applied_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
