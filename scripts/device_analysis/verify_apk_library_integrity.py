#!/usr/bin/env python3
"""Read-only APK library manifest and canonical byte integrity verifier."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=Path("data"))
    parser.add_argument("--output-root", type=Path, default=None)
    parser.add_argument("--stamp", default=None)
    parser.add_argument(
        "--verify-sha256",
        action="store_true",
        help="Hash APK bytes and compare them with manifest SHA-256 values. Slower on large stores.",
    )
    parser.add_argument("--json", action="store_true", help="Print summary JSON.")
    return parser


def build_report(
    *,
    data_root: Path,
    output_root: Path | None = None,
    stamp: str | None = None,
    verify_sha256: bool = False,
    write_outputs: bool = True,
) -> dict[str, Any]:
    data_root = data_root.expanduser()
    repo_root = data_root.parent
    stamp = stamp or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output_root = output_root or repo_root / "output" / "audit" / "apk_library_integrity" / stamp

    artifact_rows: list[dict[str, Any]] = []
    finding_rows: list[dict[str, Any]] = []
    manifest_counts = Counter()
    for manifest in _iter_library_manifests(data_root):
        manifest_counts[_manifest_kind(manifest)] += 1
        rows, findings = _verify_split_set_manifest(manifest, data_root=data_root, verify_sha256=verify_sha256)
        artifact_rows.extend(rows)
        finding_rows.extend(findings)
    for manifest in _iter_partial_manifests(data_root):
        manifest_counts["partial_artifact"] += 1
        row, findings = _verify_partial_manifest(manifest, data_root=data_root, verify_sha256=verify_sha256)
        if row:
            artifact_rows.append(row)
        finding_rows.extend(findings)

    severity_counts = Counter(row["severity"] for row in finding_rows)
    status = "BLOCKED" if severity_counts["critical"] or severity_counts["high"] else ("WARN" if severity_counts["medium"] or severity_counts["low"] else "OK")
    summary = {
        "schema_version": "apk_library_integrity_v1",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "data_root": data_root.as_posix(),
        "status": status,
        "verify_sha256": bool(verify_sha256),
        "package_version_manifest_count": len(list((data_root / "android_apks" / "packages").glob("*/*/package_manifest.json"))),
        "split_set_manifest_count": manifest_counts["planned_split_set"],
        "content_variant_manifest_count": manifest_counts["content_variant"],
        "partial_artifact_manifest_count": manifest_counts["partial_artifact"],
        "artifacts_csv_count": len(list(_iter_artifacts_csv(data_root))),
        "artifact_row_count": len(artifact_rows),
        "finding_count": len(finding_rows),
        "critical_finding_count": severity_counts["critical"],
        "high_finding_count": severity_counts["high"],
        "medium_finding_count": severity_counts["medium"],
        "low_finding_count": severity_counts["low"],
        "missing_canonical_blob_count": sum(1 for row in artifact_rows if row["byte_status"] == "missing"),
        "unreadable_canonical_blob_count": sum(1 for row in artifact_rows if row["byte_status"] == "unreadable"),
        "hash_mismatch_count": sum(1 for row in finding_rows if row["finding_id"] == "APK_BYTE_HASH_MISMATCH"),
        "content_hash_mismatch_count": sum(1 for row in finding_rows if row["finding_id"] == "CONTENT_SPLIT_SET_HASH_MISMATCH"),
        "canonical_path_mismatch_count": sum(1 for row in finding_rows if row["finding_id"] == "CANONICAL_PATH_MISMATCH"),
        "artifacts_csv_mismatch_count": sum(1 for row in finding_rows if row["finding_id"].startswith("ARTIFACTS_CSV_")),
    }
    outputs = {
        "summary_json": output_root / "summary.json",
        "artifacts_csv": output_root / "artifacts.csv",
        "findings_csv": output_root / "findings.csv",
    }
    if write_outputs:
        output_root.mkdir(parents=True, exist_ok=True)
        outputs["summary_json"].write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        _write_csv(outputs["artifacts_csv"], artifact_rows)
        _write_csv(outputs["findings_csv"], finding_rows)
    return {
        "summary": summary,
        "outputs": {key: value.as_posix() for key, value in outputs.items()},
        "artifacts": artifact_rows,
        "findings": finding_rows,
    }


def _iter_library_manifests(data_root: Path) -> Iterable[Path]:
    root = data_root / "android_apks" / "packages"
    yield from sorted(root.glob("*/*/split_sets/*/package_manifest.json"))
    yield from sorted(root.glob("*/*/split_sets/*/content_variants/*/package_manifest.json"))


def _iter_artifacts_csv(data_root: Path) -> Iterable[Path]:
    root = data_root / "android_apks" / "packages"
    yield from sorted(root.glob("*/*/split_sets/*/artifacts.csv"))
    yield from sorted(root.glob("*/*/split_sets/*/content_variants/*/artifacts.csv"))


def _iter_partial_manifests(data_root: Path) -> Iterable[Path]:
    yield from sorted((data_root / "android_apks" / "partial_artifacts").glob("*/*/*/artifact_manifest.json"))


def _manifest_kind(path: Path) -> str:
    return "content_variant" if "content_variants" in path.parts else "planned_split_set"


def _verify_split_set_manifest(
    manifest: Path,
    *,
    data_root: Path,
    verify_sha256: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    payload = _read_json(manifest)
    if not payload:
        return [], [_finding(manifest, "critical", "UNREADABLE_MANIFEST", "Manifest is unreadable or invalid JSON.")]
    artifacts = [item for item in payload.get("artifacts") or [] if isinstance(item, dict)]
    findings: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    if not artifacts:
        findings.append(_finding(manifest, "high", "MISSING_ARTIFACT_ROWS", "Split-set manifest has no artifacts."))
    expected_content_hash = _content_split_set_hash(artifacts)
    observed_content_hash = str(payload.get("split_set_hash") or "").strip()
    if expected_content_hash and observed_content_hash and expected_content_hash != observed_content_hash:
        findings.append(
            _finding(
                manifest,
                "high",
                "CONTENT_SPLIT_SET_HASH_MISMATCH",
                "Manifest split_set_hash does not match artifact role/split/SHA content.",
                expected=expected_content_hash,
                observed=observed_content_hash,
            )
        )
    for artifact in artifacts:
        row, row_findings = _verify_artifact(
            artifact,
            data_root=data_root,
            manifest=manifest,
            package_name=str(payload.get("package_name") or ""),
            version_code=str(payload.get("version_code") or ""),
            version_name=str(payload.get("version_name") or ""),
            planned_split_set_hash=str(payload.get("planned_split_set_hash") or ""),
            entry_kind=str(payload.get("entry_kind") or _manifest_kind(manifest)),
            verify_sha256=verify_sha256,
        )
        rows.append(row)
        findings.extend(row_findings)
    findings.extend(_verify_artifacts_csv_mirror(manifest, artifacts))
    return rows, findings


def _verify_artifacts_csv_mirror(manifest: Path, artifacts: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    csv_path = manifest.with_name("artifacts.csv")
    if not csv_path.exists():
        return [_finding(csv_path, "medium", "ARTIFACTS_CSV_MISSING", "APK library artifacts.csv mirror is missing.")]
    try:
        with csv_path.open("r", encoding="utf-8", newline="") as handle:
            csv_rows = list(csv.DictReader(handle))
    except OSError as exc:
        return [_finding(csv_path, "medium", "ARTIFACTS_CSV_UNREADABLE", f"APK library artifacts.csv mirror is unreadable: {exc}")]
    findings: list[dict[str, Any]] = []
    if len(csv_rows) != len(artifacts):
        findings.append(
            _finding(
                csv_path,
                "medium",
                "ARTIFACTS_CSV_ROW_COUNT_MISMATCH",
                "APK library artifacts.csv row count does not match package_manifest.json artifacts.",
                expected=str(len(artifacts)),
                observed=str(len(csv_rows)),
            )
        )
    for index, artifact in enumerate(artifacts):
        if index >= len(csv_rows):
            break
        expected = _csv_projection(artifact)
        observed = {key: str(csv_rows[index].get(key) or "") for key in expected}
        if expected != observed:
            findings.append(
                _finding(
                    csv_path,
                    "medium",
                    "ARTIFACTS_CSV_ROW_MISMATCH",
                    "APK library artifacts.csv row does not match package_manifest.json artifact.",
                    expected=json.dumps(expected, sort_keys=True),
                    observed=json.dumps(observed, sort_keys=True),
                    sha256=expected.get("sha256", ""),
                )
            )
    return findings


def _csv_projection(artifact: Mapping[str, Any]) -> dict[str, str]:
    return {
        "role": str(artifact.get("role") or ""),
        "split_name": str(artifact.get("split_name") or ""),
        "file_name": str(artifact.get("file_name") or ""),
        "device_path": str(artifact.get("device_path") or ""),
        "sha256": str(artifact.get("sha256") or "").strip().lower(),
        "size_bytes": str(artifact.get("size_bytes") or ""),
        "canonical_path": str(artifact.get("canonical_path") or ""),
    }


def _verify_partial_manifest(
    manifest: Path,
    *,
    data_root: Path,
    verify_sha256: bool,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    payload = _read_json(manifest)
    if not payload:
        return None, [_finding(manifest, "critical", "UNREADABLE_MANIFEST", "Manifest is unreadable or invalid JSON.")]
    artifact = payload.get("artifact") if isinstance(payload.get("artifact"), dict) else {}
    if not artifact:
        return None, [_finding(manifest, "high", "MISSING_ARTIFACT_ROWS", "Partial artifact manifest has no artifact payload.")]
    return _verify_artifact(
        artifact,
        data_root=data_root,
        manifest=manifest,
        package_name=str(payload.get("package_name") or ""),
        version_code=str(payload.get("version_code") or ""),
        version_name=str(payload.get("version_name") or ""),
        planned_split_set_hash=str(payload.get("planned_split_set_hash") or ""),
        entry_kind="partial_artifact",
        verify_sha256=verify_sha256,
    )


def _verify_artifact(
    artifact: Mapping[str, Any],
    *,
    data_root: Path,
    manifest: Path,
    package_name: str,
    version_code: str,
    version_name: str,
    planned_split_set_hash: str,
    entry_kind: str,
    verify_sha256: bool,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    sha = str(artifact.get("sha256") or "").strip().lower()
    canonical_rel = str(artifact.get("canonical_path") or "").strip()
    expected_rel = f"data/store/apk/sha256/{sha[:2]}/{sha}.apk" if len(sha) == 64 else ""
    canonical_path = _resolve_repo_path(data_root, canonical_rel) if canonical_rel else None
    findings: list[dict[str, Any]] = []
    byte_status = "missing"
    resolved_path = ""
    actual_size = 0
    if len(sha) != 64:
        findings.append(_finding(manifest, "high", "INVALID_ARTIFACT_SHA256", "Artifact SHA-256 is missing or invalid.", observed=sha))
    if expected_rel and canonical_rel != expected_rel:
        findings.append(
            _finding(
                manifest,
                "high",
                "CANONICAL_PATH_MISMATCH",
                "Artifact canonical_path does not match data/store/apk/sha256/<prefix>/<sha>.apk.",
                expected=expected_rel,
                observed=canonical_rel,
                sha256=sha,
            )
        )
    if canonical_path is None:
        findings.append(_finding(manifest, "high", "MISSING_CANONICAL_PATH", "Artifact canonical_path is missing.", sha256=sha))
    else:
        try:
            resolved = canonical_path.resolve(strict=True)
            resolved_path = resolved.as_posix()
            if resolved.is_file():
                actual_size = resolved.stat().st_size
                byte_status = "available"
                if actual_size <= 0:
                    findings.append(_finding(manifest, "high", "ZERO_SIZE_CANONICAL_BLOB", "Canonical APK blob is zero-size.", sha256=sha))
                declared_size = _as_int(artifact.get("size_bytes"))
                if declared_size is not None and actual_size != declared_size:
                    findings.append(
                        _finding(
                            manifest,
                            "medium",
                            "SIZE_BYTES_MISMATCH",
                            "Artifact size_bytes does not match canonical blob size.",
                            expected=str(declared_size),
                            observed=str(actual_size),
                            sha256=sha,
                        )
                    )
                if verify_sha256 and len(sha) == 64:
                    actual_sha = _sha256(resolved)
                    if actual_sha != sha:
                        findings.append(
                            _finding(
                                manifest,
                                "critical",
                                "APK_BYTE_HASH_MISMATCH",
                                "Canonical APK byte hash does not match manifest SHA-256.",
                                expected=sha,
                                observed=actual_sha,
                                sha256=sha,
                            )
                        )
            else:
                byte_status = "missing"
                findings.append(_finding(manifest, "high", "MISSING_CANONICAL_BLOB", "Canonical path does not resolve to a file.", sha256=sha))
        except FileNotFoundError:
            byte_status = "missing"
            findings.append(_finding(manifest, "high", "MISSING_CANONICAL_BLOB", "Canonical APK blob is missing.", sha256=sha))
        except OSError as exc:
            byte_status = "unreadable"
            findings.append(_finding(manifest, "high", "UNREADABLE_CANONICAL_BLOB", f"Canonical APK blob is unreadable: {exc}", sha256=sha))
    return (
        {
            "manifest_path": manifest.as_posix(),
            "entry_kind": entry_kind,
            "package_name": package_name,
            "version_code": version_code,
            "version_name": version_name,
            "planned_split_set_hash": planned_split_set_hash,
            "role": str(artifact.get("role") or ""),
            "split_name": str(artifact.get("split_name") or ""),
            "file_name": str(artifact.get("file_name") or ""),
            "sha256": sha,
            "declared_size_bytes": str(artifact.get("size_bytes") or ""),
            "actual_size_bytes": actual_size,
            "canonical_path": canonical_rel,
            "resolved_path": resolved_path,
            "byte_status": byte_status,
        },
        findings,
    )


def _content_split_set_hash(artifacts: Iterable[Mapping[str, Any]]) -> str:
    rows = []
    for item in artifacts:
        sha = str(item.get("sha256") or "").strip().lower()
        if len(sha) != 64:
            continue
        rows.append(
            {
                "role": "base" if str(item.get("role") or "").lower() == "base" else "split",
                "split_name": str(item.get("split_name") or ""),
                "sha256": sha,
            }
        )
    rows.sort(key=lambda row: (row["role"], row["split_name"], row["sha256"]))
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest() if rows else ""


def _resolve_repo_path(data_root: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    repo_root = data_root.parent
    return repo_root / path


def _finding(
    manifest: Path,
    severity: str,
    finding_id: str,
    message: str,
    *,
    expected: str = "",
    observed: str = "",
    sha256: str = "",
) -> dict[str, str]:
    return {
        "severity": severity,
        "finding_id": finding_id,
        "manifest_path": manifest.as_posix(),
        "sha256": sha256,
        "expected": expected,
        "observed": observed,
        "message": message,
    }


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _as_int(value: Any) -> int | None:
    try:
        if value is None or str(value).strip() == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


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
        verify_sha256=args.verify_sha256,
    )
    if args.json:
        print(json.dumps({"summary": report["summary"], "outputs": report["outputs"]}, indent=2, sort_keys=True))
    else:
        print("APK library integrity verifier")
        print(f"  Status : {report['summary']['status']}")
        print(f"  Output : {report['outputs']['summary_json']}")
        print(f"  Findings: {report['summary']['finding_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
