"""Paper export manifest helpers.

This module implements deterministic manifest comparison for frozen export
artifacts. It is intentionally file-system only (no DB access).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

MANIFEST_VERSION = 1
# Legacy schema field name is `paper`. Keep accepting paper ids for back-compat.
# Newer tooling should treat this as a generic export/profile id, not a paper id.
ALLOWED_PAPER_IDS = {"paper2", "publication"}
PAPER_ID = "paper2"
NORM_NONE = "none"
NORM_TEX_WHITESPACE_LF = "tex_whitespace_lf"
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ManifestCompareResult:
    payload: dict[str, Any]
    passed: bool


def _sha256_bytes(blob: bytes) -> str:
    return sha256(blob).hexdigest()


def _normalize_tex_bytes(blob: bytes) -> bytes:
    text = blob.decode("utf-8", errors="strict")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    out_lines: list[str] = []
    for raw_line in text.split("\n"):
        # Ignore spacing-only changes while preserving token and line order.
        line = re.sub(r"[ \t]+", " ", raw_line).strip()
        if not line:
            continue
        out_lines.append(line)
    return ("\n".join(out_lines) + "\n").encode("utf-8")


def _canonical_bytes(path: Path, normalization: str) -> bytes:
    blob = path.read_bytes()
    if normalization == NORM_NONE:
        return blob
    if normalization == NORM_TEX_WHITESPACE_LF:
        return _normalize_tex_bytes(blob)
    raise ValueError(f"Unsupported normalization mode: {normalization}")


def digest_artifact(path: Path, *, normalization: str) -> tuple[str, int]:
    canon = _canonical_bytes(path, normalization)
    return _sha256_bytes(canon), len(canon)


def validate_manifest_schema(payload: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    if int(payload.get("manifest_version") or -1) != MANIFEST_VERSION:
        issues.append("manifest_version_invalid")
    paper_id = str(payload.get("paper") or "").strip()
    if paper_id not in ALLOWED_PAPER_IDS:
        issues.append("paper_invalid")

    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        issues.append("artifacts_not_list")
        return issues
    if not artifacts:
        issues.append("artifacts_empty")
        return issues

    seen_paths: set[str] = set()
    for idx, entry in enumerate(artifacts):
        prefix = f"artifacts[{idx}]"
        if not isinstance(entry, dict):
            issues.append(f"{prefix}.not_object")
            continue
        rel_path = str(entry.get("path") or "").strip()
        if not rel_path:
            issues.append(f"{prefix}.path_missing")
        elif rel_path in seen_paths:
            issues.append(f"{prefix}.path_duplicate:{rel_path}")
        else:
            seen_paths.add(rel_path)

        normalization = str(entry.get("normalization") or "").strip()
        if normalization not in {NORM_NONE, NORM_TEX_WHITESPACE_LF}:
            issues.append(f"{prefix}.normalization_invalid:{normalization}")

        sha_val = str(entry.get("sha256") or "").strip().lower()
        if not _HEX_64_RE.match(sha_val):
            issues.append(f"{prefix}.sha256_invalid")

        size_val = entry.get("size_bytes")
        if not isinstance(size_val, int) or size_val < 0:
            issues.append(f"{prefix}.size_bytes_invalid")
    return issues


def build_manifest_from_artifacts(
    *,
    artifact_root: Path,
    artifact_specs: list[dict[str, Any]],
    generated_utc: str,
    description: str,
) -> dict[str, Any]:
    artifacts: list[dict[str, Any]] = []
    for spec in artifact_specs:
        rel_path = str(spec.get("path") or "").strip()
        normalization = str(spec.get("normalization") or NORM_NONE).strip() or NORM_NONE
        kind = str(spec.get("kind") or "").strip() or "artifact"
        full = artifact_root / rel_path
        digest, size = digest_artifact(full, normalization=normalization)
        artifacts.append(
            {
                "path": rel_path,
                "kind": kind,
                "normalization": normalization,
                "sha256": digest,
                "size_bytes": size,
            }
        )
    return {
        "manifest_version": MANIFEST_VERSION,
        "paper": PAPER_ID,
        "description": description,
        "generated_utc": generated_utc,
        "artifacts": artifacts,
    }


def compare_manifest(
    *,
    baseline_manifest: dict[str, Any],
    artifact_root: Path,
    compare_type: str = "paper2_export",
) -> ManifestCompareResult:
    schema_issues = validate_manifest_schema(baseline_manifest)
    diffs: list[dict[str, Any]] = []

    artifacts = baseline_manifest.get("artifacts")
    if not isinstance(artifacts, list):
        artifacts = []

    for idx, entry in enumerate(artifacts):
        if not isinstance(entry, dict):
            continue
        rel_path = str(entry.get("path") or "").strip()
        if not rel_path:
            continue
        normalization = str(entry.get("normalization") or NORM_NONE).strip() or NORM_NONE
        full = artifact_root / rel_path
        if not full.exists():
            diffs.append(
                {
                    "path": rel_path,
                    "field": "exists",
                    "expected": True,
                    "actual": False,
                    "allowed": False,
                }
            )
            continue
        expected_sha = str(entry.get("sha256") or "").strip().lower()
        expected_size = entry.get("size_bytes")
        actual_sha, actual_size = digest_artifact(full, normalization=normalization)
        if expected_sha != actual_sha:
            diffs.append(
                {
                    "path": rel_path,
                    "field": "sha256",
                    "expected": expected_sha,
                    "actual": actual_sha,
                    "allowed": False,
                }
            )
        if expected_size != actual_size:
            diffs.append(
                {
                    "path": rel_path,
                    "field": "size_bytes",
                    "expected": expected_size,
                    "actual": actual_size,
                    "allowed": False,
                }
            )

    disallowed = sum(1 for diff in diffs if not diff.get("allowed"))
    passed = (not schema_issues) and disallowed == 0
    payload = {
        "compare_type": compare_type,
        "allowed_diff_fields": [],
        "result": {
            "pass": passed,
            "fail_reason": None if passed else ("manifest_schema_invalid" if schema_issues else "artifact_drift"),
            "validation_issues": schema_issues,
            "diff_counts": {
                "total": len(diffs),
                "allowed": 0,
                "disallowed": disallowed,
            },
        },
        "diffs": diffs,
    }
    return ManifestCompareResult(payload=payload, passed=passed)


def load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_manifest(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


__all__ = [
    "MANIFEST_VERSION",
    "PAPER_ID",
    "NORM_NONE",
    "NORM_TEX_WHITESPACE_LF",
    "ManifestCompareResult",
    "build_manifest_from_artifacts",
    "compare_manifest",
    "digest_artifact",
    "dump_manifest",
    "load_manifest",
    "validate_manifest_schema",
]
