"""Read-only verification for session ``evidence_manifest.json`` (Phase 1).

Used by ``scripts/db/verify_evidence_manifest.py`` and tests. Does **not** mutate
the database or manifest files.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

RunSql = Callable[..., Any]


def _sha256_file(path: Path) -> tuple[str | None, str | None]:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest(), None
    except OSError as exc:
        return None, f"{exc.__class__.__name__}: {exc}"


def _artifact_issues(prefix: str, art: Mapping[str, Any], index: int) -> list[str]:
    issues: list[str] = []
    if art.get("status") == "missing":
        return issues
    raw_path = art.get("path")
    if not raw_path:
        issues.append(f"{prefix}[{index}]:missing_path")
        return issues
    path = Path(str(raw_path))
    if not path.is_file():
        issues.append(f"{prefix}[{index}]:missing_file:{path}")
        return issues
    expected = art.get("sha256")
    if not expected:
        return issues
    digest, err = _sha256_file(path)
    if err:
        issues.append(f"{prefix}[{index}]:hash_read_error:{err}")
        return issues
    if str(expected).lower() != str(digest).lower():
        issues.append(
            f"{prefix}[{index}]:sha256_mismatch:path={path} "
            f"expected_prefix={str(expected)[:12]}… actual_prefix={str(digest)[:12]}…"
        )
    return issues


def verify_evidence_manifest_payload(manifest: Mapping[str, Any]) -> list[str]:
    """Return human-readable issue lines (empty list means payload + files look consistent)."""

    issues: list[str] = []
    if not manifest.get("manifest_schema_version"):
        issues.append("missing:manifest_schema_version")
    if not manifest.get("session_stamp"):
        issues.append("missing:session_stamp")
    if manifest.get("generated_at_utc") in (None, ""):
        issues.append("missing:generated_at_utc")

    if not manifest.get("git_commit") and not manifest.get("build_id"):
        issues.append("missing:git_commit_and_build_id")

    arts = manifest.get("canonical_artifacts")
    if not isinstance(arts, list):
        issues.append("missing_or_invalid:canonical_artifacts")
    else:
        for i, art in enumerate(arts):
            if isinstance(art, Mapping):
                issues.extend(_artifact_issues("canonical_artifacts", art, i))

    handoff = manifest.get("handoff")
    if isinstance(handoff, Mapping):
        runs = handoff.get("runs")
        if isinstance(runs, list):
            for i, run in enumerate(runs):
                if not isinstance(run, Mapping):
                    continue
                if run.get("status") in {"missing", None} and not run.get("json_path"):
                    continue
                jp = run.get("json_path")
                if not jp:
                    continue
                path = Path(str(jp))
                if not path.is_file() and run.get("status") != "missing":
                    issues.append(f"handoff.runs[{i}]:missing_file:{path}")
                exp = run.get("sha256")
                if path.is_file() and exp:
                    digest, err = _sha256_file(path)
                    if err:
                        issues.append(f"handoff.runs[{i}]:hash_read_error:{err}")
                    elif str(exp).lower() != str(digest).lower():
                        issues.append(f"handoff.runs[{i}]:sha256_mismatch_vs_disk")

    det = manifest.get("detector_report")
    if isinstance(det, Mapping):
        druns = det.get("runs")
        if isinstance(druns, list):
            for i, run in enumerate(druns):
                if not isinstance(run, Mapping):
                    continue
                if run.get("status") == "missing":
                    continue
                jp = run.get("path")
                if not jp:
                    issues.append(f"detector_report.runs[{i}]:missing_path")
                    continue
                path = Path(str(jp))
                if not path.is_file():
                    issues.append(f"detector_report.runs[{i}]:missing_file:{path}")
                    continue
                exp = run.get("sha256")
                if exp:
                    digest, err = _sha256_file(path)
                    if err:
                        issues.append(f"detector_report.runs[{i}]:hash_read_error:{err}")
                    elif str(exp).lower() != str(digest).lower():
                        issues.append(f"detector_report.runs[{i}]:sha256_mismatch_vs_disk")

    return issues


def verify_manifest_handoff_hash_vs_database(
    manifest: Mapping[str, Any],
    *,
    run_sql: RunSql,
) -> list[str]:
    """Compare on-disk handoff JSON sha256 to ``static_analysis_runs.static_handoff_hash``."""

    issues: list[str] = []
    handoff = manifest.get("handoff")
    if not isinstance(handoff, Mapping):
        return issues
    runs = handoff.get("runs")
    if not isinstance(runs, list):
        return issues

    for i, run in enumerate(runs):
        if not isinstance(run, Mapping):
            continue
        sid = run.get("static_run_id")
        jp = run.get("json_path")
        if sid is None or not jp:
            continue
        path = Path(str(jp))
        if not path.is_file():
            continue
        digest, err = _sha256_file(path)
        if err or not digest:
            issues.append(f"db_handoff[{i}]:disk_hash_error:{err}")
            continue
        try:
            row = run_sql(
                "SELECT static_handoff_hash FROM static_analysis_runs WHERE id=%s",
                (int(sid),),
                fetch="one",
            )
        except Exception as exc:
            issues.append(f"db_handoff[{i}]:query_error:{exc.__class__.__name__}:{exc}")
            continue
        if row is None:
            sar_hash = None
        elif isinstance(row, dict):
            sar_hash = row.get("static_handoff_hash")
        else:
            sar_hash = row[0] if row else None
        if not sar_hash:
            continue
        if str(sar_hash).strip().lower() != digest.lower():
            issues.append(
                f"db_handoff[{i}]:sar_hash_mismatch_static_run_id={sid} "
                f"(manifest_disk_sha256_prefix={digest[:12]}…)"
            )
    return issues


def load_evidence_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


__all__ = [
    "load_evidence_manifest",
    "verify_evidence_manifest_payload",
    "verify_manifest_handoff_hash_vs_database",
]
