"""Freeze immutability verification (Paper #2).

Verifies that the frozen inputs for the included run set have not changed since
the freeze manifest was written.

Contract:
- Does not mutate evidence packs.
- Uses dataset_freeze.json as the citation anchor and source of expected hashes.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.utils.path_utils import resolve_contained_path
from scytaledroid.Utils.IO.atomic_write import atomic_write_text

REQUIRED_FROZEN_INPUTS = (
    "run_manifest.json",
    "inputs/static_dynamic_plan.json",
    "analysis/summary.json",
    "analysis/pcap_report.json",
    "analysis/pcap_features.json",
)


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class FreezeVerifyResult:
    freeze_path: str
    scanned: int
    mismatches: int
    missing: int
    issues: list[dict[str, Any]]


def verify_dataset_freeze_immutability(
    *,
    freeze_path: Path,
    evidence_root: Path,
    write_outputs: bool = True,
) -> FreezeVerifyResult:
    freeze = _read_json(freeze_path)
    if not isinstance(freeze, dict):
        raise RuntimeError(f"Invalid freeze JSON: {freeze_path}")

    included = freeze.get("included_run_ids") or []
    checksums = freeze.get("included_run_checksums") or {}
    if not isinstance(included, list) or not included:
        raise RuntimeError("Freeze file missing included_run_ids")
    if not isinstance(checksums, dict) or not checksums:
        raise RuntimeError("Freeze file missing included_run_checksums")

    issues: list[dict[str, Any]] = []
    scanned = 0
    missing = 0
    mismatches = 0

    seen_run_ids: set[str] = set()
    for raw_rid in included:
        if not isinstance(raw_rid, str) or not raw_rid.strip():
            missing += 1
            issues.append({"run_id": "", "issue": "invalid_run_id"})
            continue
        rid = raw_rid.strip()
        if rid in seen_run_ids:
            missing += 1
            issues.append({"run_id": rid[:8], "issue": "duplicate_run_id"})
            continue
        seen_run_ids.add(rid)
        run_dir = resolve_contained_path(evidence_root, rid)
        if run_dir is None:
            missing += 1
            issues.append({"run_id": rid[:8], "issue": "unsafe_run_id"})
            continue
        scanned += 1
        expected = checksums.get(rid)
        if not isinstance(expected, dict):
            missing += 1
            issues.append({"run_id": rid[:8], "issue": "missing_expected_checksums"})
            continue

        files = expected.get("files_sha256")
        if not isinstance(files, dict) or not files:
            missing += 1
            issues.append({"run_id": rid[:8], "issue": "missing_files_sha256"})
            continue

        for required_path in REQUIRED_FROZEN_INPUTS:
            if required_path not in files:
                missing += 1
                issues.append(
                    {
                        "run_id": rid[:8],
                        "issue": "missing_expected_checksum",
                        "path": required_path,
                    }
                )

        for rel, want in files.items():
            if (
                not isinstance(rel, str)
                or not isinstance(want, str)
                or not rel.strip()
                or not want.strip()
            ):
                missing += 1
                issues.append({"run_id": rid[:8], "issue": "invalid_checksum_entry"})
                continue
            path = resolve_contained_path(run_dir, rel)
            if path is None:
                missing += 1
                issues.append({"run_id": rid[:8], "issue": "unsafe_path", "path": rel})
                continue
            if not path.is_file():
                missing += 1
                issues.append({"run_id": rid[:8], "issue": "missing_file", "path": rel})
                continue
            got = _sha256_file(path)
            if got != want:
                mismatches += 1
                issues.append({"run_id": rid[:8], "issue": "sha_mismatch", "path": rel})

        pcap = expected.get("pcap")
        if isinstance(pcap, dict):
            rel = pcap.get("relative_path")
            want = pcap.get("sha256")
            if isinstance(rel, str) and rel and isinstance(want, str) and want:
                p = resolve_contained_path(run_dir, rel)
                if p is None:
                    missing += 1
                    issues.append({"run_id": rid[:8], "issue": "unsafe_path", "path": rel})
                elif p.is_file():
                    got = _sha256_file(p)
                    if got != want:
                        mismatches += 1
                        issues.append({"run_id": rid[:8], "issue": "sha_mismatch", "path": rel})
                else:
                    missing += 1
                    issues.append({"run_id": rid[:8], "issue": "missing_file", "path": rel})

    if write_outputs:
        out_dir = Path("output/batches/dynamic")
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        dest = out_dir / f"freeze-immutability-check-{stamp}.json"
        atomic_write_text(
            dest,
            json.dumps(
                {
                    "generated_at_utc": datetime.now(UTC).isoformat(),
                    "freeze_path": str(freeze_path),
                    "scanned": scanned,
                    "missing": missing,
                    "mismatches": mismatches,
                    "issues": issues,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
        )

    return FreezeVerifyResult(
        freeze_path=str(freeze_path),
        scanned=scanned,
        missing=missing,
        mismatches=mismatches,
        issues=issues,
    )


__all__ = [
    "FreezeVerifyResult",
    "REQUIRED_FROZEN_INPUTS",
    "verify_dataset_freeze_immutability",
]
