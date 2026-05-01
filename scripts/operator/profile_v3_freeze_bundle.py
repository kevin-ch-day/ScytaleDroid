#!/usr/bin/env python3
"""Profile v3 freeze bundle manifest (single-file audit anchor).

Goal: produce one machine-verifiable JSON that pins:
- provenance (commit/dirty/strict/fail-on-dirty)
- inputs (catalog/manifest/snapshot + hashes)
- effective minima values (windows/pcap by phase)
- included run_ids
- publication artifacts + hashes
- lint outcome + receipts

This is not required for capture, but it makes "Paper #3 is reproducible" easy to
defend with one attachment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Publication.paper_mode import PaperModeContext  # noqa: E402
from scytaledroid.DynamicAnalysis.utils.profile_v3_minima import (  # noqa: E402
    effective_min_pcap_bytes_idle,
    effective_min_pcap_bytes_scripted,
    effective_min_windows_per_run,
)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _rjson(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object: {path}")
    return payload


def _artifact_list(root: Path) -> list[dict[str, object]]:
    # Hash only the paper-facing publication bundle, deterministically ordered.
    artifacts: list[dict[str, object]] = []
    if not root.exists():
        return artifacts
    for p in sorted([x for x in root.rglob("*") if x.is_file()]):
        rel = p.relative_to(root).as_posix()
        # Skip large caches and transient files if they appear.
        if rel.startswith(".") or rel.endswith(".pyc"):
            continue
        artifacts.append(
            {
                "path": rel,
                "sha256": _sha256_file(p),
                "size_bytes": int(p.stat().st_size),
            }
        )
    return artifacts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Write Profile v3 freeze bundle manifest JSON.")
    ap.add_argument(
        "--snapshot",
        required=True,
        help="Pinned inventory snapshot used for freshness gates/harvest window.",
    )
    ap.add_argument(
        "--catalog",
        default=str(REPO_ROOT / "profiles" / "profile_v3_app_catalog.json"),
        help="Profile v3 catalog path.",
    )
    ap.add_argument(
        "--manifest",
        default=str(REPO_ROOT / "data" / "archive" / "profile_v3_manifest.json"),
        help="Profile v3 included runs manifest path.",
    )
    ap.add_argument(
        "--publication-root",
        default=str(REPO_ROOT / "output" / "publication" / "profile_v3"),
        help="Publication root to hash.",
    )
    ap.add_argument(
        "--provenance-receipt",
        default="",
        help="Optional provenance receipt path (output/audit/provenance/provenance_*.json).",
    )
    ap.add_argument(
        "--gates-receipt",
        default="",
        help="Optional v3 gates receipt path (output/audit/profile_v3/integrity_gates_*.json).",
    )
    ap.add_argument(
        "--out",
        default="",
        help="Output path. Default: output/audit/profile_v3/profile_v3_freeze_bundle_<UTC>.json",
    )
    args = ap.parse_args(argv)

    mode = PaperModeContext.detect(repo_root=REPO_ROOT)
    mode.apply_env()

    snapshot_path = Path(args.snapshot)
    catalog_path = Path(args.catalog)
    manifest_path = Path(args.manifest)
    pub_root = Path(args.publication_root)
    prov_receipt = Path(args.provenance_receipt) if str(args.provenance_receipt).strip() else None
    gates_receipt = Path(args.gates_receipt) if str(args.gates_receipt).strip() else None

    out_path: Path
    if str(args.out).strip():
        out_path = Path(args.out)
    else:
        out_dir = REPO_ROOT / "output" / "audit" / "profile_v3"
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        out_path = out_dir / f"profile_v3_freeze_bundle_{ts}.json"

    included: list[str] = []
    unique_pkgs: list[str] = []
    if manifest_path.exists():
        try:
            m = _rjson(manifest_path)
            ids = m.get("included_run_ids")
            if isinstance(ids, list):
                included = [str(x).strip() for x in ids if str(x).strip()]
            meta = m.get("included_run_metadata")
            if isinstance(meta, dict):
                pkgs = {str(v.get("package") or "").strip() for v in meta.values() if isinstance(v, dict)}
                unique_pkgs = sorted({p for p in pkgs if p})
        except Exception:
            pass

    bundle: dict[str, object] = {
        "schema_version": 1,
        "profile_id": "profile_v3_structural",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        **mode.receipt_fields(),
        "flags": {
            "paper_strict_env": str(os.environ.get("SCYTALEDROID_PAPER_STRICT") or "").strip() or "0",
            "fail_on_dirty_env": str(os.environ.get("SCYTALEDROID_FAIL_ON_DIRTY") or "").strip() or "0",
        },
        "inputs": {
            "snapshot_path": str(snapshot_path),
            "snapshot_sha256": _sha256_file(snapshot_path) if snapshot_path.exists() else "",
            "catalog_path": str(catalog_path),
            "catalog_sha256": _sha256_file(catalog_path) if catalog_path.exists() else "",
            "manifest_path": str(manifest_path),
            "manifest_sha256": _sha256_file(manifest_path) if manifest_path.exists() else "",
        },
        "minima_effective": {
            "min_windows_per_run": int(effective_min_windows_per_run()),
            "min_pcap_bytes_idle": int(effective_min_pcap_bytes_idle()),
            "min_pcap_bytes_scripted": int(effective_min_pcap_bytes_scripted()),
        },
        "cohort": {
            "included_run_ids_count": int(len(included)),
            "included_run_ids": included,
            "unique_packages_in_manifest": int(len(unique_pkgs)),
            "packages": unique_pkgs,
        },
        "receipts": {},
        "publication": {
            "root": str(pub_root),
            "root_sha256_tree": "",
            "artifacts": [],
        },
    }

    receipts: dict[str, object] = {}
    if prov_receipt and prov_receipt.exists():
        receipts["provenance_receipt"] = {"path": str(prov_receipt), "sha256": _sha256_file(prov_receipt)}
    if gates_receipt and gates_receipt.exists():
        receipts["gates_receipt"] = {"path": str(gates_receipt), "sha256": _sha256_file(gates_receipt)}
    # Stable publication receipts (written by export/lint).
    export_receipt = pub_root / "qa" / "profile_v3_export_receipt.json"
    if export_receipt.exists():
        receipts["export_receipt"] = {"path": str(export_receipt), "sha256": _sha256_file(export_receipt)}
    lint_receipt = pub_root / "qa" / "profile_v3_lint_receipt.json"
    if lint_receipt.exists():
        receipts["lint_receipt"] = {"path": str(lint_receipt), "sha256": _sha256_file(lint_receipt)}
    bundle["receipts"] = receipts

    artifacts = _artifact_list(pub_root)
    bundle["publication"]["artifacts"] = artifacts
    # Tree hash (stable over artifacts ordering) for quick comparisons.
    if artifacts:
        h = hashlib.sha256()
        for a in artifacts:
            h.update(str(a["path"]).encode("utf-8"))
            h.update(b"\0")
            h.update(str(a["sha256"]).encode("utf-8"))
            h.update(b"\0")
        bundle["publication"]["root_sha256_tree"] = h.hexdigest()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
    print(f"[COPY] v3_freeze_bundle path='{out_path.relative_to(REPO_ROOT)}' sha256={_sha256_file(out_path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

