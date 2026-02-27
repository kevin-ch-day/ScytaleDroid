#!/usr/bin/env python3
"""Build a self-contained Profile v3 manifest (no runtime extension).

This is a convenience tool for composing:
- imported runs from an existing freeze (e.g., v2)
- additional run IDs for the new apps

It writes a standalone manifest at the requested output path. It does NOT:
- compute run checksums
- validate ML artifacts
- modify any evidence packs
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.DynamicAnalysis.run_profile_norm import (  # noqa: E402
    normalize_run_profile,
    phase_from_normalized_profile,
    resolve_run_profile_from_manifest,
)


def _sha256_file(path: Path) -> str:
    import hashlib

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


def _load_run_ids_arg(values: list[str]) -> list[str]:
    out: list[str] = []
    for v in values:
        s = str(v).strip()
        if not s:
            continue
        # Allow @file syntax (one run id per line).
        if s.startswith("@"):
            p = Path(s[1:])
            for line in p.read_text(encoding="utf-8").splitlines():
                rid = line.strip()
                if rid and not rid.startswith("#"):
                    out.append(rid)
            continue
        out.append(s)
    return out


def _rjson_file(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object: {path}")
    return payload


def _read_run_manifest(evidence_root: Path, run_id: str) -> dict:
    p = evidence_root / run_id / "run_manifest.json"
    if not p.exists():
        raise SystemExit(f"Missing run_manifest.json for run_id={run_id}: {p}")
    return _rjson_file(p)


def _run_identity(manifest: dict) -> dict:
    tgt = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
    ident = tgt.get("run_identity") if isinstance(tgt.get("run_identity"), dict) else {}
    return ident


def _run_package(manifest: dict) -> str:
    tgt = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
    pkg = str(tgt.get("package_name") or tgt.get("package") or "").strip()
    if not pkg:
        raise SystemExit("run_manifest missing target.package_name")
    return pkg


def _include_run_id(
    *,
    evidence_root: Path,
    run_id: str,
    allow_manual_interaction: bool,
) -> tuple[bool, dict]:
    """Return (include?, metadata) for a run_id."""

    man = _read_run_manifest(evidence_root, run_id)
    pkg = _run_package(man)
    rp = resolve_run_profile_from_manifest(man, strict_conflict=True).normalized
    rp = normalize_run_profile(rp)
    phase = phase_from_normalized_profile(rp)
    if rp == "interaction_manual" and not allow_manual_interaction:
        return False, {
            "run_id": run_id,
            "package": pkg,
            "run_profile": rp,
            "phase": phase,
            "excluded_reason": "manual_interaction_excluded",
        }
    ident = _run_identity(man)
    meta = {
        "run_id": run_id,
        "package": pkg,
        "run_profile": rp,
        "phase": phase,
        "version_code": str(ident.get("version_code") or ident.get("observed_version_code") or "").strip(),
        "version_name": str(ident.get("version_name") or "").strip(),
        "base_apk_sha256": str(ident.get("base_apk_sha256") or "").strip(),
        "device_serial": str((man.get("environment") or {}).get("device_serial") or "").strip(),
        "build_fingerprint": str((man.get("environment") or {}).get("build_fingerprint") or "").strip(),
    }
    return True, meta


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build profile v3 structural manifest (standalone)")
    p.add_argument(
        "--base-freeze",
        default=str(REPO_ROOT / "data" / "archive" / "dataset_freeze.json"),
        help="Path to base freeze (used only for provenance refs + optional imported runs).",
    )
    p.add_argument(
        "--import-from-base",
        action="store_true",
        help="If set, import baseline + interactive runs from the base freeze apps map (deterministic).",
    )
    p.add_argument(
        "--add-run-id",
        action="append",
        default=[],
        help="Additional run IDs to include. Repeat flag, or use @file.txt (one per line).",
    )
    p.add_argument(
        "--evidence-root",
        default=str(REPO_ROOT / "output" / "evidence" / "dynamic"),
        help="Dynamic evidence root containing run directories.",
    )
    p.add_argument(
        "--allow-manual-interaction",
        action="store_true",
        help="Allow interaction_manual runs in the composed v3 manifest (default: excluded).",
    )
    p.add_argument(
        "--allow-mixed-versions",
        action="store_true",
        help="Allow a package to appear with multiple version_code values across included runs (default: fail-closed).",
    )
    p.add_argument(
        "--out",
        default=str(REPO_ROOT / "data" / "archive" / "profile_v3_manifest.json"),
        help="Output manifest path.",
    )
    args = p.parse_args(argv)

    base_path = Path(args.base_freeze)
    base = _rjson(base_path)
    base_sha = _sha256_file(base_path)
    base_hash = str(base.get("freeze_dataset_hash") or "").strip()
    base_included = base.get("included_run_ids") if isinstance(base.get("included_run_ids"), list) else []
    base_included = [str(r).strip() for r in base_included if str(r).strip()]

    evidence_root = Path(args.evidence_root)

    included: list[str] = []
    if args.import_from_base:
        apps = base.get("apps") if isinstance(base.get("apps"), dict) else {}
        for pkg in sorted(apps.keys()):
            meta = apps[pkg] if isinstance(apps.get(pkg), dict) else {}
            baselines = meta.get("baseline_run_ids") if isinstance(meta.get("baseline_run_ids"), list) else []
            inters = meta.get("interactive_run_ids") if isinstance(meta.get("interactive_run_ids"), list) else []
            for rid in baselines + inters:
                included.append(str(rid).strip())
    included.extend(_load_run_ids_arg(list(args.add_run_id)))

    # De-dup while preserving order.
    seen = set()
    deduped = []
    for r in included:
        if r in seen:
            continue
        seen.add(r)
        deduped.append(r)
    included = deduped

    # Filter / annotate runs.
    include_meta: dict[str, dict] = {}
    excluded: list[dict] = []
    for rid in included:
        ok, meta = _include_run_id(
            evidence_root=evidence_root,
            run_id=rid,
            allow_manual_interaction=bool(args.allow_manual_interaction),
        )
        if ok:
            include_meta[rid] = meta
        else:
            excluded.append(meta)

    included = [rid for rid in included if rid in include_meta]

    # Version consistency (paper-grade default).
    by_pkg: dict[str, set[str]] = {}
    for rid, meta in include_meta.items():
        pkg = str(meta.get("package") or "")
        vc = str(meta.get("version_code") or "")
        if not vc:
            continue
        by_pkg.setdefault(pkg, set()).add(vc)
    if not bool(args.allow_mixed_versions):
        mixed = {pkg: sorted(list(vs)) for pkg, vs in by_pkg.items() if len(vs) > 1}
        if mixed:
            raise SystemExit(f"PROFILE_V3_MIXED_PACKAGE_VERSIONS: {mixed}")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "profile_id": "profile_v3_structural",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "included_run_ids": included,
        "included_run_checksums": {},
        "included_run_metadata": include_meta,
        "excluded_run_metadata": excluded,
        "package_versions": {pkg: sorted(list(vs)) for pkg, vs in by_pkg.items()},
        "inputs": {
            "base_freeze_refs": [
                {
                    "profile_id": "profile_v2",
                    "freeze_path": str(base_path),
                    "freeze_sha256": base_sha,
                    "freeze_dataset_hash": base_hash or None,
                    "runs_imported": int(len(base_included)) if args.import_from_base else 0,
                }
            ]
        },
        "notes": {
            "capture_policy": "personal_account_only_no_mdm",
            "aggregation": "run_balanced_means_pooled_idle_sd_ddof_1",
            "exceedance_operator": ">",
            "primary_engine": "iforest",
            "allow_manual_interaction": bool(args.allow_manual_interaction),
            "allow_mixed_versions": bool(args.allow_mixed_versions),
        },
    }
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(f"[OK] Wrote: {out_path}")
    print(f"[OK] included_run_ids: {len(included)}")
    if excluded:
        print(f"[WARN] excluded_run_ids: {len(excluded)} (see excluded_run_metadata in manifest)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
