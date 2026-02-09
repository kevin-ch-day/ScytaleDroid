#!/usr/bin/env python3
"""Write a self-contained operational snapshot bundle (Phase F3).

Produces under output/operational/<snapshot_id>/:
- freeze_manifest.json (checksummed inputs)
- operational_lint.json (math/consistency lint)
- snapshot_bundle_manifest.json (sha256 inventory of snapshot files)
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]


def _sha256_file(path: Path) -> str:
    h = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _latest_snapshot(root: Path) -> Path | None:
    if not root.exists():
        return None
    snaps = sorted([p for p in root.iterdir() if p.is_dir()])
    if not snaps:
        return None

    # Prefer snapshots whose selection manifest points to existing evidence-pack paths.
    for snap in reversed(snaps):
        sel = snap / "selection_manifest.json"
        if not sel.exists():
            continue
        try:
            obj = json.loads(sel.read_text(encoding="utf-8"))
        except Exception:
            continue
        runs = ((obj.get("inclusion") or {}).get("runs")) if isinstance(obj.get("inclusion"), dict) else None
        if not isinstance(runs, dict):
            continue
        # If any evidence_pack_path exists, this snapshot is bundle-able.
        ok_any = False
        for meta in runs.values():
            if not isinstance(meta, dict):
                continue
            p = meta.get("evidence_pack_path")
            if isinstance(p, str) and p and Path(p).exists():
                ok_any = True
                break
        if ok_any:
            return snap
    # Fallback: newest.
    return snaps[-1]


@dataclass(frozen=True)
class BundleResult:
    snapshot_dir: Path
    ok: bool


def write_bundle(snapshot_dir: Path) -> BundleResult:
    from scytaledroid.Config import app_config
    from scytaledroid.DynamicAnalysis.ml.snapshot_freeze import write_snapshot_freeze_manifest
    from scytaledroid.DynamicAnalysis.ml.operational_lint import lint_operational_snapshot

    evidence_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    # Freeze manifest (checksummed). Best-effort: smoke snapshots may reference temp
    # evidence roots; fail-closed in linting but do not crash the bundler.
    freeze_res = None
    freeze_ok = True
    try:
        freeze_res = write_snapshot_freeze_manifest(snapshot_dir=snapshot_dir, evidence_root=evidence_root, overwrite=True)
    except Exception as exc:
        freeze_ok = False
        (snapshot_dir / "freeze_manifest_error.txt").write_text(str(exc) + "\n", encoding="utf-8")

    # Lint report.
    lint = lint_operational_snapshot(snapshot_dir)
    lint_path = snapshot_dir / "operational_lint.json"
    lint_path.write_text(json.dumps({"ok": lint.ok, "issues": lint.issues}, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # Bundle manifest: sha256 for all JSON/CSV/TEX/PNG under snapshot dir.
    manifest: dict[str, object] = {
        "artifact_type": "operational_snapshot_bundle_manifest",
        "created_at_utc": datetime.now(UTC).isoformat(),
        "snapshot_dir": str(snapshot_dir),
        "freeze_manifest": str(freeze_res.freeze_path) if freeze_res else "",
        "freeze_ok": bool(freeze_ok),
        "operational_lint": str(lint_path),
        "files": {},
    }
    files: dict[str, str] = {}
    for p in sorted(snapshot_dir.rglob("*")):
        if not p.is_file():
            continue
        if p.name.startswith("."):
            continue
        if p.suffix.lower() not in {".json", ".csv", ".tex", ".png", ".md"}:
            continue
        rel = str(p.relative_to(snapshot_dir))
        files[rel] = _sha256_file(p)
    manifest["files"] = files
    out = snapshot_dir / "snapshot_bundle_manifest.json"
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return BundleResult(snapshot_dir=snapshot_dir, ok=bool(lint.ok and freeze_ok))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", help="Path to output/operational/<snapshot_id> (default=latest).")
    args = ap.parse_args(argv)

    snap_root = ROOT / "output" / "operational"
    snap = Path(args.snapshot) if args.snapshot else _latest_snapshot(snap_root)
    if not snap:
        print(f"[FAIL] No operational snapshots found under {snap_root}")
        return 2

    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    res = write_bundle(snap)
    print(f"[OK] Wrote bundle manifest: {snap / 'snapshot_bundle_manifest.json'}")
    print(f"[{'OK' if res.ok else 'WARN'}] Operational lint: {'PASS' if res.ok else 'FAIL'}")
    return 0 if res.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
