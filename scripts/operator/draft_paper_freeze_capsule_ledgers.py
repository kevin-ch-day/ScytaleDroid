#!/usr/bin/env python3
"""Draft Paper-freeze APK and evidence capsule ledgers for human review."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Draft unreviewed APK/evidence ledgers from an explicit paper-freeze manifest.")
    parser.add_argument("--freeze-manifest", required=True, help="Paper-freeze manifest JSON.")
    parser.add_argument(
        "--paper-id",
        default="IEEE-CARS-2026",
        help="Stable submission-package identifier recorded in the drafts.",
    )
    parser.add_argument("--evidence-root", default="data/evidence/dynamic", help="Canonical dynamic evidence root.")
    parser.add_argument("--apk-store-root", default="data/store/apk/sha256", help="Canonical SHA-256 APK byte-store root.")
    parser.add_argument(
        "--display-name-map",
        default=str(REPO_ROOT / "scytaledroid" / "Publication" / "contracts" / "display_name_map.json"),
        help="Package-to-display-name JSON map used only for review labels.",
    )
    parser.add_argument("--out-dir", required=True, help="Output directory for draft ledger JSON files.")
    args = parser.parse_args(argv)

    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from scytaledroid.Publication.research_capsule_drafts import build_paper_freeze_ledger_drafts

    freeze_path = Path(args.freeze_manifest)
    freeze_manifest = json.loads(freeze_path.read_text(encoding="utf-8"))
    if not isinstance(freeze_manifest, dict):
        raise SystemExit("freeze manifest must contain a JSON object")
    display_name_map = json.loads(Path(args.display_name_map).read_text(encoding="utf-8"))
    if not isinstance(display_name_map, dict):
        raise SystemExit("display name map must contain a JSON object")
    apk_ledger, evidence_ledger = build_paper_freeze_ledger_drafts(
        freeze_manifest=freeze_manifest,
        repo_root=REPO_ROOT,
        evidence_root=args.evidence_root,
        display_name_by_package={str(package): str(name) for package, name in display_name_map.items()},
        apk_store_root=args.apk_store_root,
        paper_id=args.paper_id,
    )
    destination = Path(args.out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    apk_path = destination / f"{args.paper_id}_apk_ledger.draft.json"
    evidence_path = destination / f"{args.paper_id}_evidence_ledger.draft.json"
    apk_path.write_text(json.dumps(apk_ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    evidence_path.write_text(json.dumps(evidence_ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[COPY] draft APK ledger: {apk_path}")
    print(f"[COPY] draft evidence ledger: {evidence_path}")
    print("[WARN] Drafts are unreviewed and cannot satisfy Research Capsule readiness until approved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
