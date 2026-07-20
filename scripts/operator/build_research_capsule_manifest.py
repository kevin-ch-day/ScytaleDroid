#!/usr/bin/env python3
"""Write a hash-locked manifest for an explicit paper research capsule."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Publication.research_capsule import (  # noqa: E402
    build_research_capsule_manifest,
    sha256_file,
)
from scytaledroid.Publication.research_capsule_ledgers import (  # noqa: E402
    load_json_object,
    validate_db_export_spec,
    verify_apk_ledger,
    verify_db_export_receipt,
    verify_evidence_ledger,
)


def _item_argument(value: str) -> tuple[str, str]:
    role, separator, path = str(value).partition("=")
    if not separator or not role.strip() or not path.strip():
        raise argparse.ArgumentTypeError("items must be ROLE=PATH")
    return role.strip().lower(), path.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write a non-destructive research capsule manifest.")
    parser.add_argument("--paper-id", required=True, help="Stable paper identifier, for example paper3-submission.")
    parser.add_argument(
        "--item",
        action="append",
        default=[],
        type=_item_argument,
        metavar="ROLE=PATH",
        help="Explicit capsule input. Repeat for source, publication, freeze, apk, evidence, db_export, config, or replay_script.",
    )
    parser.add_argument("--require", action="append", default=[], help="Role required for ready_to_archive. Repeat as needed.")
    parser.add_argument("--archive-root", default="", help="Optional destination to verify, for example /mnt/MERCURY_DATA_V2.")
    parser.add_argument("--apk-ledger", default="", help="Reviewed APK selection ledger JSON.")
    parser.add_argument("--evidence-ledger", default="", help="Reviewed dynamic-evidence selection ledger JSON.")
    parser.add_argument("--db-export-spec", default="", help="Reviewed scoped DB-export specification JSON.")
    parser.add_argument("--db-export-receipt", default="", help="Completed scoped DB-export receipt JSON.")
    parser.add_argument("--out", default="", help="Manifest output path. Defaults under output/audit/research_capsules/.")
    args = parser.parse_args(argv)

    grouped: dict[str, list[str]] = {}
    for role, path in args.item:
        grouped.setdefault(role, []).append(path)

    selection_validation: dict[str, list[str]] = {}
    apk_ledger = None
    if args.apk_ledger:
        apk_ledger = load_json_object(args.apk_ledger)
        grouped.setdefault("apk_ledger", []).append(args.apk_ledger)
        selection_validation["apk_ledger"] = verify_apk_ledger(apk_ledger, repo_root=REPO_ROOT)
        if str(apk_ledger.get("paper_id") or "") != args.paper_id:
            selection_validation["apk_ledger"].append("paper_id:mismatch")
        for entry in apk_ledger.get("entries") or []:
            if isinstance(entry, dict) and str(entry.get("inclusion_disposition") or "").lower() == "included":
                selected_apk_path = str(entry.get("selected_apk_path") or "").strip()
                if selected_apk_path:
                    grouped.setdefault("apk", []).append(selected_apk_path)
    if args.evidence_ledger:
        evidence_ledger = load_json_object(args.evidence_ledger)
        grouped.setdefault("evidence_ledger", []).append(args.evidence_ledger)
        if apk_ledger is None:
            selection_validation["evidence_ledger"] = ["apk_ledger:required_for_evidence_verification"]
        else:
            selection_validation["evidence_ledger"] = verify_evidence_ledger(
                evidence_ledger,
                repo_root=REPO_ROOT,
                apk_ledger=apk_ledger,
            )
        if str(evidence_ledger.get("paper_id") or "") != args.paper_id:
            selection_validation["evidence_ledger"].append("paper_id:mismatch")
        for entry in evidence_ledger.get("entries") or []:
            if not isinstance(entry, dict):
                continue
            pcap = entry.get("pcap")
            if isinstance(pcap, dict):
                pcap_path = str(pcap.get("path") or "").strip()
                if pcap_path:
                    grouped.setdefault("evidence", []).append(pcap_path)
            for artifact in entry.get("artifacts") or []:
                if isinstance(artifact, dict):
                    artifact_path = str(artifact.get("path") or "").strip()
                    if artifact_path:
                        grouped.setdefault("evidence", []).append(artifact_path)
    if args.db_export_spec:
        grouped.setdefault("db_export_spec", []).append(args.db_export_spec)
        db_export_spec = load_json_object(args.db_export_spec)
        selection_validation["db_export_spec"] = validate_db_export_spec(db_export_spec)
        if str(db_export_spec.get("paper_id") or "") != args.paper_id:
            selection_validation["db_export_spec"].append("paper_id:mismatch")
    if args.db_export_receipt:
        grouped.setdefault("db_export", []).append(args.db_export_receipt)
        db_export_receipt = load_json_object(args.db_export_receipt)
        export_path = str(db_export_receipt.get("export_path") or "").strip()
        if export_path:
            grouped.setdefault("db_export", []).append(export_path)
        selection_validation["db_export_receipt"] = verify_db_export_receipt(
            db_export_receipt,
            repo_root=REPO_ROOT,
            expected_paper_id=args.paper_id,
        )

    required_roles = [*args.require, "apk_ledger", "evidence_ledger", "db_export_spec", "apk", "evidence", "db_export"]
    manifest = build_research_capsule_manifest(
        paper_id=args.paper_id,
        repo_root=REPO_ROOT,
        items=grouped,
        required_roles=required_roles,
        archive_root=args.archive_root or None,
        selection_validation=selection_validation,
    )
    if args.out:
        destination = Path(args.out)
    else:
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        destination = REPO_ROOT / "output" / "audit" / "research_capsules" / args.paper_id / f"manifest_{timestamp}.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[COPY] research_capsule_manifest path='{destination}' sha256={sha256_file(destination)}")
    print(f"[{'OK' if manifest['ready_to_archive'] else 'WARN'}] ready_to_archive={manifest['ready_to_archive']}")
    if manifest["missing_required_roles"]:
        print("[WARN] missing required roles: " + ", ".join(manifest["missing_required_roles"]))
    if manifest["missing_items"]:
        print("[WARN] missing items: " + ", ".join(manifest["missing_items"]))
    if manifest["unresolved_selection"]:
        print("[WARN] unresolved ledger checks: " + ", ".join(manifest["unresolved_selection"]))
    return 0 if manifest["ready_to_archive"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
