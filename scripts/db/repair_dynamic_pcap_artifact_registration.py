#!/usr/bin/env python3
"""Plan or apply non-destructive PCAP artifact registration repairs.

This script does not change quota, validity, tracker state, summaries, or DB
rows.  By default it only writes a repair plan for dynamic runs where a local
PCAP exists but run_manifest.json lacks a pcapdroid_capture artifact entry.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

PLAN_FIELDS = (
    "run_id",
    "package_name",
    "run_dir",
    "pcap_relative_path",
    "pcap_size_bytes",
    "pcap_sha256",
    "manifest_has_pcap_artifact",
    "repair_action",
    "applied",
    "limitation",
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", default=None, help="Dynamic evidence root; defaults to app_config output/evidence/dynamic.")
    parser.add_argument("--output-dir", default=None, help="Directory for repair plan outputs.")
    parser.add_argument("--run-id", action="append", default=[], help="Restrict to one or more dynamic run IDs.")
    parser.add_argument("--apply", action="store_true", help="Update run_manifest.json for safe missing-artifact repairs.")
    parser.add_argument("--stdout-json", action="store_true", help="Print summary JSON after writing outputs.")
    return parser


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]], *, fieldnames: Sequence[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames))
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def _dynamic_root() -> Path:
    from scytaledroid.Config import app_config

    return Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"


def _default_output_dir() -> Path:
    from scytaledroid.Config import app_config

    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")
    return Path(app_config.OUTPUT_DIR) / "audit" / "dynamic_pcap_artifact_registration_repair" / stamp


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _local_pcap_candidate(run_dir: Path, value: Any) -> Path | None:
    text = _norm_text(value)
    if not text:
        return None
    candidate = Path(text)
    if not candidate.is_absolute():
        candidate = run_dir / candidate
    try:
        candidate.resolve().relative_to(run_dir.resolve())
    except (OSError, ValueError):
        return None
    if candidate.is_file() and candidate.suffix.lower() in {".pcap", ".pcapng"}:
        return candidate
    return None


def _find_local_pcap(run_dir: Path, report: Mapping[str, Any] | None, meta: Mapping[str, Any] | None) -> Path | None:
    for value in (
        (report or {}).get("pcap_path"),
        (report or {}).get("pcap_capture_name"),
        (meta or {}).get("pcap_name"),
        (meta or {}).get("resolved_pcap_name"),
    ):
        candidate = _local_pcap_candidate(run_dir, value)
        if candidate is None and _norm_text(value) and not str(value).startswith("artifacts/"):
            candidate = _local_pcap_candidate(run_dir, Path("artifacts") / "pcapdroid_capture" / _norm_text(value))
        if candidate is not None:
            return candidate
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    for candidate in sorted(capture_dir.glob("*.pcap*")):
        if candidate.is_file() and candidate.suffix.lower() in {".pcap", ".pcapng"}:
            return candidate
    return None


def _pcap_artifact(manifest: Mapping[str, Any]) -> Mapping[str, Any] | None:
    for artifact in manifest.get("artifacts") or []:
        if isinstance(artifact, Mapping) and artifact.get("type") == "pcapdroid_capture":
            return artifact
    return None


def _manifest_package(manifest: Mapping[str, Any]) -> str:
    target = manifest.get("target") if isinstance(manifest.get("target"), Mapping) else {}
    return _norm_text(target.get("package_name")).lower()


def _plan_run(run_dir: Path) -> dict[str, Any] | None:
    manifest_path = run_dir / "run_manifest.json"
    manifest = _read_json(manifest_path)
    if not isinstance(manifest, dict):
        return None
    run_id = _norm_text(manifest.get("dynamic_run_id") or run_dir.name)
    report = _read_json(run_dir / "analysis" / "pcap_report.json")
    meta = _read_json(run_dir / "artifacts" / "pcapdroid_capture" / "pcapdroid_capture_meta.json")
    artifact = _pcap_artifact(manifest)
    local_pcap = _find_local_pcap(run_dir, report, meta)
    if artifact is not None:
        rel = _norm_text(artifact.get("relative_path"))
        exists = bool(rel and (run_dir / rel).is_file())
        if exists:
            return None
        if local_pcap is None:
            return None
        action = "review_path_mismatch"
        limitation = "manifest has pcapdroid_capture but registered path is missing; not auto-applied"
    else:
        if local_pcap is None:
            return None
        action = "add_missing_pcap_artifact"
        limitation = ""
    size = local_pcap.stat().st_size
    return {
        "run_id": run_id,
        "package_name": _manifest_package(manifest),
        "run_dir": str(run_dir),
        "pcap_relative_path": str(local_pcap.relative_to(run_dir)),
        "pcap_size_bytes": size,
        "pcap_sha256": _sha256(local_pcap),
        "manifest_has_pcap_artifact": int(artifact is not None),
        "repair_action": action,
        "applied": 0,
        "limitation": limitation,
    }


def _apply_plan_row(row: Mapping[str, Any]) -> bool:
    if row.get("repair_action") != "add_missing_pcap_artifact":
        return False
    run_dir = Path(str(row["run_dir"]))
    manifest_path = run_dir / "run_manifest.json"
    manifest = _read_json(manifest_path)
    if not isinstance(manifest, dict):
        return False
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        artifacts = []
        manifest["artifacts"] = artifacts
    if _pcap_artifact(manifest) is not None:
        return False
    artifacts.append(
        {
            "device_path": None,
            "origin": "host",
            "produced_by": "pcapdroid_capture",
            "pull_status": "n/a",
            "relative_path": str(row["pcap_relative_path"]),
            "sha256": str(row["pcap_sha256"]),
            "size_bytes": int(row["pcap_size_bytes"]),
            "type": "pcapdroid_capture",
        }
    )
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return True


def generate_report(
    *,
    evidence_root: Path | None = None,
    output_dir: Path | None = None,
    run_ids: Sequence[str] = (),
    apply: bool = False,
) -> dict[str, Any]:
    root = evidence_root or _dynamic_root()
    out = output_dir or _default_output_dir()
    out.mkdir(parents=True, exist_ok=True)
    run_filter = {_norm_text(value) for value in run_ids if _norm_text(value)}
    rows: list[dict[str, Any]] = []
    for manifest_path in sorted(root.glob("*/run_manifest.json")):
        run_dir = manifest_path.parent
        if run_filter and run_dir.name not in run_filter:
            manifest = _read_json(manifest_path) or {}
            if _norm_text(manifest.get("dynamic_run_id")) not in run_filter:
                continue
        row = _plan_run(run_dir)
        if row is not None:
            rows.append(row)
    applied_count = 0
    if apply:
        for row in rows:
            if _apply_plan_row(row):
                row["applied"] = 1
                applied_count += 1
    _write_csv(out / "pcap_artifact_registration_repair_plan.csv", rows, fieldnames=PLAN_FIELDS)
    summary = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "evidence_root": str(root.resolve()),
        "apply": bool(apply),
        "candidate_rows": len(rows),
        "safe_auto_repair_rows": sum(1 for row in rows if row.get("repair_action") == "add_missing_pcap_artifact"),
        "review_only_rows": sum(1 for row in rows if row.get("repair_action") != "add_missing_pcap_artifact"),
        "applied_rows": applied_count,
        "output_files": {
            "repair_plan_csv": str((out / "pcap_artifact_registration_repair_plan.csv").resolve()),
            "summary_json": str((out / "summary.json").resolve()),
        },
        "note": "Does not change quota, validity, tracker state, summaries, or DB rows.",
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    summary = generate_report(
        evidence_root=Path(args.evidence_root).resolve() if args.evidence_root else None,
        output_dir=Path(args.output_dir).resolve() if args.output_dir else None,
        run_ids=args.run_id,
        apply=bool(args.apply),
    )
    if args.stdout_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(json.dumps({"summary_json": summary["output_files"]["summary_json"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
