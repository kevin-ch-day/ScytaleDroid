#!/usr/bin/env python3
"""Run the staged dynamic evidence repair pipeline.

Dry-run is the default.  With --apply, this script still only delegates to
bounded/idempotent repair paths: PCAP artifact registration repair, dataset
validity repair from current artifacts, and evidence-pack DB reindex.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", default=None, help="Dynamic evidence root; defaults to output/evidence/dynamic.")
    parser.add_argument("--output-dir", default=None, help="Directory for the combined repair receipt bundle.")
    parser.add_argument("--run-id", action="append", default=[], help="Restrict manifest repair stages to one or more run IDs.")
    parser.add_argument("--apply", action="store_true", help="Apply safe manifest repairs and reindex current evidence into DB.")
    parser.add_argument(
        "--skip-db-reindex",
        action="store_true",
        help="With --apply, skip the full evidence-pack DB reindex stage.",
    )
    parser.add_argument("--stdout-json", action="store_true", help="Print the combined summary JSON.")
    return parser


def _default_evidence_root() -> Path:
    from scytaledroid.Config import app_config

    return Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"


def _default_output_dir() -> Path:
    from scytaledroid.Config import app_config

    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")
    return Path(app_config.OUTPUT_DIR) / "audit" / "dynamic_evidence_repair_pipeline" / stamp


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _run_pcap_artifact_registration(
    *,
    evidence_root: Path,
    output_dir: Path,
    run_ids: Sequence[str],
    apply: bool,
) -> dict[str, Any]:
    from scripts.db import repair_dynamic_pcap_artifact_registration as repair

    return repair.generate_report(
        evidence_root=evidence_root,
        output_dir=output_dir,
        run_ids=run_ids,
        apply=apply,
    )


def _run_dataset_validity_repair(
    *,
    evidence_root: Path,
    output_dir: Path,
    run_ids: Sequence[str],
    apply: bool,
) -> dict[str, Any]:
    from scripts.db import repair_dynamic_dataset_validity_from_artifacts as repair

    args: list[str] = [
        "--evidence-root",
        str(evidence_root),
        "--output-dir",
        str(output_dir),
    ]
    for run_id in run_ids:
        args.extend(["--run-id", run_id])
    if apply:
        args.append("--apply")
    rc = repair.main(args)
    if rc != 0:
        return {"ok": False, "return_code": rc, "summary_json": str(output_dir / "summary.json")}
    summary = _load_json(output_dir / "summary.json")
    summary["ok"] = True
    return summary


def _run_db_reindex(*, evidence_root: Path, output_dir: Path, apply: bool, skip_db_reindex: bool) -> dict[str, Any]:
    if not apply:
        return {"skipped": True, "reason": "dry_run"}
    if skip_db_reindex:
        return {"skipped": True, "reason": "operator_skipped"}

    from scytaledroid.DynamicAnalysis.storage.index_from_evidence import index_dynamic_evidence_packs_to_db

    result = index_dynamic_evidence_packs_to_db(evidence_root)
    result["generated_at_utc"] = datetime.now(UTC).isoformat()
    result["evidence_root"] = str(evidence_root.resolve())
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(output_dir / "summary.json", result)
    return result


def _run_db_snapshot() -> dict[str, Any]:
    try:
        from scytaledroid.Database.db_core import db_queries as q
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}

    checks = {
        "dynamic_sessions": "SELECT COUNT(*) AS n FROM dynamic_sessions",
        "dynamic_network_features": "SELECT COUNT(*) AS n FROM dynamic_network_features",
        "dynamic_network_indicators": "SELECT COUNT(*) AS n FROM dynamic_network_indicators",
        "dynamic_domain_reference": "SELECT COUNT(*) AS n FROM dynamic_domain_reference",
        "dynamic_domain_observations": "SELECT COUNT(*) AS n FROM dynamic_domain_observations",
    }
    out: dict[str, Any] = {"available": True, "tables": {}}
    for name, sql in checks.items():
        try:
            row = q.run_sql(sql, (), fetch="one", dictionary=True) or {}
            out["tables"][name] = int(row.get("n") or 0) if isinstance(row, Mapping) else 0
        except Exception as exc:  # noqa: BLE001
            out["tables"][name] = {"error": str(exc)}
    return out


def run_pipeline(
    *,
    evidence_root: Path | None = None,
    output_dir: Path | None = None,
    run_ids: Sequence[str] = (),
    apply: bool = False,
    skip_db_reindex: bool = False,
) -> dict[str, Any]:
    root = evidence_root or _default_evidence_root()
    out = output_dir or _default_output_dir()
    out.mkdir(parents=True, exist_ok=True)
    normalized_run_ids = [str(value).strip() for value in run_ids if str(value).strip()]

    stages: dict[str, Any] = {}
    stages["pcap_artifact_registration"] = _run_pcap_artifact_registration(
        evidence_root=root,
        output_dir=out / "01_pcap_artifact_registration",
        run_ids=normalized_run_ids,
        apply=apply,
    )
    stages["dataset_validity_repair"] = _run_dataset_validity_repair(
        evidence_root=root,
        output_dir=out / "02_dataset_validity_repair",
        run_ids=normalized_run_ids,
        apply=apply,
    )
    stages["db_reindex"] = _run_db_reindex(
        evidence_root=root,
        output_dir=out / "03_db_reindex",
        apply=apply,
        skip_db_reindex=skip_db_reindex,
    )
    stages["post_repair_dataset_validity_check"] = _run_dataset_validity_repair(
        evidence_root=root,
        output_dir=out / "04_post_repair_dataset_validity_check",
        run_ids=normalized_run_ids,
        apply=False,
    )
    stages["db_snapshot"] = _run_db_snapshot()

    summary = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "apply": bool(apply),
        "evidence_root": str(root.resolve()),
        "output_dir": str(out.resolve()),
        "run_ids": normalized_run_ids,
        "stages": stages,
        "combined_receipt_json": str((out / "summary.json").resolve()),
        "notes": [
            "Dry-run does not mutate manifests or DB.",
            "Apply does not relax quota, validity, or paper-eligibility policy.",
            "Post-repair dataset-validity candidates should be zero when existing artifacts are fully repaired.",
        ],
    }
    _write_json(out / "summary.json", summary)
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    summary = run_pipeline(
        evidence_root=Path(args.evidence_root).resolve() if args.evidence_root else None,
        output_dir=Path(args.output_dir).resolve() if args.output_dir else None,
        run_ids=args.run_id,
        apply=bool(args.apply),
        skip_db_reindex=bool(args.skip_db_reindex),
    )
    if args.stdout_json:
        print(json.dumps(summary, indent=2, sort_keys=True, default=str))
    else:
        print(json.dumps({"summary_json": summary["combined_receipt_json"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
