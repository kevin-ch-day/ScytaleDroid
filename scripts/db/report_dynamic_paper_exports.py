#!/usr/bin/env python3
"""Read-only paper-facing exports over dynamic evidence packs and enriched PCAP metadata."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=None, help="Optional explicit output directory.")
    return parser


def _dynamic_root() -> Path:
    from scytaledroid.Config import app_config

    return Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fields:
                fields.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fields})


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _interaction_mode(run_profile: str, interaction_level: str) -> str:
    profile = str(run_profile or "").strip().lower()
    level = str(interaction_level or "").strip().lower()
    if "baseline" in profile:
        return "baseline"
    if "manual" in profile:
        return "manual"
    if "script" in profile:
        return "scripted"
    if level:
        return level
    return "unknown"


def _summarize_missing_artifacts(run_dir: Path, manifest: dict[str, Any], issues: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    missing: list[str] = []
    pcap_present = False
    artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), list) else []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        if artifact.get("type") == "pcapdroid_capture":
            rel = str(artifact.get("relative_path") or "").strip()
            if rel and (run_dir / rel).exists():
                pcap_present = True
            else:
                missing.append(rel or "pcapdroid_capture")
    for issue in issues:
        code = str(issue.get("code") or "")
        message = str(issue.get("message") or "")
        if code in {"missing_frozen_input", "pcap_artifact_missing", "pcap_file_missing"}:
            missing.append(message)
    return pcap_present, sorted({item for item in missing if item})


def _evidence_status(*, verify_row: dict[str, Any], report_status: str, missing_artifacts: list[str]) -> str:
    issue_codes = {str(issue.get("code") or "") for issue in (verify_row.get("issues") or []) if isinstance(issue, dict)}
    valid_dataset_run = verify_row.get("valid_dataset_run")
    if "pcap_artifact_missing" in issue_codes or "pcap_file_missing" in issue_codes:
        return "legacy_broken_skipped"
    if report_status == "skip":
        return "skipped"
    if valid_dataset_run is True:
        return "valid"
    if valid_dataset_run is False:
        return "invalid"
    if missing_artifacts:
        return "skipped"
    return "review"


def _recommended_action(status: str, verify_row: dict[str, Any]) -> str:
    issue_codes = {str(issue.get("code") or "") for issue in (verify_row.get("issues") or []) if isinstance(issue, dict)}
    if status == "legacy_broken_skipped":
        return "recollect this legacy run or exclude it from the paper corpus"
    if status == "skipped":
        return "restore missing evidence inputs and rerun PCAP analysis"
    if status == "invalid":
        if verify_row.get("invalid_reason_code"):
            return f"review dataset validity: {verify_row.get('invalid_reason_code')}"
        if issue_codes:
            return "review evidence-pack QA issues before including in paper exports"
        return "review invalid dataset run before paper inclusion"
    return "none"


def _collect_unresolved_signal_rows(
    service_context: dict[str, Any],
    service_signals: dict[str, Any],
) -> list[dict[str, Any]]:
    unresolved: list[dict[str, Any]] = []
    missing_services = {
        str(item)
        for item in (service_signals.get("services_without_signal_mappings") or [])
        if str(item or "").strip()
    }
    if not missing_services:
        return unresolved
    for service in service_context.get("services") or []:
        if not isinstance(service, dict):
            continue
        service_key = str(service.get("service_key") or "")
        if service_key not in missing_services:
            continue
        for domain in service.get("domains") or []:
            if not isinstance(domain, dict):
                continue
            unresolved.append(
                {
                    "service_key": service_key,
                    "service_display_name": service.get("service_display_name"),
                    "domain": domain.get("domain"),
                    "root_domain": domain.get("root_domain"),
                    "observed_count": int(domain.get("total_hits") or 0),
                    "reason": "signal_unmapped",
                    "suggested_context": service.get("service_category"),
                }
            )
    return unresolved


def generate_report(*, output_dir: Path | None = None) -> dict[str, Any]:
    from scytaledroid.DynamicAnalysis.tools.evidence.verify_core import verify_dynamic_evidence_packs
    from scytaledroid.DynamicAnalysis.pcap.context_summary import summarize_pcap_service_context

    root = _dynamic_root()
    verify_report = verify_dynamic_evidence_packs(root)
    verify_by_run = {str(row.get("run_id") or ""): row for row in verify_report.get("runs") or [] if isinstance(row, dict)}

    per_run_rows: list[dict[str, Any]] = []
    unresolved_domain_rows: list[dict[str, Any]] = []
    invalid_or_skipped_rows: list[dict[str, Any]] = []

    per_app_valid_runs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    service_rollup: dict[tuple[str, str], dict[str, Any]] = {}
    signal_rollup: dict[tuple[str, str], dict[str, Any]] = {}
    matrix_rollup: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    package_labels: dict[str, str] = {}
    package_top_services: dict[str, Counter[str]] = defaultdict(Counter)
    package_top_signals: dict[str, Counter[str]] = defaultdict(Counter)

    for manifest_path in sorted(root.glob("*/run_manifest.json")):
        run_dir = manifest_path.parent
        manifest = _read_json(manifest_path) or {}
        run_id = str(manifest.get("dynamic_run_id") or run_dir.name)
        verify_row = verify_by_run.get(run_id, {})
        report = _read_json(run_dir / "analysis" / "pcap_report.json") or {}
        features = _read_json(run_dir / "analysis" / "pcap_features.json") or {}

        target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
        operator = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
        package = str((target or {}).get("package_name") or "").strip().lower() or "_unknown"
        app_label = str((target or {}).get("display_name") or (target or {}).get("app_label") or package)
        package_labels[package] = app_label
        run_profile = str((operator or {}).get("run_profile") or (manifest.get("dataset") or {}).get("run_profile") or "")
        interaction_level = str((operator or {}).get("interaction_level") or "")
        interaction_mode = _interaction_mode(run_profile, interaction_level)
        current_context = summarize_pcap_service_context(report, package_name=package)
        service_context = current_context.get("service_context") if isinstance(current_context.get("service_context"), dict) else {}
        service_signals = current_context.get("service_signals") if isinstance(current_context.get("service_signals"), dict) else {}
        service_rows = [row for row in (service_context.get("services") or []) if isinstance(row, dict)]
        signal_rows = [row for row in (service_signals.get("signals") or []) if isinstance(row, dict)]
        unresolved_signal_rows = _collect_unresolved_signal_rows(service_context, service_signals)
        pcap_present, missing_artifacts = _summarize_missing_artifacts(run_dir, manifest, verify_row.get("issues") or [])
        protocol_hierarchy_present = bool(report.get("protocol_hierarchy")) if isinstance(report, dict) else False
        report_status = str(report.get("report_status") or "missing")
        evidence_status = _evidence_status(
            verify_row=verify_row,
            report_status=report_status,
            missing_artifacts=missing_artifacts,
        )
        valid_pack = bool(verify_row.get("valid_dataset_run") is True and report_status == "ok")

        per_run_row = {
            "package": package,
            "app_label": app_label,
            "run_id": run_id,
            "run_profile": run_profile,
            "interaction_mode": interaction_mode,
            "evidence_status": evidence_status,
            "report_status": report_status,
            "valid_pack": int(valid_pack),
            "domain_count": int(service_context.get("observed_domain_count") or 0),
            "service_count": int(service_context.get("service_count") or 0),
            "signal_count": int(service_signals.get("signal_count") or 0),
            "unresolved_service_count": int(service_context.get("unresolved_domain_count") or 0),
            "unresolved_signal_count": len(unresolved_signal_rows),
            "pcap_present": int(pcap_present),
            "protocol_hierarchy_present": int(protocol_hierarchy_present),
        }
        per_run_rows.append(per_run_row)

        if evidence_status != "valid":
            invalid_or_skipped_rows.append(
                {
                    "package": package,
                    "app_label": app_label,
                    "run_id": run_id,
                    "evidence_path": str(run_dir.resolve()),
                    "status": evidence_status,
                    "reason": "; ".join(sorted({str(issue.get("code") or "") for issue in (verify_row.get("issues") or []) if isinstance(issue, dict)})),
                    "missing_artifacts": "; ".join(missing_artifacts),
                    "recommended_action": _recommended_action(evidence_status, verify_row),
                }
            )

        for row in (service_context.get("unresolved_domains") or []):
            if not isinstance(row, dict):
                continue
            unresolved_domain_rows.append(
                {
                    "package": package,
                    "app_label": app_label,
                    "domain": row.get("domain"),
                    "reason": "service_unresolved",
                    "observed_count": int(row.get("total_hits") or 0),
                    "suggested_context": row.get("root_domain"),
                }
            )
        for row in unresolved_signal_rows:
            unresolved_domain_rows.append(
                {
                    "package": package,
                    "app_label": app_label,
                    "domain": row.get("domain"),
                    "reason": row.get("reason"),
                    "observed_count": int(row.get("observed_count") or 0),
                    "suggested_context": row.get("suggested_context"),
                }
            )

        if not valid_pack:
            continue

        per_app_valid_runs[package].append(per_run_row)
        for service in service_rows:
            service_key = str(service.get("service_key") or "")
            if not service_key:
                continue
            package_top_services[package][service_key] += int(service.get("total_hits") or 0)
            key = (package, service_key)
            row = service_rollup.setdefault(
                key,
                {
                    "package": package,
                    "app_label": app_label,
                    "service_key": service_key,
                    "provider_or_owner": service.get("owner_name"),
                    "role_or_category": service.get("service_category") or service.get("owner_class"),
                    "run_ids": set(),
                    "domains": set(),
                    "evidence_count": 0,
                },
            )
            row["run_ids"].add(run_id)
            for domain in service.get("domains") or []:
                if isinstance(domain, dict):
                    row["domains"].add(str(domain.get("domain") or ""))
            row["evidence_count"] = int(row.get("evidence_count") or 0) + int(service.get("total_hits") or 0)
            owner_class = str(service.get("owner_class") or "")
            service_category = str(service.get("service_category") or "")
            if owner_class:
                matrix_rollup[package][f"owner__{owner_class}"] += int(service.get("total_hits") or 0)
            if service_category:
                matrix_rollup[package][f"service__{service_category}"] += int(service.get("total_hits") or 0)
        for signal in signal_rows:
            signal_key = str(signal.get("signal_key") or "")
            if not signal_key:
                continue
            package_top_signals[package][signal_key] += int(signal.get("total_hits") or 0)
            key = (package, signal_key)
            row = signal_rollup.setdefault(
                key,
                {
                    "package": package,
                    "app_label": app_label,
                    "signal_key": signal_key,
                    "signal_category": signal.get("signal_family") or signal.get("focus_area"),
                    "run_ids": set(),
                    "domains": set(),
                    "evidence_count": 0,
                },
            )
            row["run_ids"].add(run_id)
            for service in signal.get("services") or []:
                if isinstance(service, dict):
                    row["domains"].add(str(service.get("domain") or ""))
            row["evidence_count"] = int(row.get("evidence_count") or 0) + int(signal.get("total_hits") or 0)
            signal_family = str(signal.get("signal_family") or "")
            focus_area = str(signal.get("focus_area") or "")
            if signal_family:
                matrix_rollup[package][f"signal__{signal_family}"] += int(signal.get("total_hits") or 0)
            if focus_area:
                matrix_rollup[package][f"focus__{focus_area}"] += int(signal.get("total_hits") or 0)

    per_app_rows: list[dict[str, Any]] = []
    all_packages = sorted({row["package"] for row in per_run_rows})
    for package in all_packages:
        valid_rows = per_app_valid_runs.get(package, [])
        all_rows = [row for row in per_run_rows if row["package"] == package]
        valid_run_ids = {row["run_id"] for row in valid_rows}
        invalid_rows = [row for row in all_rows if row["run_id"] not in valid_run_ids]
        service_keys = {key for pkg, key in service_rollup if pkg == package}
        signal_keys = {key for pkg, key in signal_rollup if pkg == package}
        unresolved_service_count = sum(int(row["unresolved_service_count"]) for row in valid_rows)
        unresolved_signal_count = sum(int(row["unresolved_signal_count"]) for row in valid_rows)
        observed_domain_count = 0
        for (pkg, _service_key), row in service_rollup.items():
            if pkg == package:
                observed_domain_count += len(row["domains"])
        per_app_rows.append(
            {
                "package": package,
                "app_label": package_labels.get(package, package),
                "valid_run_count": len(valid_rows),
                "skipped_or_invalid_run_count": len(invalid_rows),
                "observed_domain_count": observed_domain_count,
                "service_count": len(service_keys),
                "signal_count": len(signal_keys),
                "unresolved_service_count": unresolved_service_count,
                "unresolved_signal_count": unresolved_signal_count,
            }
        )

    per_app_service_rows = []
    for (_package, _service_key), row in sorted(service_rollup.items()):
        per_app_service_rows.append(
            {
                "package": row["package"],
                "app_label": row["app_label"],
                "service_key": row["service_key"],
                "provider_or_owner": row["provider_or_owner"],
                "role_or_category": row["role_or_category"],
                "run_count": len(row["run_ids"]),
                "domain_count": len({item for item in row["domains"] if item}),
                "evidence_count": int(row["evidence_count"] or 0),
            }
        )

    per_app_signal_rows = []
    for (_package, _signal_key), row in sorted(signal_rollup.items()):
        per_app_signal_rows.append(
            {
                "package": row["package"],
                "app_label": row["app_label"],
                "signal_key": row["signal_key"],
                "signal_category": row["signal_category"],
                "run_count": len(row["run_ids"]),
                "domain_count": len({item for item in row["domains"] if item}),
                "evidence_count": int(row["evidence_count"] or 0),
            }
        )

    matrix_columns = sorted({column for values in matrix_rollup.values() for column in values.keys()})
    provider_signal_matrix_rows = []
    for package in sorted(matrix_rollup):
        row = {
            "package": package,
            "app_label": package_labels.get(package, package),
        }
        for column in matrix_columns:
            row[column] = int(matrix_rollup[package].get(column, 0))
        provider_signal_matrix_rows.append(row)

    output_root = output_dir or (_REPO_ROOT / "output" / "audit" / "dynamic_paper_exports" / datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S"))
    output_root.mkdir(parents=True, exist_ok=True)
    _write_csv(output_root / "per_run_summary.csv", per_run_rows)
    _write_csv(output_root / "per_app_summary.csv", per_app_rows)
    _write_csv(output_root / "per_app_service_summary.csv", per_app_service_rows)
    _write_csv(output_root / "per_app_signal_summary.csv", per_app_signal_rows)
    _write_csv(output_root / "provider_signal_matrix.csv", provider_signal_matrix_rows)
    _write_csv(output_root / "unresolved_domains.csv", unresolved_domain_rows)
    _write_csv(output_root / "invalid_or_skipped_packs.csv", invalid_or_skipped_rows)

    apps_seen = len(per_app_rows)
    apps_with_valid_runs = sum(1 for row in per_app_rows if int(row["valid_run_count"]) > 0)
    apps_invalid_or_skipped_only = sum(
        1 for row in per_app_rows if int(row["valid_run_count"]) == 0 and int(row["skipped_or_invalid_run_count"]) > 0
    )
    runs_seen = len(per_run_rows)
    valid_run_count = sum(1 for row in per_run_rows if int(row["valid_pack"]) == 1)

    summary = {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "repo_root": str(_REPO_ROOT),
        "dynamic_evidence_root": str(root.resolve()),
        "runs_seen": runs_seen,
        "runs_exported": runs_seen,
        "apps_seen": apps_seen,
        "apps_exported": apps_seen,
        "apps_with_valid_runs": apps_with_valid_runs,
        "apps_invalid_or_skipped_only": apps_invalid_or_skipped_only,
        "valid_run_count": valid_run_count,
        "invalid_or_skipped_pack_count": len(invalid_or_skipped_rows),
        "unresolved_service_rows": sum(1 for row in unresolved_domain_rows if row["reason"] == "service_unresolved"),
        "unresolved_signal_rows": sum(1 for row in unresolved_domain_rows if row["reason"] == "signal_unmapped"),
        "matrix_columns": matrix_columns,
        "top_services_by_app": {
            package: [f"{key}:{value}" for key, value in package_top_services[package].most_common(5)]
            for package in sorted(package_top_services)
        },
        "top_signals_by_app": {
            package: [f"{key}:{value}" for key, value in package_top_signals[package].most_common(5)]
            for package in sorted(package_top_signals)
        },
        "output_files": {
            "per_run_summary_csv": str((output_root / "per_run_summary.csv").resolve()),
            "per_app_summary_csv": str((output_root / "per_app_summary.csv").resolve()),
            "per_app_service_summary_csv": str((output_root / "per_app_service_summary.csv").resolve()),
            "per_app_signal_summary_csv": str((output_root / "per_app_signal_summary.csv").resolve()),
            "provider_signal_matrix_csv": str((output_root / "provider_signal_matrix.csv").resolve()),
            "unresolved_domains_csv": str((output_root / "unresolved_domains.csv").resolve()),
            "invalid_or_skipped_packs_csv": str((output_root / "invalid_or_skipped_packs.csv").resolve()),
            "summary_json": str((output_root / "summary.json").resolve()),
        },
        "assumptions": [
            "filesystem_first_dynamic_evidence",
            "pcap_report_top_dns_top_sni_authoritative_for_runtime_service_rollups",
            "pcap_report_top_dns_top_sni_authoritative_for_runtime_signal_rollups",
            "paper-facing app/service/signal summaries exclude invalid_or_skipped packs",
        ],
        "compatibility_aliases": {
            "apps_exported": "apps_seen",
            "runs_exported": "runs_seen",
        },
        "no_db_writes": True,
        "experimental_audit": True,
    }
    (output_root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    output_dir = Path(args.output_dir).resolve() if args.output_dir else None
    summary = generate_report(output_dir=output_dir)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
