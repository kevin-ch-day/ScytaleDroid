#!/usr/bin/env python3
"""Read-only retained dynamic evidence reuse audit.

This report answers a practical collection question: when apps update faster
than the operator can finish all current-build runs, which retained older
builds are still usable for paper/context claims, and which rows need repair
or recollection?
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=None, help="Optional explicit output directory.")
    parser.add_argument(
        "--package",
        action="append",
        default=None,
        help="Optional package filter; may be passed more than once.",
    )
    parser.add_argument(
        "--recent-days",
        type=int,
        default=14,
        help="Age window for RECENT_CONTEXT retained runs (default: 14).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print summary JSON to stdout.",
    )
    parser.add_argument(
        "--stdout-json",
        action="store_true",
        help="Alias for --json; kept for consistency with adjacent report scripts.",
    )
    return parser


def _default_output_dir() -> Path:
    from scytaledroid.Config import app_config

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Path(app_config.OUTPUT_DIR) / "audit" / "dynamic_retained_evidence_reuse" / stamp


def _dynamic_root() -> Path:
    from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root

    return dynamic_evidence_root()


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _is_true(value: Any) -> bool:
    return value in (True, 1, "1", "true", "TRUE", "yes", "YES")


def _parse_dt(value: Any) -> datetime | None:
    text = _norm_text(value)
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _age_days(value: Any, *, now: datetime) -> int | None:
    parsed = _parse_dt(value)
    if parsed is None:
        return None
    return max(0, int((now - parsed).total_seconds() // 86400))


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    row_list = list(rows)
    if not row_list:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: list[str] = []
    for row in row_list:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in row_list:
            writer.writerow({key: row.get(key) for key in fieldnames})


def _split_ids(value: Any) -> list[str]:
    text = _norm_text(value)
    if not text:
        return []
    return [item.strip() for item in text.split(",") if item.strip()]


def _pcap_exists(run_dir: Path, manifest: Mapping[str, Any]) -> bool:
    for artifact in manifest.get("artifacts") or []:
        if not isinstance(artifact, Mapping):
            continue
        rel = _norm_text(artifact.get("path") or artifact.get("relpath"))
        if rel and (run_dir / rel).is_file() and Path(rel).suffix.lower() in {".pcap", ".pcapng"}:
            return True
    return any(path.is_file() and path.suffix.lower() in {".pcap", ".pcapng"} for path in (run_dir / "artifacts").rglob("*"))


def _scan_local_runs(
    *,
    dynamic_root: Path,
    package_filter: set[str],
    now: datetime,
) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for manifest_path in sorted(dynamic_root.glob("*/run_manifest.json")):
        manifest = _read_json(manifest_path)
        if not manifest:
            continue
        run_dir = manifest_path.parent
        run_id = _norm_text(manifest.get("dynamic_run_id")) or run_dir.name
        target = manifest.get("target") if isinstance(manifest.get("target"), Mapping) else {}
        dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), Mapping) else {}
        operator = manifest.get("operator") if isinstance(manifest.get("operator"), Mapping) else {}
        scenario = manifest.get("scenario") if isinstance(manifest.get("scenario"), Mapping) else {}
        package_name = _norm_text(target.get("package_name")).lower()
        if package_filter and package_name not in package_filter:
            continue
        ended_at = _norm_text(manifest.get("ended_at") or scenario.get("ended_at"))
        rows[run_id] = {
            "run_id": run_id,
            "package_name": package_name,
            "version_code": _norm_text(target.get("version_code") or target.get("version_code_end")),
            "version_name": _norm_text(target.get("version_name") or target.get("version_name_end")),
            "base_apk_sha256": _norm_text(target.get("base_apk_sha256") or target.get("base_apk_sha256_end")),
            "run_profile": _norm_text(operator.get("run_profile")),
            "interaction_level": _norm_text(scenario.get("interaction_level")),
            "status": _norm_text(manifest.get("status")),
            "ended_at": ended_at,
            "age_days": _age_days(ended_at, now=now),
            "valid_dataset_run": _is_true(dataset.get("valid_dataset_run")),
            "countable": _is_true(dataset.get("countable")),
            "paper_eligible": _is_true(dataset.get("paper_eligible")),
            "low_signal": _is_true(dataset.get("low_signal")),
            "invalid_reason_code": _norm_text(dataset.get("invalid_reason_code")),
            "pcap_exists": _pcap_exists(run_dir, manifest),
            "pcap_size_bytes": _safe_int(dataset.get("pcap_size_bytes") or dataset.get("pcap_bytes")),
            "run_dir": str(run_dir),
        }
    return rows


def _selected_ids_by_package(manifest_rows: Iterable[Mapping[str, Any]]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for row in manifest_rows:
        pkg = _norm_text(row.get("package_name")).lower()
        if not pkg:
            continue
        out[pkg].update(_split_ids(row.get("selected_dynamic_run_ids")))
    return out


def _load_app_labels(packages: Iterable[str]) -> dict[str, str]:
    normalized = [_norm_text(package).lower() for package in packages if _norm_text(package)]
    if not normalized:
        return {}
    try:
        from scripts.db.report_dynamic_paper_freeze_readiness import _load_app_labels as load_labels
    except Exception:
        return {}
    return load_labels(normalized)


def _reuse_policy(*, tier: str, relation: str, selected_missing_artifacts: int, recent_context_runs: int) -> tuple[str, str]:
    if selected_missing_artifacts > 0:
        return "REPAIR_BEFORE_USE", "selected paper run IDs have missing local artifacts"
    if tier == "STRICT_CURRENT_BUILD_COMPLETE":
        return "PRIMARY_CURRENT_BUILD", "strict current-build evidence is complete"
    if tier == "CURRENT_BUILD_MIXED_BASELINE":
        return "PRIMARY_CURRENT_BUILD_WITH_CAVEAT", "current-build baseline is usable; report strict/QFG/interactive caveats"
    if tier == "PRIOR_BUILD_PAPER_EVIDENCE":
        return "PRIMARY_PRIOR_BUILD_WITH_PROVENANCE", "retained prior-build evidence is build-backed and paper-usable"
    if relation == "prior-build" and recent_context_runs > 0:
        return "RECENT_CONTEXT_ONLY", "recent retained runs can support context, not current-build claims"
    return "SUPPLEMENTAL_CONTEXT_ONLY", "evidence can provide background/context but is not primary paper evidence"


def generate_report(
    *,
    output_dir: Path | None = None,
    package_filter: Sequence[str] | None = None,
    recent_days: int = 14,
) -> dict[str, Any]:
    from scytaledroid.DynamicAnalysis.services.paper_freeze_readiness import (
        build_paper_evidence_tier_report,
        build_paper_freeze_manifest,
    )

    now = datetime.now(UTC)
    normalized_filter = {_norm_text(pkg).lower() for pkg in (package_filter or []) if _norm_text(pkg)}
    manifest = build_paper_freeze_manifest(package_filter=list(normalized_filter) or None)
    tier_report = build_paper_evidence_tier_report(package_filter=list(normalized_filter) or None)
    manifest_rows = [row for row in manifest.get("apps") or [] if isinstance(row, Mapping)]
    tier_rows = [row for row in tier_report.get("rows") or [] if isinstance(row, Mapping)]
    tiers_by_pkg = {_norm_text(row.get("package_name")).lower(): row for row in tier_rows}
    selected_by_pkg = _selected_ids_by_package(manifest_rows)
    label_map = _load_app_labels(_norm_text(row.get("package_name")).lower() for row in manifest_rows)
    local_runs = _scan_local_runs(dynamic_root=_dynamic_root(), package_filter=normalized_filter, now=now)

    runs_by_pkg: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for run in local_runs.values():
        runs_by_pkg[_norm_text(run.get("package_name")).lower()].append(run)

    app_rows: list[dict[str, Any]] = []
    repair_rows: list[dict[str, Any]] = []
    context_rows: list[dict[str, Any]] = []
    for manifest_row in manifest_rows:
        pkg = _norm_text(manifest_row.get("package_name")).lower()
        tier_row = tiers_by_pkg.get(pkg, {})
        selected_ids = selected_by_pkg.get(pkg, set())
        selected_runs = [local_runs[run_id] for run_id in selected_ids if run_id in local_runs]
        missing_selected = sorted(run_id for run_id in selected_ids if run_id not in local_runs)
        selected_missing_artifacts = len(missing_selected) + sum(1 for run in selected_runs if not run["pcap_exists"])
        valid_runs = [run for run in runs_by_pkg.get(pkg, []) if run["valid_dataset_run"] and run["pcap_exists"]]
        recent_context = [
            run
            for run in valid_runs
            if run["age_days"] is not None
            and int(run["age_days"]) <= int(recent_days)
            and run["run_id"] not in selected_ids
        ]
        policy, reason = _reuse_policy(
            tier=_norm_text(tier_row.get("evidence_tier")),
            relation=_norm_text(manifest_row.get("selected_relation")),
            selected_missing_artifacts=selected_missing_artifacts,
            recent_context_runs=len(recent_context),
        )
        selected_ages = [int(run["age_days"]) for run in selected_runs if run["age_days"] is not None]
        app_row = {
            "app": label_map.get(pkg) or _norm_text(manifest_row.get("app") or tier_row.get("app") or pkg),
            "package_name": pkg,
            "reuse_policy": policy,
            "reuse_reason": reason,
            "evidence_tier": _norm_text(tier_row.get("evidence_tier")),
            "paper_usable": _norm_text(tier_row.get("paper_usable")),
            "selected_relation": _norm_text(manifest_row.get("selected_relation")),
            "selected_version_code": _norm_text(manifest_row.get("selected_version_code")),
            "installed_version_code": _norm_text(manifest_row.get("installed_target_version_code") or tier_row.get("installed_version_code")),
            "selected_dynamic_run_count": len(selected_ids),
            "selected_local_run_count": len(selected_runs),
            "selected_missing_run_count": len(missing_selected),
            "selected_missing_artifact_count": selected_missing_artifacts,
            "selected_min_age_days": min(selected_ages) if selected_ages else "",
            "selected_max_age_days": max(selected_ages) if selected_ages else "",
            "valid_local_runs": len(valid_runs),
            "recent_context_runs": len(recent_context),
            "retained_prior_build_count": _safe_int(tier_row.get("retained_prior_build_count")),
            "baseline_count": _safe_int(manifest_row.get("baseline_count")),
            "interactive_count": _safe_int(manifest_row.get("interactive_count")),
            "missing_baseline_runs": _safe_int(manifest_row.get("missing_baseline_runs")),
            "missing_interactive_runs": _safe_int(manifest_row.get("missing_interactive_runs")),
            "caveat": _norm_text(tier_row.get("caveat")),
            "recommended_final_run_tonight": _norm_text(tier_row.get("recommended_final_run_tonight")),
            "future_work": _norm_text(tier_row.get("future_work")),
            "selected_dynamic_run_ids": ",".join(sorted(selected_ids)),
            "missing_selected_run_ids": ",".join(missing_selected),
        }
        app_rows.append(app_row)
        if selected_missing_artifacts:
            repair_rows.append(app_row)
        for run in recent_context:
            context_rows.append(
                {
                    "app": app_row["app"],
                    "package_name": pkg,
                    "run_id": run["run_id"],
                    "version_code": run["version_code"],
                    "version_name": run["version_name"],
                    "run_profile": run["run_profile"],
                    "age_days": run["age_days"],
                    "countable": "yes" if run["countable"] else "no",
                    "paper_eligible": "yes" if run["paper_eligible"] else "no",
                    "low_signal": "yes" if run["low_signal"] else "no",
                    "recommended_use": "context/trend support; do not call current-build unless identity matches selected build",
                }
            )

    policy_counts = Counter(row["reuse_policy"] for row in app_rows)
    relation_counts = Counter(row["selected_relation"] for row in app_rows)
    summary = {
        "generated_at_utc": now.isoformat(),
        "recent_days": int(recent_days),
        "apps_total": len(app_rows),
        "policy_counts": dict(sorted(policy_counts.items())),
        "selected_relation_counts": dict(sorted(relation_counts.items())),
        "paper_usable_apps": sum(1 for row in app_rows if row["paper_usable"] == "yes"),
        "repair_before_use_apps": sum(1 for row in app_rows if row["reuse_policy"] == "REPAIR_BEFORE_USE"),
        "recent_context_runs": len(context_rows),
        "local_dynamic_runs_scanned": len(local_runs),
        "note": "Read-only report. No evidence packs, DB rows, PCAPs, or tracker files were modified.",
    }

    out_dir = output_dir or _default_output_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    outputs = {
        "summary_json": out_dir / "summary.json",
        "app_reuse_policy_csv": out_dir / "app_reuse_policy.csv",
        "recent_context_runs_csv": out_dir / "recent_context_runs.csv",
        "repair_candidates_csv": out_dir / "repair_candidates.csv",
    }
    _write_json(outputs["summary_json"], summary)
    _write_csv(outputs["app_reuse_policy_csv"], app_rows)
    _write_csv(outputs["recent_context_runs_csv"], context_rows)
    _write_csv(outputs["repair_candidates_csv"], repair_rows)
    summary["output_files"] = {key: str(path.resolve()) for key, path in outputs.items()}
    _write_json(outputs["summary_json"], summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    summary = generate_report(
        output_dir=Path(args.output_dir) if args.output_dir else None,
        package_filter=args.package,
        recent_days=max(0, int(args.recent_days)),
    )
    if args.json or args.stdout_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(json.dumps({"summary_json": summary["output_files"]["summary_json"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
