#!/usr/bin/env python3
"""Read-only audit of dynamic evidence lineage across current and historical app builds.

This report separates:

- current-build observed evidence
- current-build stale apps (installed device build drifted from newest static plan)
- historical-only evidence
- apps with no valid dynamic evidence

It does not mutate evidence packs, tracker state, quota accounting, or the database.
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


@dataclass(frozen=True)
class AppLineageSummary:
    package_name: str
    app_label: str
    lineage_state: str
    active_version_code: str
    installed_version_code: str
    active_valid_runs: int
    legacy_valid_runs: int
    total_valid_runs: int
    db_active_sessions: int
    db_historical_sessions: int
    db_total_sessions: int
    baseline_active_countable: int
    manual_active_countable: int
    active_quota_status: str
    historical_build_count: int
    top_recommendation: str


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=None, help="Optional explicit output directory.")
    parser.add_argument("--package", default=None, help="Optional package filter.")
    parser.add_argument(
        "--device-serial",
        default=None,
        help="Optional adb serial to compare installed build versionCode against newest static plan.",
    )
    return parser


def _dynamic_root() -> Path:
    from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root

    return dynamic_evidence_root()


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


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


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_package(value: Any) -> str:
    return _norm_text(value).lower()


def _norm_sha(value: Any) -> str:
    return _norm_text(value).lower()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _auto_device_serial() -> str | None:
    try:
        proc = subprocess.run(
            ["adb", "devices", "-l"],
            cwd=str(_REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    serials: list[str] = []
    for line in (proc.stdout or "").splitlines():
        parts = line.strip().split()
        if not parts or parts[0].lower() == "list":
            continue
        if len(parts) >= 2 and parts[1] == "device":
            serials.append(parts[0])
    if len(serials) == 1:
        return serials[0]
    return None


def _load_app_profiles(packages: Iterable[str]) -> dict[str, dict[str, str]]:
    normalized = sorted({_normalize_package(package) for package in packages if _normalize_package(package)})
    if not normalized:
        return {}
    try:
        from scytaledroid.Database.db_core import db_queries as core_q

        placeholders = ", ".join(["%s"] * len(normalized))
        rows = core_q.run_sql(
            f"""
            SELECT LOWER(TRIM(package_name)) AS package_name,
                   NULLIF(display_name, '') AS display_name,
                   NULLIF(profile_key, '') AS profile_key
            FROM apps
            WHERE LOWER(TRIM(package_name)) IN ({placeholders})
            """,
            tuple(normalized),
            fetch="all",
            dictionary=True,
            query_name="dynamic.lineage_audit.app_profiles",
        ) or []
    except Exception:
        return {}
    out: dict[str, dict[str, str]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        package = _normalize_package(row.get("package_name"))
        if not package:
            continue
        out[package] = {
            "display_name": _norm_text(row.get("display_name")),
            "profile_key": _norm_text(row.get("profile_key")),
        }
    return out


def _load_installed_version_code(package_name: str, *, device_serial: str | None) -> str:
    serial = _norm_text(device_serial) or _norm_text(_auto_device_serial())
    if not serial:
        return ""
    try:
        from scytaledroid.DeviceAnalysis.adb import shell as adb_shell
        from scytaledroid.DynamicAnalysis.controllers.guided_run_checks import (
            extract_version_code_details_from_dump,
            read_observed_version_code_details,
        )

        details = read_observed_version_code_details(
            serial,
            package_name,
            run_shell_fn=lambda current_serial, command: adb_shell.run_shell(current_serial, list(command)),
            extract_details_fn=extract_version_code_details_from_dump,
        )
    except Exception:
        return ""
    return _norm_text(details.get("version_code"))


def _run_domain_roots(report: Mapping[str, Any], package_name: str) -> set[str]:
    try:
        from scytaledroid.DynamicAnalysis.pcap.context_summary import summarize_pcap_service_context
    except Exception:
        return set()
    current_context = summarize_pcap_service_context(report, package_name=package_name)
    service_context = current_context.get("service_context") if isinstance(current_context.get("service_context"), Mapping) else {}
    roots: set[str] = set()
    for row in service_context.get("services") or []:
        if not isinstance(row, Mapping):
            continue
        for domain in row.get("domains") or []:
            if not isinstance(domain, Mapping):
                continue
            root = _normalize_package(domain.get("root_domain"))
            if root:
                roots.add(root)
    for row in service_context.get("unresolved_domains") or []:
        if not isinstance(row, Mapping):
            continue
        root = _normalize_package(row.get("root_domain") or row.get("domain"))
        if root:
            roots.add(root)
    return roots


def _run_service_keys(report: Mapping[str, Any], package_name: str) -> set[str]:
    try:
        from scytaledroid.DynamicAnalysis.pcap.context_summary import summarize_pcap_service_context
    except Exception:
        return set()
    current_context = summarize_pcap_service_context(report, package_name=package_name)
    service_context = current_context.get("service_context") if isinstance(current_context.get("service_context"), Mapping) else {}
    return {
        _norm_text(row.get("service_key"))
        for row in (service_context.get("services") or [])
        if isinstance(row, Mapping) and _norm_text(row.get("service_key"))
    }


def _run_signal_keys(report: Mapping[str, Any], package_name: str) -> set[str]:
    try:
        from scytaledroid.DynamicAnalysis.pcap.context_summary import summarize_pcap_service_context
    except Exception:
        return set()
    current_context = summarize_pcap_service_context(report, package_name=package_name)
    service_signals = current_context.get("service_signals") if isinstance(current_context.get("service_signals"), Mapping) else {}
    return {
        _norm_text(row.get("signal_key"))
        for row in (service_signals.get("signals") or [])
        if isinstance(row, Mapping) and _norm_text(row.get("signal_key"))
    }


def _scan_dynamic_runs(*, package_filter: str | None = None) -> list[dict[str, Any]]:
    root = _dynamic_root()
    rows: list[dict[str, Any]] = []
    for manifest_path in sorted(root.glob("*/run_manifest.json")):
        manifest = _read_json(manifest_path) or {}
        run_dir = manifest_path.parent
        target = manifest.get("target") if isinstance(manifest.get("target"), Mapping) else {}
        dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), Mapping) else {}
        operator = manifest.get("operator") if isinstance(manifest.get("operator"), Mapping) else {}
        run_identity = target.get("run_identity") if isinstance(target.get("run_identity"), Mapping) else {}
        package_name = _normalize_package(target.get("package_name"))
        if not package_name:
            continue
        if package_filter and package_name != _normalize_package(package_filter):
            continue
        report = _read_json(run_dir / "analysis" / "pcap_report.json") or {}
        rows.append(
            {
                "run_id": _norm_text(manifest.get("dynamic_run_id") or run_dir.name),
                "package_name": package_name,
                "app_label": _norm_text(target.get("display_name") or target.get("app_label") or package_name),
                "run_profile": _norm_text(dataset.get("run_profile") or operator.get("run_profile")),
                "valid_dataset_run": dataset.get("valid_dataset_run") is True,
                "paper_eligible": dataset.get("valid_dataset_run") is True,
                "version_code": _norm_text(run_identity.get("version_code") or target.get("version_code")),
                "base_apk_sha256": _norm_sha(run_identity.get("base_apk_sha256")),
                "started_at": _norm_text(manifest.get("started_at")),
                "ended_at": _norm_text(manifest.get("ended_at")),
                "dynamic_domains": _run_domain_roots(report, package_name),
                "service_keys": _run_service_keys(report, package_name),
                "signal_keys": _run_signal_keys(report, package_name),
            }
        )
    return rows


def _identity_key(run: Mapping[str, Any]) -> tuple[str, str]:
    return (_norm_text(run.get("version_code")), _norm_sha(run.get("base_apk_sha256")))


def _quota_status(*, baseline_countable: int, manual_countable: int, baseline_required: int, interactive_required: int) -> str:
    if baseline_countable >= baseline_required and manual_countable >= interactive_required:
        return "complete"
    if baseline_countable > 0 or manual_countable > 0:
        return "partial"
    return "none"


def _load_db_dynamic_lineage_context(packages: Sequence[str]) -> dict[str, dict[str, int]]:
    normalized = sorted({_normalize_package(package) for package in packages if _normalize_package(package)})
    if not normalized:
        return {}
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_scripts import package_lineage_read_model as lineage
        from scytaledroid.DynamicAnalysis.tracker_scope import resolve_active_package_identity
    except Exception:
        return {}

    base_rows = [
        row
        for row in (lineage.fetch_base_rows(core_q, package_name=None) or [])
        if _normalize_package(row.get("package_name")) in set(normalized)
    ]
    dynamic_by_hash = lineage.fetch_dynamic_coverage(core_q)
    per_package: dict[str, dict[str, int]] = {
        package: {
            "db_active_sessions": 0,
            "db_historical_sessions": 0,
            "db_total_sessions": 0,
            "db_active_hashes": 0,
            "db_historical_hashes": 0,
        }
        for package in normalized
    }
    seen_active_hashes: dict[str, set[str]] = {package: set() for package in normalized}
    seen_historical_hashes: dict[str, set[str]] = {package: set() for package in normalized}

    for row in base_rows:
        package = _normalize_package(row.get("package_name"))
        if not package:
            continue
        sha = _norm_sha(row.get("base_apk_sha256"))
        if not sha:
            continue
        coverage = dynamic_by_hash.get(sha) or {}
        dynamic_sessions = _safe_int(coverage.get("dynamic_sessions"))
        if dynamic_sessions <= 0:
            continue
        version_code = _norm_text(row.get("version_code"))
        active_version_code, active_base_sha = resolve_active_package_identity(package)
        active_vc = _norm_text(active_version_code)
        active_sha = _norm_sha(active_base_sha)
        is_active = False
        if active_sha:
            is_active = sha == active_sha
        elif active_vc:
            is_active = version_code == active_vc

        bucket = per_package.setdefault(
            package,
            {
                "db_active_sessions": 0,
                "db_historical_sessions": 0,
                "db_total_sessions": 0,
                "db_active_hashes": 0,
                "db_historical_hashes": 0,
            },
        )
        bucket["db_total_sessions"] += dynamic_sessions
        if is_active:
            bucket["db_active_sessions"] += dynamic_sessions
            if sha not in seen_active_hashes[package]:
                seen_active_hashes[package].add(sha)
                bucket["db_active_hashes"] += 1
        else:
            bucket["db_historical_sessions"] += dynamic_sessions
            if sha not in seen_historical_hashes[package]:
                seen_historical_hashes[package].add(sha)
                bucket["db_historical_hashes"] += 1
    return per_package


def classify_lineage_state(
    *,
    active_valid_runs: int,
    legacy_valid_runs: int,
    db_active_sessions: int,
    db_historical_sessions: int,
    installed_version_code: str,
    active_version_code: str,
) -> str:
    observed = _norm_text(installed_version_code)
    active = _norm_text(active_version_code)
    if observed and active and observed != active:
        return "current_build_stale"
    if active_valid_runs > 0:
        return "current_build_observed"
    if db_active_sessions > 0:
        return "current_build_db_only"
    if legacy_valid_runs > 0:
        return "historical_local_only"
    if db_historical_sessions > 0:
        return "historical_db_only"
    return "no_evidence_anywhere"


def _recommendation_for_state(state: str) -> str:
    if state == "current_build_stale":
        return "refresh harvest/static for installed build"
    if state == "current_build_db_only":
        return "restore local evidence pack or recollect current-build evidence"
    if state == "historical_local_only":
        return "collect current-build dynamic evidence"
    if state == "historical_db_only":
        return "treat as historical-only until current-build evidence is collected"
    if state == "no_evidence_anywhere":
        return "collect baseline evidence"
    return "maintain current coverage"


def _delta_row(
    *,
    package_name: str,
    app_label: str,
    active_version_code: str,
    legacy_version_codes: set[str],
    current_domains: set[str],
    legacy_domains: set[str],
    current_services: set[str],
    legacy_services: set[str],
    current_signals: set[str],
    legacy_signals: set[str],
) -> dict[str, Any]:
    domains_only_current = sorted(current_domains - legacy_domains)
    domains_only_legacy = sorted(legacy_domains - current_domains)
    services_only_current = sorted(current_services - legacy_services)
    services_only_legacy = sorted(legacy_services - current_services)
    signals_only_current = sorted(current_signals - legacy_signals)
    signals_only_legacy = sorted(legacy_signals - current_signals)
    return {
        "package_name": package_name,
        "app_label": app_label,
        "active_version_code": active_version_code,
        "legacy_version_codes": ",".join(sorted(v for v in legacy_version_codes if v)),
        "current_only_domain_count": len(domains_only_current),
        "legacy_only_domain_count": len(domains_only_legacy),
        "current_only_service_count": len(services_only_current),
        "legacy_only_service_count": len(services_only_legacy),
        "current_only_signal_count": len(signals_only_current),
        "legacy_only_signal_count": len(signals_only_legacy),
        "current_only_domains": "; ".join(domains_only_current[:10]),
        "legacy_only_domains": "; ".join(domains_only_legacy[:10]),
        "current_only_services": "; ".join(services_only_current[:10]),
        "legacy_only_services": "; ".join(services_only_legacy[:10]),
        "current_only_signals": "; ".join(signals_only_current[:10]),
        "legacy_only_signals": "; ".join(signals_only_legacy[:10]),
    }


def generate_report(*, output_dir: Path | None = None, package_filter: str | None = None, device_serial: str | None = None) -> dict[str, Any]:
    from scytaledroid.DynamicAnalysis.research_cohort_runtime import active_research_cohort_packages
    from scytaledroid.DynamicAnalysis.tracker_scope import build_scoped_dataset_counts, resolve_active_package_identity

    all_runs = _scan_dynamic_runs(package_filter=package_filter)
    dataset_packages = set(active_research_cohort_packages())
    filter_set = {_normalize_package(package_filter)} if package_filter else set()
    run_packages = {_normalize_package(row.get("package_name")) for row in all_runs if _normalize_package(row.get("package_name"))}
    target_packages = sorted((dataset_packages if dataset_packages else run_packages) | filter_set)
    profiles = _load_app_profiles(target_packages)
    db_lineage = _load_db_dynamic_lineage_context(target_packages)
    baseline_required = 3
    interactive_required = 4

    per_app_rows: list[dict[str, Any]] = []
    per_identity_rows: list[dict[str, Any]] = []
    delta_rows: list[dict[str, Any]] = []
    lineage_state_counter: Counter[str] = Counter()

    runs_by_package: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in all_runs:
        package = _normalize_package(row.get("package_name"))
        if package:
            runs_by_package[package].append(row)

    if package_filter:
        target_packages = [_normalize_package(package_filter)]

    for package_name in target_packages:
        package_runs = runs_by_package.get(package_name, [])
        active_version_code, active_base_sha = resolve_active_package_identity(package_name)
        installed_version_code = _load_installed_version_code(package_name, device_serial=device_serial)
        scoped = build_scoped_dataset_counts(
            package_name,
            package_runs,
            cfg=type("_Cfg", (), {"baseline_required": baseline_required, "interactive_required": interactive_required})(),
            resolve_tracker_run_identity_fn=lambda _pkg, run: (_norm_text(run.get("version_code")) or None, _norm_sha(run.get("base_apk_sha256")) or None),
        )
        active_valid_runs = _safe_int(scoped.get("technical_valid_active"))
        legacy_valid_runs = _safe_int(scoped.get("legacy_valid"))
        total_valid_runs = _safe_int(scoped.get("technical_valid_total"))
        db_context = db_lineage.get(package_name) or {}
        db_active_sessions = _safe_int(db_context.get("db_active_sessions"))
        db_historical_sessions = _safe_int(db_context.get("db_historical_sessions"))
        db_total_sessions = _safe_int(db_context.get("db_total_sessions"))
        baseline_active_countable = _safe_int(scoped.get("baseline_countable"))
        manual_active_countable = _safe_int(scoped.get("interactive_countable"))
        fallback_label = _norm_text(package_runs[0].get("app_label")) if package_runs else ""
        app_label = _norm_text(profiles.get(package_name, {}).get("display_name")) or fallback_label or package_name
        state = classify_lineage_state(
            active_valid_runs=active_valid_runs,
            legacy_valid_runs=legacy_valid_runs,
            db_active_sessions=db_active_sessions,
            db_historical_sessions=db_historical_sessions,
            installed_version_code=installed_version_code,
            active_version_code=_norm_text(active_version_code),
        )
        lineage_state_counter[state] += 1
        summary = AppLineageSummary(
            package_name=package_name,
            app_label=app_label,
            lineage_state=state,
            active_version_code=_norm_text(active_version_code),
            installed_version_code=installed_version_code,
            active_valid_runs=active_valid_runs,
            legacy_valid_runs=legacy_valid_runs,
            total_valid_runs=total_valid_runs,
            db_active_sessions=db_active_sessions,
            db_historical_sessions=db_historical_sessions,
            db_total_sessions=db_total_sessions,
            baseline_active_countable=baseline_active_countable,
            manual_active_countable=manual_active_countable,
            active_quota_status=_quota_status(
                baseline_countable=baseline_active_countable,
                manual_countable=manual_active_countable,
                baseline_required=baseline_required,
                interactive_required=interactive_required,
            ),
            historical_build_count=_safe_int(scoped.get("legacy_builds")),
            top_recommendation=_recommendation_for_state(state),
        )
        per_app_rows.append(summary.__dict__)

        identities: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for run in package_runs:
            if not bool(run.get("valid_dataset_run")):
                continue
            identities[_identity_key(run)].append(run)
        active_key = (_norm_text(active_version_code), _norm_sha(active_base_sha))
        current_domains: set[str] = set()
        current_services: set[str] = set()
        current_signals: set[str] = set()
        legacy_domains: set[str] = set()
        legacy_services: set[str] = set()
        legacy_signals: set[str] = set()
        legacy_versions: set[str] = set()
        for ident_key, ident_runs in identities.items():
            version_code, base_sha = ident_key
            domains = set().union(*(set(run.get("dynamic_domains") or set()) for run in ident_runs))
            services = set().union(*(set(run.get("service_keys") or set()) for run in ident_runs))
            signals = set().union(*(set(run.get("signal_keys") or set()) for run in ident_runs))
            is_active = active_key != ("", "") and ident_key == active_key
            if is_active:
                current_domains |= domains
                current_services |= services
                current_signals |= signals
            else:
                legacy_domains |= domains
                legacy_services |= services
                legacy_signals |= signals
                if version_code:
                    legacy_versions.add(version_code)
            per_identity_rows.append(
                {
                    "package_name": package_name,
                    "app_label": app_label,
                    "version_code": version_code,
                    "base_apk_sha256": base_sha,
                    "is_active_identity": int(is_active),
                    "valid_run_count": len(ident_runs),
                    "domain_count": len(domains),
                    "service_count": len(services),
                    "signal_count": len(signals),
                    "first_seen_utc": min((_norm_text(run.get("started_at")) or _norm_text(run.get("ended_at")) or "") for run in ident_runs),
                    "last_seen_utc": max((_norm_text(run.get("ended_at")) or _norm_text(run.get("started_at")) or "") for run in ident_runs),
                }
            )

        delta_rows.append(
            _delta_row(
                package_name=package_name,
                app_label=app_label,
                active_version_code=_norm_text(active_version_code),
                legacy_version_codes=legacy_versions,
                current_domains=current_domains,
                legacy_domains=legacy_domains,
                current_services=current_services,
                legacy_services=legacy_services,
                current_signals=current_signals,
                legacy_signals=legacy_signals,
            )
        )

    stamp = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S-%f")
    output_root = output_dir or (_REPO_ROOT / "output" / "audit" / "dynamic_lineage_audit" / stamp)
    output_root.mkdir(parents=True, exist_ok=True)
    _write_csv(output_root / "per_app_lineage_summary.csv", per_app_rows)
    _write_csv(output_root / "per_identity_summary.csv", per_identity_rows)
    _write_csv(output_root / "per_app_lineage_deltas.csv", delta_rows)

    summary = {
        "report_type": "dynamic_lineage_audit",
        "generated_at_utc": datetime.now(tz=UTC).isoformat(),
        "output_dir": str(output_root),
        "package_filter": _norm_text(package_filter) or None,
        "device_serial": _norm_text(device_serial) or _auto_device_serial(),
        "apps_total": len(per_app_rows),
        "identities_total": len(per_identity_rows),
        "lineage_state_counts": dict(sorted(lineage_state_counter.items())),
        "notes": [
            "current_build_observed means the newest static identity has valid dynamic evidence.",
            "current_build_stale means older evidence exists, but the installed device build differs from the newest static plan.",
            "current_build_db_only means the database knows current-build sessions, but the local evidence corpus does not currently expose them.",
            "historical_local_only means valid local dynamic evidence exists only for non-active identities.",
            "historical_db_only means database-known dynamic lineage exists only for non-active identities.",
            "no_evidence_anywhere means neither the local corpus nor the database reported valid dynamic evidence for the package.",
        ],
    }
    (output_root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    output_dir = Path(args.output_dir) if args.output_dir else None
    payload = generate_report(
        output_dir=output_dir,
        package_filter=args.package,
        device_serial=args.device_serial,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
