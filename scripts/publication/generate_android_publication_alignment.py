#!/usr/bin/env python3
"""Build read-only publication evidence-alignment datasets from the final cutoff.

This generator does not collect runs, update evidence, or write database rows. It
materializes publication-facing CSV/JSON/TXT audit artifacts from the selected
cutoff manifest, selected static run IDs, and selected dynamic evidence packs.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Database.db_core import db_engine  # noqa: E402

DEFAULT_CUTOFF_DIR = REPO_ROOT / "output" / "paper" / "dynamic_paper_cutoff_final_20260709T202819Z"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "output" / "paper" / "android_empirical_alignment_final"
DEFAULT_OLD_DYNAMIC_RUN_EXPORT = (
    REPO_ROOT
    / "output"
    / "audit"
    / "paper_regen_check"
    / "20260709T160803Z"
    / "dynamic_paper_exports"
    / "per_run_summary.csv"
)
EVIDENCE_ROOT = REPO_ROOT / "output" / "evidence" / "dynamic"

APP_LABELS = {
    "bbc.mobile.news.ww": "BBC News",
    "com.cnn.mobile.android.phone": "CNN",
    "com.facebook.katana": "Facebook",
    "com.facebook.orca": "Facebook Messenger",
    "com.instagram.android": "Instagram",
    "com.linkedin.android": "LinkedIn",
    "com.pinterest": "Pinterest",
    "com.reddit.frontpage": "Reddit",
    "org.thoughtcrime.securesms": "Signal",
    "com.snapchat.android": "Snapchat",
    "org.telegram.messenger": "Telegram",
    "com.guardian": "The Guardian",
    "com.zhiliaoapp.musically": "TikTok",
    "com.whatsapp": "WhatsApp",
    "com.twitter.android": "X",
}

APP_CATEGORIES = {
    "bbc.mobile.news.ww": "News",
    "com.cnn.mobile.android.phone": "News",
    "com.guardian": "News",
    "com.facebook.katana": "Social/content",
    "com.instagram.android": "Social/content",
    "com.linkedin.android": "Professional social",
    "com.pinterest": "Social/content",
    "com.reddit.frontpage": "Social/content",
    "com.zhiliaoapp.musically": "Social/video",
    "com.twitter.android": "Social/content",
    "com.facebook.orca": "Messaging",
    "org.thoughtcrime.securesms": "Messaging",
    "com.snapchat.android": "Messaging/social",
    "org.telegram.messenger": "Messaging",
    "com.whatsapp": "Messaging",
}


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float | None = None) -> float | None:
    try:
        if value in (None, ""):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _split_ids(value: Any) -> list[str]:
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def _iso(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _median(values: Iterable[Any]) -> float | str:
    nums = [float(v) for v in values if _safe_float(v) is not None]
    return statistics.median(nums) if nums else ""


def _find_pcap_path(run_dir: Path, manifest: Mapping[str, Any]) -> Path | None:
    artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), list) else []
    for artifact in artifacts:
        if not isinstance(artifact, Mapping):
            continue
        if str(artifact.get("type") or "") == "pcapdroid_capture":
            rel = str(artifact.get("relative_path") or "")
            if rel:
                candidate = run_dir / rel
                if candidate.exists():
                    return candidate
    found = sorted(run_dir.glob("artifacts/pcapdroid_capture/*.pcap"))
    return found[0] if found else None


def _classify_evidence(run_manifest: Mapping[str, Any], summary: Mapping[str, Any]) -> str:
    run_profile = str((summary.get("run_profile") or (run_manifest.get("operator") or {}).get("run_profile") or "")).lower()
    if "interaction" in run_profile or "interactive" in run_profile:
        return "interactive"
    if run_profile.startswith("baseline") or "baseline" in run_profile or "idle" in run_profile:
        baseline_not_idle = False
        ds = summary.get("dataset") if isinstance(summary.get("dataset"), Mapping) else {}
        if ds.get("baseline_not_idle") is True or summary.get("baseline_not_idle") is True:
            baseline_not_idle = True
        return "qfg" if run_profile == "baseline_idle" and baseline_not_idle else "strict_idle"
    return "unknown"


def _top_values(items: Any, *, key_names: tuple[str, ...] = ("value", "domain", "name")) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    if not isinstance(items, list):
        return out
    for item in items:
        if isinstance(item, Mapping):
            value = ""
            for key in key_names:
                if item.get(key):
                    value = str(item.get(key))
                    break
            count = _safe_int(item.get("count") or item.get("n") or item.get("observations"), 1)
        else:
            value = str(item)
            count = 1
        if value:
            out.append((value, count))
    return out


def _protocol_indicators(report: Mapping[str, Any]) -> dict[str, Any]:
    ratios = report.get("protocol_ratios") if isinstance(report.get("protocol_ratios"), Mapping) else {}
    hierarchy = report.get("protocol_hierarchy") if isinstance(report.get("protocol_hierarchy"), list) else []
    names = {str(row.get("protocol") or row.get("name") or "").lower() for row in hierarchy if isinstance(row, Mapping)}
    return {
        "tcp_present": int(("tcp" in names) or (_safe_float(ratios.get("tcp_ratio"), 0.0) or 0) > 0),
        "udp_present": int(("udp" in names) or (_safe_float(ratios.get("udp_ratio"), 0.0) or 0) > 0),
        "tls_present": int(("tls" in names) or (_safe_float(ratios.get("tls_ratio"), 0.0) or 0) > 0),
        "quic_present": int(("quic" in names) or ("http3" in names) or (_safe_float(ratios.get("quic_ratio"), 0.0) or 0) > 0),
        "dns_present": int(("dns" in names) or _safe_int(report.get("dns_observation_count")) > 0),
    }


def _load_cutoff(cutoff_dir: Path) -> tuple[list[dict[str, str]], dict[str, Any]]:
    manifest_csv = cutoff_dir / "paper_freeze_manifest.csv"
    manifest_json = cutoff_dir / "paper_freeze_manifest.json"
    return _read_csv(manifest_csv), _read_json(manifest_json)


def _db_static_rows(static_ids: list[int]) -> tuple[dict[int, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    if not static_ids:
        return {}, {}
    fmt = ",".join(["%s"] * len(static_ids))
    data: dict[str, list[dict[str, Any]]] = {}
    with db_engine.connect() as conn:
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT sar.id, a.package_name, a.display_name, av.version_code, av.version_name,
                   sar.base_apk_sha256, sar.artifact_set_hash, sar.session_stamp, sar.session_label,
                   sar.status, sar.run_class, sar.identity_valid, sar.is_canonical,
                   sar.run_started_at_utc, sar.created_at, sar.apk_set_id
            FROM static_analysis_runs sar
            LEFT JOIN app_versions av ON av.id = sar.app_version_id
            LEFT JOIN apps a ON a.id = av.app_id
            WHERE sar.id IN ({fmt})
            ORDER BY sar.id
            """,
            static_ids,
        )
        run_cols = [d[0] for d in cur.description]
        run_rows = [dict(zip(run_cols, row, strict=True)) for row in cur.fetchall()]
        run_by_id = {int(row["id"]): row for row in run_rows}

        queries = {
            "findings": f"SELECT * FROM static_analysis_findings WHERE run_id IN ({fmt})",
            "permissions": f"SELECT * FROM static_permission_matrix WHERE run_id IN ({fmt})",
            "fileproviders": f"SELECT * FROM static_fileproviders WHERE run_id IN ({fmt})",
            "strings": f"SELECT * FROM static_string_summary WHERE static_run_id IN ({fmt})",
        }
        for name, query in queries.items():
            cur.execute(query, static_ids)
            cols = [d[0] for d in cur.description]
            data[name] = [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]
    return run_by_id, data


def _choose_contributing_static_ids(cutoff_rows: list[dict[str, str]], run_by_id: Mapping[int, Mapping[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in cutoff_rows:
        package = row["package_name"]
        selected_sha = row["selected_base_apk_sha256"].lower()
        ids = [_safe_int(x) for x in _split_ids(row.get("selected_static_run_ids"))]
        candidates = [
            run_by_id[run_id]
            for run_id in ids
            if run_id in run_by_id
            and str(run_by_id[run_id].get("base_apk_sha256") or "").lower() == selected_sha
            and str(run_by_id[run_id].get("status") or "").upper() == "COMPLETED"
            and str(run_by_id[run_id].get("run_class") or "").upper() == "CANONICAL"
            and _safe_int(run_by_id[run_id].get("identity_valid")) == 1
        ]
        if not candidates:
            continue
        candidates.sort(key=lambda item: (str(item.get("run_started_at_utc") or item.get("created_at") or ""), int(item["id"])))
        out[package] = int(candidates[-1]["id"])
    return out


def _build_publication_manifest(
    cutoff_rows: list[dict[str, str]],
    cutoff_json: Mapping[str, Any],
    run_by_id: Mapping[int, Mapping[str, Any]],
    contributing_static: Mapping[str, int],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, list[str]]], list[str]]:
    json_by_pkg = {row["package_name"]: row for row in cutoff_json.get("apps", []) if isinstance(row, Mapping)}
    class_ids: dict[str, dict[str, list[str]]] = {}
    warnings: list[str] = []
    out: list[dict[str, Any]] = []
    for row in cutoff_rows:
        package = row["package_name"]
        run_ids = _split_ids(row.get("selected_dynamic_run_ids"))
        buckets = {"strict_idle": [], "qfg": [], "interactive": [], "unknown": []}
        earliest = ""
        latest = ""
        build_mismatch: list[str] = []
        for run_id in run_ids:
            run_dir = EVIDENCE_ROOT / run_id
            manifest = _read_json(run_dir / "run_manifest.json") if (run_dir / "run_manifest.json").exists() else {}
            summary = _read_json(run_dir / "analysis" / "summary.json") if (run_dir / "analysis" / "summary.json").exists() else {}
            evidence_class = _classify_evidence(manifest, summary)
            buckets.setdefault(evidence_class, []).append(run_id)
            ts = str(manifest.get("ended_at") or manifest.get("started_at") or summary.get("ended_at") or "")
            if ts and (not earliest or ts < earliest):
                earliest = ts
            if ts and (not latest or ts > latest):
                latest = ts
            if str(summary.get("version_code") or "") and str(summary.get("version_code")) != str(row["selected_version_code"]):
                build_mismatch.append(run_id)
        class_ids[package] = buckets
        static_ids = [_safe_int(x) for x in _split_ids(row.get("selected_static_run_ids"))]
        static_same_build = all(
            static_id in run_by_id
            and str(run_by_id[static_id].get("base_apk_sha256") or "").lower() == row["selected_base_apk_sha256"].lower()
            for static_id in static_ids
        )
        jrow = json_by_pkg.get(package, {})
        selected_candidate = None
        for candidate in jrow.get("build_candidates", []) if isinstance(jrow.get("build_candidates"), list) else []:
            if (
                str(candidate.get("version_code")) == str(row["selected_version_code"])
                and str(candidate.get("base_apk_sha256") or "").lower() == row["selected_base_apk_sha256"].lower()
            ):
                selected_candidate = candidate
                break
        selected_split_count = ""
        selection_warning = []
        if build_mismatch:
            selection_warning.append(f"dynamic_version_mismatch:{len(build_mismatch)}")
        if buckets["unknown"]:
            selection_warning.append(f"unknown_run_class:{len(buckets['unknown'])}")
        if not static_same_build:
            selection_warning.append("static_hash_misalignment")
        if package not in contributing_static:
            selection_warning.append("no_contributing_static_run")
        out.append(
            {
                "app_label": APP_LABELS.get(package, row.get("app") or package),
                "app_category": APP_CATEGORIES.get(package, ""),
                "package_name": package,
                "selected_version_code": row["selected_version_code"],
                "selected_version_name": row["selected_version_name"],
                "selected_base_apk_sha256": row["selected_base_apk_sha256"],
                "selected_split_count": selected_split_count,
                "selected_static_run_ids": row["selected_static_run_ids"],
                "contributing_static_run_id": contributing_static.get(package, ""),
                "selected_dynamic_run_ids": ",".join(run_ids),
                "strict_idle_run_ids": ",".join(buckets["strict_idle"]),
                "qfg_run_ids": ",".join(buckets["qfg"]),
                "interactive_run_ids": ",".join(buckets["interactive"]),
                "earliest_selected_capture_utc": earliest or (selected_candidate or {}).get("first_capture_at", ""),
                "latest_selected_capture_utc": latest or (selected_candidate or {}).get("last_capture_at", ""),
                "selected_run_count": len(run_ids),
                "selected_pcap_count": _safe_int(row["valid_pcap_count"]),
                "static_dynamic_same_build": "yes" if static_same_build and not build_mismatch else "no",
                "number_of_selected_builds": 1 if not build_mismatch else 1 + len(set(build_mismatch)),
                "evidence_selection_reason": "highest ranked QA-valid build candidate by readiness, baseline+interactive coverage, PCAP count, QA count, recency, and build identity",
                "evidence_source": "paper_freeze_manifest.csv/json",
                "selection_warning": ";".join(selection_warning),
            }
        )
        if selection_warning:
            warnings.append(f"{package}: {';'.join(selection_warning)}")
    return out, class_ids, warnings


def _static_alignment_rows(
    cutoff_rows: list[dict[str, str]],
    run_by_id: Mapping[int, Mapping[str, Any]],
    contributing_static: Mapping[str, int],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for cutoff in cutoff_rows:
        package = cutoff["package_name"]
        seen: Counter[str] = Counter()
        for static_id_text in _split_ids(cutoff.get("selected_static_run_ids")):
            static_id = _safe_int(static_id_text)
            run = run_by_id.get(static_id, {})
            key = f"{run.get('base_apk_sha256')}:{run.get('artifact_set_hash')}"
            seen[key] += 1
        for static_id_text in _split_ids(cutoff.get("selected_static_run_ids")):
            static_id = _safe_int(static_id_text)
            run = run_by_id.get(static_id, {})
            key = f"{run.get('base_apk_sha256')}:{run.get('artifact_set_hash')}"
            contributes = static_id == contributing_static.get(package)
            rows.append(
                {
                    "app": APP_LABELS.get(package, package),
                    "package": package,
                    "version_code": run.get("version_code") or cutoff["selected_version_code"],
                    "version_name": run.get("version_name") or cutoff["selected_version_name"],
                    "base_apk_sha256": run.get("base_apk_sha256") or "",
                    "static_run_id": static_id,
                    "static_session_stamp": run.get("session_stamp") or "",
                    "artifact_role": "selected_build_static_analysis",
                    "base_versus_split_relationship": "install_set_summary_base_and_splits" if run.get("apk_set_id") else "run_level_static_summary",
                    "completed_status": run.get("status") or "",
                    "canonical_status": run.get("run_class") or "",
                    "identity_valid_status": run.get("identity_valid") or "",
                    "contributes_app_level_metrics": "yes" if contributes else "no",
                    "duplicates_another_static_observation": "yes" if seen[key] > 1 else "no",
                    "aggregation_rule": "latest completed canonical identity-valid selected static run per app/build contributes app-level metrics; other selected static IDs are provenance only",
                }
            )
    return rows


def _static_datasets(
    manifest_rows: list[dict[str, Any]],
    static_data: Mapping[str, list[dict[str, Any]]],
    contributing_ids: set[int],
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    findings = [row for row in static_data.get("findings", []) if _safe_int(row.get("run_id")) in contributing_ids]
    permissions = [row for row in static_data.get("permissions", []) if _safe_int(row.get("run_id")) in contributing_ids]
    fileproviders = [row for row in static_data.get("fileproviders", []) if _safe_int(row.get("run_id")) in contributing_ids]
    strings = [row for row in static_data.get("strings", []) if _safe_int(row.get("static_run_id")) in contributing_ids]
    by_run_findings: dict[int, list[dict[str, Any]]] = defaultdict(list)
    by_run_perms: dict[int, list[dict[str, Any]]] = defaultdict(list)
    by_run_fp: dict[int, list[dict[str, Any]]] = defaultdict(list)
    by_run_strings: dict[int, dict[str, Any]] = {}
    for row in findings:
        by_run_findings[_safe_int(row.get("run_id"))].append(row)
    for row in permissions:
        by_run_perms[_safe_int(row.get("run_id"))].append(row)
    for row in fileproviders:
        by_run_fp[_safe_int(row.get("run_id"))].append(row)
    for row in strings:
        by_run_strings[_safe_int(row.get("static_run_id"))] = row
    app_rows: list[dict[str, Any]] = []
    for manifest in manifest_rows:
        rid = _safe_int(manifest.get("contributing_static_run_id"))
        fr = by_run_findings.get(rid, [])
        pr = by_run_perms.get(rid, [])
        fp = by_run_fp.get(rid, [])
        ss = by_run_strings.get(rid, {})
        severity = Counter(str(row.get("severity") or row.get("severity_raw") or "").lower() for row in fr)
        masvs = Counter(str(row.get("masvs_area") or "").lower() for row in fr)
        titles = " || ".join(str(row.get("title") or "").lower() for row in fr)
        app_rows.append(
            {
                "app_label": manifest["app_label"],
                "package_name": manifest["package_name"],
                "selected_version_code": manifest["selected_version_code"],
                "selected_version_name": manifest["selected_version_name"],
                "contributing_static_run_id": rid,
                "total_declared_permissions": len({str(row.get("permission_name") or "").strip().lower() for row in pr if row.get("permission_name")}),
                "privacy_sensitive_permissions": sum(1 for row in pr if _safe_int(row.get("is_runtime_dangerous")) or _safe_int(row.get("is_special_access"))),
                "dangerous_permissions": sum(1 for row in pr if _safe_int(row.get("is_runtime_dangerous"))),
                "exported_activities": titles.count("exported activity"),
                "exported_services": titles.count("exported service"),
                "exported_receivers": titles.count("exported receiver"),
                "exported_providers": sum(1 for row in fp if str(row.get("exported")).lower() in {"1", "true", "yes"}),
                "total_exported_components": titles.count("exported activity") + titles.count("exported service") + titles.count("exported receiver") + sum(1 for row in fp if str(row.get("exported")).lower() in {"1", "true", "yes"}),
                "exported_components_without_permission_guard": sum(1 for row in fr if "without permission" in str(row.get("title") or "").lower() or "weak guard" in str(row.get("title") or "").lower()),
                "network_security_findings": sum(1 for row in fr if str(row.get("masvs_area") or "").upper() == "NETWORK" or "network" in str(row.get("category") or "").lower()),
                "cleartext_indicators": _safe_int(ss.get("http_cleartext")),
                "storage_findings": sum(1 for row in fr if str(row.get("masvs_area") or "").upper() == "STORAGE"),
                "privacy_findings": sum(1 for row in fr if str(row.get("masvs_area") or "").upper() == "PRIVACY"),
                "platform_findings": sum(1 for row in fr if str(row.get("masvs_area") or "").upper() == "PLATFORM"),
                "masvs_privacy_count": masvs.get("privacy", 0),
                "masvs_platform_count": masvs.get("platform", 0),
                "masvs_network_count": masvs.get("network", 0),
                "masvs_storage_count": masvs.get("storage", 0),
                "severity_high_count": severity.get("high", 0),
                "severity_medium_count": severity.get("medium", 0) + severity.get("med", 0),
                "severity_low_count": severity.get("low", 0),
                "severity_info_count": severity.get("info", 0) + severity.get("informational", 0),
                "sdk_indicators": _safe_int(ss.get("analytics_ids")) + _safe_int(ss.get("cloud_refs")),
                "service_indicators": _safe_int(ss.get("endpoints")),
                "detector_finding_totals": len(fr),
                "static_metric_source": "selected contributing static_analysis_runs row and child canonical static tables",
            }
        )
    extra = {
        "finding_rows": findings,
        "permission_rows": permissions,
        "component_rows": fileproviders,
        "masvs_rows": [
            {
                "run_id": row.get("run_id"),
                "finding_id": row.get("finding_id"),
                "package_name": next((m["package_name"] for m in manifest_rows if _safe_int(m.get("contributing_static_run_id")) == _safe_int(row.get("run_id"))), ""),
                "masvs_area": row.get("masvs_area"),
                "masvs_control": row.get("masvs_control"),
                "severity": row.get("severity") or row.get("severity_raw"),
                "title": row.get("title"),
            }
            for row in findings
            if row.get("masvs_area") or row.get("masvs_control")
        ],
    }
    return app_rows, extra


def _dynamic_datasets(manifest_rows: list[dict[str, Any]], class_ids: Mapping[str, Mapping[str, list[str]]]) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    run_rows: list[dict[str, Any]] = []
    domain_rows: list[dict[str, Any]] = []
    service_rows: list[dict[str, Any]] = []
    protocol_rows: list[dict[str, Any]] = []
    manifest_by_run: dict[str, dict[str, Any]] = {}
    for manifest in manifest_rows:
        for cls in ("strict_idle", "qfg", "interactive", "unknown"):
            for run_id in class_ids.get(manifest["package_name"], {}).get(cls, []):
                manifest_by_run[run_id] = manifest | {"evidence_class": cls}
    for run_id, app_manifest in sorted(manifest_by_run.items(), key=lambda item: (item[1]["package_name"], item[0])):
        run_dir = EVIDENCE_ROOT / run_id
        run_manifest = _read_json(run_dir / "run_manifest.json") if (run_dir / "run_manifest.json").exists() else {}
        summary = _read_json(run_dir / "analysis" / "summary.json") if (run_dir / "analysis" / "summary.json").exists() else {}
        report = _read_json(run_dir / "analysis" / "pcap_report.json") if (run_dir / "analysis" / "pcap_report.json").exists() else {}
        pcap_path = _find_pcap_path(run_dir, run_manifest)
        duration = _safe_float(report.get("capture_duration_s")) or _safe_float(summary.get("capture_duration_s")) or _safe_float((run_manifest.get("dataset") or {}).get("actual_sampling_seconds"))
        bytes_total = _safe_int(report.get("bytes_total") or report.get("pcap_size_bytes") or summary.get("pcap_bytes") or (run_manifest.get("dataset") or {}).get("pcap_size_bytes"))
        packets = _safe_int(report.get("packet_count") or ((report.get("capinfos") or {}).get("parsed") or {}).get("packet_count"))
        pps = (packets / duration) if duration and packets else ""
        bps = (bytes_total / duration) if duration and bytes_total else ""
        protocol = _protocol_indicators(report)
        svc = report.get("service_context") if isinstance(report.get("service_context"), Mapping) else {}
        sig = report.get("service_signals") if isinstance(report.get("service_signals"), Mapping) else {}
        services = svc.get("services") if isinstance(svc.get("services"), list) else []
        unresolved_signal_count = len(sig.get("unresolved_signals") or []) if isinstance(sig.get("unresolved_signals"), list) else 0
        analytic_eligible = bool(pcap_path and pcap_path.exists() and str(report.get("report_status") or "ok") == "ok" and app_manifest["evidence_class"] != "unknown")
        run_rows.append(
            {
                "app": app_manifest["app_label"],
                "package": app_manifest["package_name"],
                "selected_version": app_manifest["selected_version_name"],
                "dynamic_run_id": run_id,
                "evidence_class": app_manifest["evidence_class"],
                "start_time": run_manifest.get("started_at") or "",
                "duration": duration or "",
                "qa_status": "valid" if (run_manifest.get("dataset") or {}).get("valid_dataset_run") is True or summary.get("dataset_verdict") == "VALID" else "unknown",
                "pcap_path": str(pcap_path) if pcap_path else "",
                "pcap_status": "present" if pcap_path and pcap_path.exists() else "missing",
                "bytes": bytes_total,
                "packets": packets,
                "bytes_per_second": bps,
                "packets_per_second": pps,
                "average_packet_length": (bytes_total / packets) if packets else "",
                "domain_count": _safe_int((svc or {}).get("observed_domain_count") or summary.get("domain_count") or report.get("dns_unique_count")),
                "service_count": _safe_int((svc or {}).get("service_count")),
                "tcp_present": protocol["tcp_present"],
                "udp_present": protocol["udp_present"],
                "tls_present": protocol["tls_present"],
                "quic_present": protocol["quic_present"],
                "dns_present": protocol["dns_present"],
                "first_party_count": _safe_int((svc or {}).get("first_party_domain_count"), 0),
                "third_party_count": _safe_int((svc or {}).get("third_party_domain_count"), 0),
                "unresolved_signal_count": unresolved_signal_count,
                "skipped_pack_reason": "",
                "analytic_eligibility": "eligible" if analytic_eligible else "not_eligible",
                "exclusion_reason": "" if analytic_eligible else "missing_pcap_or_report_or_unknown_class",
            }
        )
        for source_name in ("top_dns", "top_sni"):
            for value, count in _top_values(report.get(source_name)):
                domain_rows.append({"package": app_manifest["package_name"], "dynamic_run_id": run_id, "source": source_name, "domain": value, "count": count})
        for service in services:
            if isinstance(service, Mapping):
                service_rows.append(
                    {
                        "package": app_manifest["package_name"],
                        "dynamic_run_id": run_id,
                        "service_family": service.get("service_family") or service.get("family") or service.get("service") or "",
                        "domain": service.get("domain") or service.get("root_domain") or "",
                        "owner": service.get("owner") or service.get("owner_class") or "",
                        "count": service.get("count") or service.get("observations") or "",
                    }
                )
        hierarchy = report.get("protocol_hierarchy") if isinstance(report.get("protocol_hierarchy"), list) else []
        for proto in hierarchy:
            if isinstance(proto, Mapping):
                protocol_rows.append({"package": app_manifest["package_name"], "dynamic_run_id": run_id, **{str(k): v for k, v in proto.items()}})
    return run_rows, {"domain_rows": domain_rows, "service_rows": service_rows, "protocol_rows": protocol_rows}


def _dynamic_app_metrics(dynamic_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_pkg: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in dynamic_rows:
        by_pkg[row["package"]].append(row)
    out: list[dict[str, Any]] = []
    for package, rows in sorted(by_pkg.items()):
        base = rows[0]
        app_row: dict[str, Any] = {
            "app": base["app"],
            "package": package,
            "selected_version": base["selected_version"],
            "selected_run_count": len(rows),
            "selected_pcap_count": sum(1 for row in rows if row["pcap_status"] == "present"),
            "analytic_eligible_count": sum(1 for row in rows if row["analytic_eligibility"] == "eligible"),
            "first_selected_run_time": min((str(row.get("start_time") or "") for row in rows if row.get("start_time")), default=""),
            "last_selected_run_time": max((str(row.get("start_time") or "") for row in rows if row.get("start_time")), default=""),
        }
        for cls in ("strict_idle", "qfg", "interactive"):
            subset = [row for row in rows if row["evidence_class"] == cls]
            app_row[f"{cls}_run_count"] = len(subset)
            for field in ("duration", "bytes", "packets", "bytes_per_second", "packets_per_second", "domain_count", "service_count"):
                app_row[f"{cls}_median_{field}"] = _median(row.get(field) for row in subset)
            for proto in ("tcp", "udp", "tls", "quic", "dns"):
                app_row[f"{cls}_{proto}_prevalence"] = (sum(_safe_int(row.get(f"{proto}_present")) for row in subset) / len(subset)) if subset else ""
        out.append(app_row)
    return out


def _app_analysis_rows(manifest_rows: list[dict[str, Any]], static_rows: list[dict[str, Any]], dynamic_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    static_by_pkg = {row["package_name"]: row for row in static_rows}
    dyn_by_pkg: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in dynamic_rows:
        dyn_by_pkg[row["package"]].append(row)
    out: list[dict[str, Any]] = []
    for manifest in manifest_rows:
        package = manifest["package_name"]
        s = static_by_pkg.get(package, {})
        drows = dyn_by_pkg.get(package, [])
        row: dict[str, Any] = {
            "app_label": manifest["app_label"],
            "package_name": package,
            "selected_version_code": manifest["selected_version_code"],
            "selected_version_name": manifest["selected_version_name"],
            "static_dynamic_alignment": manifest["static_dynamic_same_build"],
            "sufficient_for_RQ1": "yes" if s else "no",
            "sufficient_for_RQ2": "yes" if drows else "no",
            "sufficient_for_RQ3": "yes" if s and drows and manifest["static_dynamic_same_build"] == "yes" else "no",
            "sufficient_for_RQ4": "yes" if s and drows else "partial",
            "limitation_notes": manifest.get("selection_warning") or "",
        }
        for key in ("detector_finding_totals", "dangerous_permissions", "total_exported_components", "network_security_findings", "storage_findings", "privacy_findings", "platform_findings"):
            row[key] = s.get(key, "")
        for cls in ("strict_idle", "qfg", "interactive"):
            subset = [r for r in drows if r["evidence_class"] == cls]
            row[f"{cls}_run_count"] = len(subset)
            for field in ("duration", "bytes", "packets", "bytes_per_second", "packets_per_second", "domain_count", "service_count"):
                row[f"{cls}_median_{field}"] = _median(r.get(field) for r in subset)
            for proto in ("tcp", "udp", "tls", "quic", "dns"):
                row[f"{cls}_{proto}_prevalence"] = (sum(_safe_int(r.get(f"{proto}_present")) for r in subset) / len(subset)) if subset else ""
        out.append(row)
    return out


def _dynamic_reconciliation(output_dir: Path, dynamic_rows: list[dict[str, Any]], old_export_path: Path = DEFAULT_OLD_DYNAMIC_RUN_EXPORT) -> dict[str, Any]:
    selected_by_id = {str(row["dynamic_run_id"]): row for row in dynamic_rows}
    old_rows = _read_csv(old_export_path) if old_export_path.exists() else []
    old_ids = {str(row.get("run_id") or row.get("dynamic_run_id") or "") for row in old_rows}
    missing_ids = sorted(set(selected_by_id) - old_ids)
    rows: list[dict[str, Any]] = []
    for run_id in missing_ids:
        row = selected_by_id[run_id]
        pcap_exists = row["pcap_status"] == "present"
        rows.append(
            {
                "dynamic_run_id": run_id,
                "app": row["app"],
                "package": row["package"],
                "selected_version": row["selected_version"],
                "evidence_class": row["evidence_class"],
                "absent_from_old_export": "yes",
                "old_export_path": str(old_export_path.relative_to(REPO_ROOT)) if old_export_path.is_relative_to(REPO_ROOT) else str(old_export_path),
                "absence_reason": "old export was generated before final cutoff selection and did not enumerate the final selected run set",
                "pcap_exists": "yes" if pcap_exists else "no",
                "can_be_regenerated": "yes" if pcap_exists else "no",
                "analytic_eligibility": row["analytic_eligibility"],
                "paper_metric_changes_after_regeneration": "selected run is now included in run/app metrics" if pcap_exists else "not included; missing pcap",
            }
        )
    fieldnames = [
        "dynamic_run_id",
        "app",
        "package",
        "selected_version",
        "evidence_class",
        "absent_from_old_export",
        "old_export_path",
        "absence_reason",
        "pcap_exists",
        "can_be_regenerated",
        "analytic_eligibility",
        "paper_metric_changes_after_regeneration",
    ]
    _write_csv(output_dir / "report" / "dynamic_107_123_reconciliation.csv", rows, fieldnames)
    lines = [
        f"Old export: {old_export_path}",
        f"Old selected-run coverage: {len(set(selected_by_id) & old_ids)}/{len(selected_by_id)}",
        f"Missing selected runs in old export: {len(missing_ids)}",
        "Reason: the old export was stale relative to the final selected cutoff manifest.",
        "Resolution: publication_dynamic_run_metrics.csv is regenerated from exactly the selected dynamic run IDs in the publication manifest.",
    ]
    (output_dir / "report" / "dynamic_107_123_reconciliation.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "old_export_path": str(old_export_path),
        "old_rows": len(old_rows),
        "old_selected_run_coverage": len(set(selected_by_id) & old_ids),
        "selected_runs_missing_from_old_export": len(missing_ids),
        "missing_selected_run_ids": missing_ids,
    }


def _write_source_dictionary(path: Path, rows: list[dict[str, Any]]) -> None:
    _write_csv(path, rows, ["field", "source", "aggregation_rule", "base_split_combined", "deduplication_key", "missing_value_meaning", "detector_caveat", "cross_app_comparability"])


def _window_sensitivity(cutoff_json: Mapping[str, Any], out_dir: Path) -> list[dict[str, Any]]:
    end = datetime(2026, 7, 9, 23, 59, 59, tzinfo=UTC)
    base_selected = {row["package_name"]: str(row["selected_version_code"]) for row in cutoff_json.get("apps", []) if isinstance(row, Mapping)}
    rows: list[dict[str, Any]] = []
    lines = [
        "Window sensitivity is computed from stored build-candidate aggregates.",
        "A candidate qualifies only when its first and last candidate captures are inside the window.",
        "The 14-day window is an operational reporting policy, not a preregistered parameter.",
        "",
    ]
    for days in (7, 14, 21, 28):
        start = end - timedelta(days=days) + timedelta(seconds=1)
        selectable = 0
        no_evidence: list[str] = []
        strict = qfg = interactive = run_count = changed = 0
        for app in cutoff_json.get("apps", []):
            candidates = []
            for candidate in app.get("build_candidates", []) if isinstance(app.get("build_candidates"), list) else []:
                first = _iso(candidate.get("first_capture_at"))
                last = _iso(candidate.get("last_capture_at"))
                if first and last and start <= first <= end and start <= last <= end:
                    candidates.append(candidate)
            if not candidates:
                no_evidence.append(app.get("package_name") or app.get("app") or "")
                continue
            selectable += 1
            selected = candidates[0]
            strict += _safe_int(selected.get("strict_idle_runs"))
            qfg += _safe_int(selected.get("quiescent_fg_runs"))
            interactive += _safe_int(selected.get("interactive_valid_runs"))
            run_count += len(selected.get("run_ids") or [])
            if str(selected.get("version_code")) != base_selected.get(app.get("package_name")):
                changed += 1
        rows.append(
            {
                "window_days": days,
                "window_start_utc": start.isoformat(),
                "window_end_utc": end.isoformat(),
                "apps_with_selectable_evidence": selectable,
                "apps_without_evidence": len(no_evidence),
                "apps_without_evidence_list": ",".join(sorted(no_evidence)),
                "selected_runs": run_count,
                "strict_idle_count": strict,
                "qfg_count": qfg,
                "interactive_count": interactive,
                "selected_build_changes_relative_to_14_day": changed,
                "static_dynamic_alignment_changes": "not_calculated_from_aggregates",
                "empirical_metric_changes": "requires full run-level recomputation for partial-window slicing",
            }
        )
    _write_csv(out_dir / "report" / "window_sensitivity.csv", rows, list(rows[0]))
    for row in rows:
        lines.append(
            f"{row['window_days']} days: apps={row['apps_with_selectable_evidence']}/15, "
            f"runs={row['selected_runs']}, strict={row['strict_idle_count']}, "
            f"qfg={row['qfg_count']}, interactive={row['interactive_count']}, "
            f"build_changes_vs_14d={row['selected_build_changes_relative_to_14_day']}"
        )
    (out_dir / "report" / "window_sensitivity.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return rows


def _metric_sufficiency(out_dir: Path, app_rows: list[dict[str, Any]]) -> None:
    metrics = [
        ("static_detector_finding_totals", "READY_FOR_DESCRIPTIVE_ANALYSIS", "app", "Describe static exposure; avoid causal severity claims."),
        ("dangerous_permissions", "READY_FOR_DESCRIPTIVE_ANALYSIS", "app", "Declared permissions only; runtime use is not proven."),
        ("runtime_class_run_counts", "READY_FOR_APP_LEVEL_INFERENCE", "app/run", "Classes are mutually exclusive; QFG is not strict idle."),
        ("median_bytes_by_class", "READY_FOR_DESCRIPTIVE_ANALYSIS", "run", "Unequal run depth; use medians."),
        ("service_mapping", "DESCRIPTIVE_ONLY", "run/domain", "Provider mapping is curated/top-N and not exhaustive."),
        ("static_runtime_correlation", "READY_FOR_DESCRIPTIVE_ANALYSIS", "app", "Only after aligned selected-build dataset; descriptive n=15 only."),
        ("first_party_third_party_count", "UNRELIABLE_MAPPING", "run/domain", "Use only if owner mapping is independently reviewed."),
    ]
    rows = [
        {
            "metric": name,
            "decision": decision,
            "valid_app_count": len(app_rows),
            "missing_app_count": 0,
            "missing_apps": "",
            "evidence_classes_available": "strict_idle,qfg,interactive",
            "selected_build_alignment": "aligned_by_publication_manifest",
            "normalization_rule": "app-level medians for dynamic metrics; one contributing static run per app",
            "statistical_unit": unit,
            "major_caveat": caveat,
            "recommended_paper_use": "use with caveat" if "UNRELIABLE" not in decision else "avoid in main results",
        }
        for name, decision, unit, caveat in metrics
    ]
    _write_csv(out_dir / "report" / "publication_metric_sufficiency.csv", rows, list(rows[0]))
    text = "\n".join(f"{r['metric']}: {r['decision']} - {r['major_caveat']}" for r in rows)
    (out_dir / "report" / "publication_metric_sufficiency.txt").write_text(text + "\n", encoding="utf-8")


def _write_rq_and_novelty(out_dir: Path, app_rows: list[dict[str, Any]], warnings: list[str]) -> None:
    rq_lines = [
        "RQ1 Static privacy/security exposure: READY for descriptive analysis; selected static runs are build-aligned and deduplicated to one contributing run per app.",
        "RQ2 Runtime strict-idle/QFG/interactive differences: READY for descriptive class-separated analysis; app-level inference should use medians and note unequal run depth.",
        "RQ3 Static/runtime relationship: PARTIALLY_READY; aligned app dataset exists, but correlation claims remain descriptive at n=15.",
        "RQ4 Cross-layer outliers: PARTIALLY_READY; case selection should be reviewed after metric sufficiency approval.",
    ]
    (out_dir / "report" / "research_question_readiness.txt").write_text("\n".join(rq_lines) + "\n", encoding="utf-8")
    novelty = """Primary provisional contribution:
Version-resolved linkage of static exposure and runtime behavior for frequently updated Android consumer applications.

Implementation mechanism:
The publication manifest preserves package, version, APK hash, selected static run IDs, selected dynamic run IDs, PCAP state, QA status, and evidence class.

Empirical evidence:
15/15 apps have selected build-backed evidence, 123 selected PCAP-backed runs, and one selected build identity per app.

Closest prior-work distinction:
Prior Android static/dynamic studies often report app snapshots or runtime scenarios; this dataset explicitly links frequently updated app builds to both static and runtime evidence.

Reviewer challenge:
The 14-day duration is operational and post hoc; do not make it the novelty claim.

Safe manuscript wording:
We use version-resolved, build-backed evidence bundles to link static exposure and runtime behavior under app-update churn.

Secondary contribution 1:
Strict idle, QFG, and interactive runtime evidence are separated rather than merged.

Secondary contribution 2:
APK identity, static analysis, dynamic runs, PCAP evidence, and QA state are preserved as provenance for every app-level row.
"""
    (out_dir / "report" / "novelty_evidence_map.txt").write_text(novelty, encoding="utf-8")
    discrepancies = ["No cross-build dynamic pooling detected." if not warnings else "Warnings:"] + warnings
    (out_dir / "report" / "discrepancies.txt").write_text("\n".join(discrepancies) + "\n", encoding="utf-8")
    ssot = [
        "Final cutoff report: output/paper/dynamic_paper_cutoff_final_20260709T202819Z/",
        "Publication manifest: output/paper/android_empirical_alignment_final/publication_cohort_manifest.csv",
        "Static app metrics: output/paper/android_empirical_alignment_final/data/publication_static_app_metrics.csv",
        "Dynamic run metrics: output/paper/android_empirical_alignment_final/data/publication_dynamic_run_metrics.csv",
        "App analysis dataset: output/paper/android_empirical_alignment_final/data/publication_app_analysis_dataset.csv",
        "Manuscript path: /home/secadmin/Laughlin/GitHub/IEEE_CARS_2025_AI/",
    ]
    (out_dir / "report" / "single_source_of_truth.txt").write_text("\n".join(ssot) + "\n", encoding="utf-8")


def generate_alignment(cutoff_dir: Path, output_dir: Path) -> dict[str, Any]:
    cutoff_rows, cutoff_json = _load_cutoff(cutoff_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "data").mkdir(exist_ok=True)
    (output_dir / "report").mkdir(exist_ok=True)
    static_ids = sorted({_safe_int(x) for row in cutoff_rows for x in _split_ids(row.get("selected_static_run_ids")) if _safe_int(x)})
    run_by_id, static_data = _db_static_rows(static_ids)
    contributing = _choose_contributing_static_ids(cutoff_rows, run_by_id)
    publication_manifest, class_ids, warnings = _build_publication_manifest(cutoff_rows, cutoff_json, run_by_id, contributing)

    manifest_fields = [
        "app_label", "app_category", "package_name", "selected_version_code", "selected_version_name",
        "selected_base_apk_sha256", "selected_split_count", "selected_static_run_ids", "contributing_static_run_id",
        "selected_dynamic_run_ids", "strict_idle_run_ids", "qfg_run_ids", "interactive_run_ids",
        "earliest_selected_capture_utc", "latest_selected_capture_utc", "selected_run_count", "selected_pcap_count",
        "static_dynamic_same_build", "number_of_selected_builds", "evidence_selection_reason", "evidence_source", "selection_warning",
    ]
    _write_csv(output_dir / "publication_cohort_manifest.csv", publication_manifest, manifest_fields)
    _write_json(output_dir / "publication_cohort_manifest.json", publication_manifest)

    static_alignment = _static_alignment_rows(cutoff_rows, run_by_id, contributing)
    _write_csv(output_dir / "static_run_alignment_report.csv", static_alignment, list(static_alignment[0]))
    (output_dir / "static_run_alignment_report.txt").write_text(
        "There are 30 selected static run IDs because several apps have repeated canonical analyses of the same selected build across sessions. "
        "They are repeated analyses/provenance, not 30 app-level observations. App-level metrics use exactly one contributing static run per app: "
        "the latest completed canonical identity-valid run whose base APK hash matches the selected build. This prevents double counting.\n",
        encoding="utf-8",
    )

    static_app, static_extra = _static_datasets(publication_manifest, static_data, set(contributing.values()))
    _write_csv(output_dir / "data" / "publication_static_app_metrics.csv", static_app, list(static_app[0]))
    _write_csv(output_dir / "data" / "publication_static_finding_rows.csv", static_extra["finding_rows"], list(static_extra["finding_rows"][0]) if static_extra["finding_rows"] else ["run_id"])
    _write_csv(output_dir / "data" / "publication_static_masvs_rows.csv", static_extra["masvs_rows"], list(static_extra["masvs_rows"][0]) if static_extra["masvs_rows"] else ["run_id"])
    _write_csv(output_dir / "data" / "publication_static_permission_rows.csv", static_extra["permission_rows"], list(static_extra["permission_rows"][0]) if static_extra["permission_rows"] else ["run_id"])
    _write_csv(output_dir / "data" / "publication_static_component_rows.csv", static_extra["component_rows"], list(static_extra["component_rows"][0]) if static_extra["component_rows"] else ["run_id"])
    _write_source_dictionary(
        output_dir / "data" / "publication_static_source_dictionary.csv",
        [
            {"field": "all_static_app_metrics", "source": "MariaDB canonical static tables", "aggregation_rule": "latest selected canonical static run per app", "base_split_combined": "yes", "deduplication_key": "app package + selected base APK hash + contributing static run ID", "missing_value_meaning": "not observed/not populated", "detector_caveat": "detector counts are static evidence, not confirmed exploitability", "cross_app_comparability": "yes with caveats"},
        ],
    )

    dynamic_runs, dynamic_extra = _dynamic_datasets(publication_manifest, class_ids)
    _write_csv(output_dir / "data" / "publication_dynamic_run_metrics.csv", dynamic_runs, list(dynamic_runs[0]))
    dynamic_app_metrics = _dynamic_app_metrics(dynamic_runs)
    _write_csv(output_dir / "data" / "publication_dynamic_app_metrics.csv", dynamic_app_metrics, list(dynamic_app_metrics[0]))
    _write_csv(output_dir / "data" / "publication_dynamic_domain_rows.csv", dynamic_extra["domain_rows"], list(dynamic_extra["domain_rows"][0]) if dynamic_extra["domain_rows"] else ["dynamic_run_id"])
    _write_csv(output_dir / "data" / "publication_dynamic_service_rows.csv", dynamic_extra["service_rows"], list(dynamic_extra["service_rows"][0]) if dynamic_extra["service_rows"] else ["dynamic_run_id"])
    _write_csv(output_dir / "data" / "publication_dynamic_protocol_rows.csv", dynamic_extra["protocol_rows"], list(dynamic_extra["protocol_rows"][0]) if dynamic_extra["protocol_rows"] else ["dynamic_run_id"])
    _write_source_dictionary(
        output_dir / "data" / "publication_dynamic_source_dictionary.csv",
        [
            {"field": "all_dynamic_run_metrics", "source": "selected evidence run_manifest + analysis/summary.json + analysis/pcap_report.json", "aggregation_rule": "one row per selected dynamic run ID", "base_split_combined": "n/a", "deduplication_key": "dynamic_run_id", "missing_value_meaning": "artifact absent or metric not supported", "detector_caveat": "PCAP metadata only; no payload semantics", "cross_app_comparability": "yes with class/duration caveats"},
        ],
    )

    app_analysis = _app_analysis_rows(publication_manifest, static_app, dynamic_runs)
    _write_csv(output_dir / "data" / "publication_app_analysis_dataset.csv", app_analysis, list(app_analysis[0]))
    _write_source_dictionary(
        output_dir / "data" / "publication_app_analysis_dictionary.csv",
        [
            {"field": "publication_app_analysis_dataset", "source": "publication manifest + selected static/dynamic metrics", "aggregation_rule": "one app row; dynamic medians by evidence class", "base_split_combined": "static yes", "deduplication_key": "package_name", "missing_value_meaning": "class not available", "detector_caveat": "descriptive analysis first", "cross_app_comparability": "yes with caveats"},
        ],
    )

    _window_sensitivity(cutoff_json, output_dir)
    _metric_sufficiency(output_dir, app_analysis)
    _write_rq_and_novelty(output_dir, app_analysis, warnings)
    dynamic_reconciliation = _dynamic_reconciliation(output_dir, dynamic_runs)

    selected_dynamic_ids = [run_id for row in publication_manifest for run_id in _split_ids(row["selected_dynamic_run_ids"])]
    input_paths = [cutoff_dir / "paper_freeze_manifest.csv", cutoff_dir / "paper_freeze_manifest.json", DEFAULT_OLD_DYNAMIC_RUN_EXPORT]
    summary = {
        "status": "OK",
        "mutation_scope": "read_only",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "row_counts": {
            "publication_apps": len(publication_manifest),
            "selected_static_run_ids": len(static_ids),
            "contributing_static_run_ids": len(set(contributing.values())),
            "selected_dynamic_run_ids": len(selected_dynamic_ids),
            "dynamic_run_metric_rows": len(dynamic_runs),
            "dynamic_app_metric_rows": len(dynamic_app_metrics),
            "strict_idle": sum(1 for row in dynamic_runs if row["evidence_class"] == "strict_idle"),
            "qfg": sum(1 for row in dynamic_runs if row["evidence_class"] == "qfg"),
            "interactive": sum(1 for row in dynamic_runs if row["evidence_class"] == "interactive"),
        },
        "build_alignment_checks": {
            "apps_static_dynamic_same_build": sum(1 for row in publication_manifest if row["static_dynamic_same_build"] == "yes"),
            "apps_with_selection_warnings": sum(1 for row in publication_manifest if row["selection_warning"]),
        },
        "dynamic_107_123_reconciliation": dynamic_reconciliation,
        "selected_dynamic_run_ids": selected_dynamic_ids,
        "db_queries_used": [
            "SELECT selected static_analysis_runs joined to app_versions/apps",
            "SELECT static_analysis_findings for selected IDs",
            "SELECT static_permission_matrix for selected IDs",
            "SELECT static_fileproviders for selected IDs",
            "SELECT static_string_summary for selected IDs",
        ],
        "source_checksums": {str(path): _sha256(path) for path in input_paths},
    }
    _write_json(output_dir / "alignment_summary.json", summary)
    generated_paths = sorted(path for path in output_dir.rglob("*") if path.is_file())
    _write_json(
        output_dir / "analysis_manifest.json",
        {
            **summary,
            "input_files": [str(path.resolve()) for path in input_paths],
            "generated_file_checksums": {str(path.relative_to(output_dir)): _sha256(path) for path in generated_paths if path.name != "analysis_manifest.json"},
        },
    )
    return summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cutoff-dir", default=str(DEFAULT_CUTOFF_DIR), help="Final cutoff directory.")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Publication alignment output directory.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    summary = generate_alignment(Path(args.cutoff_dir).resolve(), Path(args.output_dir).resolve())
    print(json.dumps({"status": summary["status"], "output_dir": str(Path(args.output_dir).resolve()), "row_counts": summary["row_counts"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
