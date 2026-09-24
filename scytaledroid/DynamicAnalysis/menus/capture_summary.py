"""Capture facts without interpreting cohort exclusion as capture failure."""

from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
from scytaledroid.DynamicAnalysis.utils.path_utils import (
    bound_manifest_run_id,
    dynamic_evidence_roots,
    iter_dynamic_run_dirs,
    resolve_evidence_path,
)


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def local_runs() -> list[tuple[Path, dict]]:
    rows = []
    roots = [root.resolve() for root in dynamic_evidence_roots()]
    for path in iter_dynamic_run_dirs():
        try:
            resolved = path.resolve()
            if not any(resolved.is_relative_to(root) and resolved != root for root in roots):
                continue
            manifest_path = resolved / "run_manifest.json"
            if not manifest_path.resolve().is_relative_to(resolved):
                continue
            manifest = read_json(manifest_path)
            if not manifest or bound_manifest_run_id(manifest, resolved) is None:
                continue
            rows.append((resolved, manifest))
        except (OSError, RuntimeError):
            continue
    return sorted(rows, key=lambda row: str(row[1].get("created_at") or ""), reverse=True)


def exact_build_history(package: str, selection: dict, runs=None) -> dict:
    counts = {"total": 0, "current": 0, "idle_intent": 0, "qfg_intent": 0, "interactive": 0}
    for _path, manifest in local_runs() if runs is None else runs:
        target = manifest.get("target") or {}
        if target.get("package_name") != package:
            continue
        counts["total"] += 1
        identity = target.get("identity_start") or {}
        # Legacy unknown versions never become current-build observations by inference.
        if not selection.get("artifact_set_hash_version") or not selection.get("artifact_set_hash"):
            continue
        if any(
            str(identity.get(key) or "") != str(selection.get(key) or "")
            for key in (
                "artifact_set_hash_version",
                "artifact_set_hash",
                "base_apk_sha256",
                "version_code",
            )
        ):
            continue
        counts["current"] += 1
        operator = manifest.get("operator") or {}
        intent = operator.get("capture_behavior_intent")
        profile = str(operator.get("run_profile") or "")
        if intent == "quiescent_foreground":
            counts["qfg_intent"] += 1
        elif intent == "idle" or profile == "baseline_idle":
            counts["idle_intent"] += 1
        elif intent == "interactive" or profile.startswith("interaction"):
            counts["interactive"] += 1
    return counts


def print_capture_summary(result, label: str, behavior: str, selection: dict) -> None:
    failure = getattr(result, "startup_failure", None)
    if failure:
        print("\nDynamic run could not start.")
        for key, value in (
            ("Stage", failure["stage"]),
            ("Run ID", result.dynamic_run_id),
            ("Capture started", "No"),
            ("Database persisted", "No (not attempted)"),
            ("Diagnostic evidence", failure["diagnostic_evidence"]),
            ("Evidence path", result.evidence_path),
            ("Recovery", failure["recovery"]),
            ("QA / archive / research eligibility", "Not eligible; startup failed"),
            ("Error", failure["error"]),
        ):
            print(f"  {key}: {value}")
        return
    path = resolve_evidence_path(result.evidence_path) if result.evidence_path else None
    manifest = read_json(path / "run_manifest.json") if path else {}
    report = read_json(path / "analysis/pcap_report.json") if path else {}
    features = read_json(path / "analysis/pcap_features.json") if path else {}
    receipt = (
        read_json(
            EvidencePackWriter(path).derived_writer().run_dir
            / "analysis/index/v1/db_persistence_status.json"
        )
        if path
        else {}
    )
    cap = (report.get("capinfos") or {}).get("parsed") or {}
    operator = manifest.get("operator") or {}
    checks = operator.get("capture_build_verification") or {}
    end_match = checks.get("end_matches_start")
    qa = "not evaluated"
    if (
        result.status == "success"
        and not result.errors
        and manifest.get("sealed_at")
        and report.get("report_status") == "ok"
        and end_match is True
    ):
        qa = "session, build and PCAP checks passed; full pack integrity not rechecked"
    elif result.errors or result.status in {"failed", "blocked", "degraded"} or end_match is False:
        qa = "review required; any collected evidence is preserved"
    elif checks and end_match is None:
        qa = "end-build verification unavailable; review required"
    persistence = (
        "OK"
        if receipt.get("ok") is True
        else (
            f"not persisted ({receipt.get('error_code') or 'see receipt'})"
            if receipt.get("attempted")
            else "not confirmed"
        )
    )
    print(f"\nDYNAMIC CAPTURE: {str(result.status).upper()}")
    artifacts = list(manifest.get("artifacts") or [])
    for observer in manifest.get("observers") or []:
        if isinstance(observer, dict):
            artifacts.extend(observer.get("artifacts") or [])
    pcap = next(
        (
            a
            for a in artifacts
            if isinstance(a, dict)
            and str(a.get("relative_path") or "").lower().endswith((".pcap", ".pcapng"))
        ),
        {},
    )
    values = [
        ("App", f"{label} ({result.package_name})"),
        ("Run ID", result.dynamic_run_id),
        ("Capture intent", behavior),
        (
            "Duration",
            f"{result.elapsed_seconds if result.elapsed_seconds is not None else result.duration_seconds}s",
        ),
        ("Build SHA-256", selection.get("base_apk_sha256")),
        ("PCAP file", pcap.get("relative_path", "not recorded")),
        ("PCAP SHA-256", pcap.get("sha256") or "not recorded"),
        ("PCAP analysis", report.get("report_status", "unavailable")),
        ("Packets", cap.get("packet_count", "unknown")),
        (
            "Domains (reported top-N)",
            (features.get("proxies") or {}).get("unique_domains_topn", "unknown"),
        ),
        ("QA", qa),
        ("Persistence", persistence),
        ("Evidence pack", "sealed" if manifest.get("sealed_at") else "not confirmed sealed"),
        ("Evidence path", path or "unavailable"),
        ("Research eligibility", "not evaluated"),
    ]
    for key, value in values:
        print(f"  {key}: {value}")
    history = exact_build_history(result.package_name, selection)
    print(
        f"  Local current-build run records: {history['current']} | idle intent {history['idle_intent']} | foreground no-touch intent {history['qfg_intent']} | interactive {history['interactive']}"
    )
    print("  Observation counts are not validity or research-qualification counts.")
    if result.errors:
        print("  Capture errors: " + "; ".join(str(e) for e in result.errors))


def show_recent_runs() -> None:
    from scytaledroid.Utils.DisplayUtils import prompt_utils

    rows = local_runs()[:20]
    print("\nRecent local evidence packs (all capture modes)")
    for path, manifest in rows:
        target = manifest.get("target") or {}
        print(
            f"  {manifest.get('created_at', '?')} | {target.get('package_name', '?')} | {manifest.get('status', '?')}\n    {path}"
        )
    if not rows:
        print("  No readable local run manifests. DB-only or archived runs are not included.")
    prompt_utils.press_enter_to_continue()
