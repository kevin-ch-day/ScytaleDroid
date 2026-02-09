"""Verify dynamic evidence packs against the Paper #2 frozen-input contract.

This module is intentionally DB-free and operates only on evidence packs on disk.
It is safe to run on an air-gapped machine.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REQUIRED_FROZEN_INPUTS = (
    "run_manifest.json",
    "inputs/static_dynamic_plan.json",
    "analysis/summary.json",
    "analysis/pcap_report.json",
    "analysis/pcap_features.json",
)

# Hostname-ish filter for quick "junk in top-N" detection (not a strict DNS validator).
_HOSTNAME_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.?$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class VerifyIssue:
    code: str
    message: str


@dataclass(frozen=True)
class RunVerifyResult:
    run_id: str
    package_name: str
    tier: str | None
    status: str | None
    valid_dataset_run: bool | None
    invalid_reason_code: str | None
    issues: list[VerifyIssue]


def verify_dynamic_evidence_packs(
    output_root: Path,
    *,
    dataset_only: bool = False,
) -> dict[str, Any]:
    """Verify all evidence packs under output_root.

    Returns a deterministic JSON-serializable report.
    """
    started_at = datetime.now(UTC).isoformat()
    results: list[RunVerifyResult] = []
    scanned = 0

    if not output_root.exists():
        return {
            "started_at": started_at,
            "finished_at": datetime.now(UTC).isoformat(),
            "output_root": str(output_root),
            "scanned": 0,
            "runs": [],
            "summary": {"valid": 0, "invalid": 0, "unknown": 0, "issues": {}},
        }

    for run_dir in sorted([p for p in output_root.iterdir() if p.is_dir()]):
        manifest_path = run_dir / "run_manifest.json"
        if not manifest_path.exists():
            continue
        scanned += 1
        run_id = run_dir.name
        issues: list[VerifyIssue] = []
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            results.append(
                RunVerifyResult(
                    run_id=run_id,
                    package_name="_unknown",
                    tier=None,
                    status=None,
                    valid_dataset_run=None,
                    invalid_reason_code="MANIFEST_INVALID_JSON",
                    issues=[VerifyIssue("manifest_invalid_json", "run_manifest.json not parseable")],
                )
            )
            continue

        target = manifest.get("target") if isinstance(manifest, dict) else None
        operator = manifest.get("operator") if isinstance(manifest, dict) else None
        dataset = manifest.get("dataset") if isinstance(manifest, dict) else None
        pkg = (target.get("package_name") if isinstance(target, dict) else None) or "_unknown"
        status = manifest.get("status") if isinstance(manifest, dict) else None
        tier = (operator.get("tier") if isinstance(operator, dict) else None) or (
            dataset.get("tier") if isinstance(dataset, dict) else None
        )

        if dataset_only and str(tier or "").lower() != "dataset":
            continue

        # Dataset block contract: must exist for dataset runs (authoritative validity).
        if str(tier or "").lower() == "dataset":
            if not isinstance(dataset, dict) or not dataset:
                issues.append(
                    VerifyIssue(
                        "manifest_dataset_missing",
                        "manifest.dataset missing/empty for dataset-tier run",
                    )
                )
            # Legacy mirrors (e.g., operator.dataset_validity) are intentionally ignored.
            # Do not warn: many runs contain this mirror due to prior migrations, and the
            # Paper #2 contract treats `manifest.dataset` as authoritative.

        valid = dataset.get("valid_dataset_run") if isinstance(dataset, dict) else None
        invalid_reason = dataset.get("invalid_reason_code") if isinstance(dataset, dict) else None

        # Frozen inputs existence checks.
        for rel in REQUIRED_FROZEN_INPUTS:
            if not (run_dir / rel).exists():
                issues.append(VerifyIssue("missing_frozen_input", f"Missing {rel}"))

        # PCAP existence: trust the artifact record for the path.
        pcap_rel = None
        for art in manifest.get("artifacts") or []:
            if not isinstance(art, dict):
                continue
            if art.get("type") == "pcapdroid_capture" and art.get("relative_path"):
                pcap_rel = str(art.get("relative_path"))
                break
        if not pcap_rel:
            issues.append(VerifyIssue("pcap_artifact_missing", "No pcapdroid_capture artifact in manifest"))
        else:
            if not (run_dir / pcap_rel).exists():
                issues.append(VerifyIssue("pcap_file_missing", f"PCAP referenced but missing: {pcap_rel}"))

        # Plan identity: ensure run_identity tuple exists (static snapshot contract).
        plan_path = run_dir / "inputs/static_dynamic_plan.json"
        if plan_path.exists():
            try:
                plan = json.loads(plan_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                plan = None
                issues.append(VerifyIssue("plan_invalid_json", "inputs/static_dynamic_plan.json not parseable"))
            if isinstance(plan, dict):
                ri = plan.get("run_identity") or {}
                if not isinstance(ri, dict):
                    issues.append(VerifyIssue("plan_identity_missing", "plan.run_identity missing"))
                else:
                    needed = ["base_apk_sha256", "artifact_set_hash", "run_signature", "run_signature_version"]
                    missing = [k for k in needed if not ri.get(k)]
                    if missing:
                        issues.append(
                            VerifyIssue(
                                "plan_identity_incomplete",
                                f"plan.run_identity missing keys: {', '.join(missing)}",
                            )
                        )
                    if ri.get("identity_valid") is False:
                        issues.append(VerifyIssue("plan_identity_invalid", "plan.run_identity.identity_valid=false"))

        # pcap_report consistency and transport ratios sanity.
        report_path = run_dir / "analysis/pcap_report.json"
        if report_path.exists():
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                report = None
                issues.append(VerifyIssue("pcap_report_invalid_json", "analysis/pcap_report.json not parseable"))
            if isinstance(report, dict):
                missing_tools = report.get("missing_tools") or []
                if str(tier or "").lower() == "dataset" and missing_tools:
                    issues.append(VerifyIssue("missing_tools_dataset", f"Dataset-tier run has missing_tools={missing_tools}"))
                proto = report.get("protocol_hierarchy") or []
                if isinstance(proto, list) and not proto:
                    if int(report.get("no_traffic_observed") or 0) != 1:
                        issues.append(
                            VerifyIssue(
                                "protocol_empty_no_reason",
                                "protocol_hierarchy empty but no_traffic_observed != 1",
                            )
                        )
                # Report-level normalized ratios (if present) must be bounded.
                ratios = report.get("protocol_ratios") if isinstance(report.get("protocol_ratios"), dict) else {}
                for key in ("tls_ratio", "quic_ratio", "tcp_ratio", "udp_ratio"):
                    v = ratios.get(key) if isinstance(ratios, dict) else None
                    if v is None:
                        continue
                    try:
                        vf = float(v)
                    except Exception:
                        issues.append(VerifyIssue("ratio_invalid", f"pcap_report.protocol_ratios.{key} not numeric"))
                        continue
                    if vf < 0 or vf > 1:
                        issues.append(
                            VerifyIssue(
                                "ratio_out_of_range",
                                f"pcap_report.protocol_ratios.{key}={vf} not in [0,1]",
                            )
                        )

                # Quick indicator hygiene checks (top-N only).
                top_sni = report.get("top_sni") if isinstance(report.get("top_sni"), list) else []
                top_dns = report.get("top_dns") if isinstance(report.get("top_dns"), list) else []
                junk = 0
                for item in (top_sni + top_dns)[:20]:
                    if not isinstance(item, dict):
                        continue
                    v = str(item.get("value") or "").strip()
                    if not v:
                        continue
                    if len(v) > 260 or " " in v or "/" in v or ":" in v:
                        junk += 1
                        continue
                    if not _HOSTNAME_RE.match(v):
                        junk += 1
                if junk >= 3:
                    issues.append(
                        VerifyIssue(
                            "indicator_junk_topn",
                            f"Top DNS/SNI contains {junk} suspicious values (top-N only)",
                        )
                    )

                # Dominance is not necessarily bad (streaming), but it is a useful quality signal.
                try:
                    top1_sni = report.get("top1_sni_share")
                    if top1_sni is not None and float(top1_sni) >= 0.95:
                        issues.append(VerifyIssue("top1_sni_dominant", f"top1_sni_share={top1_sni}"))
                except Exception:
                    pass
                try:
                    top1_dns = report.get("top1_dns_share")
                    if top1_dns is not None and float(top1_dns) >= 0.95:
                        issues.append(VerifyIssue("top1_dns_dominant", f"top1_dns_share={top1_dns}"))
                except Exception:
                    pass

        feat_path = run_dir / "analysis/pcap_features.json"
        if feat_path.exists():
            try:
                feats = json.loads(feat_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                feats = None
                issues.append(VerifyIssue("pcap_features_invalid_json", "analysis/pcap_features.json not parseable"))
            if isinstance(feats, dict):
                proxies = feats.get("proxies") or {}
                for key in ("tls_ratio", "quic_ratio", "tcp_ratio", "udp_ratio"):
                    if key in proxies and proxies[key] is not None:
                        try:
                            v = float(proxies[key])
                        except Exception:
                            issues.append(VerifyIssue("ratio_invalid", f"{key} not numeric"))
                            continue
                        if v < 0 or v > 1:
                            issues.append(VerifyIssue("ratio_out_of_range", f"{key}={v} not in [0,1]"))
                # If both report and features provide normalized ratios, they should not drift significantly.
                if isinstance(report, dict) and isinstance(report.get("protocol_ratios"), dict):
                    rrat = report["protocol_ratios"]
                    for key in ("tls_ratio", "quic_ratio", "tcp_ratio", "udp_ratio"):
                        pv = proxies.get(key)
                        rv = rrat.get(key)
                        if pv is None or rv is None:
                            continue
                        try:
                            pf = float(pv)
                            rf = float(rv)
                        except Exception:
                            continue
                        if abs(pf - rf) > 0.15:
                            issues.append(
                                VerifyIssue(
                                    "transport_ratio_drift",
                                    f"{key} differs (features={pf:.2f} report={rf:.2f})",
                                )
                            )

        results.append(
            RunVerifyResult(
                run_id=str(manifest.get("dynamic_run_id") or run_id),
                package_name=str(pkg),
                tier=str(tier) if tier is not None else None,
                status=str(status) if status is not None else None,
                valid_dataset_run=valid if isinstance(valid, bool) else None,
                invalid_reason_code=str(invalid_reason) if invalid_reason is not None else None,
                issues=issues,
            )
        )

    # Summary counts and issue codes.
    valid_n = sum(1 for r in results if r.valid_dataset_run is True)
    invalid_n = sum(1 for r in results if r.valid_dataset_run is False)
    unknown_n = sum(1 for r in results if r.valid_dataset_run is None)
    issue_counts: dict[str, int] = {}
    for r in results:
        for i in r.issues:
            issue_counts[i.code] = issue_counts.get(i.code, 0) + 1

    finished_at = datetime.now(UTC).isoformat()
    return {
        "started_at": started_at,
        "finished_at": finished_at,
        "output_root": str(output_root),
        "scanned": scanned,
        "runs": [
            {
                "run_id": r.run_id,
                "package_name": r.package_name,
                "tier": r.tier,
                "status": r.status,
                "valid_dataset_run": r.valid_dataset_run,
                "invalid_reason_code": r.invalid_reason_code,
                "issues": [{"code": i.code, "message": i.message} for i in r.issues],
            }
            for r in results
        ],
        "summary": {
            "valid": valid_n,
            "invalid": invalid_n,
            "unknown": unknown_n,
            "issue_counts": dict(sorted(issue_counts.items())),
        },
    }


def write_verify_report(report: dict[str, Any], *, dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = dest_dir / f"dynamic-verify-{stamp}.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return path


__all__ = [
    "REQUIRED_FROZEN_INPUTS",
    "RunVerifyResult",
    "VerifyIssue",
    "verify_dynamic_evidence_packs",
    "write_verify_report",
]
