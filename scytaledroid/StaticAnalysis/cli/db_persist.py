"""High-level run persistence helpers (buckets, metrics, findings, contributors)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Mapping, MutableMapping, Optional, Sequence

from scytaledroid.Persistence import db_writer as _dw
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.StaticAnalysis.modules.permissions.simple import (
    _classify_permissions as _classify,
    _fetch_protections as _prot_map,
)
from scytaledroid.StaticAnalysis.modules.permissions.analysis.scoring import (
    permission_risk_score_detail as _perm_detail,
    permission_points_0_20 as _perm_pts,
)
from scytaledroid.Database.db_func.static_analysis import (
    static_findings as _sf,
    string_analysis as _sa,
)


@lru_cache(maxsize=1)
def _load_cvss_map() -> Mapping[str, Mapping[str, Optional[str]]]:
    path = Path("config/masvs_map.json")
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text("utf-8"))
    except Exception:
        return {}
    mapping = {}
    for finding_id, payload in data.items():
        if not isinstance(payload, dict):
            continue
        codes = payload.get("masvs") or []
        area = None
        if isinstance(codes, list) and codes:
            code = str(codes[0])
            parts = code.split("-")
            if len(parts) >= 2:
                area = parts[1].upper()
        mapping[str(finding_id)] = {
            "masvs": area,
            "cvss": payload.get("cvss_v4"),
        }
    return mapping


@dataclass(slots=True)
class PersistenceOutcome:
    run_id: int | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return not self.errors

    def add_error(self, message: str) -> None:
        self.errors.append(message)


def persist_run_summary(
    base_report,
    string_data: Mapping[str, object],
    run_package: str,
    *,
    session_stamp: str | None,
    scope_label: str,
    finding_totals: Mapping[str, int],
    baseline_payload: Mapping[str, object],
    dry_run: bool = False,
) -> PersistenceOutcome:
    outcome = PersistenceOutcome()
    if dry_run:
        log.info("Dry-run enabled; skipping persistence for %s", run_package, category="static_analysis")
        return outcome

    if not session_stamp:
        message = f"Missing session stamp for {run_package}; static persistence will be skipped."
        log.warning(message, category="static_analysis")
        outcome.add_error(message)
        return outcome

    br = base_report
    target_sdk = None
    try:
        target_sdk = int(br.manifest.target_sdk) if br.manifest.target_sdk else None
    except Exception:
        target_sdk = None
    if not session_stamp:
        try:
            meta = getattr(br, "metadata", {}) or {}
            value = meta.get("session_stamp")
            if isinstance(value, str) and value.strip():
                session_stamp = value.strip()
        except Exception:
            pass

    run_id = _dw.create_run(
        package=br.manifest.package_name or run_package,
        version_code=int(br.manifest.version_code) if br.manifest.version_code else None,
        version_name=br.manifest.version_name,
        target_sdk=target_sdk,
        session_stamp=session_stamp,
    )
    if not run_id:
        message = f"Failed to create run record for {run_package}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)
        return outcome

    outcome.run_id = int(run_id)

    declared = list(br.permissions.declared or ())
    shorts_only = [n.split(".")[-1].upper() for n in declared if n.startswith("android.")]
    pmap = _prot_map(shorts_only)
    rc, groups, vc, _fw_ds, _vn = _classify([(n, "uses-permission") for n in declared], pmap)
    d = rc.get("dangerous", 0)
    s = rc.get("signature", 0)
    v = vc.get("ADS", 0)
    flags = br.manifest_flags
    d_detail = _perm_detail(
        dangerous=d,
        signature=s,
        vendor=v,
        groups=groups,
        target_sdk=target_sdk,
        allow_backup=flags.allow_backup,
        legacy_external_storage=flags.request_legacy_external_storage,
    )
    perm_points = _perm_pts(float(d_detail.get("score_3dp", 0.0)))

    # Compute code-path and asset HTTP hosts for metrics
    def _code_asset_http_counts() -> tuple[int, int]:
        try:
            samples = string_data.get("samples", {}) if isinstance(string_data, dict) else {}
            http_samples = (samples.get("http_cleartext") or []) + (samples.get("endpoints") or [])
            code_hosts: set[str] = set()
            asset_hosts: set[str] = set()
            for s in http_samples:
                st = str(s.get("source_type") or "").lower()
                scheme = str(s.get("scheme") or "").lower()
                root = str(s.get("root_domain") or "")
                if scheme != "http":
                    continue
                if st in {"code", "dex", "native"}:
                    code_hosts.add(root or "")
                else:
                    asset_hosts.add(root or "")
            return (len({h for h in code_hosts if h}), len({h for h in asset_hosts if h}))
        except Exception:
            return (0, 0)

    code_http_hosts, asset_http_hosts = _code_asset_http_counts()
    has_code_http = code_http_hosts > 0
    uses_ct = bool(flags.uses_cleartext_traffic)
    net_points = 20.0 if (uses_ct and has_code_http) else (5.0 if has_code_http else 0.0)

    sto_points = 10.0 if bool(flags.request_legacy_external_storage) else 0.0
    exp_total = br.exported_components.total()
    comp_points = float(min(15, exp_total))
    agg = string_data.get("aggregates", {}) if isinstance(string_data, dict) else {}
    validated = len(agg.get("api_keys_high", []) or [])
    entropy = int(string_data.get("counts", {}).get("high_entropy", 0)) if isinstance(string_data, dict) else 0
    secrets_points = float(min(25, validated)) + float(min(5, 5 if entropy else 0))
    webssl_points = 0.0
    corr_points = 0.0
    if has_code_http and ("android.permission.INTERNET" in declared):
        corr_points += 1.0
    if any(p.endswith("READ_CONTACTS") for p in declared) and agg.get("endpoint_roots"):
        corr_points += 1.0
    corr_points = min(5.0, corr_points)

    buckets_payload = {
        "permissions": (perm_points, 20.0),
        "network": (net_points, 20.0),
        "storage": (sto_points, 10.0),
        "components": (comp_points, 15.0),
        "secrets": (secrets_points, 25.0),
        "webssl": (webssl_points, 10.0),
        "correlations": (corr_points, 5.0),
    }
    if not _dw.write_buckets(int(run_id), buckets_payload):
        message = f"Failed to persist scoring buckets for run_id={run_id}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)

    metrics_payload = {
        "network.code_http_hosts": (float(code_http_hosts), None),
        "network.asset_http_hosts": (float(asset_http_hosts), None),
        "exports.total": (float(exp_total), None),
    }
    if not _dw.write_metrics(int(run_id), metrics_payload):
        message = f"Failed to persist metrics for run_id={run_id}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)

    # Persist a small finding sample (for DB-backed MASVS summary)
    severity_map = {"P0": "High", "P1": "Medium", "P2": "Low", "NOTE": "Info"}
    cvss_map = _load_cvss_map()
    rows_findings = []
    try:
        for result in (br.detector_results or ()):  # type: ignore[attr-defined]
            for f in result.findings:
                sev = severity_map.get(f.severity_gate.value, "Info")
                mapping = cvss_map.get(f.finding_id)
                masvs_area = (mapping.get("masvs") if mapping else None) or f.category_masvs.value
                cvss = mapping.get("cvss") if mapping else ""
                kind = result.detector_id
                ev = "; ".join(p.location for p in (f.evidence or ())) if f.evidence else f.because
                rows_findings.append((sev, masvs_area, cvss or "", kind, ev[:480]))
                if len(rows_findings) >= 50:
                    break
            if len(rows_findings) >= 50:
                break
    except Exception as exc:
        message = f"Failed to derive MASVS finding sample for {run_package}: {exc}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)
        rows_findings = []
    if rows_findings and not _dw.write_findings(int(run_id), rows_findings):
        message = f"Failed to persist MASVS finding samples for run_id={run_id}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)

    contributors = []
    try:
        sig_components = d_detail.get("signal_components", {})
        breadth = float(d_detail.get("breadth", {}).get("applied", 0.0) or 0.0)
        modernization = float(d_detail.get("modernization_credit", 0.0) or 0.0)

        def _points(value: float) -> float:
            return round(float(value) * 2.0, 2)

        if sig_components:
            dangerous_pts = _points(sig_components.get("dangerous", 0.0))
            signature_pts = _points(sig_components.get("signature", 0.0))
            vendor_pts = _points(sig_components.get("vendor", 0.0))
            if dangerous_pts:
                contributors.append(("permissions_dangerous", dangerous_pts, f"Dangerous permissions footprint (+{dangerous_pts})", 0))
            if signature_pts:
                contributors.append(("permissions_signature", signature_pts, f"Signature-level capabilities (+{signature_pts})", 0))
            if vendor_pts:
                contributors.append(("permissions_vendor", vendor_pts, f"Vendor/ads permissions (+{vendor_pts})", 0))
        breadth_pts = _points(breadth)
        if breadth_pts:
            contributors.append(("permissions_breadth", breadth_pts, f"Capability breadth bonus (+{breadth_pts})", 0))
        modernization_pts = _points(modernization)
        if modernization_pts:
            contributors.append(("permissions_modernization", -modernization_pts, f"Modernization credit (targetSdk/flags) (−{modernization_pts})", 0))
        if net_points:
            if uses_ct and has_code_http:
                reason = "usesCleartextTraffic with code-path HTTP endpoints"
            elif has_code_http:
                reason = "HTTP endpoints observed in code paths"
            else:
                reason = "Network hygiene signal"
            contributors.append(("network", net_points, f"{reason} (+{net_points})", 0))
        if comp_points:
            contributors.append(("components", comp_points, f"Exported components without guards (+{comp_points})", 0))
        if sto_points:
            contributors.append(("storage", sto_points, f"Legacy storage flag/requestLegacyExternalStorage (+{sto_points})", 0))
        if secrets_points:
            contributors.append(("secrets", secrets_points, f"Validated secrets & entropy findings (+{secrets_points})", 0))
        if webssl_points:
            contributors.append(("webssl", webssl_points, f"WebView/SSL configuration signals (+{webssl_points})", 0))
        if corr_points:
            contributors.append(("correlations", corr_points, f"Composite risk correlations (+{corr_points})", 0))
    except Exception as exc:
        message = f"Failed to derive contributor weights for {run_package}: {exc}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)
        contributors = []

    if contributors:
        contrib_sorted = sorted(contributors, key=lambda row: abs(row[1]), reverse=True)
        contrib_ranked = [
            (name, round(points, 2), explanation, idx + 1)
            for idx, (name, points, explanation, _rank) in enumerate(contrib_sorted)
            if points or "modernization" in name
        ]
        if contrib_ranked and not _dw.write_contributors(int(run_id), contrib_ranked):
            message = f"Failed to persist contributor breakdown for run_id={run_id}"
            log.warning(message, category="static_analysis")
            outcome.add_error(message)

    baseline_section = baseline_payload.get("baseline") if isinstance(baseline_payload, Mapping) else {}
    string_payload = baseline_section.get("string_analysis") if isinstance(baseline_section, Mapping) else {}
    static_errors = _persist_static_tables(
        package_name=br.manifest.package_name or run_package,
        session_stamp=session_stamp,
        scope_label=scope_label,
        finding_totals=finding_totals,
        baseline_section=baseline_section if isinstance(baseline_section, Mapping) else {},
        string_payload=string_payload if isinstance(string_payload, Mapping) else {},
    )
    for err in static_errors:
        outcome.add_error(err)

    return outcome


def _persist_static_tables(
    *,
    package_name: str,
    session_stamp: str,
    scope_label: str,
    finding_totals: Mapping[str, int],
    baseline_section: Mapping[str, object],
    string_payload: Mapping[str, object],
) -> list[str]:
    errors: list[str] = []

    severity_counts = _coerce_severity_counts(finding_totals)
    details = {
        "manifest_flags": baseline_section.get("manifest_flags"),
        "exports": baseline_section.get("exports"),
        "permissions": baseline_section.get("permissions"),
        "nsc": baseline_section.get("nsc"),
        "string_counts": (string_payload.get("counts") if isinstance(string_payload.get("counts"), Mapping) else {}),
    }

    try:
        if not _sf.ensure_tables():
            raise RuntimeError("static_findings tables unavailable")
        summary_id = _sf.upsert_summary(
            package_name=package_name,
            session_stamp=session_stamp,
            scope_label=scope_label,
            severity_counts=severity_counts,
            details=details,
        )
        if summary_id is None:
            raise RuntimeError("upsert_summary returned None")
        findings = baseline_section.get("findings")
        if isinstance(findings, Sequence) and findings:
            _sf.replace_findings(summary_id, tuple(findings))
    except Exception as exc:
        message = f"Failed to persist static findings summary for {package_name}: {exc}"
        log.warning(message, category="static_analysis")
        errors.append(message)

    try:
        if not _sa.ensure_tables():
            raise RuntimeError("static_string tables unavailable")
        counts = _normalise_string_counts(string_payload.get("counts"))
        summary_record = _sa.StringSummaryRecord(
            package_name=package_name,
            session_stamp=session_stamp,
            scope_label=scope_label,
            counts=counts,
        )
        summary_id = _sa.upsert_summary(summary_record)
        if summary_id is None:
            raise RuntimeError("upsert_summary returned None")
        samples_payload = string_payload.get("samples")
        samples = samples_payload if isinstance(samples_payload, Mapping) else {}
        _sa.replace_top_samples(summary_id, samples, top_n=3)
    except Exception as exc:
        message = f"Failed to persist string analysis summary for {package_name}: {exc}"
        log.warning(message, category="static_analysis")
        errors.append(message)

    return errors


def _coerce_severity_counts(totals: Mapping[str, int]) -> Mapping[str, int]:
    def _value(*keys: str) -> int:
        for key in keys:
            value = totals.get(key)
            if value is not None:
                try:
                    return int(value)
                except (TypeError, ValueError):
                    continue
        return 0

    return {
        "High": _value("High", "H"),
        "Medium": _value("Medium", "Med", "M"),
        "Low": _value("Low", "L"),
        "Info": _value("Info", "Information", "I"),
    }


def _normalise_string_counts(raw: object) -> Mapping[str, int]:
    source = raw if isinstance(raw, Mapping) else {}
    keys = (
        "endpoints",
        "http_cleartext",
        "api_keys",
        "analytics_ids",
        "cloud_refs",
        "ipc",
        "uris",
        "flags",
        "certs",
        "high_entropy",
    )
    return {key: int(source.get(key, 0) or 0) for key in keys}


__all__ = ["persist_run_summary", "PersistenceOutcome"]
