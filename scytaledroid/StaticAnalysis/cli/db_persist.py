"""High-level run persistence helpers (buckets, metrics, findings, contributors)."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

from scytaledroid.Persistence import db_writer as _dw
from scytaledroid.StaticAnalysis.modules.permissions.simple import (
    _classify_permissions as _classify,
    _fetch_protections as _prot_map,
)
from scytaledroid.StaticAnalysis.modules.permissions.analysis.scoring import (
    permission_risk_score_detail as _perm_detail,
    permission_points_0_20 as _perm_pts,
)


def persist_run_summary(base_report, string_data: Mapping[str, object], run_package: str) -> None:
    br = base_report
    target_sdk = None
    try:
        target_sdk = int(br.manifest.target_sdk) if br.manifest.target_sdk else None
    except Exception:
        target_sdk = None
    run_id = _dw.create_run(
        package=br.manifest.package_name or run_package,
        version_code=int(br.manifest.version_code) if br.manifest.version_code else None,
        version_name=br.manifest.version_name,
        target_sdk=target_sdk,
    )
    if not run_id:
        return

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

    _dw.write_buckets(
        int(run_id),
        {
            "permissions": (perm_points, 20.0),
            "network": (net_points, 20.0),
            "storage": (sto_points, 10.0),
            "components": (comp_points, 15.0),
            "secrets": (secrets_points, 25.0),
            "webssl": (webssl_points, 10.0),
            "correlations": (corr_points, 5.0),
        },
    )
    _dw.write_metrics(
        int(run_id),
        {
            "network.code_http_hosts": (float(code_http_hosts), None),
            "network.asset_http_hosts": (float(asset_http_hosts), None),
            "exports.total": (float(exp_total), None),
        },
    )

    # Persist a small finding sample and contributors (explainability)
    try:
        rows_findings = []
        severity_map = {"P0": "High", "P1": "Medium", "P2": "Low", "NOTE": "Info"}
        for result in (br.detector_results or ()):  # type: ignore[attr-defined]
            for f in result.findings:
                sev = severity_map.get(f.severity_gate.value, "Info")
                masvs = f.category_masvs.value
                cvss = None  # TODO: map finding_id to CVSS v4 from config
                kind = result.detector_id
                ev = "; ".join(p.location for p in (f.evidence or ())) if f.evidence else f.because
                rows_findings.append((sev, masvs, cvss or "", kind, ev[:480]))
                if len(rows_findings) >= 20:
                    break
            if len(rows_findings) >= 20:
                break
        if rows_findings:
            _dw.write_findings(int(run_id), rows_findings)
    except Exception:
        pass

    try:
        contrib = [
            ("permissions", perm_points, "Permission risk (0–20)", 1),
            ("network", net_points, "Network hygiene (0–20)", 2),
            ("components", comp_points, "Exported/unguarded components (0–15)", 3),
            ("storage", sto_points, "Storage hygiene (0–10)", 4),
            ("secrets", secrets_points, "Validated secrets (≤25) + entropy-only (≤5)", 5),
            ("webssl", webssl_points, "WebView/SSL config (0–10)", 6),
            ("correlations", corr_points, "Composite signals (cap +5)", 7),
        ]
        contrib_sorted = sorted(contrib, key=lambda r: r[1], reverse=True)
        contrib_ranked = [
            (name, pts, expl, idx + 1) for idx, (name, pts, expl, _r) in enumerate(contrib_sorted)
        ]
        _dw.write_contributors(int(run_id), contrib_ranked)
    except Exception:
        pass


__all__ = ["persist_run_summary"]

