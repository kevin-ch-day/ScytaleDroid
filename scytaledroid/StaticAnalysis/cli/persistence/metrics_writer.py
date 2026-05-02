"""Derive and persist scoring buckets, metrics, and contributor breakdowns."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from typing import Any

from scytaledroid.StaticAnalysis.modules.permissions.permission_console_rendering import (
    _classify_permissions as _classify,
)
from scytaledroid.StaticAnalysis.modules.permissions.permission_console_rendering import (
    _resolve_declared_permissions_and_sdk as _resolve_perm_inputs,
)
from scytaledroid.StaticAnalysis.modules.permissions.permission_protection_lookup import (
    _fetch_protections as _prot_map,
)
from scytaledroid.StaticAnalysis.risk.permission import (
    permission_points_0_20 as _perm_pts,
)
from scytaledroid.StaticAnalysis.risk.permission import (
    permission_risk_grade as _perm_grade,
)
from scytaledroid.StaticAnalysis.risk.permission import (
    permission_risk_score_detail as _perm_detail,
)
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .utils import require_canonical_schema

_SUPPRESSED_RISK_TAGS = {
    "policy_drift",
    "dev_placeholder",
    "doc_reference",
    "doc_placeholder",
    "doc_noise",
}

_EFFECTIVE_DECISIONS = {"effective"}


@dataclass(slots=True)
class MetricsBundle:
    buckets: MutableMapping[str, tuple[float, float]]
    contributors: list[tuple[str, float, str, int]]
    code_http_hosts: int
    asset_http_hosts: int
    uses_cleartext: bool
    dangerous_permissions: int
    signature_permissions: int
    oem_permissions: int
    permission_score: float
    permission_grade: str
    permission_detail: Mapping[str, Any]


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _effective_http_counts(string_data: Mapping[str, object]) -> tuple[int, int]:
    samples_section = string_data.get("samples") if isinstance(string_data, Mapping) else {}
    samples_map: Mapping[str, Sequence[Mapping[str, Any]]] = (
        samples_section if isinstance(samples_section, Mapping) else {}
    )
    http_samples: list[Mapping[str, Any]] = []
    for bucket in ("http_cleartext", "endpoints"):
        bucket_entries = samples_map.get(bucket) or []
        if isinstance(bucket_entries, Sequence):
            http_samples.extend(
                [entry for entry in bucket_entries if isinstance(entry, Mapping)]
            )
    code_hosts: set[str] = set()
    asset_hosts: set[str] = set()
    for sample in http_samples:
        scheme = str(sample.get("scheme") or "").lower()
        if scheme != "http":
            continue
        decision = str(sample.get("decision") or "").strip().lower()
        risk_tag = str(sample.get("risk_tag") or "").strip().lower()
        if decision:
            if decision not in _EFFECTIVE_DECISIONS:
                continue
        elif risk_tag and risk_tag in _SUPPRESSED_RISK_TAGS:
            continue
        root = str(sample.get("root_domain") or "").strip()
        if not root:
            continue
        source_type = str(sample.get("source_type") or "").lower()
        if source_type in {"code", "dex", "native"}:
            code_hosts.add(root)
        else:
            asset_hosts.add(root)
    return len(code_hosts), len(asset_hosts)


def compute_metrics_bundle(report: Any, string_data: Mapping[str, object]) -> MetricsBundle:
    declared_pairs, _resolved_sdk, target_sdk, allow_backup_flag, legacy_ext_flag = _resolve_perm_inputs(
        report=report,
        sdk=None,
        declared=None,
    )
    declared = [name for name, _tag in declared_pairs]
    flags = getattr(report, "manifest_flags", None)

    shorts_only = [
        name.split(".")[-1].upper()
        for name in declared
        if isinstance(name, str) and name.startswith("android.")
    ]
    detector_metrics = getattr(report, "detector_metrics", None)
    permissions_metrics: Mapping[str, Any] | None = None
    if isinstance(detector_metrics, Mapping):
        permissions_metrics = detector_metrics.get("permissions_profile")

    profiles_section = {}
    if isinstance(permissions_metrics, Mapping):
        raw_profiles = permissions_metrics.get("permission_profiles")
        if isinstance(raw_profiles, Mapping):
            profiles_section = raw_profiles

    flagged_normals_set: set[str] = set()
    noteworthy_normals_set: set[str] = set()
    special_risk_normals_set: set[str] = set()
    weak_guard_count = 0
    if profiles_section:
        for perm_name, data in profiles_section.items():
            if not isinstance(data, Mapping):
                continue
            if data.get("is_flagged_normal"):
                flagged_normals_set.add(str(perm_name))
            flagged_class = str(data.get("flagged_normal_class") or "").strip().lower()
            if flagged_class == "noteworthy_normal":
                noteworthy_normals_set.add(str(perm_name))
            elif flagged_class == "special_risk_normal":
                special_risk_normals_set.add(str(perm_name))
            guard_strength = str(data.get("guard_strength") or "").lower()
            if guard_strength in {"weak", "unknown"} and data.get("is_runtime_dangerous"):
                weak_guard_count += 1
    elif isinstance(permissions_metrics, Mapping):
        flagged_list = permissions_metrics.get("flagged_normal_permissions")
        if isinstance(flagged_list, (list, tuple, set)):
            flagged_normals_set.update(str(item) for item in flagged_list)

    flagged_normals = len(flagged_normals_set)
    noteworthy_normals = len(noteworthy_normals_set)
    special_risk_normals = len(special_risk_normals_set)

    pmap = _prot_map(shorts_only, target_sdk)
    rc, groups, vc, _fw_ds, _vn = _classify(declared_pairs, pmap)
    dangerous = rc.get("dangerous", 0)
    signature = rc.get("signature", 0)
    oem = vc.get("ADS", 0)
    flags = flags or type("_Flags", (), {
        "allow_backup": False,
        "request_legacy_external_storage": False,
        "uses_cleartext_traffic": False,
    })()
    raw_detail = _perm_detail(
        dangerous=dangerous,
        signature=signature,
        vendor=oem,
        groups=groups,
        target_sdk=target_sdk,
        allow_backup=(
            bool(allow_backup_flag)
            if allow_backup_flag is not None
            else getattr(flags, "allow_backup", False)
        ),
        legacy_external_storage=(
            bool(legacy_ext_flag)
            if legacy_ext_flag is not None
            else getattr(flags, "request_legacy_external_storage", False)
        ),
        flagged_normals=flagged_normals,
        noteworthy_normals=noteworthy_normals,
        special_risk_normals=special_risk_normals,
        weak_guards=weak_guard_count,
    )
    detail: MutableMapping[str, Any] = dict(raw_detail) if isinstance(raw_detail, Mapping) else {}
    permission_score = float(detail.get("score_3dp", detail.get("score_capped", detail.get("score_raw", 0.0)) or 0.0) or 0.0)
    permission_score = round(permission_score, 3)
    permission_grade = _perm_grade(permission_score)
    detail["score_3dp"] = permission_score
    detail.setdefault("score_capped", float(detail.get("score_capped", permission_score)))
    detail.setdefault("score_raw", float(detail.get("score_raw", permission_score)))
    detail.setdefault("grade", permission_grade)
    detail.setdefault("dangerous_count", int(dangerous))
    detail.setdefault("signature_count", int(signature))
    detail.setdefault("oem_count", int(oem))
    detail.setdefault("vendor_count", int(oem))
    detail.setdefault("flagged_normal_count", flagged_normals)
    detail.setdefault("noteworthy_normal_count", noteworthy_normals)
    detail.setdefault("special_risk_normal_count", special_risk_normals)
    detail.setdefault("weak_guard_count", int(weak_guard_count))
    if flagged_normals_set and "flagged_permissions" not in detail:
        detail["flagged_permissions"] = sorted(flagged_normals_set)
    perm_points = _perm_pts(permission_score)

    code_http_hosts, asset_http_hosts = _effective_http_counts(string_data)
    has_code_http = code_http_hosts > 0
    uses_cleartext = bool(getattr(flags, "uses_cleartext_traffic", False))
    net_points = 20.0 if (uses_cleartext and has_code_http) else (5.0 if has_code_http else 0.0)
    sto_points = 10.0 if bool(getattr(flags, "request_legacy_external_storage", False)) else 0.0
    exp_total = 0
    try:
        exp_total = int(getattr(getattr(report, "exported_components", None), "total", lambda: 0)())
    except Exception:  # pragma: no cover - defensive
        exp_total = 0
    comp_points = float(min(15, exp_total))
    aggregates = string_data.get("aggregates") if isinstance(string_data, Mapping) else {}
    aggregates_map: Mapping[str, Any] = aggregates if isinstance(aggregates, Mapping) else {}
    validated = len(aggregates_map.get("api_keys_high", []) or [])
    counts_section = string_data.get("counts") if isinstance(string_data, Mapping) else {}
    counts_map: Mapping[str, Any] = counts_section if isinstance(counts_section, Mapping) else {}
    entropy = int(counts_map.get("high_entropy", 0) or 0)
    secrets_points = float(min(25, validated)) + float(min(5, 5 if entropy else 0))
    webssl_points = 0.0
    corr_points = 0.0
    if has_code_http and ("android.permission.INTERNET" in declared):
        corr_points += 1.0
    if any(str(p).endswith("READ_CONTACTS") for p in declared) and aggregates_map.get("endpoint_roots"):
        corr_points += 1.0
    corr_points = min(5.0, corr_points)

    buckets = {
        "permissions": (float(perm_points), 20.0),
        "network": (float(net_points), 20.0),
        "storage": (float(sto_points), 10.0),
        "components": (float(comp_points), 15.0),
        "secrets": (float(secrets_points), 25.0),
        "webssl": (float(webssl_points), 10.0),
        "correlations": (float(corr_points), 5.0),
    }

    contributors: list[tuple[str, float, str, int]] = []

    try:
        sig_components = detail.get("signal_components", {}) if isinstance(detail, Mapping) else {}
        breadth = float(detail.get("breadth", {}).get("applied", 0.0) or 0.0)
        modernization = float(detail.get("modernization_credit", 0.0) or 0.0)

        def _points(value: float) -> float:
            return round(float(value) * 2.0, 2)

        if sig_components:
            dangerous_pts = _points(sig_components.get("dangerous", 0.0))
            signature_pts = _points(sig_components.get("signature", 0.0))
            vendor_pts = _points(sig_components.get("oem", sig_components.get("vendor", 0.0)))
            if dangerous_pts:
                contributors.append((
                    "permissions_dangerous",
                    dangerous_pts,
                    f"Dangerous permissions footprint (+{dangerous_pts})",
                    0,
                ))
            if signature_pts:
                contributors.append((
                    "permissions_signature",
                    signature_pts,
                    f"Signature-level capabilities (+{signature_pts})",
                    0,
                ))
            if vendor_pts:
                contributors.append((
                    "permissions_oem",
                    vendor_pts,
                    f"OEM/custom permissions (+{vendor_pts})",
                    0,
                ))
        penalty_components = detail.get("penalty_components", {}) if isinstance(detail, Mapping) else {}
        flagged_component = penalty_components.get("flagged_normal", detail.get("flagged_normal_component", 0.0))
        weak_guard_component = penalty_components.get("weak_guard", detail.get("weak_guard_component", 0.0))

        flagged_pts = _points(flagged_component)
        if flagged_pts:
            contributors.append(
                (
                    "permissions_flagged_normals",
                    flagged_pts,
                    f"Flagged normal permissions (+{flagged_pts})",
                    0,
                )
            )

        weak_guard_pts = _points(weak_guard_component)
        if weak_guard_pts:
            contributors.append(
                (
                    "permissions_weak_guard",
                    weak_guard_pts,
                    f"Weak guard strength on runtime-dangerous permissions (+{weak_guard_pts})",
                    0,
                )
            )

        breadth_pts = _points(breadth)
        if breadth_pts:
            contributors.append((
                "permissions_breadth",
                breadth_pts,
                f"Capability breadth bonus (+{breadth_pts})",
                0,
            ))
        modernization_pts = _points(modernization)
        if modernization_pts:
            contributors.append((
                "permissions_modernization",
                -modernization_pts,
                f"Modernization credit (targetSdk/flags) (−{modernization_pts})",
                0,
            ))
        if net_points:
            if uses_cleartext and has_code_http:
                reason = "usesCleartextTraffic with code-path HTTP endpoints"
            elif has_code_http:
                reason = "HTTP endpoints observed in code paths"
            else:
                reason = "Network hygiene signal"
            contributors.append(("network", net_points, f"{reason} (+{net_points})", 0))
        if comp_points:
            contributors.append((
                "components",
                comp_points,
                f"Exported components without guards (+{comp_points})",
                0,
            ))
        if sto_points:
            contributors.append((
                "storage",
                sto_points,
                f"Legacy storage flag/requestLegacyExternalStorage (+{sto_points})",
                0,
            ))
        if secrets_points:
            contributors.append((
                "secrets",
                secrets_points,
                f"Validated secrets & entropy findings (+{secrets_points})",
                0,
            ))
        if webssl_points:
            contributors.append((
                "webssl",
                webssl_points,
                f"WebView/SSL configuration signals (+{webssl_points})",
                0,
            ))
        if corr_points:
            contributors.append((
                "correlations",
                corr_points,
                f"Composite risk correlations (+{corr_points})",
                0,
            ))
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(
            f"Failed to derive contributor weights: {exc}",
            category="static_analysis",
        )
        contributors = []

    if contributors:
        contrib_sorted = sorted(contributors, key=lambda row: abs(row[1]), reverse=True)
        contributors = [
            (name, round(points, 2), explanation, idx + 1)
            for idx, (name, points, explanation, _rank) in enumerate(contrib_sorted)
            if points or "modernization" in name
        ]

    return MetricsBundle(
        buckets=buckets,
        contributors=contributors,
        code_http_hosts=code_http_hosts,
        asset_http_hosts=asset_http_hosts,
        uses_cleartext=uses_cleartext,
        dangerous_permissions=int(detail.get("dangerous_count", dangerous)),
        signature_permissions=int(detail.get("signature_count", signature)),
        oem_permissions=int(detail.get("oem_count", oem)),
        permission_score=permission_score,
        permission_grade=permission_grade,
        permission_detail=dict(detail),
    )


__all__ = [
    "MetricsBundle",
    "compute_metrics_bundle",
]
