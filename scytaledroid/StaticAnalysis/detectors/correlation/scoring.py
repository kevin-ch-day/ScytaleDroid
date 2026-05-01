"""Risk scoring helpers for the correlation detector."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ...core.context import DetectorContext
from ...core.findings import Badge, Finding, MasvsCategory, SeverityLevel
from .models import NetworkDiff, NetworkSnapshot


def finding_weight(finding: Finding) -> int:
    """Assign a weight to a finding based on severity and badge."""

    severity_weights = {
        SeverityLevel.P0: 120,
        SeverityLevel.P1: 70,
        SeverityLevel.P2: 35,
        SeverityLevel.NOTE: 8,
    }
    badge_bonus = {
        Badge.FAIL: 24,
        Badge.WARN: 12,
        Badge.INFO: 6,
        Badge.OK: 0,
        Badge.SKIPPED: 0,
    }
    weight = severity_weights.get(finding.severity_gate, 0)
    weight += badge_bonus.get(finding.status, 0)
    return weight


def _resolve_oem_factor(metadata: Mapping[str, object]) -> float:
    candidate = ""
    for key in ("oem_profile", "device_oem", "oem"):
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            candidate = value.strip().lower()
            break
    mapping = {
        "samsung": 1.10,
        "xiaomi": 1.08,
        "huawei": 1.12,
        "oppo": 1.07,
        "vivo": 1.07,
    }
    return mapping.get(candidate, 1.0)


def risk_score(
    context: DetectorContext,
    aggregate_findings: Sequence[Finding],
    network_diff: NetworkDiff,
    current_snapshot: NetworkSnapshot,
    split_metrics: Mapping[str, object],
) -> Mapping[str, object]:
    metrics_map = {
        result.detector_id: dict(result.metrics)
        for result in context.intermediate_results
        if result.detector_id != "correlation_engine" and result.metrics
    }

    ipc_metrics = metrics_map.get("ipc_components", {})
    exported = int(ipc_metrics.get("components_exported", 0))
    permissioned = int(ipc_metrics.get("permission_enforced", 0))
    open_components = max(exported - permissioned, 0)
    shared_user = ipc_metrics.get("shared_user_id")
    provider_result = next(
        (result for result in context.intermediate_results if result.detector_id == "provider_acl"),
        None,
    )
    provider_risky = (
        sum(1 for finding in provider_result.findings if finding.status in {Badge.FAIL, Badge.WARN})
        if provider_result
        else 0
    )
    dangerous_perm_count = len(context.permissions.dangerous)
    component_score = open_components * (12 + min(dangerous_perm_count, 12))
    if shared_user:
        component_score += 25
    component_score += provider_risky * 18

    network_metrics = metrics_map.get("network_surface", {})
    http_count = 0
    https_count = 0
    surface = network_metrics.get("surface")
    if isinstance(surface, Mapping):
        counts = surface.get("counts")
        if isinstance(counts, Mapping):
            http_count = int(counts.get("http", 0))
            https_count = int(counts.get("https", 0))

    network_score = http_count * 15 + https_count * 3
    if context.manifest_flags.uses_cleartext_traffic:
        network_score += 20
    network_score += len(current_snapshot.cleartext_domains) * 10
    if network_diff.cleartext_flip and network_diff.cleartext_flip[1] is True:
        network_score += 30
    network_score += len(network_diff.cleartext_domains_added) * 12
    network_score += len(network_diff.pinning_removed) * 15
    if network_diff.user_certs_flip and network_diff.user_certs_flip[1] is True:
        network_score += 8
    if isinstance(network_metrics.get("NSC"), Mapping):
        nsc = network_metrics["NSC"]  # type: ignore[index]
        if bool(nsc.get("trust_user_certs")):
            network_score += 6

    split_http_union = split_metrics.get("union_http_hosts")
    if isinstance(split_http_union, Sequence):
        extra_http = max(0, len(split_http_union) - len(current_snapshot.http_hosts))
        network_score += extra_http * 9

    secret_metrics = metrics_map.get("secrets_credentials", {})
    secret_count = 0
    if isinstance(secret_metrics.get("secret_types"), Mapping):
        for data in secret_metrics["secret_types"].values():  # type: ignore[index]
            if isinstance(data, Mapping):
                secret_count += int(data.get("found", 0))
    secret_score = secret_count * 18

    storage_metrics = metrics_map.get("storage_backup", {})
    storage_score = 0
    if storage_metrics.get("allow_backup"):
        storage_score += 15
    if storage_metrics.get("legacy_external_storage"):
        storage_score += 12
    storage_score += int(storage_metrics.get("sensitive_keys", 0)) * 4

    crypto_metrics = metrics_map.get("crypto_hygiene", {})
    crypto_score = (
        int(crypto_metrics.get("aes_ecb", 0)) * 32
        + int(crypto_metrics.get("des_usage", 0)) * 32
        + int(crypto_metrics.get("md5_digest", 0)) * 12
        + int(crypto_metrics.get("sha1_digest", 0)) * 10
        + int(crypto_metrics.get("sha1prng", 0)) * 6
    )

    split_score = 0
    union_exported = split_metrics.get("union_exported")
    if isinstance(union_exported, Mapping):
        split_total = sum(len(values) for values in union_exported.values())
        split_extra = max(0, split_total - context.exported_components.total())
        split_score += split_extra * 6
    union_cleartext = split_metrics.get("union_cleartext_domains")
    if isinstance(union_cleartext, Sequence):
        extra_cleartext = max(0, len(union_cleartext) - len(current_snapshot.cleartext_domains))
        split_score += extra_cleartext * 8

    finding_score = sum(
        finding_weight(finding)
        for result in context.intermediate_results
        if result.detector_id != "correlation_engine"
        for finding in result.findings
    )

    diff_score = sum(finding_weight(finding) for finding in aggregate_findings)

    scores = {
        "components": component_score,
        "network": network_score,
        "secrets": secret_score,
        "storage": storage_score,
        "crypto": crypto_score,
        "split": split_score,
        "diff": diff_score,
        "findings": finding_score,
    }

    total_raw = sum(scores.values())
    oem_factor = _resolve_oem_factor(context.metadata or {})
    total_score = int(round(total_raw * oem_factor))

    if total_score >= 240:
        grade = "Critical"
    elif total_score >= 160:
        grade = "High"
    elif total_score >= 90:
        grade = "Medium"
    elif total_score > 0:
        grade = "Low"
    else:
        grade = "Informational"

    profile = {
        "score": total_score,
        "grade": grade,
        "factors": scores,
        "oem_factor": oem_factor,
        "dangerous_permissions": dangerous_perm_count,
        "http_endpoints": http_count,
        "https_endpoints": https_count,
        "open_components": open_components,
    }

    group_id = split_metrics.get("group_id")
    if group_id is not None:
        profile["split_group_id"] = group_id

    return profile


def risk_finding(profile: Mapping[str, object]) -> Finding:
    score = profile.get("score", 0)
    grade = profile.get("grade", "Informational")
    if grade == "Critical":
        severity = SeverityLevel.P0
        badge = Badge.FAIL
    elif grade == "High":
        severity = SeverityLevel.P1
        badge = Badge.WARN
    elif grade == "Medium":
        severity = SeverityLevel.P2
        badge = Badge.WARN
    else:
        severity = SeverityLevel.NOTE
        badge = Badge.INFO

    because = f"Composite static risk score {score} ({grade})."

    return Finding(
        finding_id="risk_profile",
        title=f"Composite risk — {grade}",
        severity_gate=severity,
        category_masvs=MasvsCategory.OTHER,
        status=badge,
        because=because,
        metrics=profile,
        remediate="Prioritise remediation of P0/P1 findings to reduce the score.",
    )


__all__ = ["risk_score", "risk_finding", "finding_weight"]
