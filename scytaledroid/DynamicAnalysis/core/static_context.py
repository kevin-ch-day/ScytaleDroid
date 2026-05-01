"""Static context helpers for dynamic analysis.

This module is intentionally conservative:
- Inputs come from the embedded static dynamic plan JSON.
- Outputs are advisory context tags and small summaries for reporting/QA.
- Nothing here changes scoring or enforces runtime behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class StaticContextPolicy:
    export_heavy_threshold: int = 20


def compute_static_context(plan_payload: dict[str, Any] | None, *, policy: StaticContextPolicy | None = None) -> dict[str, Any]:
    """Compute stable, paper-safe context signals from a static plan payload."""

    pol = policy or StaticContextPolicy()
    plan = plan_payload if isinstance(plan_payload, dict) else {}

    permissions = plan.get("permissions") if isinstance(plan.get("permissions"), dict) else {}
    exported = plan.get("exported_components") if isinstance(plan.get("exported_components"), dict) else {}
    risk_flags = plan.get("risk_flags") if isinstance(plan.get("risk_flags"), dict) else {}
    network_targets = plan.get("network_targets") if isinstance(plan.get("network_targets"), dict) else {}

    high_value = permissions.get("high_value") if isinstance(permissions.get("high_value"), list) else []
    declared = permissions.get("declared") if isinstance(permissions.get("declared"), list) else []
    dangerous = permissions.get("dangerous") if isinstance(permissions.get("dangerous"), list) else []

    exported_total = exported.get("total")
    try:
        exported_total_int = int(exported_total) if exported_total is not None else None
    except Exception:
        exported_total_int = None

    tags: list[str] = []

    if high_value:
        tags.append("PRIVACY_SENSITIVE")
    if exported_total_int is not None and exported_total_int >= pol.export_heavy_threshold:
        tags.append("EXPORT_HEAVY")
    if risk_flags.get("uses_cleartext_traffic") is True:
        tags.append("NETWORK_CLEARTEXT_ALLOWED")
    if risk_flags.get("request_legacy_external_storage") is True:
        tags.append("LEGACY_STORAGE")
    if risk_flags.get("allow_backup") is True:
        tags.append("ALLOW_BACKUP")

    domains = network_targets.get("domains") if isinstance(network_targets.get("domains"), list) else []
    cleartext_domains = (
        network_targets.get("cleartext_domains")
        if isinstance(network_targets.get("cleartext_domains"), list)
        else []
    )
    domain_sources = (
        network_targets.get("domain_sources")
        if isinstance(network_targets.get("domain_sources"), list)
        else []
    )
    src_counts: dict[str, int] = {}
    for item in domain_sources:
        if not isinstance(item, dict):
            continue
        src = str(item.get("source") or "").strip().lower()
        if not src:
            continue
        src_counts[src] = src_counts.get(src, 0) + 1

    return {
        "tags": sorted(set(tags)),
        "policy": {"export_heavy_threshold": pol.export_heavy_threshold},
        "permissions": {
            "declared_count": len(declared),
            "dangerous_count": len(dangerous),
            "high_value_count": len(high_value),
            "high_value_sample": [str(x) for x in high_value[:8]],
        },
        "exported_components": {
            "total": exported_total_int,
        },
        "risk_flags": {
            "uses_cleartext_traffic": risk_flags.get("uses_cleartext_traffic"),
            "request_legacy_external_storage": risk_flags.get("request_legacy_external_storage"),
            "allow_backup": risk_flags.get("allow_backup"),
            "debuggable": risk_flags.get("debuggable"),
            "network_security_config": risk_flags.get("network_security_config"),
        },
        "network_expectations": {
            "domains_count": len(domains),
            "cleartext_domains_count": len(cleartext_domains),
            "domain_sources_counts": src_counts,
            "domain_sources_note": network_targets.get("domain_sources_note"),
        },
        "note": (
            "Static context is advisory and used for interpretation/stratification only; "
            "it does not enforce runtime behavior or imply causality."
        ),
    }


def build_operator_guidance(plan_payload: dict[str, Any] | None, *, run_profile: str | None) -> list[str]:
    """Build a short, optional guidance block for interactive dynamic runs."""

    ctx = compute_static_context(plan_payload)
    tags = ctx.get("tags") if isinstance(ctx, dict) else []
    tag_text = ", ".join(tags) if tags else "none"

    lines = [f"Static context tags: {tag_text}"]

    if str(run_profile or "").strip().lower().startswith("baseline"):
        return lines

    # Advisory suggestions only; do not imply requirements or label behavior.
    if "PRIVACY_SENSITIVE" in tags:
        hv = ((ctx.get("permissions") or {}).get("high_value_sample") or []) if isinstance(ctx, dict) else []
        if hv:
            lines.append(
                "Optional: exercise relevant capabilities (Location/Camera/Microphone/Contacts/Notifications-IPC). "
                "Press P to view raw permission names."
            )
    if "EXPORT_HEAVY" in tags:
        lines.append("Optional: open deep links/notifications flows to exercise IPC surface (if safe).")
    if "NETWORK_CLEARTEXT_ALLOWED" in tags:
        lines.append("Note: cleartext allowed statically; dynamic traffic may still be mostly encrypted.")
    return lines


__all__ = ["StaticContextPolicy", "build_operator_guidance", "compute_static_context"]
