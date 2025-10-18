"""Network surface and TLS heuristics detector."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from time import perf_counter
from typing import Dict, Mapping, Optional, Sequence

from ..core.context import DetectorContext
from ..core.findings import (
    Badge,
    DetectorResult,
    EvidencePointer,
    Finding,
    MasvsCategory,
    SeverityLevel,
)
from ..core.pipeline import make_detector_result
from ..modules import (
    EndpointMatch,
    IndexedString,
    detect_tls_keywords,
    extract_endpoints,
)
from ..modules.network_security import DomainPolicy, NetworkSecurityPolicy
from .base import BaseDetector, register_detector


def _hash_host(host: str) -> str:
    return hashlib.sha256(host.encode("utf-8")).hexdigest()


def _select_evidence_candidates(
    matches: Sequence[EndpointMatch],
    limit: int = 2,
) -> Sequence[EndpointMatch]:
    selected: list[EndpointMatch] = []
    for match in matches:
        if len(selected) >= limit:
            break
        selected.append(match)
    return tuple(selected)


def _build_evidence_pointers(
    matches: Sequence[EndpointMatch],
    *,
    apk_path: Path,
) -> Sequence[EvidencePointer]:
    base_location = apk_path.resolve().as_posix()
    pointers: list[EvidencePointer] = []
    for match in matches:
        pointer = EvidencePointer(
            location=f"{base_location}!string[{match.string_entry.origin}]",
            hash_short=f"#h:{match.string_entry.sha256[:8]}",
            description=f"{match.scheme.upper()} {match.host}",
            extra={
                "url": match.url,
                "origin": match.string_entry.origin,
                "origin_type": match.string_entry.origin_type,
            },
        )
        pointers.append(pointer)
    return tuple(pointers)


def _summarise_surface(
    http_matches: Sequence[EndpointMatch],
    https_matches: Sequence[EndpointMatch],
    tls_hits: Mapping[str, Sequence[IndexedString]],
    manifest_flags,
) -> tuple[Dict[str, object], str]:
    endpoints_line = f"http={len(http_matches)}  https={len(https_matches)}"

    uses_cleartext = _fmt_bool_flag(manifest_flags.uses_cleartext_traffic)
    network_security = _fmt_value(manifest_flags.network_security_config)
    pinning_present = bool(tls_hits.get("certificate_pinning"))
    policy_line = (
        f"usesCleartextTraffic={uses_cleartext}  "
        f"NSC={network_security}  "
        f"Pinning={_fmt_bool_flag(True if pinning_present else None)}"
    )

    metrics: Dict[str, object] = {
        "Endpoints": endpoints_line,
        "Policy": policy_line,
    }

    http_hosts = sorted({match.host for match in http_matches})
    https_hosts = sorted({match.host for match in https_matches})
    host_hashes: Dict[str, Sequence[str]] = {}
    if http_hosts:
        host_hashes["http"] = [f"#h:{_hash_host(host)}" for host in http_hosts]
    if https_hosts:
        host_hashes["https"] = [f"#h:{_hash_host(host)}" for host in https_hosts]
    if host_hashes:
        metrics["Host hashes"] = host_hashes

    surface_payload: Dict[str, object] = {
        "counts": {"http": len(http_matches), "https": len(https_matches), "ws": 0},
        "hosts": {"http": http_hosts, "https": https_hosts},
        "urls": {
            "http": [match.url for match in http_matches[:10]],
            "https": [match.url for match in https_matches[:10]],
        },
    }
    metrics["surface"] = surface_payload

    overrides = _summarise_tls_hits(tls_hits)
    if overrides:
        metrics["TLS overrides"] = overrides

    status = "ok"
    if http_matches:
        status = "warn"
    elif overrides:
        status = "review"

    return metrics, status


def _build_policy_graph(
    policy: Optional[NetworkSecurityPolicy],
) -> Mapping[str, object]:
    if policy is None:
        return {}

    nodes: list[Mapping[str, object]] = []
    edges: list[Mapping[str, object]] = []

    base_node: Dict[str, object] = {
        "id": "base",
        "type": "base",
        "cleartext": bool(policy.base_cleartext),
        "debug_cleartext": bool(policy.debug_overrides_cleartext),
        "trust_user_certs": bool(policy.trust_user_certificates),
    }
    nodes.append(base_node)

    seen_domains: set[str] = set()
    domain_entries: list[tuple[str, DomainPolicy]] = []
    for domain_policy in policy.domain_policies:
        for domain in domain_policy.domains:
            if domain in seen_domains:
                continue
            seen_domains.add(domain)
            domain_entries.append((domain, domain_policy))

    for domain, domain_policy in sorted(domain_entries, key=lambda item: item[0]):
        domain_id = f"domain:{domain}"
        node: Dict[str, object] = {
            "id": domain_id,
            "type": "domain",
            "label": domain,
            "include_subdomains": bool(domain_policy.include_subdomains),
            "cleartext": bool(domain_policy.cleartext_permitted),
            "user_certificates": bool(domain_policy.user_certificates_allowed),
            "pinned_certificates": len(domain_policy.pinned_certificates),
        }
        if domain_policy.source:
            node["source"] = domain_policy.source
        nodes.append(node)
        edges.append(
            {
                "from": "base",
                "to": domain_id,
                "relation": "applies",
            }
        )

    if not edges and not any(
        base_node.get(flag)
        for flag in ("cleartext", "debug_cleartext", "trust_user_certs")
    ):
        return {}

    payload: Dict[str, object] = {"nodes": nodes, "edges": edges}
    payload["hash"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return payload


def _fmt_bool_flag(value: Optional[bool]) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return "—"


def _fmt_value(value: object) -> str:
    if value in (None, "", "null"):
        return "—"
    return str(value)


def _summarise_tls_hits(
    tls_hits: Mapping[str, Sequence[IndexedString]]
) -> Dict[str, Sequence[str]]:
    mapping = {
        "trust_manager": "Trust manager override",
        "hostname_verifier": "Hostname verifier override",
        "certificate_pinning": "Certificate pinning",
    }
    summary: Dict[str, Sequence[str]] = {}
    for key, label in mapping.items():
        entries = tls_hits.get(key, ())
        if not entries:
            continue
        summary[label] = [entry.sha256 for entry in entries]
    return summary


def _assess_policy(policy: Optional[NetworkSecurityPolicy], *, has_code_http: bool) -> tuple[Finding, ...]:
    if policy is None or policy.source_path is None:
        return tuple()

    findings: list[Finding] = []

    if policy.base_cleartext and has_code_http:
        findings.append(
            Finding(
                finding_id="network_nsc_base_cleartext",
                title="Network Security Config allows cleartext globally",
                severity_gate=SeverityLevel.P1,
                category_masvs=MasvsCategory.NETWORK,
                status=Badge.WARN,
                because="Base configuration permits cleartext traffic for all domains.",
                remediate="Disable cleartextTrafficPermitted or scope cleartext to debug domains.",
            )
        )

    if policy.debug_overrides_cleartext and has_code_http:
        findings.append(
            Finding(
                finding_id="network_nsc_debug_cleartext",
                title="Debug override permits cleartext",
                severity_gate=SeverityLevel.P2,
                category_masvs=MasvsCategory.NETWORK,
                status=Badge.WARN,
                because="Debug overrides loosen cleartext restrictions; ensure debug builds are not shipped.",
                remediate="Separate production NSC without debug overrides.",
            )
        )

    risky_domains = [
        policy_entry
        for policy_entry in policy.domain_policies
        if policy_entry.cleartext_permitted
    ]
    if risky_domains and has_code_http:
        domain_list = ", ".join(
            ", ".join(domain.domains)
            for domain in risky_domains[:3]
        )
        findings.append(
            Finding(
                finding_id="network_nsc_domain_cleartext",
                title="Domain-config permits cleartext",
                severity_gate=SeverityLevel.P1,
                category_masvs=MasvsCategory.NETWORK,
                status=Badge.WARN,
                because=f"NSC domain-config allows cleartext for: {domain_list}",
                remediate="Restrict cleartext domain-config to development builds or enforce TLS.",
            )
        )

    if policy.trust_user_certificates:
        findings.append(
            Finding(
                finding_id="network_nsc_user_certs",
                title="User-added CA trusted",
                severity_gate=SeverityLevel.P2,
                category_masvs=MasvsCategory.NETWORK,
                status=Badge.INFO,
                because="NSC trusts user-added certificates which weakens pinning assumptions.",
                remediate="Avoid trusting user-added CAs for production builds unless justified.",
            )
        )

    return tuple(findings)


def _policy_evidence(
    policy: Optional[NetworkSecurityPolicy],
    apk_path: Path,
) -> tuple[EvidencePointer, ...]:
    if policy is None or policy.source_path is None:
        return tuple()
    location = f"{apk_path.resolve().as_posix()}!{policy.source_path}"
    pointer = EvidencePointer(
        location=location,
        description="networkSecurityConfig",
        extra={"base_cleartext": policy.base_cleartext},
    )
    return (pointer,)


def _attach_policy_metrics(
    metrics: Mapping[str, object],
    policy: Optional[NetworkSecurityPolicy],
) -> Mapping[str, object]:
    payload = dict(metrics)
    if policy is None:
        return payload

    nsc_payload: Dict[str, object] = dict(payload.get("NSC", {}))
    if policy.source_path:
        nsc_payload["source"] = policy.source_path
    nsc_payload["base_cleartext"] = policy.base_cleartext
    nsc_payload["debug_cleartext"] = policy.debug_overrides_cleartext
    nsc_payload["trust_user_certs"] = policy.trust_user_certificates
    nsc_payload["domain_count"] = len(policy.domain_policies)

    graph = _build_policy_graph(policy)
    if graph:
        nsc_payload["graph"] = graph

    payload["NSC"] = nsc_payload
    return payload


def _pick_badge(status_key: str, findings: Sequence[Finding]) -> Badge:
    badge = {
        "warn": Badge.WARN,
        "ok": Badge.OK,
        "review": Badge.INFO,
    }.get((status_key or "").lower(), Badge.INFO)

    if any(f.status is Badge.FAIL for f in findings):
        return Badge.FAIL
    if any(f.status is Badge.WARN for f in findings):
        return Badge.WARN if badge is Badge.OK else badge
    if findings and badge is Badge.OK:
        return Badge.INFO
    return badge


@register_detector
class NetworkSurfaceDetector(BaseDetector):
    """Surfaces HTTP endpoints and TLS customisations seen in the APK."""

    detector_id = "network_surface"
    name = "Network surface & TLS detector"
    default_profiles = ("quick", "full")
    section_key = "network_surface"

    def run(self, context: DetectorContext) -> DetectorResult:
        started = perf_counter()
        index = context.string_index
        if index is None or index.is_empty():
            metrics, status_key = _summarise_surface(
                tuple(),
                tuple(),
                {},
                context.manifest_flags,
            )
            findings = _assess_policy(context.network_security_policy)
            return make_detector_result(
                detector_id=self.detector_id,
                section_key=self.section_key,
                status=_pick_badge(status_key, findings),
                started_at=started,
                findings=findings,
                metrics=_attach_policy_metrics(metrics, context.network_security_policy),
                evidence=_policy_evidence(context.network_security_policy, context.apk_path),
            )

        endpoints = extract_endpoints(index)
        tls_hits = detect_tls_keywords(index)
        http_matches = tuple(match for match in endpoints if match.scheme == "http")
        https_matches = tuple(match for match in endpoints if match.scheme == "https")
        metrics, status_key = _summarise_surface(
            http_matches,
            https_matches,
            tls_hits,
            context.manifest_flags,
        )

        evidence_pool: list[EndpointMatch] = list(http_matches)
        for match in https_matches:
            if match not in evidence_pool:
                evidence_pool.append(match)
        evidence_candidates = _select_evidence_candidates(evidence_pool)
        evidence = list(
            _build_evidence_pointers(evidence_candidates, apk_path=context.apk_path)
        )

        # Determine if any HTTP endpoints come from code paths (dex/native)
        has_code_http = any(
            (m.string_entry.origin_type in {"code", "dex", "native"}) for m in http_matches
        )
        policy_findings = _assess_policy(context.network_security_policy, has_code_http=has_code_http)
        findings = tuple(policy_findings)
        evidence.extend(
            _policy_evidence(context.network_security_policy, context.apk_path)
        )

        badge = {
            "warn": Badge.WARN,
            "ok": Badge.OK,
            "review": Badge.INFO,
        }.get(status_key.lower(), Badge.INFO)

        if any(f.status is Badge.FAIL for f in findings):
            badge = Badge.FAIL
        elif findings and badge is Badge.OK:
            badge = Badge.WARN if any(f.status is Badge.WARN for f in findings) else Badge.INFO

        return make_detector_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            status=badge,
            started_at=started,
            findings=findings,
            metrics=_attach_policy_metrics(metrics, context.network_security_policy),
            evidence=tuple(evidence),
        )


__all__ = ["NetworkSurfaceDetector"]
