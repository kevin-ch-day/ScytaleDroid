"""Network surface and TLS heuristics detector."""

from __future__ import annotations

import hashlib
from typing import Dict, List, Mapping, Sequence

from ..core.context import DetectorContext
from ..core.findings import DetectorResult
from ..modules import (
    EndpointMatch,
    IndexedString,
    detect_tls_keywords,
    extract_endpoints,
)
from .base import BaseDetector, register_detector


def _hash_host(host: str) -> str:
    return hashlib.sha256(host.encode("utf-8")).hexdigest()


def _serialize_endpoints(matches: Sequence[EndpointMatch], limit: int = 2) -> List[Dict[str, str]]:
    serialized: List[Dict[str, str]] = []
    for match in matches[:limit]:
        serialized.append(
            {
                "scheme": match.scheme,
                "hash": match.string_entry.sha256,
                "origin": match.string_entry.origin,
            }
        )
    return serialized


def _build_metrics(
    endpoints: Sequence[EndpointMatch],
    tls_hits: Mapping[str, Sequence[IndexedString]],
    manifest_flags,
) -> Dict[str, object]:
    http_hosts = {match.host for match in endpoints if match.scheme == "http"}
    https_hosts = {match.host for match in endpoints if match.scheme == "https"}
    http_matches = [match for match in endpoints if match.scheme == "http"]
    https_matches = [match for match in endpoints if match.scheme == "https"]

    evidence_pool = http_matches + [match for match in https_matches if match not in http_matches]
    evidence = _serialize_endpoints(evidence_pool, limit=2)

    status = "ok"
    if http_matches:
        status = "warn"
    elif tls_hits.get("trust_manager") or tls_hits.get("hostname_verifier"):
        status = "review"

    return {
        "http_endpoints": len(http_matches),
        "https_endpoints": len(https_matches),
        "http_host_hashes": [_hash_host(host) for host in sorted(http_hosts)],
        "https_host_hashes": [_hash_host(host) for host in sorted(https_hosts)],
        "tls_trust_manager_hits": [entry.sha256 for entry in tls_hits.get("trust_manager", ())],
        "tls_hostname_verifier_hits": [entry.sha256 for entry in tls_hits.get("hostname_verifier", ())],
        "tls_certificate_pinning_hits": [entry.sha256 for entry in tls_hits.get("certificate_pinning", ())],
        "uses_cleartext_manifest": manifest_flags.uses_cleartext_traffic,
        "network_security_config": manifest_flags.network_security_config,
        "evidence": evidence,
        "status": status,
    }


@register_detector
class NetworkSurfaceDetector(BaseDetector):
    """Surfaces HTTP endpoints and TLS customisations seen in the APK."""

    detector_id = "network_surface"
    name = "Network surface & TLS detector"
    default_profiles = ("quick", "full")

    def run(self, context: DetectorContext) -> DetectorResult:
        index = context.string_index
        if index is None or index.is_empty():
            metrics = {
                "http_endpoints": 0,
                "https_endpoints": 0,
                "http_host_hashes": [],
                "https_host_hashes": [],
                "tls_trust_manager_hits": [],
                "tls_hostname_verifier_hits": [],
                "tls_certificate_pinning_hits": [],
                "uses_cleartext_manifest": context.manifest_flags.uses_cleartext_traffic,
                "network_security_config": context.manifest_flags.network_security_config,
                "evidence": [],
                "status": "ok",
            }
            return DetectorResult(detector_id=self.detector_id, findings=tuple(), metrics=metrics)

        endpoints = extract_endpoints(index)
        tls_hits = detect_tls_keywords(index)
        metrics = _build_metrics(endpoints, tls_hits, context.manifest_flags)

        return DetectorResult(
            detector_id=self.detector_id,
            findings=tuple(),
            metrics=metrics,
        )


__all__ = ["NetworkSurfaceDetector"]
