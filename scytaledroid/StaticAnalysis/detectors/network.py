"""Network surface and TLS heuristics detector."""

from __future__ import annotations

import hashlib
from pathlib import Path
from time import perf_counter
from typing import Dict, Mapping, Optional, Sequence

from ..core.context import DetectorContext
from ..core.findings import Badge, DetectorResult, EvidencePointer
from ..core.pipeline import make_detector_result
from ..modules import (
    EndpointMatch,
    IndexedString,
    detect_tls_keywords,
    extract_endpoints,
)
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
            return make_detector_result(
                detector_id=self.detector_id,
                section_key=self.section_key,
                status=Badge.OK,
                started_at=started,
                findings=tuple(),
                metrics=metrics,
                evidence=tuple(),
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
        evidence = _build_evidence_pointers(
            evidence_candidates, apk_path=context.apk_path
        )

        badge = {
            "warn": Badge.WARN,
            "ok": Badge.OK,
            "review": Badge.INFO,
        }.get(status_key.lower(), Badge.INFO)

        return make_detector_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            status=badge,
            started_at=started,
            findings=tuple(),
            metrics=metrics,
            evidence=evidence,
        )


__all__ = ["NetworkSurfaceDetector"]
