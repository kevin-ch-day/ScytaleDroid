"""Ethical-hacking oriented PCAP metadata analysis (no payload bodies).

Extracts cleartext protocol surfaces, DNS anomalies, TLS certificate metadata,
domain inventories, and conservative threat heuristics for operator review.
"""

from __future__ import annotations

import json
import math
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from scytaledroid.DynamicAnalysis.domain_context import (
    classify_domain,
    normalize_domain,
    root_domain,
)

_PLAINTEXT_PROTOCOLS = frozenset(
    {"http", "ftp", "ftp-data", "smtp", "imap", "pop", "irc", "telnet", "xmpp"}
)
_OPAQUE_PROTOCOLS = frozenset({"tls", "ssl", "quic", "http2"})
_PHS_RE = re.compile(r"^\s*(?P<name>[A-Za-z0-9_.-]+)\s+frames:(?P<frames>\d+)\s+bytes:(?P<bytes>\d+)")
_LONG_OR_TOKENISH_RE = re.compile(r"([A-Za-z0-9_-]{16,}|[0-9a-fA-F]{12,}|\d{5,})")


@dataclass(frozen=True)
class SecuritySurfaceConfig:
    max_http_rows: int = 500
    max_inventory_values: int = 500
    max_decoded_streams: int = 50
    timeout_s: int = 45


def summarize_security_surface(
    pcap_path: Path,
    *,
    tshark_path: str,
    package_name: str | None = None,
    protocol_hierarchy: list[dict[str, Any]] | None = None,
    flow_summary: dict[str, Any] | None = None,
    burst_summary: dict[str, Any] | None = None,
    config: SecuritySurfaceConfig | None = None,
) -> dict[str, Any]:
    """Build ethical-hacking metadata bundle for one PCAP."""
    cfg = config or SecuritySurfaceConfig()
    if not tshark_path or not pcap_path.exists():
        return _empty_surface(status="skipped", reason="tshark_or_pcap_unavailable")

    hierarchy = list(protocol_hierarchy or _protocol_hierarchy(pcap_path, tshark_path, timeout=cfg.timeout_s))
    by_protocol = _protocol_frame_counts(hierarchy)

    cleartext = _analyze_cleartext(
        pcap_path,
        tshark_path,
        by_protocol=by_protocol,
        hierarchy=hierarchy,
        timeout=cfg.timeout_s,
        max_http_rows=cfg.max_http_rows,
        max_decoded_streams=cfg.max_decoded_streams,
    )
    dns = _analyze_dns_anomalies(
        pcap_path,
        tshark_path,
        timeout=cfg.timeout_s,
        package_name=package_name,
    )
    tls = _analyze_tls_surface(pcap_path, tshark_path, timeout=cfg.timeout_s)
    inventory = _build_domain_inventory(
        pcap_path,
        tshark_path,
        timeout=cfg.timeout_s,
        max_values=cfg.max_inventory_values,
    )
    threats = _analyze_threat_heuristics(
        cleartext=cleartext,
        dns=dns,
        tls=tls,
        flow_summary=flow_summary or {},
        burst_summary=burst_summary or {},
        inventory=inventory,
    )
    findings = _build_security_findings(
        cleartext=cleartext,
        dns=dns,
        tls=tls,
        inventory=inventory,
        threats=threats,
    )
    risk_flags = sorted(
        {
            *cleartext.get("risk_flags", []),
            *dns.get("risk_flags", []),
            *tls.get("risk_flags", []),
            *threats.get("risk_flags", []),
        }
    )
    return {
        "schema_version": "v1",
        "status": "ok",
        "analysis_contract": "metadata_only_no_payload_bodies",
        "cleartext": cleartext,
        "dns_anomalies": dns,
        "tls_surface": tls,
        "domain_inventory": inventory,
        "threat_heuristics": threats,
        "findings": findings,
        "risk_flags": risk_flags,
        "finding_count": len(findings),
    }


def sanitize_http_path(value: Any) -> tuple[str, str]:
    text = str(value or "").strip()
    if not text:
        return "", ""
    parsed = urlsplit(text)
    path = parsed.path or text.split("?", 1)[0] or "/"
    if not path.startswith("/"):
        path = "/" + path
    parts: list[str] = []
    for part in path.split("/"):
        if part == "":
            continue
        if _LONG_OR_TOKENISH_RE.search(part):
            parts.append("{id}")
        elif len(part) > 40:
            parts.append("{long}")
        else:
            parts.append(part[:40])
    sanitized = "/" + "/".join(parts)
    if sanitized == "/":
        return "/", "root"
    if any(part in {"{id}", "{long}"} for part in parts):
        return sanitized, "parameterized"
    return sanitized, "literal_path"


def _empty_surface(*, status: str, reason: str) -> dict[str, Any]:
    return {
        "schema_version": "v1",
        "status": status,
        "reason": reason,
        "analysis_contract": "metadata_only_no_payload_bodies",
        "cleartext": {},
        "dns_anomalies": {},
        "tls_surface": {},
        "domain_inventory": {},
        "threat_heuristics": {},
        "findings": [],
        "risk_flags": [],
        "finding_count": 0,
    }


def _run_tshark(args: list[str], *, timeout: int) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return 124, stdout, stderr or f"timeout after {timeout}s"
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _protocol_hierarchy(pcap_path: Path, tshark_path: str, *, timeout: int) -> list[dict[str, Any]]:
    rc, stdout, _stderr = _run_tshark(
        [tshark_path, "-r", str(pcap_path), "-q", "-z", "io,phs"],
        timeout=timeout,
    )
    if rc != 0:
        return []
    rows: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        match = _PHS_RE.match(line)
        if not match:
            continue
        rows.append(
            {
                "protocol": match.group("name").lower(),
                "frames": _safe_int(match.group("frames")),
                "bytes": _safe_int(match.group("bytes")),
            }
        )
    return rows


def _protocol_frame_counts(rows: list[dict[str, Any]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in rows:
        protocol = str(row.get("protocol") or "").strip().lower()
        if not protocol:
            continue
        counts[protocol] = max(counts[protocol], _safe_int(row.get("frames")))
    return counts


def _analyze_cleartext(
    pcap_path: Path,
    tshark_path: str,
    *,
    by_protocol: Counter[str],
    hierarchy: list[dict[str, Any]],
    timeout: int,
    max_http_rows: int,
    max_decoded_streams: int,
) -> dict[str, Any]:
    http_rows, http_status = _extract_http_metadata(
        pcap_path,
        tshark_path,
        timeout=timeout,
        max_rows=max_http_rows,
    )
    plaintext_frames = sum(by_protocol.get(protocol, 0) for protocol in _PLAINTEXT_PROTOCOLS)
    encrypted_frames = sum(by_protocol.get(protocol, 0) for protocol in _OPAQUE_PROTOCOLS)
    http_request_rows = sum(_safe_int(row.get("rows")) for row in http_rows if row.get("method"))
    http_response_rows = sum(_safe_int(row.get("rows")) for row in http_rows if row.get("response_code"))
    decoded_streams = _extract_decoded_cleartext_streams(
        pcap_path,
        tshark_path,
        by_protocol=by_protocol,
        timeout=timeout,
        max_streams=max_decoded_streams,
    )
    protocol_visibility = [
        {
            "protocol": str(row.get("protocol") or "").strip().lower(),
            "frames": _safe_int(row.get("frames")),
            "bytes": _safe_int(row.get("bytes")),
            "visibility": _visibility_for_protocol(str(row.get("protocol") or "")),
        }
        for row in hierarchy
        if isinstance(row, dict) and row.get("protocol")
    ]
    risk_flags: list[str] = []
    if not hierarchy:
        risk_flags.append("protocol_probe_failed")
    if plaintext_frames:
        risk_flags.append("decoded_cleartext_application_protocol_observed")
    if decoded_streams:
        risk_flags.append("decoded_cleartext_streams_observed")
    if http_rows:
        risk_flags.append("http_metadata_observed")
    if http_status != "ok":
        risk_flags.append("http_probe_failed")
    if encrypted_frames and not plaintext_frames:
        visibility = "encrypted_or_opaque_dominant"
    elif plaintext_frames or http_rows:
        visibility = "cleartext_surface_present"
    elif by_protocol.get("dns", 0):
        visibility = "name_metadata_only"
    else:
        visibility = "transport_only_or_unknown"
    top_hosts = _top_counter_rows(
        [str(row.get("host") or "").lower() for row in http_rows if row.get("host")],
        limit=10,
    )
    top_methods = _top_counter_rows(
        [str(row.get("method") or "").upper() for row in http_rows if row.get("method")],
        limit=8,
    )
    plaintext_protocols_observed = sorted(
        protocol for protocol in _PLAINTEXT_PROTOCOLS if by_protocol.get(protocol, 0) > 0
    )
    decoded_protocols_observed = sorted(
        {
            str(row.get("protocol") or "").strip().lower()
            for row in decoded_streams
            if isinstance(row, dict) and str(row.get("protocol") or "").strip()
        }
    )
    return {
        "visibility_class": visibility,
        "plaintext_protocol_frames": plaintext_frames,
        "plaintext_protocols_observed": plaintext_protocols_observed,
        "decoded_protocols_observed": decoded_protocols_observed,
        "cleartext_protocol_observed": bool(plaintext_frames or http_rows or decoded_streams),
        "http_observed": bool(http_rows),
        "http_status": http_status,
        "http_frames": by_protocol.get("http", 0),
        "http2_frames": by_protocol.get("http2", 0),
        "http_request_rows": http_request_rows,
        "http_response_rows": http_response_rows,
        "http_host_count": len({row.get("host") for row in http_rows if row.get("host")}),
        "top_http_hosts": top_hosts,
        "top_http_methods": top_methods,
        "sanitized_http_samples": http_rows[:25],
        "protocol_visibility": protocol_visibility,
        "decoded_streams": decoded_streams,
        "decoded_stream_count": len(decoded_streams),
        "risk_flags": risk_flags,
    }


def _visibility_for_protocol(protocol: str) -> str:
    key = str(protocol or "").strip().lower()
    if key in _PLAINTEXT_PROTOCOLS:
        return "cleartext_protocol_decoded"
    if key in _OPAQUE_PROTOCOLS:
        return "encrypted_or_opaque"
    if key == "dns":
        return "cleartext_name_metadata"
    return "transport_or_other"


def _extract_decoded_cleartext_streams(
    pcap_path: Path,
    tshark_path: str,
    *,
    by_protocol: Counter[str],
    timeout: int,
    max_streams: int,
) -> list[dict[str, Any]]:
    protocols = sorted(protocol for protocol in _PLAINTEXT_PROTOCOLS if by_protocol.get(protocol, 0) > 0)
    if not protocols:
        return []
    display_filter = " || ".join(protocols)
    cmd = [
        tshark_path,
        "-r",
        str(pcap_path),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "frame.protocols",
        "-e",
        "frame.len",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "udp.srcport",
        "-e",
        "udp.dstport",
        "-e",
        "tcp.stream",
    ]
    rc, stdout, _stderr = _run_tshark(cmd, timeout=timeout)
    if rc != 0:
        return []
    aggregate: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for line in stdout.splitlines():
        proto_stack, frame_len, tcp_src, tcp_dst, udp_src, udp_dst, tcp_stream = (
            line.split("\t") + ["", "", "", "", "", "", ""]
        )[:7]
        stack_parts = {part.lower() for part in proto_stack.split(":")}
        matched_protocols = [protocol for protocol in protocols if protocol in stack_parts]
        if not matched_protocols:
            continue
        transport = "tcp" if tcp_src or tcp_dst else "udp" if udp_src or udp_dst else "unknown"
        src_port = str(tcp_src or udp_src or "").strip()
        dst_port = str(tcp_dst or udp_dst or "").strip()
        size = _safe_int(frame_len)
        stream_id = str(tcp_stream or "").strip()
        for protocol in matched_protocols:
            key = (protocol, transport, src_port, dst_port, stream_id)
            slot = aggregate.setdefault(
                key,
                {
                    "protocol": protocol,
                    "transport": transport,
                    "src_port": src_port or None,
                    "dst_port": dst_port or None,
                    "tcp_stream": stream_id or None,
                    "frames": 0,
                    "bytes_total": 0,
                    "bytes_min": 0,
                    "bytes_max": 0,
                },
            )
            slot["frames"] = int(slot["frames"]) + 1
            slot["bytes_total"] = int(slot["bytes_total"]) + size
            slot["bytes_min"] = size if int(slot["bytes_min"]) == 0 else min(int(slot["bytes_min"]), size)
            slot["bytes_max"] = max(int(slot["bytes_max"]), size)
    rows = sorted(
        aggregate.values(),
        key=lambda row: (
            row["protocol"],
            row["transport"],
            row["src_port"] or "",
            row["dst_port"] or "",
            row["tcp_stream"] or "",
        ),
    )
    return rows[: max(max_streams, 0)]


def _extract_http_metadata(
    pcap_path: Path,
    tshark_path: str,
    *,
    timeout: int,
    max_rows: int,
) -> tuple[list[dict[str, Any]], str]:
    cmd = [
        tshark_path,
        "-r",
        str(pcap_path),
        "-Y",
        "http.request || http.response",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "http.host",
        "-e",
        "http.request.method",
        "-e",
        "http.request.uri",
        "-e",
        "http.response.code",
    ]
    rc, stdout, stderr = _run_tshark(cmd, timeout=timeout)
    if rc != 0:
        return [], f"failed: {stderr.strip()[:180]}"
    aggregate: Counter[tuple[str, str, str, str, str]] = Counter()
    retained = 0
    for line in stdout.splitlines():
        if retained >= max_rows:
            break
        host, method, uri, response = (line.split("\t") + ["", "", "", ""])[:4]
        sanitized, path_class = sanitize_http_path(uri)
        key = (
            str(host or "").strip().lower(),
            str(method or "").strip().upper(),
            str(response or "").strip(),
            sanitized,
            path_class,
        )
        aggregate[key] += 1
        retained += 1
    rows = [
        {
            "host": host,
            "method": method,
            "response_code": response,
            "sanitized_path": path,
            "path_class": path_class,
            "rows": count,
        }
        for (host, method, response, path, path_class), count in sorted(
            aggregate.items(),
            key=lambda item: (-item[1], item[0]),
        )
    ]
    return rows, "ok"


def _analyze_dns_anomalies(
    pcap_path: Path,
    tshark_path: str,
    *,
    timeout: int,
    package_name: str | None = None,
) -> dict[str, Any]:
    qnames, qname_status = _collect_field_values(
        pcap_path,
        tshark_path,
        "dns.qry.name",
        display_filter="dns.flags.response == 0",
        timeout=timeout,
        max_values=2000,
    )
    qtypes, _qtype_status = _collect_field_values(
        pcap_path,
        tshark_path,
        "dns.qry.type",
        display_filter="dns",
        timeout=timeout,
        max_values=32,
    )
    nxdomain_count = _count_display_filter(
        pcap_path,
        tshark_path,
        'dns.flags.response == 1 && dns.flags.rcode == 3',
        timeout=timeout,
    )
    txt_count = _count_display_filter(
        pcap_path,
        tshark_path,
        "dns.qry.type == 16",
        timeout=timeout,
    )
    entropies = [_label_entropy(name) for name in qnames if name]
    depths = [_subdomain_depth(name) for name in qnames if name]
    avg_entropy = _mean(entropies)
    max_entropy = max(entropies) if entropies else None
    max_depth = max(depths) if depths else 0
    long_labels = sum(1 for name in qnames if len(name) >= 48)
    risk_flags: list[str] = []
    if txt_count >= 5:
        risk_flags.append("elevated_dns_txt_queries")
    if nxdomain_count >= 10:
        risk_flags.append("elevated_dns_nxdomain_responses")
    if max_entropy is not None and max_entropy >= 4.2 and len(qnames) >= 8:
        risk_flags.append("high_entropy_dns_labels")
    if max_depth >= 5:
        risk_flags.append("deep_subdomain_queries")
    if long_labels >= 3:
        risk_flags.append("long_dns_label_queries")
    high_entropy_samples = sorted(
        [name for name in qnames if _label_entropy(name) >= 4.0],
        key=_label_entropy,
        reverse=True,
    )[:10]
    deep_samples = sorted(
        [name for name in qnames if _subdomain_depth(name) >= 5],
        key=lambda name: (_subdomain_depth(name), len(name)),
        reverse=True,
    )[:10]
    long_label_samples = sorted(
        [name for name in qnames if len(name) >= 48],
        key=len,
        reverse=True,
    )[:10]
    contextualized = _contextualize_dns_anomaly_samples(
        high_entropy_samples=high_entropy_samples,
        deep_subdomain_samples=deep_samples,
        long_label_samples=long_label_samples,
        package_name=package_name,
    )
    return {
        "status": qname_status,
        "unique_qnames": len(qnames),
        "unique_qtypes": len(qtypes),
        "qtype_distribution": _top_counter_rows(qtypes, limit=12),
        "nxdomain_responses": nxdomain_count,
        "txt_queries": txt_count,
        "avg_label_entropy": avg_entropy,
        "max_label_entropy": max_entropy,
        "max_subdomain_depth": max_depth,
        "long_label_count": long_labels,
        "high_entropy_samples": high_entropy_samples,
        "deep_subdomain_samples": deep_samples,
        "long_label_samples": long_label_samples,
        "known_context_samples": contextualized["known_context_samples"],
        "unknown_anomaly_samples": contextualized["unknown_anomaly_samples"],
        "risk_flags": risk_flags,
    }


def _contextualize_dns_anomaly_samples(
    *,
    high_entropy_samples: list[str],
    deep_subdomain_samples: list[str],
    long_label_samples: list[str],
    package_name: str | None,
) -> dict[str, list[dict[str, Any]]]:
    sample_reasons: dict[str, set[str]] = {}
    for reason, values in (
        ("high_entropy", high_entropy_samples),
        ("deep_subdomain", deep_subdomain_samples),
        ("long_label", long_label_samples),
    ):
        for value in values:
            domain = normalize_domain(value)
            if not domain:
                continue
            sample_reasons.setdefault(domain, set()).add(reason)

    known: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    package_key = str(package_name or "").strip().lower()
    for domain, reasons in sorted(sample_reasons.items()):
        classified = classify_domain(domain, package_name=package_key)
        row = {
            "domain": domain,
            "root_domain": str(classified.get("root_domain") or root_domain(domain)),
            "reason_classes": sorted(reasons),
            "owner_class": classified.get("owner_class"),
            "role_class": classified.get("role_class"),
            "confidence": classified.get("confidence"),
            "basis": classified.get("basis"),
            "match_type": classified.get("match_type"),
        }
        if classified.get("owner_class") and classified.get("owner_class") != "unknown":
            known.append(row)
        else:
            unknown.append(row)
    return {
        "known_context_samples": sorted(
            known,
            key=lambda row: (str(row.get("owner_class")), str(row.get("root_domain")), str(row.get("domain"))),
        ),
        "unknown_anomaly_samples": sorted(
            unknown,
            key=lambda row: (str(row.get("root_domain")), str(row.get("domain"))),
        ),
    }


def _analyze_tls_surface(pcap_path: Path, tshark_path: str, *, timeout: int) -> dict[str, Any]:
    alert_count = _count_display_filter(
        pcap_path,
        tshark_path,
        "tls.alert_message",
        timeout=timeout,
    )
    alert_messages, _alert_status = _collect_field_values(
        pcap_path,
        tshark_path,
        "tls.alert_message",
        display_filter="tls.alert_message",
        timeout=timeout,
        max_values=20,
    )
    cert_rows, cert_status = _extract_tls_cert_metadata(pcap_path, tshark_path, timeout=timeout)
    risk_flags: list[str] = []
    if alert_count:
        risk_flags.append("tls_alerts_observed")
    self_signed = sum(1 for row in cert_rows if row.get("self_signed"))
    if self_signed:
        risk_flags.append("self_signed_certificates_observed")
    sni_mismatch = sum(1 for row in cert_rows if row.get("sni_mismatch"))
    if sni_mismatch:
        risk_flags.append("tls_sni_certificate_mismatch")
    return {
        "cert_probe_status": cert_status,
        "certificate_observations": len(cert_rows),
        "self_signed_count": self_signed,
        "sni_mismatch_count": sni_mismatch,
        "tls_alert_count": alert_count,
        "tls_alert_messages": alert_messages[:10],
        "cert_samples": cert_rows[:15],
        "risk_flags": risk_flags,
    }


def _extract_tls_cert_metadata(
    pcap_path: Path,
    tshark_path: str,
    *,
    timeout: int,
) -> tuple[list[dict[str, Any]], str]:
    cmd = [
        tshark_path,
        "-r",
        str(pcap_path),
        "-Y",
        "tls.handshake.type == 11",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "tls.handshake.extensions_server_name",
        "-e",
        "x509sat.printableString",
        "-e",
        "x509ce.dNotBefore",
        "-e",
        "x509ce.dNotAfter",
        "-e",
        "x509if.id",
    ]
    rc, stdout, stderr = _run_tshark(cmd, timeout=timeout)
    if rc != 0:
        return [], f"failed: {stderr.strip()[:180]}"
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for line in stdout.splitlines():
        sni, subject, not_before, not_after, cert_id = (line.split("\t") + ["", "", "", "", ""])[:5]
        sni_text = str(sni or "").strip().lower()
        subject_text = str(subject or "").strip()
        key = (sni_text, subject_text, str(not_before or "").strip())
        if key in seen:
            continue
        seen.add(key)
        self_signed = bool(subject_text) and subject_text.lower() in sni_text
        rows.append(
            {
                "sni": sni_text or None,
                "subject": subject_text or None,
                "not_before": str(not_before or "").strip() or None,
                "not_after": str(not_after or "").strip() or None,
                "self_signed": self_signed,
                "sni_mismatch": bool(sni_text and subject_text and sni_text not in subject_text.lower()),
            }
        )
        if len(rows) >= 50:
            break
    return rows, "ok"


def _build_domain_inventory(
    pcap_path: Path,
    tshark_path: str,
    *,
    timeout: int,
    max_values: int,
) -> dict[str, Any]:
    dns_names, dns_status = _collect_field_values(
        pcap_path,
        tshark_path,
        "dns.qry.name",
        display_filter="dns.qry.name",
        timeout=timeout,
        max_values=max_values,
    )
    sni_names, sni_status = _collect_field_values(
        pcap_path,
        tshark_path,
        "tls.handshake.extensions_server_name",
        display_filter="tls.handshake.extensions_server_name",
        timeout=timeout,
        max_values=max_values,
    )
    dns_only = sorted(set(dns_names) - set(sni_names))
    sni_only = sorted(set(sni_names) - set(dns_names))
    overlap = sorted(set(dns_names) & set(sni_names))
    return {
        "dns_status": dns_status,
        "sni_status": sni_status,
        "dns_unique_count": len(dns_names),
        "sni_unique_count": len(sni_names),
        "dns_names": dns_names,
        "sni_names": sni_names,
        "dns_sni_overlap_count": len(overlap),
        "dns_only_count": len(dns_only),
        "sni_only_count": len(sni_only),
        "dns_only_samples": dns_only[:25],
        "sni_only_samples": sni_only[:25],
    }


def _analyze_threat_heuristics(
    *,
    cleartext: dict[str, Any],
    dns: dict[str, Any],
    tls: dict[str, Any],
    flow_summary: dict[str, Any],
    burst_summary: dict[str, Any],
    inventory: dict[str, Any],
) -> dict[str, Any]:
    top_flows = flow_summary.get("top_flows") if isinstance(flow_summary.get("top_flows"), list) else []
    outbound_only = [
        row for row in top_flows if isinstance(row, dict) and row.get("directionality") == "outbound_only"
    ]
    small_outbound = [
        row
        for row in outbound_only
        if _safe_int(row.get("packets")) <= 12 and _safe_int(row.get("bytes")) <= 4096
    ]
    risk_flags: list[str] = []
    if len(small_outbound) >= 3:
        risk_flags.append("multiple_small_outbound_only_flows")
    if inventory.get("dns_only_count", 0) >= 10 and inventory.get("sni_unique_count", 0) <= 3:
        risk_flags.append("dns_rich_sni_sparse_pattern")
    if cleartext.get("http_observed") and cleartext.get("http_host_count", 0) >= 3:
        risk_flags.append("multi_host_cleartext_http")
    score = len(risk_flags) + len(dns.get("risk_flags") or []) + len(tls.get("risk_flags") or [])
    return {
        "outbound_only_flow_count": len(outbound_only),
        "small_outbound_flow_count": len(small_outbound),
        "burst_count": _safe_int(burst_summary.get("burst_count")),
        "median_interburst_gap_s": burst_summary.get("median_interburst_gap_s"),
        "dns_only_destinations": inventory.get("dns_only_count", 0),
        "heuristic_score": score,
        "risk_flags": risk_flags,
    }


def _build_security_findings(
    *,
    cleartext: dict[str, Any],
    dns: dict[str, Any],
    tls: dict[str, Any],
    inventory: dict[str, Any],
    threats: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    def _add(severity: str, category: str, title: str, detail: str, evidence: dict[str, Any] | None = None) -> None:
        findings.append(
            {
                "severity": severity,
                "category": category,
                "title": title,
                "detail": detail,
                "evidence": evidence or {},
            }
        )

    if cleartext.get("http_observed"):
        _add(
            "high",
            "cleartext",
            "HTTP metadata observed",
            "Sanitized HTTP host/method/path metadata was extracted without payload bodies.",
            {
                "http_host_count": cleartext.get("http_host_count"),
                "top_http_hosts": cleartext.get("top_http_hosts"),
            },
        )
    if cleartext.get("plaintext_protocol_frames", 0) > 0:
        protocols = cleartext.get("plaintext_protocols_observed") or []
        _add(
            "medium",
            "cleartext",
            "Cleartext application protocols decoded",
            "One or more non-TLS application protocols were observed in the capture.",
            {"protocols": protocols},
        )
        if "xmpp" in protocols:
            xmpp_review = _classify_xmpp_dissector_signal(cleartext)
            _add(
                xmpp_review["severity"],
                "cleartext",
                "XMPP cleartext dissector signal",
                xmpp_review["detail"],
                {
                    "plaintext_protocol_frames": cleartext.get("plaintext_protocol_frames"),
                    "decoded_stream_count": cleartext.get("decoded_stream_count"),
                    "decoded_protocols_observed": cleartext.get("decoded_protocols_observed"),
                    "classification": xmpp_review["classification"],
                    "classification_reason": xmpp_review["reason"],
                },
            )
    if cleartext.get("decoded_stream_count", 0) > 0:
        _add(
            "medium",
            "cleartext",
            "Decoded cleartext streams observed",
            "Cleartext protocol streams were grouped by transport/port for manual pivoting (no payload bodies).",
            {
                "decoded_stream_count": cleartext.get("decoded_stream_count"),
                "decoded_streams": (cleartext.get("decoded_streams") or [])[:5],
            },
        )
    for flag in dns.get("risk_flags") or []:
        _add(
            "medium",
            "dns",
            flag.replace("_", " "),
            "DNS metadata pattern may warrant manual review for tunneling or DGA-like behavior.",
            {
                "unique_qnames": dns.get("unique_qnames"),
                "txt_queries": dns.get("txt_queries"),
                "nxdomain_responses": dns.get("nxdomain_responses"),
                "max_label_entropy": dns.get("max_label_entropy"),
                "max_subdomain_depth": dns.get("max_subdomain_depth"),
                "known_context_samples": (dns.get("known_context_samples") or [])[:5],
                "unknown_anomaly_sample_count": len(dns.get("unknown_anomaly_samples") or []),
            },
        )
    for flag in tls.get("risk_flags") or []:
        _add(
            "medium",
            "tls",
            flag.replace("_", " "),
            "TLS handshake metadata suggests certificate or alert anomalies.",
            {
                "tls_alert_count": tls.get("tls_alert_count"),
                "self_signed_count": tls.get("self_signed_count"),
                "sni_mismatch_count": tls.get("sni_mismatch_count"),
            },
        )
    for flag in threats.get("risk_flags") or []:
        _add(
            "low",
            "behavior",
            flag.replace("_", " "),
            "Conservative traffic-shape heuristic fired; verify manually before treating as malicious.",
            {
                "small_outbound_flow_count": threats.get("small_outbound_flow_count"),
                "dns_only_destinations": threats.get("dns_only_destinations"),
            },
        )
    if inventory.get("dns_unique_count", 0) > 0 or inventory.get("sni_unique_count", 0) > 0:
        _add(
            "info",
            "inventory",
            "Domain inventory captured",
            "Full unique DNS/SNI name lists are attached for manual pivoting (metadata only).",
            {
                "dns_unique_count": inventory.get("dns_unique_count"),
                "sni_unique_count": inventory.get("sni_unique_count"),
                "dns_sni_overlap_count": inventory.get("dns_sni_overlap_count"),
            },
        )
    return findings


def _classify_xmpp_dissector_signal(cleartext: dict[str, Any]) -> dict[str, str]:
    decoded_streams = [row for row in cleartext.get("decoded_streams") or [] if isinstance(row, dict)]
    xmpp_streams = [
        row
        for row in decoded_streams
        if str(row.get("protocol") or "").strip().lower() == "xmpp"
    ]
    xmpp_frames = sum(_safe_int(row.get("frames")) for row in xmpp_streams)
    xmpp_bytes = sum(_safe_int(row.get("bytes_total")) for row in xmpp_streams)
    has_port_5222 = any(
        str(row.get("src_port") or "") == "5222" or str(row.get("dst_port") or "") == "5222"
        for row in xmpp_streams
    )
    if (
        xmpp_streams
        and has_port_5222
        and not cleartext.get("http_observed")
        and xmpp_frames <= 4
        and xmpp_bytes <= 1024
    ):
        return {
            "severity": "medium",
            "classification": "xmpp_small_handshake_or_messaging_transport_probe",
            "reason": "tiny_xmpp_port_5222_no_http",
            "detail": (
                "XMPP frames were decoded by tshark on port 5222, but the observed payload is tiny "
                "and no HTTP metadata was present. Treat as a Meta-style realtime transport or "
                "handshake probe unless a larger decoded stream appears."
            ),
        }
    return {
        "severity": "high",
        "classification": "xmpp_cleartext_review_required",
        "reason": "xmpp_decoded_stream_requires_manual_review",
        "detail": (
            "XMPP frames were decoded as cleartext by tshark. Common on Meta-family stacks; "
            "validate whether this is handshake/STARTTLS noise versus true cleartext messaging."
        ),
    }


def rehydrate_security_surface(surface: dict[str, Any]) -> dict[str, Any]:
    """Recompute findings and derived cleartext labels from stored surface blocks (no PCAP I/O)."""
    if str(surface.get("status") or "").lower() != "ok":
        return surface
    cleartext = dict(surface.get("cleartext") or {}) if isinstance(surface.get("cleartext"), dict) else {}
    dns = surface.get("dns_anomalies") if isinstance(surface.get("dns_anomalies"), dict) else {}
    tls = surface.get("tls_surface") if isinstance(surface.get("tls_surface"), dict) else {}
    inventory = surface.get("domain_inventory") if isinstance(surface.get("domain_inventory"), dict) else {}
    threats = surface.get("threat_heuristics") if isinstance(surface.get("threat_heuristics"), dict) else {}
    decoded_streams = cleartext.get("decoded_streams") or []
    if not cleartext.get("decoded_protocols_observed"):
        cleartext["decoded_protocols_observed"] = sorted(
            {
                str(row.get("protocol") or "").strip().lower()
                for row in decoded_streams
                if isinstance(row, dict) and str(row.get("protocol") or "").strip()
            }
        )
    if "cleartext_protocol_observed" not in cleartext:
        cleartext["cleartext_protocol_observed"] = bool(
            cleartext.get("http_observed")
            or _safe_int(cleartext.get("plaintext_protocol_frames")) > 0
            or decoded_streams
        )
    findings = _build_security_findings(
        cleartext=cleartext,
        dns=dns,
        tls=tls,
        inventory=inventory,
        threats=threats,
    )
    risk_flags = sorted(
        {
            *cleartext.get("risk_flags", []),
            *dns.get("risk_flags", []),
            *tls.get("risk_flags", []),
            *threats.get("risk_flags", []),
        }
    )
    return {
        **surface,
        "cleartext": cleartext,
        "findings": findings,
        "finding_count": len(findings),
        "risk_flags": risk_flags,
    }


def _collect_field_values(
    pcap_path: Path,
    tshark_path: str,
    field: str,
    *,
    display_filter: str | None,
    timeout: int,
    max_values: int,
) -> tuple[list[str], str]:
    cmd = [tshark_path, "-n", "-r", str(pcap_path), "-T", "fields", "-e", field]
    if display_filter:
        cmd.extend(["-Y", display_filter])
    rc, stdout, stderr = _run_tshark(cmd, timeout=timeout)
    if rc != 0:
        return [], f"failed: {stderr.strip()[:180]}"
    seen: set[str] = set()
    ordered: list[str] = []
    for line in stdout.splitlines():
        value = str(line or "").strip().lower().rstrip(".")
        if not value or value in seen:
            continue
        seen.add(value)
        ordered.append(value)
        if len(ordered) >= max_values:
            break
    return ordered, "ok"


def _count_display_filter(
    pcap_path: Path,
    tshark_path: str,
    display_filter: str,
    *,
    timeout: int,
) -> int:
    rc, stdout, _stderr = _run_tshark(
        [tshark_path, "-r", str(pcap_path), "-Y", display_filter, "-T", "fields", "-e", "frame.number"],
        timeout=timeout,
    )
    if rc != 0:
        return 0
    return sum(1 for line in stdout.splitlines() if line.strip())


def _label_entropy(label: str) -> float:
    text = str(label or "").strip().lower()
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _subdomain_depth(name: str) -> int:
    text = str(name or "").strip().lower().rstrip(".")
    if not text:
        return 0
    return max(0, text.count("."))


def _top_counter_rows(values: list[str], *, limit: int) -> list[dict[str, Any]]:
    counter = Counter(value for value in values if value)
    return [{"value": value, "count": count} for value, count in counter.most_common(limit)]


def _mean(values: list[float]) -> float | None:
    if not values:
        return None
    return float(sum(values) / len(values))


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def http_observed_from_report(report: dict[str, Any]) -> bool:
    """Return whether HTTP metadata was observed, not all cleartext protocols."""
    surface = report.get("security_surface")
    if isinstance(surface, dict) and surface.get("status") == "ok":
        cleartext = surface.get("cleartext")
        if isinstance(cleartext, dict):
            if cleartext.get("http_observed"):
                return True
            visibility = str(cleartext.get("visibility_class") or "").strip()
            if visibility == "encrypted_or_opaque_dominant":
                return False
    rows = report.get("protocol_hierarchy") if isinstance(report.get("protocol_hierarchy"), list) else []
    for row in rows:
        if not isinstance(row, dict):
            continue
        protocol = str(row.get("protocol") or "").strip().lower()
        if protocol.startswith("http"):
            return True
    return False


def compute_static_dynamic_cleartext_posture(
    plan: dict[str, Any] | None,
    report: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compare static cleartext permission vs dynamic cleartext observations."""
    plan = plan if isinstance(plan, dict) else {}
    report = report if isinstance(report, dict) else {}
    static_features = plan.get("static_features") if isinstance(plan.get("static_features"), dict) else {}
    risk_flags = plan.get("risk_flags") if isinstance(plan.get("risk_flags"), dict) else {}
    network = plan.get("network_targets") if isinstance(plan.get("network_targets"), dict) else {}
    static_allowed = bool(
        static_features.get("uses_cleartext_traffic")
        if "uses_cleartext_traffic" in static_features
        else risk_flags.get("uses_cleartext_traffic")
    )
    cleartext_domains = sorted(
        {
            str(item or "").strip().lower().rstrip(".")
            for item in (network.get("cleartext_domains") or [])
            if str(item or "").strip()
        }
    )
    dynamic_http = http_observed_from_report(report)
    surface = report.get("security_surface") if isinstance(report.get("security_surface"), dict) else {}
    cleartext = surface.get("cleartext") if isinstance(surface.get("cleartext"), dict) else {}
    visibility = cleartext.get("visibility_class")
    dynamic_cleartext_protocol = bool(
        cleartext.get("cleartext_protocol_observed")
        or _safe_int(cleartext.get("plaintext_protocol_frames")) > 0
        or _safe_int(cleartext.get("decoded_stream_count")) > 0
    )
    http_hosts = sorted(
        {
            str(item.get("value") or "").strip().lower()
            for item in (cleartext.get("top_http_hosts") or [])
            if isinstance(item, dict) and str(item.get("value") or "").strip()
        }
    )
    if static_allowed and dynamic_http:
        mismatch_class = "allowed_and_observed"
    elif static_allowed and dynamic_cleartext_protocol:
        mismatch_class = "allowed_cleartext_protocol_observed"
    elif static_allowed and not dynamic_http:
        mismatch_class = (
            "allowed_not_observed_encrypted"
            if visibility == "encrypted_or_opaque_dominant"
            else "allowed_not_observed"
        )
    elif not static_allowed and dynamic_http:
        mismatch_class = "denied_but_observed"
    elif not static_allowed and dynamic_cleartext_protocol:
        mismatch_class = "denied_but_cleartext_protocol"
    else:
        mismatch_class = "aligned_encrypted"
    summary_map = {
        "allowed_and_observed": "Static cleartext is permitted and HTTP/cleartext metadata was observed dynamically.",
        "allowed_cleartext_protocol_observed": (
            "Static cleartext is permitted and non-HTTP cleartext protocol metadata was observed dynamically."
        ),
        "allowed_not_observed": "Static cleartext is permitted but no HTTP/cleartext metadata was observed in this capture.",
        "allowed_not_observed_encrypted": "Static cleartext is permitted; capture looks encrypted/opaque with no HTTP metadata.",
        "denied_but_observed": "Static posture denies cleartext, but HTTP/cleartext metadata was observed dynamically.",
        "denied_but_cleartext_protocol": (
            "Static posture denies cleartext, but non-HTTP cleartext protocol metadata was observed dynamically."
        ),
        "aligned_encrypted": "Static posture denies cleartext and no HTTP/cleartext metadata was observed.",
        "unknown": "Cleartext posture could not be classified.",
    }
    return {
        "static_cleartext_allowed": static_allowed,
        "static_cleartext_domain_count": len(cleartext_domains),
        "static_cleartext_domains_sample": cleartext_domains[:10],
        "dynamic_http_observed": dynamic_http,
        "dynamic_cleartext_protocol_observed": dynamic_cleartext_protocol,
        "cleartext_visibility_class": visibility,
        "dynamic_http_host_count": len(http_hosts),
        "dynamic_http_hosts_sample": http_hosts[:10],
        "mismatch_class": mismatch_class,
        "mismatch_summary": summary_map.get(mismatch_class, summary_map["unknown"]),
    }


def security_surface_summary_from_report(report: dict[str, Any]) -> dict[str, Any]:
    """Compact operator summary derived from pcap_report.security_surface."""
    surface = report.get("security_surface")
    if not isinstance(surface, dict):
        return {"status": "missing", "finding_count": None, "visibility_class": None, "risk_flags": []}
    cleartext = surface.get("cleartext") if isinstance(surface.get("cleartext"), dict) else {}
    return {
        "status": surface.get("status"),
        "finding_count": surface.get("finding_count"),
        "visibility_class": cleartext.get("visibility_class"),
        "http_observed": cleartext.get("http_observed"),
        "cleartext_protocol_observed": cleartext.get("cleartext_protocol_observed"),
        "plaintext_protocols_observed": cleartext.get("plaintext_protocols_observed") or [],
        "decoded_protocols_observed": cleartext.get("decoded_protocols_observed") or [],
        "decoded_stream_count": cleartext.get("decoded_stream_count"),
        "risk_flags": surface.get("risk_flags") or [],
        "top_findings": [
            str(item.get("title") or "").strip()
            for item in (surface.get("findings") or [])
            if isinstance(item, dict) and str(item.get("title") or "").strip()
        ][:3],
    }


def _load_json_dict(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def security_operator_labels_from_run_dir(run_dir: Path) -> dict[str, Any]:
    """Operator-facing cleartext/security labels for one evidence pack directory."""
    surface = _load_json_dict(run_dir / "analysis" / "security_surface.json")
    if not isinstance(surface, dict) or surface.get("status") != "ok":
        report = _load_json_dict(run_dir / "analysis" / "pcap_report.json")
        if isinstance(report, dict) and isinstance(report.get("security_surface"), dict):
            surface = report.get("security_surface")
    if isinstance(surface, dict) and surface.get("status") == "ok":
        summary = security_surface_summary_from_report({"security_surface": surface})
        http_observed = summary.get("http_observed")
        return {
            "status": "ok",
            "cleartext_http_label": "Y" if http_observed else "N",
            "finding_count": summary.get("finding_count"),
            "visibility_class": summary.get("visibility_class"),
            "risk_flags": summary.get("risk_flags") or [],
            "top_findings": summary.get("top_findings") or [],
        }
    features = _load_json_dict(run_dir / "analysis" / "pcap_features.json")
    proxies = features.get("proxies") if isinstance(features, dict) and isinstance(features.get("proxies"), dict) else {}
    cleartext_obs = proxies.get("cleartext_http_observed")
    if cleartext_obs in (0, 1):
        surface_summary = (
            features.get("security_surface", {}).get("summary")
            if isinstance(features.get("security_surface"), dict)
            else {}
        )
        return {
            "status": "proxies_only",
            "cleartext_http_label": "Y" if cleartext_obs == 1 else "N",
            "finding_count": proxies.get("security_finding_count"),
            "visibility_class": surface_summary.get("cleartext_visibility_class") if isinstance(surface_summary, dict) else None,
            "risk_flags": surface_summary.get("risk_flags") if isinstance(surface_summary, dict) else [],
            "top_findings": [],
        }
    return {
        "status": "missing",
        "cleartext_http_label": "—",
        "finding_count": None,
        "visibility_class": None,
        "risk_flags": [],
        "top_findings": [],
    }


def render_security_review_md(
    surface: dict[str, Any],
    *,
    package_name: str | None = None,
    dynamic_run_id: str | None = None,
) -> str:
    """Render operator-friendly ethical-hacking review markdown (metadata only)."""
    cleartext = surface.get("cleartext") if isinstance(surface.get("cleartext"), dict) else {}
    dns = surface.get("dns_anomalies") if isinstance(surface.get("dns_anomalies"), dict) else {}
    tls = surface.get("tls_surface") if isinstance(surface.get("tls_surface"), dict) else {}
    inventory = surface.get("domain_inventory") if isinstance(surface.get("domain_inventory"), dict) else {}
    lines = [
        "# PCAP Security Review (metadata)",
        "",
        "Privacy contract: no payload bodies, cookies, authorization headers, or query strings.",
        "",
    ]
    if dynamic_run_id:
        lines.append(f"- Run ID: `{dynamic_run_id}`")
    if package_name:
        lines.append(f"- Package: `{package_name}`")
    lines.extend(
        [
            f"- Surface status: {surface.get('status') or 'unknown'}",
            f"- Visibility class: {cleartext.get('visibility_class') or 'unknown'}",
            f"- Findings: {surface.get('finding_count') if surface.get('finding_count') is not None else 'unknown'}",
            f"- Risk flags: {', '.join(surface.get('risk_flags') or []) or 'none'}",
            "",
            "## Cleartext surface",
            f"- HTTP metadata observed: {'yes' if cleartext.get('http_observed') else 'no'}",
            f"- Plaintext protocol frames: {cleartext.get('plaintext_protocol_frames') or 0}",
            f"- Decoded cleartext streams: {cleartext.get('decoded_stream_count') or 0}",
        ]
    )
    plain_protocols = cleartext.get("plaintext_protocols_observed") or []
    if plain_protocols:
        lines.append(f"- Plaintext protocols: {', '.join(str(item) for item in plain_protocols)}")
    decoded_protocols = cleartext.get("decoded_protocols_observed") or []
    if decoded_protocols:
        lines.append(f"- Decoded stream protocols: {', '.join(str(item) for item in decoded_protocols)}")
    top_hosts = cleartext.get("top_http_hosts") or []
    if top_hosts:
        host_text = ", ".join(
            f"{item.get('value')} ({item.get('count')})"
            for item in top_hosts[:5]
            if isinstance(item, dict) and item.get("value")
        )
        if host_text:
            lines.append(f"- Top HTTP hosts: {host_text}")
    lines.extend(
        [
            "",
            "## DNS anomalies",
            f"- Unique qnames: {dns.get('unique_qnames') or 0}",
            f"- NXDOMAIN responses: {dns.get('nxdomain_responses') or 0}",
            f"- TXT queries: {dns.get('txt_queries') or 0}",
            f"- Max label entropy: {dns.get('max_label_entropy') if dns.get('max_label_entropy') is not None else 'n/a'}",
        ]
    )
    known_context_samples = [
        row for row in (dns.get("known_context_samples") or []) if isinstance(row, dict)
    ]
    if known_context_samples:
        known_text = "; ".join(
            f"{row.get('domain')} -> {row.get('role_class')} ({row.get('owner_class')})"
            for row in known_context_samples[:5]
            if row.get("domain")
        )
        if known_text:
            lines.append(f"- Known context samples: {known_text}")
    unknown_anomaly_samples = [
        row for row in (dns.get("unknown_anomaly_samples") or []) if isinstance(row, dict)
    ]
    if unknown_anomaly_samples:
        unknown_text = "; ".join(
            str(row.get("domain"))
            for row in unknown_anomaly_samples[:5]
            if row.get("domain")
        )
        if unknown_text:
            lines.append(f"- Unknown anomaly samples: {unknown_text}")
    lines.extend(
        [
            "",
            "## TLS surface",
            f"- TLS alerts: {tls.get('tls_alert_count') or 0}",
            f"- Self-signed certs: {tls.get('self_signed_count') or 0}",
            f"- SNI/cert mismatches: {tls.get('sni_mismatch_count') or 0}",
            "",
            "## Domain inventory",
            f"- DNS unique: {inventory.get('dns_unique_count') or 0}",
            f"- SNI unique: {inventory.get('sni_unique_count') or 0}",
            f"- DNS-only destinations: {inventory.get('dns_only_count') or 0}",
            "",
            "## Findings",
        ]
    )
    findings = surface.get("findings") or []
    if not findings:
        lines.append("- none")
    else:
        for item in findings:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or "").strip() or "untitled"
            severity = str(item.get("severity") or "").strip() or "info"
            detail = str(item.get("detail") or "").strip()
            lines.append(f"- **[{severity.upper()}] {title}** — {detail or 'see evidence JSON'}")
    lines.append("")
    return "\n".join(lines)


def export_payload_audit_rows(
    *,
    run_id: str,
    package: str,
    app_label: str,
    run_profile: str,
    valid_dataset_run: int,
    pcap_path: Path,
    surface: dict[str, Any],
    report: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Map a security_surface bundle to payload-audit CSV row shapes."""
    report = report or {}
    cleartext = surface.get("cleartext") if isinstance(surface.get("cleartext"), dict) else {}
    cap = (report.get("capinfos") or {}).get("parsed") if isinstance(report.get("capinfos"), dict) else {}
    protocol_rows_raw = [
        row for row in (cleartext.get("protocol_visibility") or []) if isinstance(row, dict)
    ]

    def _frames_for(protocol: str) -> int:
        key = protocol.lower()
        for row in protocol_rows_raw:
            if str(row.get("protocol") or "").lower() == key:
                return _safe_int(row.get("frames"))
        return 0

    http_rows = [
        {
            "run_id": run_id,
            "package": package,
            "app_label": app_label,
            "host": row.get("host"),
            "method": row.get("method"),
            "response_code": row.get("response_code"),
            "sanitized_path": row.get("sanitized_path"),
            "path_class": row.get("path_class"),
            "rows": row.get("rows"),
        }
        for row in (cleartext.get("sanitized_http_samples") or [])
        if isinstance(row, dict)
    ]
    protocol_rows = [
        {
            "run_id": run_id,
            "package": package,
            "app_label": app_label,
            "protocol": row.get("protocol"),
            "frames": row.get("frames"),
            "bytes": row.get("bytes"),
            "visibility": row.get("visibility"),
        }
        for row in protocol_rows_raw
    ]
    decoded_rows = [
        {
            "run_id": run_id,
            "package": package,
            "app_label": app_label,
            "protocol": row.get("protocol"),
            "transport": row.get("transport"),
            "src_port": row.get("src_port"),
            "dst_port": row.get("dst_port"),
            "tcp_stream": row.get("tcp_stream"),
            "frames": row.get("frames"),
            "bytes_total": row.get("bytes_total"),
            "bytes_min": row.get("bytes_min"),
            "bytes_max": row.get("bytes_max"),
        }
        for row in (cleartext.get("decoded_streams") or [])
        if isinstance(row, dict)
    ]
    risk_flags = surface.get("risk_flags") or []
    http_status = str(cleartext.get("http_status") or "ok")
    run_row = {
        "run_id": run_id,
        "package": package,
        "app_label": app_label,
        "run_profile": run_profile,
        "valid_dataset_run": valid_dataset_run,
        "pcap_path": str(pcap_path),
        "pcap_bytes": pcap_path.stat().st_size if pcap_path.exists() else 0,
        "capinfos_packets": _safe_int(cap.get("packet_count")),
        "capinfos_duration_s": cap.get("capture_duration_s") or 0,
        "tshark_status": http_status,
        "protocols_observed": ";".join(
            sorted({str(row.get("protocol") or "").lower() for row in protocol_rows_raw if row.get("protocol")})
        ),
        "dns_frames": _frames_for("dns"),
        "tls_frames": _frames_for("tls") + _frames_for("ssl"),
        "quic_frames": _frames_for("quic") + _frames_for("gquic"),
        "http_frames": _frames_for("http"),
        "http2_frames": _frames_for("http2"),
        "plaintext_protocol_frames": _safe_int(cleartext.get("plaintext_protocol_frames")),
        "http_request_rows": _safe_int(cleartext.get("http_request_rows")),
        "http_response_rows": _safe_int(cleartext.get("http_response_rows")),
        "http_host_count": _safe_int(cleartext.get("http_host_count")),
        "http_method_count": len({row.get("method") for row in http_rows if row.get("method")}),
        "sanitized_http_path_count": len({row.get("sanitized_path") for row in http_rows if row.get("sanitized_path")}),
        "payload_visibility_class": cleartext.get("visibility_class"),
        "payload_risk_flags": ";".join(str(flag) for flag in risk_flags if flag),
        "plaintext_protocols_observed": ";".join(cleartext.get("plaintext_protocols_observed") or []),
        "decoded_protocols_observed": ";".join(cleartext.get("decoded_protocols_observed") or []),
        "decoded_stream_count": _safe_int(cleartext.get("decoded_stream_count")),
    }
    return run_row, http_rows, protocol_rows, decoded_rows


__all__ = [
    "SecuritySurfaceConfig",
    "compute_static_dynamic_cleartext_posture",
    "export_payload_audit_rows",
    "http_observed_from_report",
    "rehydrate_security_surface",
    "render_security_review_md",
    "sanitize_http_path",
    "security_operator_labels_from_run_dir",
    "security_surface_summary_from_report",
    "summarize_security_surface",
]
