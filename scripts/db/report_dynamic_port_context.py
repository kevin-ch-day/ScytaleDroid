#!/usr/bin/env python3
"""Read-only runtime port-context report from dynamic PCAP summaries.

The report uses ``analysis/pcap_report.json`` files only. It does not parse
packet payloads, modify evidence, or write database rows.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


KNOWN_PORTS: dict[tuple[str, int], tuple[str, str]] = {
    ("tcp", 80): ("http_cleartext", "cleartext_http"),
    ("tcp", 443): ("https_tls", "encrypted_web_or_api"),
    ("udp", 443): ("quic_or_udp_443", "quic_https_or_udp_media"),
    ("tcp", 5222): ("xmpp_or_messaging", "long_lived_messaging_transport"),
    ("tcp", 5223): ("push_or_messaging", "push_or_messaging_transport"),
    ("tcp", 8883): ("mqtt_tls", "mqtt_over_tls"),
    ("tcp", 993): ("imaps", "mail_transport"),
    ("tcp", 995): ("pop3s", "mail_transport"),
    ("udp", 53): ("dns", "name_resolution"),
    ("tcp", 53): ("dns", "name_resolution"),
    ("udp", 123): ("ntp", "time_sync"),
    ("udp", 3478): ("stun_turn_rtc", "nat_traversal_or_relay"),
    ("tcp", 3478): ("stun_turn_rtc", "nat_traversal_or_relay"),
    ("udp", 3479): ("stun_turn_rtc", "nat_traversal_or_relay"),
    ("tcp", 3479): ("stun_turn_rtc", "nat_traversal_or_relay"),
    ("udp", 3480): ("stun_turn_rtc", "nat_traversal_or_relay"),
    ("tcp", 3480): ("stun_turn_rtc", "nat_traversal_or_relay"),
    ("udp", 5349): ("turn_tls", "nat_traversal_or_relay_tls"),
    ("tcp", 5349): ("turn_tls", "nat_traversal_or_relay_tls"),
    ("udp", 19302): ("google_stun", "nat_traversal_or_relay"),
    ("tcp", 8080): ("http_alt", "alternate_http_or_proxy"),
    ("tcp", 8443): ("https_alt", "alternate_https_or_api"),
}

COMMON_STANDARD_PORTS: dict[tuple[str, int], tuple[str, str]] = {
    ("tcp", 20): ("ftp-data", "File Transfer Protocol data"),
    ("tcp", 21): ("ftp", "File Transfer Protocol control"),
    ("tcp", 22): ("ssh", "Secure Shell"),
    ("tcp", 23): ("telnet", "Telnet"),
    ("tcp", 25): ("smtp", "Simple Mail Transfer Protocol"),
    ("udp", 53): ("domain", "Domain Name System"),
    ("tcp", 53): ("domain", "Domain Name System"),
    ("udp", 67): ("bootps", "DHCP/BOOTP server"),
    ("udp", 68): ("bootpc", "DHCP/BOOTP client"),
    ("udp", 69): ("tftp", "Trivial File Transfer Protocol"),
    ("tcp", 80): ("http", "Hypertext Transfer Protocol"),
    ("udp", 123): ("ntp", "Network Time Protocol"),
    ("tcp", 143): ("imap", "Internet Message Access Protocol"),
    ("udp", 161): ("snmp", "Simple Network Management Protocol"),
    ("tcp", 389): ("ldap", "Lightweight Directory Access Protocol"),
    ("udp", 443): ("https", "HTTP over TLS / QUIC candidate"),
    ("tcp", 443): ("https", "HTTP over TLS"),
    ("tcp", 465): ("submissions", "Message Submission over TLS"),
    ("tcp", 587): ("submission", "Message Submission"),
    ("udp", 596): ("smsd", "SMSD"),
    ("udp", 597): ("ptcnameservice", "PTC Name Service"),
    ("udp", 598): ("sco-websrvrmg3", "SCO Web Server Manager 3"),
    ("udp", 599): ("acp", "Aeolon Core Protocol"),
    ("tcp", 993): ("imaps", "IMAP over TLS"),
    ("tcp", 995): ("pop3s", "POP3 over TLS"),
    ("udp", 1400): ("cadkey-tablet", "Cadkey Tablet Daemon"),
    ("udp", 3478): ("stun", "Session Traversal Utilities for NAT"),
    ("tcp", 3478): ("stun", "Session Traversal Utilities for NAT"),
    ("udp", 3479): ("turn", "Traversal Using Relays around NAT"),
    ("tcp", 3479): ("turn", "Traversal Using Relays around NAT"),
    ("udp", 3480): ("stun", "STUN/TURN alternate"),
    ("tcp", 3480): ("stun", "STUN/TURN alternate"),
    ("tcp", 5222): ("xmpp-client", "XMPP client connection"),
    ("tcp", 5223): ("hpvirtgrp", "Registered service; commonly also seen in legacy push contexts"),
    ("udp", 5349): ("stuns", "STUN over TLS"),
    ("tcp", 5349): ("stuns", "STUN over TLS"),
    ("tcp", 8883): ("secure-mqtt", "MQTT over TLS"),
}

DEFAULT_LABEL_MAP_CANDIDATES = (
    _REPO_ROOT / "output" / "paper" / "android_empirical_alignment_final" / "publication_cohort_manifest.csv",
    _REPO_ROOT / "output" / "paper" / "dynamic_paper_cutoff_final_20260709T202819Z" / "paper_freeze_manifest.csv",
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", action="append", default=[], help="Restrict to one or more package names.")
    parser.add_argument("--dynamic-root", default=None, help="Override dynamic evidence root.")
    parser.add_argument(
        "--publication-manifest",
        default=None,
        help="Optional publication manifest CSV for labels and publication-summary cohort filtering.",
    )
    parser.add_argument("--output-dir", default=None, help="Optional explicit output directory.")
    return parser


def _norm_text(value: object) -> str:
    return str(value or "").strip()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fields})


def _write_markdown_table(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    lines: list[str] = []
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    lines.append("| " + " | ".join(fields) + " |")
    lines.append("| " + " | ".join("---" for _ in fields) + " |")
    for row in rows:
        values = []
        for field in fields:
            value = str(row.get(field) or "")
            values.append(value.replace("|", "\\|").replace("\n", " "))
        lines.append("| " + " | ".join(values) + " |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _dynamic_root_from_config() -> Path:
    try:
        from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root

        return dynamic_evidence_root()
    except Exception:
        return _REPO_ROOT / "data" / "evidence" / "dynamic"


def _load_publication_manifest_labels(paths: tuple[Path, ...] = DEFAULT_LABEL_MAP_CANDIDATES) -> dict[str, str]:
    labels: dict[str, str] = {}
    for path in paths:
        if not path.exists():
            continue
        try:
            with path.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
        except OSError:
            continue
        for row in rows:
            package = _norm_text(row.get("package_name") or row.get("package")).lower()
            label = _norm_text(row.get("app") or row.get("app_label") or row.get("display_name"))
            if package and label:
                labels.setdefault(package, label)
    return labels


def _apply_label_overrides(rows: list[dict[str, Any]], label_overrides: Mapping[str, str]) -> int:
    updated = 0
    for row in rows:
        package = _norm_text(row.get("package")).lower()
        label = _norm_text(label_overrides.get(package))
        if not label:
            continue
        if row.get("app_label") != label:
            row["app_label"] = label
            updated += 1
    return updated


def _iana_port_range(port: int | None) -> str:
    if port is None:
        return "unknown"
    value = int(port)
    if value < 0 or value > 65535:
        return "invalid"
    if value <= 1023:
        return "well_known"
    if value <= 49151:
        return "registered"
    return "dynamic_private"


@lru_cache(maxsize=1)
def _load_system_service_ports() -> dict[tuple[str, int], tuple[str, str]]:
    services_path = Path("/etc/services")
    if not services_path.exists():
        return {}
    out: dict[tuple[str, int], tuple[str, str]] = {}
    try:
        lines = services_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        body, _, comment = line.partition("#")
        parts = body.split()
        if len(parts) < 2 or "/" not in parts[1]:
            continue
        service_name = parts[0].strip()
        port_text, proto = parts[1].split("/", 1)
        proto = proto.strip().lower()
        if proto not in {"tcp", "udp", "sctp", "dccp"}:
            continue
        try:
            port = int(port_text)
        except ValueError:
            continue
        if port < 0 or port > 65535:
            continue
        description = comment.strip() or service_name
        out.setdefault((proto, port), (service_name, description))
    return out


def _standard_service_for_port(protocol: str, port: int | None) -> tuple[str, str, str]:
    if port is None:
        return "", "", ""
    proto = _norm_text(protocol).lower()
    key = (proto, int(port))
    common = COMMON_STANDARD_PORTS.get(key)
    if common:
        return common[0], common[1], "curated_common"
    system = _load_system_service_ports().get(key)
    if system:
        return system[0], system[1], "system_etc_services"
    return "", "", ""


def _split_endpoint(endpoint: object) -> tuple[str, int | None]:
    text = _norm_text(endpoint)
    if not text:
        return "", None
    if text.startswith("[") and "]:" in text:
        host, port_text = text.rsplit("]:", 1)
        host = host.lstrip("[")
    elif ":" in text:
        host, port_text = text.rsplit(":", 1)
    else:
        return text, None
    try:
        port = int(port_text)
    except ValueError:
        return host, None
    if port < 0 or port > 65535:
        return host, None
    return host, port


def _is_private_or_local_ip(host: str) -> bool:
    try:
        addr = ip_address(host)
    except ValueError:
        return False
    return bool(addr.is_private or addr.is_loopback or addr.is_link_local)


def _remote_host_scope(host: str) -> str:
    if not host:
        return "unknown"
    try:
        addr = ip_address(host)
    except ValueError:
        return "hostname"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_private:
        return "private"
    if addr.is_multicast:
        return "multicast"
    return "public"


def _remote_endpoint(flow: Mapping[str, Any]) -> tuple[str, int | None]:
    endpoint_a_host, endpoint_a_port = _split_endpoint(flow.get("endpoint_a"))
    endpoint_b_host, endpoint_b_port = _split_endpoint(flow.get("endpoint_b"))
    if endpoint_b_host and not _is_private_or_local_ip(endpoint_b_host):
        return endpoint_b_host, endpoint_b_port
    if endpoint_a_host and not _is_private_or_local_ip(endpoint_a_host):
        return endpoint_a_host, endpoint_a_port
    return endpoint_b_host or endpoint_a_host, endpoint_b_port if endpoint_b_host else endpoint_a_port


def _classify_port(protocol: str, port: int | None) -> tuple[str, str, int]:
    proto = _norm_text(protocol).lower()
    if port is None:
        return "unknown_port", "missing_or_unparseable_remote_port", 0
    known = KNOWN_PORTS.get((proto, int(port)))
    if known:
        notable = 1 if known[0] in {"http_cleartext", "quic_or_udp_443", "stun_turn_rtc", "turn_tls", "google_stun", "xmpp_or_messaging"} else 0
        return known[0], known[1], notable
    standard_name, _, _ = _standard_service_for_port(proto, int(port))
    port_range = _iana_port_range(int(port))
    if port_range == "well_known" and standard_name:
        return "well_known_standard_other", "standard_well_known_service_review_if_repeated", 1
    if port_range == "well_known":
        return "well_known_other", "review_if_repeated_or_high_volume", 1
    if port_range == "registered" and standard_name:
        return "registered_standard_other", "standard_registered_service_review_if_repeated", 1
    if int(port) >= 49152:
        return "remote_ephemeral_or_peer_port", "review_direct_ip_or_peer_transport", 1
    if int(port) >= 1024:
        return "app_specific_registered_or_dynamic_port", "review_if_repeated_or_high_volume", 1
    return "well_known_other", "review_if_repeated_or_high_volume", 1


def _iter_report_paths(dynamic_root: Path, package_filters: set[str]) -> list[Path]:
    paths: list[Path] = []
    for report_path in sorted(dynamic_root.glob("*/analysis/pcap_report.json")):
        if not package_filters:
            paths.append(report_path)
            continue
        report = _read_json(report_path)
        package = _norm_text(report.get("package_name")).lower()
        if package in package_filters:
            paths.append(report_path)
    return paths


def _port_rows_for_report(report_path: Path) -> list[dict[str, Any]]:
    report = _read_json(report_path)
    run_dir = report_path.parents[1]
    manifest = _read_json(run_dir / "run_manifest.json")
    target = manifest.get("target") if isinstance(manifest.get("target"), Mapping) else {}
    operator = manifest.get("operator") if isinstance(manifest.get("operator"), Mapping) else {}
    package = _norm_text(report.get("package_name") or target.get("package_name")).lower()
    app_label = _norm_text(report.get("app_label") or target.get("display_name") or target.get("app_label") or package)
    run_id = _norm_text(manifest.get("dynamic_run_id") or run_dir.name)
    run_profile = _norm_text(operator.get("run_profile"))
    flow_summary = report.get("flow_summary") if isinstance(report.get("flow_summary"), Mapping) else {}
    rows: list[dict[str, Any]] = []
    for flow in flow_summary.get("top_flows") or []:
        if not isinstance(flow, Mapping):
            continue
        protocol = _norm_text(flow.get("protocol")).lower()
        remote_host, remote_port = _remote_endpoint(flow)
        port_class, port_role, notable = _classify_port(protocol, remote_port)
        standard_name, standard_description, standard_source = _standard_service_for_port(protocol, remote_port)
        rows.append(
            {
                "run_id": run_id,
                "package": package,
                "app_label": app_label,
                "run_profile": run_profile,
                "protocol": protocol,
                "remote_host": remote_host,
                "remote_host_scope": _remote_host_scope(remote_host),
                "remote_port": remote_port if remote_port is not None else "",
                "iana_port_range": _iana_port_range(remote_port),
                "standard_service_name": standard_name,
                "standard_service_description": standard_description,
                "standard_service_source": standard_source,
                "port_class": port_class,
                "port_role": port_role,
                "notable_port": notable,
                "bytes": int(flow.get("bytes") or 0),
                "packets": int(flow.get("packets") or 0),
                "directionality": _norm_text(flow.get("directionality")),
                "endpoint_a": _norm_text(flow.get("endpoint_a")),
                "endpoint_b": _norm_text(flow.get("endpoint_b")),
            }
        )
    return rows


def _package_summary_rows(run_port_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for row in run_port_rows:
        package = str(row["package"])
        slot = grouped.setdefault(
            package,
            {
                "package": package,
                "app_label": row.get("app_label"),
                "run_ids": set(),
                "ports": set(),
                "port_classes": Counter(),
                "iana_port_ranges": Counter(),
                "standard_services": set(),
                "protocols": set(),
                "bytes_by_class": Counter(),
                "notable_rows": 0,
                "total_top_flow_bytes": 0,
                "total_top_flow_packets": 0,
            },
        )
        slot["run_ids"].add(row.get("run_id"))
        if row.get("remote_port") != "":
            slot["ports"].add(f"{row.get('protocol')}/{row.get('remote_port')}")
        slot["port_classes"][row.get("port_class")] += 1
        slot["iana_port_ranges"][row.get("iana_port_range")] += 1
        if row.get("standard_service_name"):
            slot["standard_services"].add(
                f"{row.get('protocol')}/{row.get('remote_port')}={row.get('standard_service_name')}"
            )
        slot["protocols"].add(row.get("protocol"))
        slot["bytes_by_class"][row.get("port_class")] += int(row.get("bytes") or 0)
        slot["notable_rows"] += int(row.get("notable_port") or 0)
        slot["total_top_flow_bytes"] += int(row.get("bytes") or 0)
        slot["total_top_flow_packets"] += int(row.get("packets") or 0)
    out: list[dict[str, Any]] = []
    for slot in grouped.values():
        out.append(
            {
                "package": slot["package"],
                "app_label": slot["app_label"],
                "run_count": len(slot["run_ids"]),
                "distinct_protocol_port_count": len(slot["ports"]),
                "protocol_ports": ", ".join(sorted(slot["ports"])),
                "protocols": ", ".join(sorted(str(item) for item in slot["protocols"] if item)),
                "port_class_counts": json.dumps(dict(sorted(slot["port_classes"].items())), sort_keys=True),
                "iana_port_range_counts": json.dumps(dict(sorted(slot["iana_port_ranges"].items())), sort_keys=True),
                "standard_services": ", ".join(sorted(slot["standard_services"])),
                "bytes_by_port_class": json.dumps(dict(sorted(slot["bytes_by_class"].items())), sort_keys=True),
                "notable_top_flow_rows": slot["notable_rows"],
                "total_top_flow_bytes": slot["total_top_flow_bytes"],
                "total_top_flow_packets": slot["total_top_flow_packets"],
            }
        )
    out.sort(key=lambda item: (-int(item["notable_top_flow_rows"]), str(item["package"])))
    return out


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _paper_transport_statement(*, app_label: str, flags: set[str], peer_private_bytes: int) -> tuple[str, str]:
    parts: list[str] = []
    caveats: list[str] = []
    if "https_tls" in flags:
        parts.append("TLS/HTTPS top-flow traffic")
    if "quic_or_udp_443" in flags:
        parts.append("UDP/443 traffic consistent with QUIC or UDP-based encrypted transport")
        caveats.append("UDP/443 is a candidate signal, not proof of HTTP/3 without protocol corroboration")
    if "stun_turn_rtc" in flags:
        parts.append("STUN/TURN-style NAT traversal traffic")
        caveats.append("STUN/TURN indicates relay/NAT traversal context, not call semantics by itself")
    if "xmpp_or_messaging" in flags:
        parts.append("XMPP/client-messaging transport")
    if "remote_ephemeral_or_peer_port" in flags:
        parts.append("private dynamic UDP peer transport")
        caveats.append("dynamic/private UDP ports are interpreted as peer/local-network transport only with endpoint context")
    if "well_known_standard_other" in flags or "registered_standard_other" in flags:
        parts.append("additional named standard ports requiring app-specific interpretation")
        caveats.append("standard port names do not establish application-layer semantics by themselves")
    if not parts:
        return f"{app_label} had no notable top-flow port classes in this audit.", ""
    statement = f"{app_label} top flows included " + "; ".join(parts) + "."
    if peer_private_bytes:
        caveats.append(f"private peer UDP accounted for {peer_private_bytes} top-flow bytes")
    return statement, "; ".join(dict.fromkeys(caveats))


def _publication_transport_summary_rows(package_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in package_rows:
        try:
            class_counts = json.loads(str(row.get("port_class_counts") or "{}"))
        except json.JSONDecodeError:
            class_counts = {}
        try:
            bytes_by_class = json.loads(str(row.get("bytes_by_port_class") or "{}"))
        except json.JSONDecodeError:
            bytes_by_class = {}
        flags = {str(key) for key, value in class_counts.items() if int(value or 0) > 0}
        app_label = str(row.get("app_label") or row.get("package") or "")
        peer_private_bytes = int(bytes_by_class.get("remote_ephemeral_or_peer_port") or 0)
        statement, caveat = _paper_transport_statement(
            app_label=app_label,
            flags=flags,
            peer_private_bytes=peer_private_bytes,
        )
        out.append(
            {
                "package": row.get("package"),
                "app_label": app_label,
                "run_count": row.get("run_count"),
                "protocol_ports": row.get("protocol_ports"),
                "standard_services": row.get("standard_services"),
                "has_tls_https": _yes_no("https_tls" in flags),
                "has_udp443_quic_candidate": _yes_no("quic_or_udp_443" in flags),
                "has_stun_turn_candidate": _yes_no("stun_turn_rtc" in flags or "turn_tls" in flags or "google_stun" in flags),
                "has_xmpp_or_messaging_port": _yes_no("xmpp_or_messaging" in flags),
                "has_private_peer_udp": _yes_no("remote_ephemeral_or_peer_port" in flags),
                "has_other_standard_ports": _yes_no(
                    "well_known_standard_other" in flags or "registered_standard_other" in flags
                ),
                "notable_top_flow_rows": row.get("notable_top_flow_rows"),
                "total_top_flow_bytes": row.get("total_top_flow_bytes"),
                "transport_statement": statement,
                "required_caveat": caveat,
            }
        )
    out.sort(key=lambda item: str(item["app_label"]).lower())
    return out


def _port_catalog_rows(run_port_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for row in run_port_rows:
        if row.get("remote_port") == "":
            continue
        key = (str(row.get("protocol") or ""), str(row.get("remote_port") or ""))
        slot = grouped.setdefault(
            key,
            {
                "protocol": key[0],
                "remote_port": key[1],
                "iana_port_range": row.get("iana_port_range"),
                "standard_service_name": row.get("standard_service_name"),
                "standard_service_description": row.get("standard_service_description"),
                "standard_service_source": row.get("standard_service_source"),
                "port_class": row.get("port_class"),
                "port_role": row.get("port_role"),
                "packages": set(),
                "run_ids": set(),
                "remote_host_scopes": Counter(),
                "row_count": 0,
                "total_top_flow_bytes": 0,
                "total_top_flow_packets": 0,
            },
        )
        slot["packages"].add(row.get("package"))
        slot["run_ids"].add(row.get("run_id"))
        slot["remote_host_scopes"][row.get("remote_host_scope")] += 1
        slot["row_count"] += 1
        slot["total_top_flow_bytes"] += int(row.get("bytes") or 0)
        slot["total_top_flow_packets"] += int(row.get("packets") or 0)

    out: list[dict[str, Any]] = []
    for slot in grouped.values():
        out.append(
            {
                "protocol": slot["protocol"],
                "remote_port": slot["remote_port"],
                "iana_port_range": slot["iana_port_range"],
                "standard_service_name": slot["standard_service_name"],
                "standard_service_description": slot["standard_service_description"],
                "standard_service_source": slot["standard_service_source"],
                "port_class": slot["port_class"],
                "port_role": slot["port_role"],
                "package_count": len(slot["packages"]),
                "packages": ", ".join(sorted(str(item) for item in slot["packages"] if item)),
                "run_count": len(slot["run_ids"]),
                "remote_host_scope_counts": json.dumps(dict(sorted(slot["remote_host_scopes"].items())), sort_keys=True),
                "row_count": slot["row_count"],
                "total_top_flow_bytes": slot["total_top_flow_bytes"],
                "total_top_flow_packets": slot["total_top_flow_packets"],
            }
        )
    out.sort(key=lambda item: (-int(item["total_top_flow_bytes"]), str(item["protocol"]), int(item["remote_port"])))
    return out


def generate_report(
    *,
    dynamic_root: Path | None = None,
    packages: list[str] | None = None,
    publication_manifest: Path | None = None,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    dynamic_root = dynamic_root or _dynamic_root_from_config()
    package_filters = {str(item or "").strip().lower() for item in (packages or []) if str(item or "").strip()}
    report_paths = _iter_report_paths(dynamic_root, package_filters)
    run_port_rows: list[dict[str, Any]] = []
    for path in report_paths:
        run_port_rows.extend(_port_rows_for_report(path))
    manifest_paths = (publication_manifest,) if publication_manifest else DEFAULT_LABEL_MAP_CANDIDATES
    publication_labels = _load_publication_manifest_labels(tuple(path for path in manifest_paths if path))
    publication_packages = set(publication_labels)
    label_override_count = _apply_label_overrides(run_port_rows, publication_labels)
    package_rows = _package_summary_rows(run_port_rows)
    port_catalog_rows = _port_catalog_rows(run_port_rows)
    publication_package_rows = [
        row for row in package_rows if not publication_packages or str(row.get("package") or "").lower() in publication_packages
    ]
    publication_rows = _publication_transport_summary_rows(publication_package_rows)
    publication_excluded_packages = sorted(
        str(row.get("package") or "")
        for row in package_rows
        if publication_packages and str(row.get("package") or "").lower() not in publication_packages
    )
    unusual_rows = [
        row
        for row in run_port_rows
        if row.get("notable_port") and row.get("port_class") not in {"https_tls", "quic_or_udp_443"}
    ]
    unmapped_rows = [row for row in run_port_rows if row.get("remote_port") != "" and not row.get("standard_service_name")]
    port_class_counts = Counter(str(row.get("port_class") or "") for row in run_port_rows)
    iana_port_range_counts = Counter(str(row.get("iana_port_range") or "") for row in run_port_rows)
    remote_host_scope_counts = Counter(str(row.get("remote_host_scope") or "") for row in run_port_rows)
    standard_service_counts = Counter(
        f"{row.get('protocol')}/{row.get('remote_port')}={row.get('standard_service_name')}"
        for row in run_port_rows
        if row.get("remote_port") != "" and row.get("standard_service_name")
    )
    protocol_port_counts = Counter(
        f"{row.get('protocol')}/{row.get('remote_port')}"
        for row in run_port_rows
        if row.get("remote_port") != ""
    )
    unmapped_protocol_port_counts = Counter(
        f"{row.get('protocol')}/{row.get('remote_port')}"
        for row in unmapped_rows
    )

    if output_dir is None:
        output_dir = _REPO_ROOT / "output" / "audit" / "dynamic_port_context" / datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "dynamic_root": str(dynamic_root.resolve()),
        "packages_filter": sorted(package_filters),
        "pcap_report_count": len(report_paths),
        "top_flow_port_rows": len(run_port_rows),
        "package_count": len(package_rows),
        "publication_transport_summary_rows": len(publication_rows),
        "publication_manifest_package_count": len(publication_packages),
        "publication_transport_excluded_package_count": len(publication_excluded_packages),
        "publication_transport_excluded_packages": publication_excluded_packages,
        "publication_manifest": str(publication_manifest.resolve()) if publication_manifest else "default_candidates",
        "label_override_rows": label_override_count,
        "distinct_protocol_port_count": len(port_catalog_rows),
        "notable_port_rows": len(unusual_rows),
        "port_class_counts": dict(sorted(port_class_counts.items())),
        "iana_port_range_counts": dict(sorted(iana_port_range_counts.items())),
        "remote_host_scope_counts": dict(sorted(remote_host_scope_counts.items())),
        "standard_service_mapped_rows": sum(standard_service_counts.values()),
        "standard_service_unmapped_rows": len(unmapped_rows),
        "top_standard_services": dict(standard_service_counts.most_common(20)),
        "top_protocol_ports": dict(protocol_port_counts.most_common(20)),
        "unmapped_protocol_ports": dict(unmapped_protocol_port_counts.most_common(20)),
        "assumptions": [
            "Port evidence is derived from pcap_report.json flow_summary.top_flows, not every packet flow.",
            "Port range labels follow IANA convention: well-known 0-1023, registered 1024-49151, dynamic/private 49152-65535.",
            "Standard service names are local context from a curated common-port map and /etc/services when available.",
            "Private/dynamic remote ports are not treated as missing standard mappings when they appear to be peer or local-network transports.",
            "UDP/443 is labeled as QUIC or UDP-443 candidate, not proof of HTTP/3 without protocol corroboration.",
            "STUN/TURN port classes indicate NAT traversal or relay context; application semantics require app/run context.",
            "No DB writes or evidence mutations were performed.",
        ],
        "output_files": {
            "summary_json": str((output_dir / "summary.json").resolve()),
            "run_ports_csv": str((output_dir / "run_ports.csv").resolve()),
            "port_catalog_csv": str((output_dir / "port_catalog.csv").resolve()),
            "package_port_summary_csv": str((output_dir / "package_port_summary.csv").resolve()),
            "publication_transport_summary_csv": str((output_dir / "publication_transport_summary.csv").resolve()),
            "publication_transport_summary_md": str((output_dir / "publication_transport_summary.md").resolve()),
            "notable_ports_csv": str((output_dir / "notable_ports.csv").resolve()),
            "unmapped_ports_csv": str((output_dir / "unmapped_ports.csv").resolve()),
        },
        "no_db_writes": True,
        "experimental_audit": True,
    }
    _write_json(output_dir / "summary.json", summary)
    _write_csv(output_dir / "run_ports.csv", sorted(run_port_rows, key=lambda item: (str(item["package"]), str(item["run_id"]), str(item["protocol"]), int(item["remote_port"] or 0))))
    _write_csv(output_dir / "port_catalog.csv", port_catalog_rows)
    _write_csv(output_dir / "package_port_summary.csv", package_rows)
    _write_csv(output_dir / "publication_transport_summary.csv", publication_rows)
    _write_markdown_table(
        output_dir / "publication_transport_summary.md",
        publication_rows,
        [
            "app_label",
            "has_tls_https",
            "has_udp443_quic_candidate",
            "has_stun_turn_candidate",
            "has_xmpp_or_messaging_port",
            "has_private_peer_udp",
            "has_other_standard_ports",
            "transport_statement",
            "required_caveat",
        ],
    )
    _write_csv(output_dir / "notable_ports.csv", sorted(unusual_rows, key=lambda item: (-int(item["bytes"] or 0), str(item["package"]))))
    _write_csv(output_dir / "unmapped_ports.csv", sorted(unmapped_rows, key=lambda item: (str(item["package"]), str(item["run_id"]), str(item["protocol"]), int(item["remote_port"] or 0))))
    return summary


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    dynamic_root = Path(args.dynamic_root) if args.dynamic_root else None
    publication_manifest = Path(args.publication_manifest) if args.publication_manifest else None
    output_dir = Path(args.output_dir) if args.output_dir else None
    summary = generate_report(
        dynamic_root=dynamic_root,
        packages=args.package,
        publication_manifest=publication_manifest,
        output_dir=output_dir,
    )
    print("# dynamic port context")
    print(f"pcap_report_count: {summary['pcap_report_count']}")
    print(f"top_flow_port_rows: {summary['top_flow_port_rows']}")
    print(f"package_count: {summary['package_count']}")
    print(f"publication_transport_summary_rows: {summary['publication_transport_summary_rows']}")
    print(f"publication_transport_excluded_package_count: {summary['publication_transport_excluded_package_count']}")
    print(f"label_override_rows: {summary['label_override_rows']}")
    print(f"notable_port_rows: {summary['notable_port_rows']}")
    print(f"distinct_protocol_port_count: {summary['distinct_protocol_port_count']}")
    print(f"port_class_counts: {json.dumps(summary['port_class_counts'], sort_keys=True)}")
    print(f"iana_port_range_counts: {json.dumps(summary['iana_port_range_counts'], sort_keys=True)}")
    print(f"remote_host_scope_counts: {json.dumps(summary['remote_host_scope_counts'], sort_keys=True)}")
    print(f"standard_service_mapped_rows: {summary['standard_service_mapped_rows']}")
    print(f"standard_service_unmapped_rows: {summary['standard_service_unmapped_rows']}")
    print(f"output_dir: {Path(summary['output_files']['summary_json']).parent}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
