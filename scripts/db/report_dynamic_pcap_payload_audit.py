#!/usr/bin/env python3
"""Read-only, privacy-preserving payload-surface audit for dynamic PCAPs.

This inspects protocol and cleartext metadata without exporting packet bodies,
cookies, authorization headers, message text, form values, or raw payload bytes.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

RUN_FIELDS = (
    "run_id",
    "package",
    "app_label",
    "run_profile",
    "valid_dataset_run",
    "pcap_path",
    "pcap_bytes",
    "capinfos_packets",
    "capinfos_duration_s",
    "tshark_status",
    "protocols_observed",
    "dns_frames",
    "tls_frames",
    "quic_frames",
    "http_frames",
    "http2_frames",
    "plaintext_protocol_frames",
    "http_request_rows",
    "http_response_rows",
    "http_host_count",
    "http_method_count",
    "sanitized_http_path_count",
    "payload_visibility_class",
    "payload_risk_flags",
    "static_uses_cleartext_traffic",
    "cleartext_mismatch_class",
    "plaintext_protocols_observed",
    "decoded_protocols_observed",
    "decoded_stream_count",
)

HTTP_FIELDS = (
    "run_id",
    "package",
    "app_label",
    "host",
    "method",
    "response_code",
    "sanitized_path",
    "path_class",
    "rows",
)

PROTOCOL_FIELDS = (
    "run_id",
    "package",
    "app_label",
    "protocol",
    "frames",
    "bytes",
    "visibility",
)

DECODED_CLEARTEXT_FIELDS = (
    "run_id",
    "package",
    "app_label",
    "protocol",
    "transport",
    "src_port",
    "dst_port",
    "tcp_stream",
    "frames",
    "bytes_total",
    "bytes_min",
    "bytes_max",
)

APP_ROLLUP_FIELDS = (
    "package",
    "app_label",
    "runs_scanned",
    "valid_dataset_runs",
    "pcap_bytes_total",
    "encrypted_or_opaque_runs",
    "cleartext_surface_runs",
    "http_observed_runs",
    "http_hosts_total",
    "http_request_rows",
    "http_response_rows",
    "dns_frames_total",
    "tls_frames_total",
    "quic_frames_total",
    "plaintext_protocol_frames_total",
    "plaintext_protocols_observed",
    "decoded_cleartext_streams",
    "top_protocols",
    "static_cleartext_allowed_runs",
    "cleartext_mismatch_denied_observed_runs",
    "cleartext_mismatch_allowed_not_observed_runs",
)

PLAINTEXT_PROTOCOLS = {
    "http",
    "ftp",
    "ftp-data",
    "smtp",
    "imap",
    "pop",
    "irc",
    "telnet",
    "xmpp",
}

OPAQUE_OR_ENCRYPTED_PROTOCOLS = {
    "tls",
    "ssl",
    "quic",
    "http2",
}

_PHS_RE = re.compile(r"^\s*(?P<name>[A-Za-z0-9_.-]+)\s+frames:(?P<frames>\d+)\s+bytes:(?P<bytes>\d+)")
_LONG_OR_TOKENISH_RE = re.compile(r"([A-Za-z0-9_-]{16,}|[0-9a-fA-F]{12,}|\d{5,})")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=None, help="Optional explicit output directory.")
    parser.add_argument("--package", action="append", default=[], help="Restrict to package name; may be repeated.")
    parser.add_argument("--run-id", action="append", default=[], help="Restrict to dynamic run id; may be repeated.")
    parser.add_argument("--timeout", type=int, default=90, help="Per-tshark command timeout in seconds.")
    parser.add_argument(
        "--max-http-rows",
        type=int,
        default=2000,
        help="Maximum sanitized HTTP metadata rows retained per run.",
    )
    parser.add_argument("--stdout-json", action="store_true", help="Print summary JSON after writing files.")
    return parser


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value in (None, ""):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _cleartext_posture_run_fields(run_dir: Path, report: dict[str, Any] | None) -> dict[str, Any]:
    overlap = _read_json(run_dir / "analysis" / "static_dynamic_overlap.json")
    posture: dict[str, Any] = {}
    if isinstance(overlap, dict) and isinstance(overlap.get("cleartext_posture"), dict):
        posture = overlap["cleartext_posture"]
    else:
        plan = _read_json(run_dir / "inputs" / "static_dynamic_plan.json")
        if isinstance(plan, dict):
            from scytaledroid.DynamicAnalysis.pcap.security_surface import (
                compute_static_dynamic_cleartext_posture,
            )

            posture = compute_static_dynamic_cleartext_posture(plan, report or {})
    static_allowed = posture.get("static_cleartext_allowed")
    return {
        "static_uses_cleartext_traffic": int(bool(static_allowed)) if static_allowed is not None else "",
        "cleartext_mismatch_class": str(posture.get("mismatch_class") or ""),
    }


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]], *, fieldnames: Sequence[str]) -> None:
    resolved = [str(item) for item in fieldnames]
    for row in rows:
        for key in row:
            if key not in resolved:
                resolved.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=resolved)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in resolved})


def _dynamic_root() -> Path:
    from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root

    return dynamic_evidence_root()


def _default_output_dir() -> Path:
    from scytaledroid.Config import app_config

    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")
    return Path(app_config.OUTPUT_DIR) / "audit" / "dynamic_pcap_payload_audit" / stamp


def _run_cmd(args: Sequence[str], *, timeout: int) -> tuple[int, str, str]:
    proc = subprocess.run(
        list(args),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _run_cmd_timeout(args: Sequence[str], *, timeout: int) -> tuple[int, str, str]:
    try:
        return _run_cmd(args, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return 124, stdout, stderr or f"timeout after {timeout}s"


def _display_name_map(packages: Iterable[str]) -> dict[str, str]:
    normalized = sorted({_norm_text(package).lower() for package in packages if _norm_text(package)})
    if not normalized:
        return {}
    try:
        from scytaledroid.Database.db_func.apps.app_labels import fetch_display_name_map

        labels = fetch_display_name_map(normalized)
    except Exception:
        return {}
    return {
        _norm_text(package).lower(): _norm_text(label)
        for package, label in (labels or {}).items()
        if _norm_text(package) and _norm_text(label)
    }


def _iter_runs(packages: Sequence[str], run_ids: Sequence[str]) -> Iterable[dict[str, Any]]:
    package_filter = {_norm_text(value).lower() for value in packages if _norm_text(value)}
    run_filter = {_norm_text(value) for value in run_ids if _norm_text(value)}
    candidates: list[dict[str, Any]] = []
    for manifest_path in sorted(_dynamic_root().glob("*/run_manifest.json")):
        run_dir = manifest_path.parent
        manifest = _read_json(manifest_path) or {}
        run_id = _norm_text(manifest.get("dynamic_run_id") or run_dir.name)
        target = manifest.get("target") if isinstance(manifest.get("target"), Mapping) else {}
        operator = manifest.get("operator") if isinstance(manifest.get("operator"), Mapping) else {}
        dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), Mapping) else {}
        package = _norm_text(target.get("package_name")).lower()
        if package_filter and package not in package_filter:
            continue
        if run_filter and run_id not in run_filter:
            continue
        pcap_path = _find_pcap(run_dir, manifest)
        if pcap_path is None:
            continue
        candidates.append(
            {
                "run_id": run_id,
                "run_dir": run_dir,
                "package": package or "_unknown",
                "manifest_app_label": _norm_text(target.get("display_name") or target.get("app_label")),
                "run_profile": _norm_text(operator.get("run_profile") or dataset.get("run_profile")),
                "valid_dataset_run": int(bool(dataset.get("valid_dataset_run") is True)),
                "pcap_path": pcap_path,
            }
        )
    display_names = _display_name_map(row["package"] for row in candidates)
    for row in candidates:
        package = _norm_text(row.get("package")).lower()
        row["app_label"] = _norm_text(row.pop("manifest_app_label", "")) or display_names.get(package) or package
        yield row


def _find_pcap(run_dir: Path, manifest: Mapping[str, Any]) -> Path | None:
    for artifact in manifest.get("artifacts") or []:
        if not isinstance(artifact, Mapping):
            continue
        if artifact.get("type") != "pcapdroid_capture":
            continue
        rel = _norm_text(artifact.get("relative_path"))
        if rel:
            candidate = run_dir / rel
            if candidate.is_file():
                return candidate
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    for candidate in sorted(capture_dir.glob("*.pcap*")):
        if candidate.is_file() and candidate.suffix.lower() in {".pcap", ".pcapng"}:
            return candidate
    return None


def _capinfos(path: Path, *, timeout: int) -> dict[str, Any]:
    rc, stdout, stderr = _run_cmd_timeout(["capinfos", "-M", "-c", "-u", "-s", str(path)], timeout=timeout)
    out: dict[str, Any] = {"capinfos_status": "ok" if rc == 0 else "failed", "capinfos_error": stderr.strip()[:240]}
    for line in stdout.splitlines():
        if ":" not in line:
            continue
        key, value = [item.strip() for item in line.split(":", 1)]
        key_lc = key.lower()
        if key_lc == "number of packets":
            out["packets"] = _safe_int(value.split()[0])
        elif key_lc == "capture duration":
            out["duration_s"] = _safe_float(value.split()[0])
    return out


def _protocol_hierarchy(path: Path, *, timeout: int) -> tuple[str, list[dict[str, Any]]]:
    rc, stdout, stderr = _run_cmd_timeout(["tshark", "-r", str(path), "-q", "-z", "io,phs"], timeout=timeout)
    if rc != 0:
        return f"failed: {stderr.strip()[:180]}", []
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
    return "ok", rows


def _protocol_frame_counts(rows: Sequence[Mapping[str, Any]]) -> Counter[str]:
    """Collapse nested protocol-hierarchy rows without double-counting same-name dissectors."""
    counts: Counter[str] = Counter()
    for row in rows:
        protocol = str(row.get("protocol") or "").strip().lower()
        if not protocol:
            continue
        counts[protocol] = max(counts[protocol], _safe_int(row.get("frames")))
    return counts


def _sanitize_http_path(value: Any) -> tuple[str, str]:
    text = _norm_text(value)
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


def _http_rows(path: Path, run: Mapping[str, Any], *, timeout: int, max_rows: int) -> tuple[str, list[dict[str, Any]]]:
    fields = [
        "tshark",
        "-r",
        str(path),
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
    rc, stdout, stderr = _run_cmd_timeout(fields, timeout=timeout)
    if rc != 0:
        return f"failed: {stderr.strip()[:180]}", []
    aggregate: Counter[tuple[str, str, str, str, str]] = Counter()
    retained = 0
    for line in stdout.splitlines():
        if retained >= max_rows:
            break
        host, method, uri, response = (line.split("\t") + ["", "", "", ""])[:4]
        sanitized, path_class = _sanitize_http_path(uri)
        key = (
            _norm_text(host).lower(),
            _norm_text(method).upper(),
            _norm_text(response),
            sanitized,
            path_class,
        )
        aggregate[key] += 1
        retained += 1
    rows = [
        {
            "run_id": run["run_id"],
            "package": run["package"],
            "app_label": run["app_label"],
            "host": host,
            "method": method,
            "response_code": response,
            "sanitized_path": path,
            "path_class": path_class,
            "rows": count,
        }
        for (host, method, response, path, path_class), count in sorted(aggregate.items())
    ]
    return "ok", rows


def _decoded_cleartext_rows(
    path: Path,
    run: Mapping[str, Any],
    protocol_rows_raw: Sequence[Mapping[str, Any]],
    *,
    timeout: int,
) -> list[dict[str, Any]]:
    protocols = sorted(
        {
            str(row.get("protocol") or "").strip().lower()
            for row in protocol_rows_raw
            if str(row.get("protocol") or "").strip().lower() in PLAINTEXT_PROTOCOLS
        }
    )
    if not protocols:
        return []
    display_filter = " || ".join(protocols)
    cmd = [
        "tshark",
        "-r",
        str(path),
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
    rc, stdout, _stderr = _run_cmd_timeout(cmd, timeout=timeout)
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
        src_port = _norm_text(tcp_src or udp_src)
        dst_port = _norm_text(tcp_dst or udp_dst)
        size = _safe_int(frame_len)
        for protocol in matched_protocols:
            key = (protocol, transport, src_port, dst_port, _norm_text(tcp_stream))
            slot = aggregate.setdefault(
                key,
                {
                    "run_id": run["run_id"],
                    "package": run["package"],
                    "app_label": run["app_label"],
                    "protocol": protocol,
                    "transport": transport,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "tcp_stream": _norm_text(tcp_stream),
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
    return sorted(
        aggregate.values(),
        key=lambda row: (row["protocol"], row["transport"], row["src_port"], row["dst_port"], row["tcp_stream"]),
    )


def _visibility_for_protocol(protocol: str) -> str:
    if protocol in PLAINTEXT_PROTOCOLS:
        return "cleartext_protocol_decoded"
    if protocol in OPAQUE_OR_ENCRYPTED_PROTOCOLS:
        return "encrypted_or_opaque"
    if protocol == "dns":
        return "cleartext_name_metadata"
    return "transport_or_other"


def _decoded_stream_key(row: Mapping[str, Any]) -> str:
    protocol = str(row.get("protocol") or "")
    transport = str(row.get("transport") or "")
    tcp_stream = str(row.get("tcp_stream") or "")
    if tcp_stream:
        return ":".join([protocol, transport, tcp_stream])
    ports = sorted([str(row.get("src_port") or ""), str(row.get("dst_port") or "")])
    return ":".join([protocol, transport, ports[0], ports[1]])


def _run_payload_audit(
    run: Mapping[str, Any],
    *,
    timeout: int,
    max_http_rows: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    run_dir = run.get("run_dir")
    if isinstance(run_dir, Path):
        surface = _read_json(run_dir / "analysis" / "security_surface.json")
        report = _read_json(run_dir / "analysis" / "pcap_report.json")
        if isinstance(surface, dict) and surface.get("status") == "ok":
            from scytaledroid.DynamicAnalysis.pcap.security_surface import export_payload_audit_rows

            run_row, http_rows, protocol_rows, decoded_rows = export_payload_audit_rows(
                run_id=str(run["run_id"]),
                package=str(run["package"]),
                app_label=str(run["app_label"]),
                run_profile=str(run["run_profile"]),
                valid_dataset_run=int(run["valid_dataset_run"]),
                pcap_path=Path(run["pcap_path"]),
                surface=surface,
                report=report if isinstance(report, dict) else None,
            )
            run_row.update(_cleartext_posture_run_fields(run_dir, report if isinstance(report, dict) else {}))
            return run_row, http_rows, protocol_rows, decoded_rows

    pcap_path = Path(run["pcap_path"])
    cap = _capinfos(pcap_path, timeout=timeout)
    tshark_status, protocol_rows_raw = _protocol_hierarchy(pcap_path, timeout=timeout)
    protocol_rows = [
        {
            "run_id": run["run_id"],
            "package": run["package"],
            "app_label": run["app_label"],
            "protocol": row["protocol"],
            "frames": row["frames"],
            "bytes": row["bytes"],
            "visibility": _visibility_for_protocol(str(row["protocol"])),
        }
        for row in protocol_rows_raw
    ]
    by_protocol = _protocol_frame_counts(protocol_rows_raw)
    http_status, http_rows = _http_rows(pcap_path, run, timeout=timeout, max_rows=max_http_rows)
    decoded_rows = _decoded_cleartext_rows(pcap_path, run, protocol_rows_raw, timeout=timeout)
    http_request_rows = sum(_safe_int(row.get("rows")) for row in http_rows if row.get("method"))
    http_response_rows = sum(_safe_int(row.get("rows")) for row in http_rows if row.get("response_code"))
    plaintext_frames = sum(by_protocol.get(protocol, 0) for protocol in PLAINTEXT_PROTOCOLS)
    risk_flags: list[str] = []
    if plaintext_frames:
        risk_flags.append("decoded_cleartext_application_protocol_observed")
    if http_rows:
        risk_flags.append("http_metadata_observed")
    if http_status != "ok":
        risk_flags.append("http_probe_failed")
    if tshark_status != "ok":
        risk_flags.append("protocol_probe_failed")
    encrypted_frames = sum(by_protocol.get(protocol, 0) for protocol in OPAQUE_OR_ENCRYPTED_PROTOCOLS)
    if encrypted_frames and not plaintext_frames:
        visibility = "encrypted_or_opaque_dominant"
    elif plaintext_frames:
        visibility = "cleartext_surface_present"
    elif by_protocol.get("dns", 0):
        visibility = "name_metadata_only"
    else:
        visibility = "transport_only_or_unknown"
    run_row = {
        "run_id": run["run_id"],
        "package": run["package"],
        "app_label": run["app_label"],
        "run_profile": run["run_profile"],
        "valid_dataset_run": run["valid_dataset_run"],
        "pcap_path": str(pcap_path),
        "pcap_bytes": pcap_path.stat().st_size,
        "capinfos_packets": _safe_int(cap.get("packets")),
        "capinfos_duration_s": cap.get("duration_s", 0),
        "tshark_status": tshark_status if tshark_status != "ok" else http_status,
        "protocols_observed": ";".join(sorted({str(row["protocol"]) for row in protocol_rows_raw})),
        "dns_frames": by_protocol.get("dns", 0),
        "tls_frames": by_protocol.get("tls", 0) + by_protocol.get("ssl", 0),
        "quic_frames": by_protocol.get("quic", 0),
        "http_frames": by_protocol.get("http", 0),
        "http2_frames": by_protocol.get("http2", 0),
        "plaintext_protocol_frames": plaintext_frames,
        "http_request_rows": http_request_rows,
        "http_response_rows": http_response_rows,
        "http_host_count": len({row["host"] for row in http_rows if row.get("host")}),
        "http_method_count": len({row["method"] for row in http_rows if row.get("method")}),
        "sanitized_http_path_count": len({row["sanitized_path"] for row in http_rows if row.get("sanitized_path")}),
        "payload_visibility_class": visibility,
        "payload_risk_flags": ";".join(risk_flags),
    }
    if isinstance(run_dir, Path):
        run_row.update(_cleartext_posture_run_fields(run_dir, None))
    return run_row, http_rows, protocol_rows, decoded_rows


def _app_rollup_rows(
    run_rows: Sequence[Mapping[str, Any]],
    protocol_rows: Sequence[Mapping[str, Any]],
    decoded_rows: Sequence[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    protocol_grouped: dict[str, Counter[str]] = defaultdict(Counter)
    plaintext_protocols: dict[str, set[str]] = defaultdict(set)
    decoded_streams: dict[str, set[str]] = defaultdict(set)
    for row in run_rows:
        grouped[str(row["package"])].append(row)
    per_run_protocol_rows: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in protocol_rows:
        per_run_protocol_rows[(str(row["package"]), str(row.get("run_id") or ""))].append(row)
        if row.get("visibility") == "cleartext_protocol_decoded":
            plaintext_protocols[str(row["package"])].add(str(row["protocol"]))
    for (package, _run_id), rows_for_run in per_run_protocol_rows.items():
        protocol_grouped[package].update(_protocol_frame_counts(rows_for_run))
    for row in decoded_rows:
        package = str(row.get("package") or "")
        stream_id = _decoded_stream_key(row)
        if package and stream_id.strip(":"):
            decoded_streams[package].add(stream_id)
    out: list[dict[str, Any]] = []
    for package, rows in sorted(grouped.items()):
        app_label = str(rows[0].get("app_label") or package)
        top_protocols = ";".join(
            f"{protocol}:{count}"
            for protocol, count in protocol_grouped.get(package, Counter()).most_common(8)
        )
        out.append(
            {
                "package": package,
                "app_label": app_label,
                "runs_scanned": len(rows),
                "valid_dataset_runs": sum(_safe_int(row.get("valid_dataset_run")) for row in rows),
                "pcap_bytes_total": sum(_safe_int(row.get("pcap_bytes")) for row in rows),
                "encrypted_or_opaque_runs": sum(
                    1 for row in rows if row.get("payload_visibility_class") == "encrypted_or_opaque_dominant"
                ),
                "cleartext_surface_runs": sum(
                    1 for row in rows if row.get("payload_visibility_class") == "cleartext_surface_present"
                ),
                "http_observed_runs": sum(1 for row in rows if _safe_int(row.get("http_frames")) > 0),
                "http_hosts_total": sum(_safe_int(row.get("http_host_count")) for row in rows),
                "http_request_rows": sum(_safe_int(row.get("http_request_rows")) for row in rows),
                "http_response_rows": sum(_safe_int(row.get("http_response_rows")) for row in rows),
                "dns_frames_total": sum(_safe_int(row.get("dns_frames")) for row in rows),
                "tls_frames_total": sum(_safe_int(row.get("tls_frames")) for row in rows),
                "quic_frames_total": sum(_safe_int(row.get("quic_frames")) for row in rows),
                "plaintext_protocol_frames_total": sum(
                    _safe_int(row.get("plaintext_protocol_frames")) for row in rows
                ),
                "plaintext_protocols_observed": ";".join(sorted(plaintext_protocols.get(package, set()))),
                "decoded_cleartext_streams": len(decoded_streams.get(package, set())),
                "top_protocols": top_protocols,
                "static_cleartext_allowed_runs": sum(
                    1 for row in rows if _safe_int(row.get("static_uses_cleartext_traffic")) == 1
                ),
                "cleartext_mismatch_denied_observed_runs": sum(
                    1 for row in rows if row.get("cleartext_mismatch_class") == "denied_but_observed"
                ),
                "cleartext_mismatch_allowed_not_observed_runs": sum(
                    1
                    for row in rows
                    if str(row.get("cleartext_mismatch_class") or "").startswith("allowed_not_observed")
                ),
            }
        )
    return out


def generate_report(
    *,
    output_dir: Path | None = None,
    packages: Sequence[str] = (),
    run_ids: Sequence[str] = (),
    timeout: int = 90,
    max_http_rows: int = 2000,
) -> dict[str, Any]:
    if output_dir is None:
        output_dir = _default_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    run_rows: list[dict[str, Any]] = []
    http_rows: list[dict[str, Any]] = []
    protocol_rows: list[dict[str, Any]] = []
    decoded_rows: list[dict[str, Any]] = []
    for run in _iter_runs(packages, run_ids):
        run_row, http_part, protocol_part, decoded_part = _run_payload_audit(
            run,
            timeout=timeout,
            max_http_rows=max_http_rows,
        )
        run_rows.append(run_row)
        http_rows.extend(http_part)
        protocol_rows.extend(protocol_part)
        decoded_rows.extend(decoded_part)
    _write_csv(output_dir / "pcap_payload_runs.csv", run_rows, fieldnames=RUN_FIELDS)
    _write_csv(output_dir / "cleartext_http_observations.csv", http_rows, fieldnames=HTTP_FIELDS)
    _write_csv(output_dir / "protocol_visibility_rows.csv", protocol_rows, fieldnames=PROTOCOL_FIELDS)
    _write_csv(
        output_dir / "decoded_cleartext_protocol_events.csv",
        decoded_rows,
        fieldnames=DECODED_CLEARTEXT_FIELDS,
    )
    app_rows = _app_rollup_rows(run_rows, protocol_rows, decoded_rows)
    _write_csv(output_dir / "app_payload_rollup.csv", app_rows, fieldnames=APP_ROLLUP_FIELDS)
    visibility_counts = Counter(str(row["payload_visibility_class"]) for row in run_rows)
    flag_counts = Counter(
        flag
        for row in run_rows
        for flag in str(row.get("payload_risk_flags") or "").split(";")
        if flag
    )
    summary = {
        "report_type": "dynamic_pcap_payload_surface_audit",
        "generated_at": datetime.now(UTC).isoformat(),
        "privacy_model": "No raw payload bytes, message bodies, cookies, authorization headers, query strings, or form values are exported.",
        "known_limitations": [
            "Decoded cleartext protocol rows are tshark dissector signals and should be manually validated before treating them as content exposure.",
            "This audit does not decrypt TLS, QUIC, DTLS, SRTP, or application-layer encryption.",
            "HTTP paths are query-stripped and token-like path segments are parameterized before export.",
        ],
        "dynamic_root": str(_dynamic_root().resolve()),
        "package_filter": sorted({_norm_text(value).lower() for value in packages if _norm_text(value)}),
        "run_id_filter": sorted({_norm_text(value) for value in run_ids if _norm_text(value)}),
        "runs_scanned": len(run_rows),
        "pcap_bytes_total": sum(_safe_int(row.get("pcap_bytes")) for row in run_rows),
        "visibility_counts": dict(sorted(visibility_counts.items())),
        "payload_risk_flag_counts": dict(sorted(flag_counts.items())),
        "http_observation_rows": len(http_rows),
        "decoded_cleartext_protocol_event_rows": len(decoded_rows),
        "app_payload_rollup_rows": len(app_rows),
        "protocol_visibility_rows": len(protocol_rows),
        "output_files": {
            "app_payload_rollup_csv": str((output_dir / "app_payload_rollup.csv").resolve()),
            "pcap_payload_runs_csv": str((output_dir / "pcap_payload_runs.csv").resolve()),
            "cleartext_http_observations_csv": str((output_dir / "cleartext_http_observations.csv").resolve()),
            "decoded_cleartext_protocol_events_csv": str(
                (output_dir / "decoded_cleartext_protocol_events.csv").resolve()
            ),
            "protocol_visibility_rows_csv": str((output_dir / "protocol_visibility_rows.csv").resolve()),
            "summary_json": str((output_dir / "summary.json").resolve()),
        },
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    summary = generate_report(
        output_dir=Path(args.output_dir).resolve() if args.output_dir else None,
        packages=args.package,
        run_ids=args.run_id,
        timeout=int(args.timeout),
        max_http_rows=int(args.max_http_rows),
    )
    if args.stdout_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"summary_json: {summary['output_files']['summary_json']}")
        print(f"runs_scanned: {summary['runs_scanned']}")
        print(f"visibility_counts: {summary['visibility_counts']}")
        print(f"payload_risk_flag_counts: {summary['payload_risk_flag_counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
