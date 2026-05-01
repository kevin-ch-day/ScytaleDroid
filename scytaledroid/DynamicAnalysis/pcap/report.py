"""PCAP post-analysis report for dynamic runs."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.DynamicAnalysis.core.event_logger import RunEventLogger
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest

_CAPINFOS_FIELDS = {
    "Number of packets": "packet_count",
    "File size": "file_size_bytes",
    "Data size": "data_size_bytes",
    "Capture duration": "capture_duration_s",
    "Earliest packet time": "first_packet_time",
    "Latest packet time": "last_packet_time",
    "Data byte rate": "data_byte_rate_bps",
    "Data bit rate": "data_bit_rate_bps",
    "Average packet size": "avg_packet_size_bytes",
    "Average packet rate": "avg_packet_rate_pps",
    "File encapsulation": "encapsulation",
}


@dataclass(frozen=True)
class PcapReportConfig:
    top_n: int = 10


def write_pcap_report(
    manifest: RunManifest,
    run_dir: Path,
    *,
    config: PcapReportConfig | None = None,
    event_logger: RunEventLogger | None = None,
) -> ArtifactRecord | None:
    cfg = config or PcapReportConfig()
    report_path = run_dir / "analysis/pcap_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)

    pcap_artifact = _find_pcap_artifact(manifest)
    pcap_rel = pcap_artifact.relative_path if pcap_artifact else None
    pcap_path = (run_dir / pcap_rel) if pcap_rel else None
    capinfos_path = shutil.which("capinfos")
    tshark_path = shutil.which("tshark")
    missing_tools: list[str] = []
    report_status = "ok"
    if not capinfos_path:
        missing_tools.append("capinfos")
        report_status = "skip"
    if not tshark_path:
        missing_tools.append("tshark")
        if report_status == "ok":
            report_status = "partial"

    reason_codes: list[str] = []
    if not pcap_artifact or not pcap_rel:
        reason_codes.append("pcap_artifact_missing")
        report_status = "skip"
    elif not pcap_path or not pcap_path.exists():
        reason_codes.append("pcap_file_missing")
        report_status = "skip"

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "pcap_path": str(pcap_path.relative_to(run_dir)) if pcap_path else None,
        "pcap_sha256": pcap_artifact.sha256 if pcap_artifact else None,
        "pcap_size_bytes": pcap_artifact.size_bytes if pcap_artifact else None,
        # Convenience summary fields for offline windowing/ML.
        # These duplicate capinfos.parsed values in a stable, easy-to-consume location.
        "packet_count": None,
        "bytes_total": None,
        "capture_duration_s": None,
        # PCAP-relative time anchors (seconds). We treat first_ts as 0.0 and last_ts as capture duration.
        "first_ts": None,
        "last_ts": None,
        "report_status": report_status,
        "missing_tools": missing_tools,
        "reason_codes": reason_codes,
        "no_traffic_observed": 0,
        "capinfos": {"raw": "", "parsed": {}, "error": "skipped"} if report_status == "skip" else _run_capinfos(capinfos_path, pcap_path),  # type: ignore[arg-type]
        "protocol_hierarchy": [],
        # Aggregated protocol hierarchy (tshark output can include duplicates).
        "protocol_hierarchy_agg": {"bytes": {}, "frames": {}, "duplicates": []},
        # Normalized transport ratios derived from the aggregated hierarchy (clamped to [0,1]).
        # These are redundant with pcap_features.json but useful for audit/debug.
        "protocol_ratios": {"tcp_ratio": None, "udp_ratio": None, "tls_ratio": None, "quic_ratio": None},
        "top_sni": [],
        "top_dns": [],
        # Extra counters for network diversity QA (no payload inspection).
        "sni_observation_count": None,
        "sni_unique_count": None,
        "dns_observation_count": None,
        "dns_unique_count": None,
        "top1_sni_share": None,
        "top1_dns_share": None,
    }

    # capinfos-derived "no traffic" flag for interpretability and deterministic QA gating.
    try:
        parsed = (report.get("capinfos") or {}).get("parsed") or {}
        pkt = parsed.get("packet_count")
        if isinstance(pkt, (int, float)):
            report["packet_count"] = int(pkt)
        data_bytes = parsed.get("data_size_bytes") or parsed.get("file_size_bytes")
        if isinstance(data_bytes, (int, float)):
            report["bytes_total"] = int(data_bytes)
        dur = parsed.get("capture_duration_s")
        if isinstance(dur, (int, float)):
            report["capture_duration_s"] = float(dur)
            report["first_ts"] = 0.0
            report["last_ts"] = float(dur)
        pkt = parsed.get("packet_count")
        if isinstance(pkt, (int, float)) and int(pkt) == 0:
            report["no_traffic_observed"] = 1
    except Exception:
        pass

    if report_status != "skip" and tshark_path and pcap_path:
        report["protocol_hierarchy"] = _run_protocol_hierarchy(tshark_path, pcap_path)
        agg = _aggregate_protocol_hierarchy(report["protocol_hierarchy"])
        report["protocol_hierarchy_agg"] = agg["agg"]
        report["protocol_ratios"] = _compute_protocol_ratios(agg["bytes"])
        sni = _run_top_fields_with_stats(
            tshark_path,
            pcap_path,
            "tls.handshake.extensions_server_name",
            cfg.top_n,
        )
        report["top_sni"] = sni.get("items") or []
        report["sni_observation_count"] = sni.get("total_count")
        report["sni_unique_count"] = sni.get("unique_count")
        report["top1_sni_share"] = sni.get("top1_share")

        dns = _run_top_fields_with_stats(
            tshark_path,
            pcap_path,
            "dns.qry.name",
            cfg.top_n,
            display_filter="dns",
        )
        report["top_dns"] = dns.get("items") or []
        report["dns_observation_count"] = dns.get("total_count")
        report["dns_unique_count"] = dns.get("unique_count")
        report["top1_dns_share"] = dns.get("top1_share")
    elif report_status != "skip" and not tshark_path:
        _log(event_logger, "pcap_report_partial", {"reason": "tshark_missing"})

    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return ArtifactRecord(
        relative_path=str(report_path.relative_to(run_dir)),
        type="pcap_report",
        sha256=_sha256(report_path),
        size_bytes=report_path.stat().st_size,
        produced_by="pcap_reporter",
        origin="host",
        pull_status="n/a",
    )


def _find_pcap_artifact(manifest: RunManifest):
    for artifact in manifest.artifacts:
        if artifact.type == "pcapdroid_capture":
            return artifact
    return None


def _run_capinfos(capinfos_path: str, pcap_path: Path) -> dict[str, object]:
    result = _run_command([capinfos_path, "-M", str(pcap_path)])
    payload: dict[str, object] = {
        "raw": result.get("stdout", ""),
        "parsed": {},
        "error": result.get("error"),
    }
    if result.get("stdout"):
        payload["parsed"] = _parse_capinfos(result["stdout"])
    return payload


def _parse_capinfos(text: str) -> dict[str, object]:
    parsed: dict[str, object] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        label, value = [part.strip() for part in line.split(":", 1)]
        key = _CAPINFOS_FIELDS.get(label)
        if not key:
            continue
        parsed[key] = _parse_capinfos_value(key, value)
    return parsed


def _parse_capinfos_value(key: str, value: str) -> object:
    if key == "packet_count":
        return _parse_int(value)
    if key.endswith("_bytes"):
        return _parse_int(value)
    if key.endswith("_bps") or key.endswith("_pps"):
        return _parse_float(value)
    if key.endswith("_s"):
        return _parse_float(value)
    return value


def _run_protocol_hierarchy(tshark_path: str, pcap_path: Path) -> list[dict[str, object]]:
    result = _run_command([tshark_path, "-r", str(pcap_path), "-q", "-z", "io,phs"])
    return _parse_protocol_hierarchy_output(str(result.get("stdout") or ""))


def _parse_protocol_hierarchy_output(stdout: str) -> list[dict[str, object]]:
    if not stdout:
        return []
    rows: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if not line.strip() or line.startswith("=") or line.startswith("Filter"):
            continue
        # Example line:
        #   udp                                frames:8091 bytes:8112162
        match = re.match(r"\s*(\S+)\s+frames:(\d+)\s+bytes:(\d+)", line)
        if not match:
            continue
        rows.append(
            {
                "protocol": match.group(1),
                "frames": int(match.group(2)),
                "bytes": int(match.group(3)),
            }
        )
    return rows


def _aggregate_protocol_hierarchy(rows: list[dict[str, object]]) -> dict[str, object]:
    bytes_by: dict[str, int] = {}
    frames_by: dict[str, int] = {}
    seen: set[str] = set()
    duplicates: list[str] = []

    for row in rows or []:
        if not isinstance(row, dict):
            continue
        proto = str(row.get("protocol") or "").strip().lower()
        if not proto:
            continue
        try:
            b = int(row.get("bytes") or 0)
        except Exception:
            b = 0
        try:
            f = int(row.get("frames") or 0)
        except Exception:
            f = 0

        if proto in seen and proto not in duplicates:
            duplicates.append(proto)
        seen.add(proto)

        bytes_by[proto] = bytes_by.get(proto, 0) + max(0, b)
        frames_by[proto] = frames_by.get(proto, 0) + max(0, f)

    return {"bytes": bytes_by, "frames": frames_by, "agg": {"bytes": bytes_by, "frames": frames_by, "duplicates": duplicates}}


def _bounded_ratio(numer: int | None, denom: int | None) -> float | None:
    if numer is None or denom is None:
        return None
    if denom <= 0 or numer < 0:
        return None
    try:
        r = float(numer) / float(denom)
    except Exception:
        return None
    if r < 0:
        return 0.0
    if r > 1:
        return 1.0
    return r


def _compute_protocol_ratios(bytes_by: dict[str, int]) -> dict[str, float | None]:
    # Keep formulas aligned with pcap_features proxies.
    ip_bytes = bytes_by.get("ip") or bytes_by.get("frame") or None
    tcp_bytes = bytes_by.get("tcp")
    udp_bytes = bytes_by.get("udp")
    tls_bytes = bytes_by.get("tls")
    quic_bytes = int((bytes_by.get("quic") or 0) + (bytes_by.get("gquic") or 0))

    tcp_ratio = _bounded_ratio(tcp_bytes, ip_bytes)
    udp_ratio = _bounded_ratio(udp_bytes, ip_bytes)
    quic_ratio = _bounded_ratio(quic_bytes, max(int(udp_bytes or 0), int(quic_bytes or 0)) or None)

    tls_ratio = None
    if tls_bytes is not None and tcp_bytes is not None:
        tls_ratio = _bounded_ratio(min(int(tls_bytes), int(tcp_bytes)), int(tcp_bytes))

    return {"tcp_ratio": tcp_ratio, "udp_ratio": udp_ratio, "tls_ratio": tls_ratio, "quic_ratio": quic_ratio}


def _run_top_fields(
    tshark_path: str,
    pcap_path: Path,
    field: str,
    top_n: int,
    *,
    display_filter: str | None = None,
) -> list[dict[str, object]]:
    cmd = [tshark_path, "-r", str(pcap_path)]
    if display_filter:
        cmd += ["-Y", display_filter]
    cmd += ["-T", "fields", "-e", field]
    result = _run_command(cmd)
    if not result.get("stdout"):
        return []
    counts: dict[str, int] = {}
    for value in result["stdout"].splitlines():
        value = value.strip()
        if not value:
            continue
        counts[value] = counts.get(value, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)[: max(top_n, 1)]
    return [{"value": value, "count": count} for value, count in ranked]


def _run_top_fields_with_stats(
    tshark_path: str,
    pcap_path: Path,
    field: str,
    top_n: int,
    *,
    display_filter: str | None = None,
) -> dict[str, object]:
    cmd = [tshark_path, "-r", str(pcap_path)]
    if display_filter:
        cmd += ["-Y", display_filter]
    cmd += ["-T", "fields", "-e", field]
    result = _run_command(cmd)
    if not result.get("stdout"):
        return {"items": [], "total_count": 0, "unique_count": 0, "top1_share": None}
    counts: dict[str, int] = {}
    for value in result["stdout"].splitlines():
        value = value.strip()
        if not value:
            continue
        counts[value] = counts.get(value, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    items = [{"value": value, "count": count} for value, count in ranked[: max(top_n, 1)]]
    total = sum(counts.values())
    top1 = ranked[0][1] if ranked else 0
    top1_share = (float(top1) / float(total)) if total > 0 else None
    return {
        "items": items,
        "total_count": int(total),
        "unique_count": int(len(counts)),
        "top1_share": top1_share,
    }


def _run_command(cmd: list[str]) -> dict[str, object]:
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
        )
    except Exception as exc:  # noqa: BLE001
        return {"stdout": "", "stderr": "", "error": str(exc)}
    return {
        "stdout": completed.stdout or "",
        "stderr": completed.stderr or "",
        "error": None if completed.returncode == 0 else completed.stderr.strip() or "command_failed",
    }


def _parse_int(value: str) -> int | None:
    try:
        cleaned = value.split(" ")[0].replace(",", "")
        return int(cleaned)
    except Exception:
        return None


def _parse_float(value: str) -> float | None:
    try:
        cleaned = value.split(" ")[0].replace(",", "")
        return float(cleaned)
    except Exception:
        return None


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _log(event_logger: RunEventLogger | None, event: str, payload: dict[str, object]) -> None:
    if event_logger:
        event_logger.log(event, payload)


__all__ = ["PcapReportConfig", "write_pcap_report"]
