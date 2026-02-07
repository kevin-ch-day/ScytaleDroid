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
        "report_status": report_status,
        "missing_tools": missing_tools,
        "reason_codes": reason_codes,
        "no_traffic_observed": 0,
        "capinfos": {"raw": "", "parsed": {}, "error": "skipped"} if report_status == "skip" else _run_capinfos(capinfos_path, pcap_path),  # type: ignore[arg-type]
        "protocol_hierarchy": [],
        "top_sni": [],
        "top_dns": [],
    }

    # capinfos-derived "no traffic" flag for interpretability and deterministic QA gating.
    try:
        parsed = (report.get("capinfos") or {}).get("parsed") or {}
        pkt = parsed.get("packet_count")
        if isinstance(pkt, (int, float)) and int(pkt) == 0:
            report["no_traffic_observed"] = 1
    except Exception:
        pass

    if report_status != "skip" and tshark_path and pcap_path:
        report["protocol_hierarchy"] = _run_protocol_hierarchy(tshark_path, pcap_path)
        report["top_sni"] = _run_top_fields(
            tshark_path,
            pcap_path,
            "tls.handshake.extensions_server_name",
            cfg.top_n,
        )
        report["top_dns"] = _run_top_fields(tshark_path, pcap_path, "dns.qry.name", cfg.top_n, display_filter="dns")
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
    if key.endswith("_bytes"):
        return _parse_int(value)
    if key.endswith("_bps") or key.endswith("_pps"):
        return _parse_float(value)
    if key.endswith("_s"):
        return _parse_float(value)
    return value


def _run_protocol_hierarchy(tshark_path: str, pcap_path: Path) -> list[dict[str, object]]:
    result = _run_command([tshark_path, "-r", str(pcap_path), "-q", "-z", "io,phs"])
    if not result.get("stdout"):
        return []
    rows = []
    for line in result["stdout"].splitlines():
        if not line.strip() or line.startswith("=") or line.startswith("Filter"):
            continue
        match = re.match(r"\\s*(\\S+)\\s+frames:(\\d+)\\s+bytes:(\\d+)", line)
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
