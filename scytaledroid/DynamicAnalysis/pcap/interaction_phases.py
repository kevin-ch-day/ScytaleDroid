"""Derived scripted-interaction timelines and phase-aware transport summaries."""

from __future__ import annotations

import json
import subprocess
import tempfile
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest, manifest_to_dict
from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
from scytaledroid.DynamicAnalysis.pcap.enrichment import infer_direction_from_ports, safe_port
from scytaledroid.DynamicAnalysis.scenarios.manual_templates import template_steps_for_id


TIMELINE_RELATIVE_PATH = "analysis/interaction_timeline.json"


@dataclass(frozen=True)
class PhasePacketRecord:
    t: float
    length: int
    protocols: str
    src_port: int | None = None
    dst_port: int | None = None


def build_interaction_timeline_from_run_dir(
    run_dir: Path,
    *,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    manifest = manifest or _read_json(run_dir / "run_manifest.json")
    if not isinstance(manifest, dict):
        return None
    operator = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
    target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
    scenario = manifest.get("scenario") if isinstance(manifest.get("scenario"), dict) else {}
    run_profile = str(operator.get("run_profile") or "").strip().lower()
    if run_profile != "interaction_scripted":
        return None

    template_id = str(
        operator.get("template_id")
        or operator.get("scenario_template")
        or ""
    ).strip()
    template_hash = str(operator.get("template_hash") or operator.get("script_hash") or "").strip()
    mapping_version = str(operator.get("template_map_version") or "").strip()
    events = _load_jsonl(run_dir / "notes" / "run_events.jsonl")

    script_start: dict[str, Any] | None = None
    script_end: dict[str, Any] | None = None
    step_rows: dict[int, dict[str, Any]] = {}
    limitations: list[str] = []

    for event in events:
        event_type = str(event.get("event_type") or "").strip().upper()
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        timestamp = str(event.get("timestamp") or "").strip()
        if event_type == "SCRIPT_START":
            script_start = {"timestamp": timestamp, "details": details}
            template_id = template_id or str(details.get("template_id") or details.get("scenario_template") or "").strip()
            template_hash = template_hash or str(details.get("template_hash") or details.get("script_hash") or "").strip()
            mapping_version = mapping_version or str(details.get("template_map_version") or "").strip()
        elif event_type == "SCRIPT_END":
            script_end = {"timestamp": timestamp, "details": details}
            template_id = template_id or str(details.get("template_id") or details.get("scenario_template") or "").strip()
            template_hash = template_hash or str(details.get("template_hash") or details.get("script_hash") or "").strip()
            mapping_version = mapping_version or str(details.get("template_map_version") or "").strip()
        elif event_type == "STEP_START":
            idx = _coerce_int(details.get("step_index"))
            if idx is None:
                continue
            row = step_rows.setdefault(idx, {"step_index": idx})
            row.update(
                {
                    "step_id": details.get("step_id"),
                    "step_variant": details.get("step_variant"),
                    "planned_duration_sec": _coerce_int(details.get("expected_duration_s")),
                    "actual_start_timestamp": timestamp or None,
                }
            )
        elif event_type == "STEP_END":
            idx = _coerce_int(details.get("step_index"))
            if idx is None:
                continue
            row = step_rows.setdefault(idx, {"step_index": idx})
            row.update(
                {
                    "step_id": details.get("step_id"),
                    "step_variant": details.get("step_variant"),
                    "planned_duration_sec": _coerce_int(details.get("expected_duration_s")) or row.get("planned_duration_sec"),
                    "actual_end_timestamp": timestamp or None,
                    "actual_duration_sec": _coerce_float(details.get("elapsed_s")),
                    "step_outcome": str(details.get("step_outcome") or "").strip() or None,
                    "limitation_reason": str(details.get("limitation_reason") or "").strip() or None,
                    "operator_note": str(details.get("operator_note") or "").strip() or None,
                }
            )

    planned_steps = template_steps_for_id(template_id) if template_id else None
    if planned_steps is None:
        planned_steps = ()
        limitations.append("template_definition_unavailable")

    planned_step_count = _coerce_int(operator.get("step_count_planned"))
    if planned_step_count is None and script_start:
        planned_step_count = _coerce_int((script_start.get("details") or {}).get("step_count_planned"))
    if planned_step_count is None and script_end:
        planned_step_count = _coerce_int((script_end.get("details") or {}).get("step_count_planned"))
    if planned_step_count is None:
        planned_step_count = len(planned_steps)

    completed_step_count = _coerce_int(operator.get("step_count_completed"))
    if completed_step_count is None and script_end:
        completed_step_count = _coerce_int((script_end.get("details") or {}).get("step_count_completed"))
    if completed_step_count is None:
        completed_step_count = sum(1 for row in step_rows.values() if row.get("actual_end_timestamp"))

    if not script_start:
        limitations.append("missing_script_start")
    if not script_end:
        limitations.append("missing_script_end")

    max_index = max([len(planned_steps), planned_step_count or 0, *step_rows.keys()], default=0)
    steps: list[dict[str, Any]] = []
    for idx in range(1, max_index + 1):
        row = dict(step_rows.get(idx) or {})
        planned_def = planned_steps[idx - 1] if idx - 1 < len(planned_steps) else None
        step_id = str(row.get("step_id") or (planned_def[0] if planned_def else "")).strip()
        planned_prompt = str(planned_def[1] if planned_def else "").strip()
        planned_duration = _coerce_int(row.get("planned_duration_sec"))
        if planned_duration is None and planned_def:
            planned_duration = int(planned_def[2])
        start_ts = str(row.get("actual_start_timestamp") or "").strip() or None
        end_ts = str(row.get("actual_end_timestamp") or "").strip() or None
        actual_duration = _coerce_float(row.get("actual_duration_sec"))
        if actual_duration is None and start_ts and end_ts:
            start_dt = _parse_iso8601(start_ts)
            end_dt = _parse_iso8601(end_ts)
            if start_dt and end_dt:
                actual_duration = round(max((end_dt - start_dt).total_seconds(), 0.0), 3)
        step_outcome = str(row.get("step_outcome") or "").strip().lower() or None
        limitation_reason = str(row.get("limitation_reason") or "").strip() or None
        operator_note = str(row.get("operator_note") or "").strip() or None
        operator_completed = bool(end_ts and step_outcome != "skipped_not_found")
        notes: list[str] = []
        if step_outcome and step_outcome != "completed":
            notes.append(f"outcome={step_outcome}")
        if limitation_reason:
            notes.append(f"limitation={limitation_reason}")
        if operator_note:
            notes.append(f"note={operator_note}")
        if start_ts and not end_ts:
            notes.append("missing_step_end")
            limitations.append(f"missing_step_end:{idx}:{step_id or 'unknown'}")
        steps.append(
            {
                "step_id": step_id,
                "step_index": idx,
                "step_variant": row.get("step_variant") or "",
                "phase_label": _humanize_step_id(step_id) if step_id else f"Step {idx}",
                "planned_duration_sec": planned_duration,
                "actual_start_timestamp": start_ts,
                "actual_end_timestamp": end_ts,
                "actual_duration_sec": actual_duration,
                "operator_prompt": planned_prompt,
                "operator_completed": operator_completed,
                "step_outcome": step_outcome or "unknown",
                "limitation_reason": limitation_reason,
                "operator_note": operator_note,
                "notes": "; ".join(notes),
            }
        )

    if completed_step_count < planned_step_count:
        limitations.append("step_count_incomplete")
    timeline_complete = not limitations

    return {
        "schema_name": "scytaledroid.interaction_timeline",
        "schema_version": "1.1",
        "run_id": str(manifest.get("dynamic_run_id") or run_dir.name),
        "package": str(target.get("package_name") or "").strip().lower(),
        "run_profile": str(operator.get("run_profile") or ""),
        "interaction_level": str(operator.get("interaction_level") or ""),
        "scenario_id": str(scenario.get("id") or manifest.get("scenario_id") or ""),
        "template_id": template_id,
        "template_hash": template_hash,
        "mapping_version": mapping_version,
        "script_started_at": script_start.get("timestamp") if script_start else None,
        "script_ended_at": script_end.get("timestamp") if script_end else None,
        "planned_step_count": planned_step_count,
        "completed_step_count": completed_step_count,
        "timeline_complete": bool(timeline_complete),
        "steps": steps,
        "limitations": sorted({item for item in limitations if item}),
    }


def write_interaction_timeline_artifact(
    *,
    writer: EvidencePackWriter,
    manifest: dict[str, Any] | RunManifest,
) -> ArtifactRecord | None:
    manifest_payload = manifest_to_dict(manifest) if isinstance(manifest, RunManifest) else manifest
    payload = build_interaction_timeline_from_run_dir(writer.run_dir, manifest=manifest_payload)
    if not payload:
        return None
    path = writer.write_json(TIMELINE_RELATIVE_PATH, payload)
    return ArtifactRecord(
        relative_path=TIMELINE_RELATIVE_PATH,
        type="interaction_timeline",
        sha256=writer.hash_file(path),
        size_bytes=path.stat().st_size,
        produced_by="interaction_timeline",
        origin="host",
        pull_status="n/a",
    )


def phase_packet_transport_summary(
    run_dir: Path,
    *,
    timeline: dict[str, Any] | None = None,
    manifest: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    timeline = timeline or _read_json(run_dir / TIMELINE_RELATIVE_PATH)
    if not isinstance(timeline, dict):
        timeline = build_interaction_timeline_from_run_dir(run_dir, manifest=manifest)
    if not isinstance(timeline, dict):
        return []
    if not bool(timeline.get("timeline_complete")) and not timeline.get("steps"):
        return []

    capture_start_epoch = _capture_start_epoch(run_dir, manifest=manifest)
    pcap_path = _pcap_path(run_dir, manifest=manifest)
    if capture_start_epoch is None or pcap_path is None or not pcap_path.exists():
        return []
    packets = list(extract_phase_packet_timeline(pcap_path))
    if not packets:
        return []
    packet_times = [pkt.t for pkt in packets]
    rows: list[dict[str, Any]] = []
    for step in timeline.get("steps") or []:
        if not isinstance(step, dict):
            continue
        start_ts = str(step.get("actual_start_timestamp") or "").strip()
        end_ts = str(step.get("actual_end_timestamp") or "").strip()
        if not start_ts or not end_ts:
            continue
        start_dt = _parse_iso8601(start_ts)
        end_dt = _parse_iso8601(end_ts)
        if not start_dt or not end_dt:
            continue
        start_rel = max(start_dt.timestamp() - capture_start_epoch, 0.0)
        end_rel = max(end_dt.timestamp() - capture_start_epoch, start_rel)
        lo = bisect_left(packet_times, start_rel)
        hi = bisect_right(packet_times, end_rel)
        phase_packets = packets[lo:hi]
        packet_count = len(phase_packets)
        byte_count = sum(int(pkt.length) for pkt in phase_packets)
        tcp_packet_count = 0
        udp_packet_count = 0
        tls_packet_count = 0
        quic_packet_count = 0
        dns_packet_count = 0
        uplink_packet_count = 0
        downlink_packet_count = 0
        unknown_direction_packet_count = 0
        for pkt in phase_packets:
            proto = str(pkt.protocols or "").lower()
            if "tcp" in proto:
                tcp_packet_count += 1
            if "udp" in proto:
                udp_packet_count += 1
            if "tls" in proto:
                tls_packet_count += 1
            if "quic" in proto:
                quic_packet_count += 1
            if "dns" in proto:
                dns_packet_count += 1
            direction, _, _ = infer_direction_from_ports(src_port=pkt.src_port, dst_port=pkt.dst_port)
            if direction == "outbound":
                uplink_packet_count += 1
            elif direction == "inbound":
                downlink_packet_count += 1
            else:
                unknown_direction_packet_count += 1
        visibility_loss_flag = bool(
            packet_count > 0
            and dns_packet_count == 0
            and (tls_packet_count > 0 or quic_packet_count > 0)
        )
        rows.append(
            {
                "step_index": step.get("step_index"),
                "step_id": step.get("step_id"),
                "phase_label": step.get("phase_label"),
                "step_outcome": step.get("step_outcome"),
                "limitation_reason": step.get("limitation_reason"),
                "packet_count": packet_count,
                "byte_count": byte_count,
                "tcp_packet_count": tcp_packet_count,
                "udp_packet_count": udp_packet_count,
                "tls_packet_count": tls_packet_count,
                "quic_packet_count": quic_packet_count,
                "dns_packet_count": dns_packet_count,
                "uplink_packet_count": uplink_packet_count,
                "downlink_packet_count": downlink_packet_count,
                "unknown_direction_packet_count": unknown_direction_packet_count,
                "visibility_loss_flag": int(visibility_loss_flag),
            }
        )
    return rows


def extract_phase_packet_timeline(pcap_path: Path) -> list[PhasePacketRecord]:
    cmd = [
        "tshark",
        "-n",
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-E",
        "separator=,",
        "-e",
        "frame.time_relative",
        "-e",
        "frame.len",
        "-e",
        "frame.protocols",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "udp.srcport",
        "-e",
        "udp.dstport",
    ]
    err = tempfile.TemporaryFile(mode="w+b")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err, text=True)
    assert proc.stdout is not None
    rows: list[PhasePacketRecord] = []
    rc: int | None = None
    err_tail: str = ""
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) < 3:
                continue
            try:
                t = float(parts[0])
                length = int(float(parts[1]))
            except Exception:
                continue
            if t < 0 or length < 0:
                continue
            tcp_src = safe_port(parts[3] if len(parts) >= 4 else "")
            tcp_dst = safe_port(parts[4] if len(parts) >= 5 else "")
            udp_src = safe_port(parts[5] if len(parts) >= 6 else "")
            udp_dst = safe_port(parts[6] if len(parts) >= 7 else "")
            src_port = tcp_src if tcp_src is not None or tcp_dst is not None else udp_src
            dst_port = tcp_dst if tcp_src is not None or tcp_dst is not None else udp_dst
            rows.append(
                PhasePacketRecord(
                    t=t,
                    length=length,
                    protocols=str(parts[2] or ""),
                    src_port=src_port,
                    dst_port=dst_port,
                )
            )
    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass
        try:
            proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=10)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
        try:
            rc = proc.returncode
            if rc is None:
                rc = -1
            err.seek(0, 2)
            size = err.tell()
            err.seek(max(0, size - 4096), 0)
            err_tail = err.read().decode("utf-8", errors="replace").strip()
            err.close()
        except Exception:
            pass
    if rc is not None and rc != 0:
        raise RuntimeError(f"tshark failed (rc={rc}) for PCAP: {pcap_path} ({err_tail})")
    return rows


def _pcap_path(run_dir: Path, *, manifest: dict[str, Any] | None = None) -> Path | None:
    manifest = manifest or _read_json(run_dir / "run_manifest.json")
    if not isinstance(manifest, dict):
        return None
    for artifact in manifest.get("artifacts") or []:
        if not isinstance(artifact, dict):
            continue
        if str(artifact.get("type") or "").strip() != "pcapdroid_capture":
            continue
        rel = str(artifact.get("relative_path") or "").strip()
        if rel:
            path = run_dir / rel
            if path.exists() and path.is_file():
                return path
    for candidate in sorted((run_dir / "artifacts" / "pcapdroid_capture").glob("*.pcap")):
        return candidate
    return None


def _capture_start_epoch(run_dir: Path, *, manifest: dict[str, Any] | None = None) -> float | None:
    meta = _read_json(run_dir / "artifacts" / "pcapdroid_capture" / "pcapdroid_capture_meta.json")
    if isinstance(meta, dict):
        value = _coerce_float(meta.get("capture_start_epoch"))
        if value is not None:
            return value
    manifest = manifest or _read_json(run_dir / "run_manifest.json")
    if not isinstance(manifest, dict):
        return None
    started_at = _parse_iso8601(str(manifest.get("started_at") or "").strip())
    if started_at is None:
        return None
    return started_at.timestamp()


def _humanize_step_id(step_id: str) -> str:
    return str(step_id or "").strip().replace("_", " ").strip().title()


def _coerce_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except Exception:
        return None


def _coerce_float(value: Any) -> float | None:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except Exception:
        return None


def _parse_iso8601(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            text = line.strip()
            if not text:
                continue
            payload = json.loads(text)
            if isinstance(payload, dict):
                rows.append(payload)
    except Exception:
        return []
    return rows


__all__ = [
    "TIMELINE_RELATIVE_PATH",
    "PhasePacketRecord",
    "build_interaction_timeline_from_run_dir",
    "extract_phase_packet_timeline",
    "phase_packet_transport_summary",
    "write_interaction_timeline_artifact",
]
