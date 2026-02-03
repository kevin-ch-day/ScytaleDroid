"""Post-processing summarizer for dynamic analysis runs."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
from scytaledroid.Utils.network_quality import evaluate_network_signal_quality
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest


class DynamicRunSummarizer:
    def __init__(self, writer: EvidencePackWriter) -> None:
        self.writer = writer

    def summarize(self, manifest: RunManifest) -> list[ArtifactRecord]:
        summary = self._build_summary(manifest)
        summary_path = self.writer.write_json("analysis/summary.json", summary)
        summary_md_path = self.writer.write_text(
            "analysis/summary.md",
            self._render_summary_md(summary),
        )
        return [
            self._artifact_record(
                summary_path,
                "analysis_summary_json",
                "summarizer",
            ),
            self._artifact_record(
                summary_md_path,
                "analysis_summary_md",
                "summarizer",
            ),
        ]

    def _build_summary(self, manifest: RunManifest) -> dict[str, Any]:
        destinations = self._load_destinations(manifest)
        cleartext_flag = self._detect_cleartext(destinations)
        notable_logs = self._scan_log_signals(manifest)
        tls_mitm = "true" if "SSLHandshakeException" in notable_logs else "false"
        pcap_meta = self._load_pcap_meta(manifest)
        network_present = self._network_capture_present(manifest, pcap_meta)
        evidence_sizes = self._evidence_sizes(manifest)
        capture_sources, capture_bytes = self._capture_sources(manifest)
        pcap_available = pcap_meta.get("pcap_available")
        pcap_size_bytes = pcap_meta.get("pcap_size_bytes")
        pcap_valid = pcap_meta.get("pcap_valid")
        capture_mode = pcap_meta.get("capture_mode")
        static_plan = manifest.target.get("static_plan_summary") if isinstance(manifest.target, dict) else None
        telemetry_stats = None
        telemetry_counts = None
        telemetry_schema_version = None
        if isinstance(manifest.operator, dict):
            telemetry_stats = manifest.operator.get("telemetry_stats")
            telemetry_counts = manifest.operator.get("telemetry_counts")
            telemetry_schema_version = manifest.operator.get("telemetry_schema_version")
        tier = None
        if isinstance(manifest.operator, dict):
            tier = manifest.operator.get("tier")
        stored_quality = None
        if isinstance(telemetry_stats, dict):
            stored_quality = telemetry_stats.get("network_signal_quality")
        netstats_rows = int((telemetry_stats or {}).get("netstats_rows") or 0) if telemetry_stats else 0
        netstats_missing = int((telemetry_stats or {}).get("netstats_missing_rows") or 0) if telemetry_stats else 0
        netstats_in = (telemetry_stats or {}).get("netstats_bytes_in_total") if telemetry_stats else None
        netstats_out = (telemetry_stats or {}).get("netstats_bytes_out_total") if telemetry_stats else None
        network_signal_quality = evaluate_network_signal_quality(
            netstats_rows=netstats_rows,
            netstats_missing_rows=netstats_missing,
            sum_bytes_in=_safe_int(netstats_in),
            sum_bytes_out=_safe_int(netstats_out),
            pcap_present=pcap_valid is True,
            pcap_bytes=_safe_int(pcap_size_bytes),
        )
        telemetry_quality = self._telemetry_quality(telemetry_stats)
        if isinstance(telemetry_stats, dict):
            netstats_available = telemetry_stats.get("netstats_available")
            if netstats_available is not None:
                telemetry_quality["netstats_available"] = bool(netstats_available)
        if telemetry_quality.get("netstats_available") is False:
            telemetry_quality["netstats_warning"] = "netstats_unavailable"
        netstats_missing_rows = int((telemetry_stats or {}).get("netstats_missing_rows") or 0) if telemetry_stats else 0
        if netstats_missing_rows:
            telemetry_quality["netstats_warning"] = "netstats_missing"
        if network_signal_quality == "netstats_zero_bytes":
            telemetry_quality["netstats_warning"] = "netstats_zero_bytes"
        return {
            "dynamic_run_id": manifest.dynamic_run_id,
            "status": manifest.status,
            "tier": tier,
            "target": manifest.target,
            "environment": manifest.environment,
            "scenario": manifest.scenario,
            "observers": [asdict(observer) for observer in manifest.observers],
            "destinations_observed": destinations,
            "telemetry": {
                "schema_version": telemetry_schema_version,
                "counts": telemetry_counts,
                "stats": telemetry_stats,
                "quality": telemetry_quality,
                "network_signal_quality": network_signal_quality,
                "network_signal_quality_stored": stored_quality,
                "network_signal_quality_computed": network_signal_quality,
                "network_quality_mismatch": bool(
                    stored_quality
                    and isinstance(stored_quality, str)
                    and network_signal_quality
                    and stored_quality != network_signal_quality
                ),
            },
            "flags": {
                "network_capture_present": network_present,
                "cleartext_http_detected": cleartext_flag,
                "tls_mitm_suspected": tls_mitm,
                "notable_log_signals": notable_logs,
                "static_watchlist_used": bool(static_plan),
                "capture_sources": capture_sources,
            },
            "static_watchlist": static_plan,
            "capture": {
                "sources": capture_sources,
                "total_bytes": capture_bytes,
                "pcap_available": pcap_available,
                "pcap_size_bytes": pcap_size_bytes,
                "pcap_valid": pcap_valid,
                "capture_mode": capture_mode,
                "network_signal_quality": network_signal_quality,
                "evidence_sizes": evidence_sizes,
            },
            "evidence": [
                {
                    "relative_path": artifact.relative_path,
                    "sha256": artifact.sha256,
                    "type": artifact.type,
                    "size_bytes": artifact.size_bytes,
                    "produced_by": artifact.produced_by,
                }
                for artifact in manifest.artifacts
            ],
        }

    def _render_summary_md(self, summary: dict[str, Any]) -> str:
        destinations = summary.get("destinations_observed", [])
        destinations_text = ", ".join(destinations) if destinations else "none recorded"
        telemetry = summary.get("telemetry", {}) or {}
        quality = telemetry.get("quality", {}) or {}
        environment = summary.get("environment", {}) or {}
        capture = summary.get("capture", {}) or {}
        capture_sources = capture.get("sources") or []
        capture_sources_text = ", ".join(capture_sources) if capture_sources else "none"
        capture_bytes = capture.get("total_bytes")
        capture_bytes_text = f"{capture_bytes} bytes" if isinstance(capture_bytes, int) else "unknown"
        capture_mode = capture.get("capture_mode") or "unknown"
        pcap_valid = capture.get("pcap_valid")
        pcap_valid_text = "true" if pcap_valid is True else "false" if pcap_valid is False else "unknown"
        target = summary.get("target", {}) or {}
        lines = [
            "# Dynamic Run Summary",
            "",
            f"- Run ID: {summary['dynamic_run_id']}",
            f"- Status: {summary['status']}",
            f"- Tier: {summary.get('tier', 'unknown')}.",
            f"- Scenario: {summary['scenario'].get('id', 'unknown')}",
            f"- Package: {target.get('package_name', 'unknown')}.",
            f"- Device: {environment.get('device_model', 'unknown')} / {environment.get('android_version', 'unknown')}.",
            f"- Security patch: {environment.get('security_patch_level', 'unknown')}.",
            f"- Play Services: {environment.get('play_services_version', 'unknown')}.",
            "",
            "## Observations",
            f"- Destinations observed: {destinations_text}.",
            f"- Cleartext HTTP detected: {summary['flags'].get('cleartext_http_detected')}.",
            f"- Network capture present: {summary['flags'].get('network_capture_present')}.",
            f"- Network capture sources: {capture_sources_text} ({capture_bytes_text}).",
            f"- Capture mode: {capture_mode}.",
            f"- PCAP valid: {pcap_valid_text}.",
            f"- Static watchlist used: {summary['flags'].get('static_watchlist_used')}.",
            f"- TLS MITM suspected: {summary['flags'].get('tls_mitm_suspected')}.",
            "",
            "## Telemetry",
            f"- Schema version: {summary.get('telemetry', {}).get('schema_version')}.",
            f"- Counts: {summary.get('telemetry', {}).get('counts')}.",
            f"- Stats: {summary.get('telemetry', {}).get('stats')}.",
            f"- Quality: {quality}.",
            f"- Network signal quality: {telemetry.get('network_signal_quality')}.",
            "",
            "## Evidence",
        ]
        for item in summary.get("evidence", []):
            lines.append(f"- {item['relative_path']} ({item['sha256']})")
        lines.append("")
        return "\n".join(lines)

    def _artifact_record(self, path: Path, artifact_type: str, produced_by: str) -> ArtifactRecord:
        sha256 = self.writer.hash_file(path)
        return ArtifactRecord(
            relative_path=str(path.relative_to(self.writer.run_dir)),
            type=artifact_type,
            sha256=sha256,
            size_bytes=path.stat().st_size,
            produced_by=produced_by,
        )

    def _load_destinations(self, manifest: RunManifest) -> list[str]:
        for artifact in manifest.artifacts:
            if artifact.type != "network_flow_summary":
                continue
            path = self.writer.run_dir / artifact.relative_path
            try:
                payload = json.loads(path.read_text())
            except json.JSONDecodeError:
                continue
            destinations = payload.get("destinations", [])
            if isinstance(destinations, list):
                return [str(item) for item in destinations]
        return []

    def _detect_cleartext(self, destinations: list[str]) -> str:
        if not destinations:
            return "unknown"
        for entry in destinations:
            if entry.endswith(".80") or entry.endswith(":80"):
                return "true"
        return "false"

    def _evidence_sizes(self, manifest: RunManifest) -> dict[str, int]:
        sizes: dict[str, int] = {}
        for artifact in manifest.artifacts:
            if artifact.size_bytes is None:
                continue
            sizes[artifact.type] = sizes.get(artifact.type, 0) + int(artifact.size_bytes)
        return sizes

    def _capture_sources(self, manifest: RunManifest) -> tuple[list[str], int | None]:
        sources: list[str] = []
        total_bytes: int = 0
        found_size = False
        for artifact in manifest.artifacts:
            if artifact.type not in {"proxy_capture", "network_capture", "pcapdroid_capture"}:
                continue
            sources.append(artifact.type.replace("_capture", ""))
            if artifact.size_bytes is not None:
                total_bytes += int(artifact.size_bytes)
                found_size = True
        unique_sources = sorted(set(sources))
        if not unique_sources:
            return [], None
        return unique_sources, total_bytes if found_size else None

    def _telemetry_quality(self, stats: dict[str, Any] | None) -> dict[str, Any]:
        if not isinstance(stats, dict):
            return {}
        expected = stats.get("expected_samples")
        captured = stats.get("captured_samples")
        ratio = None
        try:
            if expected and int(expected) > 0:
                ratio = round(float(captured or 0) / float(expected), 4)
        except Exception:
            ratio = None
        return {
            "capture_ratio": ratio,
            "sampling_duration_seconds": stats.get("sampling_duration_seconds"),
            "max_gap_s": stats.get("sample_max_gap_s"),
            "avg_delta_s": stats.get("sample_avg_delta_s"),
        }

    def _scan_log_signals(self, manifest: RunManifest) -> list[str]:
        signals: list[str] = []
        for artifact in manifest.artifacts:
            if artifact.type != "system_log_capture":
                continue
            path = self.writer.run_dir / artifact.relative_path
            try:
                content = path.read_text(errors="ignore")
            except OSError:
                continue
            if "SSLHandshakeException" in content:
                signals.append("SSLHandshakeException")
            if "Cleartext" in content:
                signals.append("CleartextTraffic")
        return sorted(set(signals))

    def _network_capture_present(self, manifest: RunManifest, pcap_meta: dict[str, Any]) -> str:
        capture_types = {"network_capture", "proxy_capture", "pcapdroid_capture"}
        min_bytes = _safe_int(pcap_meta.get("min_pcap_bytes"))
        if not min_bytes:
            min_bytes = 30 * 1024
        for artifact in manifest.artifacts:
            if artifact.type not in capture_types:
                continue
            if artifact.size_bytes is not None:
                if artifact.size_bytes >= min_bytes:
                    return "true"
                continue
            path = self.writer.run_dir / artifact.relative_path
            try:
                if path.exists() and path.stat().st_size >= min_bytes:
                    return "true"
            except OSError:
                continue
        return "false"

    def _load_pcap_meta(self, manifest: RunManifest) -> dict[str, Any]:
        meta_path = None
        for artifact in manifest.artifacts:
            if artifact.type == "pcapdroid_capture_meta":
                meta_path = self.writer.run_dir / artifact.relative_path
                break
        if not meta_path or not meta_path.exists():
            return {}
        try:
            payload = json.loads(meta_path.read_text())
        except json.JSONDecodeError:
            return {}
        meta: dict[str, Any] = {}
        for key in ("pcap_size_bytes", "pcap_valid", "min_pcap_bytes", "capture_mode"):
            if key in payload:
                meta[key] = payload.get(key)
        meta["pcap_available"] = bool(payload.get("pcap_name") or payload.get("resolved_pcap_name"))
        return meta


def _safe_int(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


__all__ = ["DynamicRunSummarizer"]
