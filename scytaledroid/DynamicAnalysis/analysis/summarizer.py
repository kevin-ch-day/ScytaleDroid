"""Post-processing summarizer for dynamic analysis runs."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
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
        network_present = self._network_capture_present(manifest)
        static_plan = manifest.target.get("static_plan_summary") if isinstance(manifest.target, dict) else None
        return {
            "dynamic_run_id": manifest.dynamic_run_id,
            "status": manifest.status,
            "target": manifest.target,
            "environment": manifest.environment,
            "scenario": manifest.scenario,
            "observers": [asdict(observer) for observer in manifest.observers],
            "destinations_observed": destinations,
            "flags": {
                "network_capture_present": network_present,
                "cleartext_http_detected": cleartext_flag,
                "tls_mitm_suspected": "unknown",
                "notable_log_signals": notable_logs,
                "static_watchlist_used": bool(static_plan),
            },
            "static_watchlist": static_plan,
            "evidence": [
                {
                    "relative_path": artifact.relative_path,
                    "sha256": artifact.sha256,
                    "type": artifact.type,
                }
                for artifact in manifest.artifacts
            ],
        }

    def _render_summary_md(self, summary: dict[str, Any]) -> str:
        destinations = summary.get("destinations_observed", [])
        destinations_text = ", ".join(destinations) if destinations else "none recorded"
        lines = [
            "# Dynamic Run Summary",
            "",
            f"- Run ID: {summary['dynamic_run_id']}",
            f"- Status: {summary['status']}",
            f"- Scenario: {summary['scenario'].get('id', 'unknown')}",
            "",
            "## Observations",
            f"- Destinations observed: {destinations_text}.",
            f"- Cleartext HTTP detected: {summary['flags'].get('cleartext_http_detected')}.",
            f"- Network capture present: {summary['flags'].get('network_capture_present')}.",
            f"- Static watchlist used: {summary['flags'].get('static_watchlist_used')}.",
            "- TLS MITM suspected: unknown.",
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

    def _network_capture_present(self, manifest: RunManifest) -> str:
        for artifact in manifest.artifacts:
            if artifact.type in {"network_capture", "proxy_capture"}:
                return "true"
        return "false"


__all__ = ["DynamicRunSummarizer"]
