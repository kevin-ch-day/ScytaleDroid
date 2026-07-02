"""Post-processing summarizer for dynamic analysis runs."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.run_qualification import qualification_fields_from_dataset
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest
from scytaledroid.Utils.network_quality import evaluate_network_signal_quality


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
        pcap_report = self._load_pcap_report()
        destinations = self._load_destinations(manifest, pcap_report=pcap_report)
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
        dataset = manifest.dataset if isinstance(manifest.dataset, dict) else {}
        operator = manifest.operator if isinstance(manifest.operator, dict) else {}
        invalid_reason = str(dataset.get("invalid_reason_code") or "").strip() or None
        if not invalid_reason and dataset.get("valid_dataset_run") is True and dataset.get("countable") is False:
            invalid_reason = str(dataset.get("paper_exclusion_primary_reason_code") or "").strip() or None
        countability_label = self._countability_label(
            dataset=dataset,
            run_profile=operator.get("run_profile"),
            invalid_reason=invalid_reason,
        )
        qualification = qualification_fields_from_dataset(dataset)
        dataset_verdict = (
            "VALID"
            if dataset.get("valid_dataset_run") is True
            else "INVALID"
            if dataset.get("valid_dataset_run") is False
            else None
        )
        return {
            "dynamic_run_id": manifest.dynamic_run_id,
            "status": manifest.status,
            "tier": tier,
            "run_profile": operator.get("run_profile"),
            "dataset_verdict": dataset_verdict,
            "counts_toward_quota": dataset.get("countable"),
            "quota_detail": {
                "countable": dataset.get("countable"),
                "countability_label": countability_label,
                "cohort_eligibility": dataset.get("cohort_eligibility"),
                "invalid_reason_code": invalid_reason,
            },
            "evidence_qualification": qualification,
            "verdicts": {
                "technical": dataset_verdict,
                "protocol": "COMPLIANT" if dataset_verdict == "VALID" else ("NON_COMPLIANT" if dataset_verdict == "INVALID" else None),
                "cohort": dataset.get("cohort_eligibility"),
            },
            "dataset": dataset,
            "target": manifest.target,
            "environment": manifest.environment,
            "scenario": manifest.scenario,
            "observers": [asdict(observer) for observer in manifest.observers],
            "destinations_observed": destinations,
            "indicators": {
                "top_dns": pcap_report.get("top_dns") if isinstance(pcap_report.get("top_dns"), list) else [],
                "top_sni": pcap_report.get("top_sni") if isinstance(pcap_report.get("top_sni"), list) else [],
                "service_context": (
                    pcap_report.get("service_context")
                    if isinstance(pcap_report.get("service_context"), dict)
                    else {}
                ),
                "service_signals": (
                    pcap_report.get("service_signals")
                    if isinstance(pcap_report.get("service_signals"), dict)
                    else {}
                ),
            },
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
        pcap_valid_text = self._bool_text(pcap_valid)
        target = summary.get("target", {}) or {}
        dataset = summary.get("dataset", {}) or {}
        quota_detail = summary.get("quota_detail", {}) or {}
        indicators = summary.get("indicators", {}) or {}
        cleartext_http_text = self._bool_text(summary.get("flags", {}).get("cleartext_http_detected"))
        network_capture_text = self._bool_text(summary.get("flags", {}).get("network_capture_present"))
        static_watchlist_text = self._bool_text(summary.get("flags", {}).get("static_watchlist_used"))
        invalid_reason_text = self._display_text(quota_detail.get("invalid_reason_code"))
        top_dns = indicators.get("top_dns") or []
        top_sni = indicators.get("top_sni") or []
        top_dns_text = self._top_indicator_text(top_dns)
        top_sni_text = self._top_indicator_text(top_sni)
        lines = [
            "# Dynamic Run Summary",
            "",
            f"- Run ID: {summary['dynamic_run_id']}",
            f"- Status: {summary['status']}",
            f"- Tier: {summary.get('tier', 'unknown')}.",
            f"- Scenario: {summary['scenario'].get('id', 'unknown')}",
            f"- Package: {target.get('package_name', 'unknown')}.",
            f"- Run profile: {summary.get('run_profile', 'unknown')}.",
            f"- Device: {environment.get('device_model', 'unknown')} / {environment.get('android_version', 'unknown')}.",
            f"- Security patch: {environment.get('security_patch_level', 'unknown')}.",
            f"- Play Services: {environment.get('play_services_version', 'unknown')}.",
            "",
            "## Observations",
            f"- Destinations observed: {destinations_text}.",
            f"- Cleartext HTTP detected: {cleartext_http_text}.",
            f"- Network capture present: {network_capture_text}.",
            f"- Network capture sources: {capture_sources_text} ({capture_bytes_text}).",
            f"- Capture mode: {capture_mode}.",
            f"- PCAP valid: {pcap_valid_text}.",
            f"- Dataset verdict: {summary.get('dataset_verdict', 'unknown')}.",
            f"- Counts toward quota: {quota_detail.get('countability_label') or 'UNKNOWN'}.",
            f"- Cohort eligibility: {quota_detail.get('cohort_eligibility')}.",
            f"- Invalid reason: {invalid_reason_text}.",
            f"- Static watchlist used: {static_watchlist_text}.",
            f"- TLS MITM suspected: {self._bool_text(summary['flags'].get('tls_mitm_suspected'))}.",
            f"- Top DNS: {top_dns_text}.",
            f"- Top SNI: {top_sni_text}.",
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

    @staticmethod
    def _bool_text(value: object) -> str:
        if value is True or str(value).strip().lower() == "true":
            return "yes"
        if value is False or str(value).strip().lower() == "false":
            return "no"
        return "unknown"

    @staticmethod
    def _display_text(value: object) -> str:
        text = str(value or "").strip()
        return text or "—"

    def _countability_label(
        self,
        *,
        dataset: dict[str, Any],
        run_profile: object,
        invalid_reason: str | None,
    ) -> str:
        if dataset.get("valid_dataset_run") is False:
            return f"NO ({str(invalid_reason or 'INVALID').strip() or 'INVALID'})"
        if dataset.get("countable") is True:
            return f"YES ({str(run_profile or 'dataset').strip() or 'dataset'})"
        profile_lc = str(run_profile or "").strip().lower()
        exclusion_reason = str(dataset.get("paper_exclusion_primary_reason_code") or "").strip().upper()
        cohort_eligibility = str(dataset.get("cohort_eligibility") or "").strip().upper()
        if dataset.get("low_signal") is True and profile_lc == "baseline_idle":
            return "NO (LOW_SIGNAL_IDLE)"
        if exclusion_reason == "EXCLUDED_MANUAL_NON_COHORT":
            return "NO (manual exploratory)"
        if cohort_eligibility == "EXTRA":
            return "NO (extra run)"
        if dataset.get("countable") is False:
            return "NO (extra run)"
        return "UNKNOWN"

    def _artifact_record(self, path: Path, artifact_type: str, produced_by: str) -> ArtifactRecord:
        sha256 = self.writer.hash_file(path)
        return ArtifactRecord(
            relative_path=str(path.relative_to(self.writer.run_dir)),
            type=artifact_type,
            sha256=sha256,
            size_bytes=path.stat().st_size,
            produced_by=produced_by,
            origin="host",
            pull_status="n/a",
        )

    def _load_destinations(self, manifest: RunManifest, pcap_report: dict[str, Any] | None = None) -> list[str]:
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
        report = pcap_report if isinstance(pcap_report, dict) else self._load_pcap_report()
        return self._destinations_from_pcap_report(report)

    def _load_pcap_report(self) -> dict[str, Any]:
        report_path = self.writer.run_dir / "analysis" / "pcap_report.json"
        if not report_path.exists():
            return {}
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def _top_indicator_text(self, items: list[dict[str, Any]]) -> str:
        out: list[str] = []
        for item in items[:3]:
            if not isinstance(item, dict):
                continue
            value = str(item.get("value") or "").strip()
            count = item.get("count")
            if not value:
                continue
            out.append(f"{value} ({count})" if count is not None else value)
        return ", ".join(out) if out else "none"

    def _detect_cleartext(self, destinations: list[str]) -> str:
        if not destinations:
            return "unknown"
        has_port_hint = False
        for entry in destinations:
            if ":" in entry or entry.rsplit(".", 1)[-1].isdigit():
                has_port_hint = True
            if entry.endswith(".80") or entry.endswith(":80"):
                return "true"
        return "false" if has_port_hint else "unknown"

    def _destinations_from_pcap_report(self, report: dict[str, Any]) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []

        def _append(value: object) -> None:
            text = str(value or "").strip()
            if not text or text in seen:
                return
            seen.add(text)
            ordered.append(text)

        for key in ("top_dns", "top_sni"):
            items = report.get(key)
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                _append(item.get("value"))

        service_context = report.get("service_context")
        if isinstance(service_context, dict):
            for service in service_context.get("services") or []:
                if not isinstance(service, dict):
                    continue
                for domain in service.get("domains") or []:
                    if not isinstance(domain, dict):
                        continue
                    _append(domain.get("domain"))
            for unresolved in service_context.get("unresolved_domains") or []:
                if isinstance(unresolved, dict):
                    _append(unresolved.get("domain"))
                else:
                    _append(unresolved)

        return ordered

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
            if artifact.type != "pcapdroid_capture":
                continue
            sources.append("pcapdroid")
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
        capture_types = {"pcapdroid_capture"}
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
        pcap_artifact_present = False
        for artifact in manifest.artifacts:
            if artifact.type == "pcapdroid_capture":
                pcap_artifact_present = True
            if artifact.type == "pcapdroid_capture_meta":
                meta_path = self.writer.run_dir / artifact.relative_path
        if not meta_path or not meta_path.exists():
            return {"pcap_available": pcap_artifact_present}
        try:
            payload = json.loads(meta_path.read_text())
        except json.JSONDecodeError:
            return {"pcap_available": pcap_artifact_present}
        meta: dict[str, Any] = {}
        for key in ("pcap_size_bytes", "pcap_valid", "min_pcap_bytes", "capture_mode"):
            if key in payload:
                meta[key] = payload.get(key)
        meta["pcap_available"] = pcap_artifact_present
        return meta


def _safe_int(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


__all__ = ["DynamicRunSummarizer"]
