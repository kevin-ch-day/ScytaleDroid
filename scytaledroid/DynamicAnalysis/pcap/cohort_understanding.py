"""Filesystem-first synthesis of PCAP evidence across a dynamic cohort."""

from __future__ import annotations

import json
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.pcap.security_surface import (
    compute_static_dynamic_cleartext_posture,
    rehydrate_security_surface,
)


@dataclass(frozen=True)
class RunUnderstandingRow:
    run_id: str
    package_name: str | None
    app_label: str | None
    run_profile: str | None
    valid_dataset_run: bool | None
    pcap_bytes: int | None
    capture_duration_s: float | None
    packet_count: int | None
    tls_ratio: float | None
    quic_ratio: float | None
    tcp_ratio: float | None
    udp_ratio: float | None
    unique_dns: int | None
    unique_sni: int | None
    dns_only_count: int | None
    sni_only_count: int | None
    tls_alert_count: int | None
    dns_max_entropy: float | None
    security_findings: int | None
    visibility_class: str | None
    plaintext_protocols: str
    decoded_protocols: str
    decoded_stream_count: int | None
    mismatch_class: str | None
    overlap_count: int | None
    dynamic_only_count: int | None
    static_only_count: int | None
    overlap_ratio: float | None
    has_interaction_timeline: bool
    phase_cleartext_steps: int


@dataclass
class CohortUnderstanding:
    generated_at: str
    evidence_root: str
    runs_scanned: int = 0
    runs_with_surface: int = 0
    runs_with_features: int = 0
    runs_with_overlap: int = 0
    valid_runs: int = 0
    total_pcap_bytes: int = 0
    cleartext_surface_runs: int = 0
    http_metadata_runs: int = 0
    xmpp_runs: int = 0
    denied_but_observed: int = 0
    tls_alert_runs: int = 0
    high_dns_entropy_runs: int = 0
    scripted_runs: int = 0
    transport_tls_median: float | None = None
    transport_quic_median: float | None = None
    visibility_counts: dict[str, int] = field(default_factory=dict)
    mismatch_counts: dict[str, int] = field(default_factory=dict)
    plaintext_protocol_counts: dict[str, int] = field(default_factory=dict)
    risk_flag_counts: dict[str, int] = field(default_factory=dict)
    top_cohort_domains_dns: list[tuple[str, int]] = field(default_factory=list)
    top_cohort_domains_sni: list[tuple[str, int]] = field(default_factory=list)
    top_dynamic_only_domains: list[tuple[str, int]] = field(default_factory=list)
    domain_context_rollups: list[dict[str, Any]] = field(default_factory=list)
    rows: list[RunUnderstandingRow] = field(default_factory=list)
    app_rollups: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "evidence_root": self.evidence_root,
            "runs_scanned": self.runs_scanned,
            "runs_with_surface": self.runs_with_surface,
            "runs_with_features": self.runs_with_features,
            "runs_with_overlap": self.runs_with_overlap,
            "valid_runs": self.valid_runs,
            "total_pcap_bytes": self.total_pcap_bytes,
            "cleartext_surface_runs": self.cleartext_surface_runs,
            "http_metadata_runs": self.http_metadata_runs,
            "xmpp_runs": self.xmpp_runs,
            "denied_but_observed": self.denied_but_observed,
            "tls_alert_runs": self.tls_alert_runs,
            "high_dns_entropy_runs": self.high_dns_entropy_runs,
            "scripted_runs": self.scripted_runs,
            "transport_tls_median": self.transport_tls_median,
            "transport_quic_median": self.transport_quic_median,
            "visibility_counts": dict(self.visibility_counts),
            "mismatch_counts": dict(self.mismatch_counts),
            "plaintext_protocol_counts": dict(self.plaintext_protocol_counts),
            "risk_flag_counts": dict(self.risk_flag_counts),
            "top_cohort_domains_dns": self.top_cohort_domains_dns,
            "top_cohort_domains_sni": self.top_cohort_domains_sni,
            "top_dynamic_only_domains": self.top_dynamic_only_domains,
            "domain_context_rollups": self.domain_context_rollups,
            "rows": [row.__dict__ for row in self.rows],
            "app_rollups": self.app_rollups,
        }


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _safe_float(value: Any) -> float | None:
    try:
        if value in (None, ""):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _safe_int(value: Any) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _phase_cleartext_steps(run_dir: Path) -> int:
    transport_path = run_dir / "analysis" / "phase_packet_transport_summary.json"
    payload = _read_json(transport_path)
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = payload.get("rows") or payload.get("transport_summary") or []
    else:
        timeline = _read_json(run_dir / "analysis" / "interaction_timeline.json")
        if not isinstance(timeline, dict):
            return 0
        try:
            from scytaledroid.DynamicAnalysis.pcap.interaction_phases import (
                phase_packet_transport_summary,
            )

            rows = phase_packet_transport_summary(run_dir, timeline=timeline)
        except Exception:
            return 0
    count = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        if int(row.get("cleartext_surface_flag") or 0) > 0 or int(row.get("http_packet_count") or 0) > 0:
            count += 1
    return count


def build_cohort_understanding(
    evidence_root: Path,
    *,
    packages: set[str] | None = None,
) -> CohortUnderstanding:
    summary = CohortUnderstanding(
        generated_at=datetime.now(UTC).isoformat(),
        evidence_root=str(evidence_root.resolve()),
    )
    if not evidence_root.exists():
        return summary

    dns_domain_hits: Counter[str] = Counter()
    sni_domain_hits: Counter[str] = Counter()
    dynamic_only_hits: Counter[str] = Counter()
    domain_package_hints: dict[str, str] = {}
    tls_ratios: list[float] = []
    quic_ratios: list[float] = []
    app_buckets: dict[str, list[RunUnderstandingRow]] = defaultdict(list)
    package_filter = {str(package).strip().lower() for package in packages or set() if str(package).strip()}

    for run_dir in sorted([p for p in evidence_root.iterdir() if p.is_dir()], key=lambda p: p.name):
        manifest = _read_json(run_dir / "run_manifest.json")
        if not manifest:
            continue
        target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
        operator = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
        dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), dict) else {}
        package_name = str(target.get("package_name") or "").strip() or None
        if package_filter and str(package_name or "").lower() not in package_filter:
            continue
        summary.runs_scanned += 1
        app_label = str(target.get("display_name") or target.get("app_label") or package_name or "").strip() or None
        run_id = str(manifest.get("dynamic_run_id") or run_dir.name)
        run_profile = str(operator.get("run_profile") or "").strip() or None
        valid = dataset.get("valid_dataset_run")
        valid_bool = valid if isinstance(valid, bool) else None
        if valid_bool:
            summary.valid_runs += 1

        report = _read_json(run_dir / "analysis" / "pcap_report.json") or {}
        features = _read_json(run_dir / "analysis" / "pcap_features.json") or {}
        if features:
            summary.runs_with_features += 1
        proxies = features.get("proxies") if isinstance(features.get("proxies"), dict) else {}
        metrics = features.get("metrics") if isinstance(features.get("metrics"), dict) else {}
        cap = (report.get("capinfos") or {}).get("parsed") if isinstance(report.get("capinfos"), dict) else {}

        surface = _read_json(run_dir / "analysis" / "security_surface.json")
        if not isinstance(surface, dict) or surface.get("status") != "ok":
            surface = report.get("security_surface") if isinstance(report.get("security_surface"), dict) else None
        cleartext: dict[str, Any] = {}
        dns: dict[str, Any] = {}
        tls: dict[str, Any] = {}
        inventory: dict[str, Any] = {}
        if isinstance(surface, dict) and surface.get("status") == "ok":
            summary.runs_with_surface += 1
            surface = rehydrate_security_surface(surface)
            cleartext = surface.get("cleartext") if isinstance(surface.get("cleartext"), dict) else {}
            dns = surface.get("dns_anomalies") if isinstance(surface.get("dns_anomalies"), dict) else {}
            tls = surface.get("tls_surface") if isinstance(surface.get("tls_surface"), dict) else {}
            inventory = surface.get("domain_inventory") if isinstance(surface.get("domain_inventory"), dict) else {}
            visibility = str(cleartext.get("visibility_class") or "")
            summary.visibility_counts[visibility] = summary.visibility_counts.get(visibility, 0) + 1
            if visibility == "cleartext_surface_present":
                summary.cleartext_surface_runs += 1
            if cleartext.get("http_observed"):
                summary.http_metadata_runs += 1
            for protocol in cleartext.get("plaintext_protocols_observed") or []:
                key = str(protocol)
                summary.plaintext_protocol_counts[key] = summary.plaintext_protocol_counts.get(key, 0) + 1
                if key == "xmpp":
                    summary.xmpp_runs += 1
            for flag in surface.get("risk_flags") or []:
                text = str(flag)
                summary.risk_flag_counts[text] = summary.risk_flag_counts.get(text, 0) + 1
            for name in inventory.get("dns_names") or []:
                if name:
                    domain = str(name).lower()
                    dns_domain_hits[domain] += 1
                    if package_name:
                        domain_package_hints.setdefault(domain, package_name)
            for name in inventory.get("sni_names") or []:
                if name:
                    domain = str(name).lower()
                    sni_domain_hits[domain] += 1
                    if package_name:
                        domain_package_hints.setdefault(domain, package_name)
            if _safe_int(tls.get("tls_alert_count")):
                summary.tls_alert_runs += 1
            entropy = _safe_float(dns.get("max_label_entropy"))
            if entropy is not None and entropy >= 3.5:
                summary.high_dns_entropy_runs += 1

        overlap = _read_json(run_dir / "analysis" / "static_dynamic_overlap.json") or {}
        if overlap:
            summary.runs_with_overlap += 1
        plan = _read_json(run_dir / "inputs" / "static_dynamic_plan.json")
        mismatch_class = None
        if isinstance(plan, dict) and isinstance(surface, dict):
            mismatch_class = compute_static_dynamic_cleartext_posture(
                plan,
                {**report, "security_surface": surface},
            ).get("mismatch_class")
        if mismatch_class:
            summary.mismatch_counts[str(mismatch_class)] = summary.mismatch_counts.get(str(mismatch_class), 0) + 1
            if mismatch_class == "denied_but_observed":
                summary.denied_but_observed += 1
        for domain in overlap.get("dynamic_only") or []:
            if domain:
                dynamic_only_hits[str(domain).lower()] += 1

        tls_ratio = _safe_float(proxies.get("tls_ratio"))
        quic_ratio = _safe_float(proxies.get("quic_ratio"))
        if tls_ratio is not None:
            tls_ratios.append(tls_ratio)
        if quic_ratio is not None:
            quic_ratios.append(quic_ratio)

        pcap_bytes = _safe_int(dataset.get("pcap_size_bytes")) or _safe_int(cap.get("file_size_bytes"))
        if pcap_bytes:
            summary.total_pcap_bytes += pcap_bytes

        timeline = _read_json(run_dir / "analysis" / "interaction_timeline.json")
        has_timeline = isinstance(timeline, dict) and bool(timeline.get("steps"))
        if has_timeline:
            summary.scripted_runs += 1

        row = RunUnderstandingRow(
            run_id=run_id,
            package_name=package_name,
            app_label=app_label,
            run_profile=run_profile,
            valid_dataset_run=valid_bool,
            pcap_bytes=pcap_bytes,
            capture_duration_s=_safe_float(cap.get("capture_duration_s") or metrics.get("capture_duration_s")),
            packet_count=_safe_int(cap.get("packet_count")),
            tls_ratio=tls_ratio,
            quic_ratio=quic_ratio,
            tcp_ratio=_safe_float(proxies.get("tcp_ratio")),
            udp_ratio=_safe_float(proxies.get("udp_ratio")),
            unique_dns=_safe_int(inventory.get("dns_unique_count")),
            unique_sni=_safe_int(inventory.get("sni_unique_count")),
            dns_only_count=_safe_int(inventory.get("dns_only_count")),
            sni_only_count=_safe_int(inventory.get("sni_only_count")),
            tls_alert_count=_safe_int(tls.get("tls_alert_count")),
            dns_max_entropy=_safe_float(dns.get("max_label_entropy")),
            security_findings=_safe_int(surface.get("finding_count")) if isinstance(surface, dict) else None,
            visibility_class=str(cleartext.get("visibility_class") or "") or None,
            plaintext_protocols=";".join(str(p) for p in (cleartext.get("plaintext_protocols_observed") or [])),
            decoded_protocols=";".join(str(p) for p in (cleartext.get("decoded_protocols_observed") or [])),
            decoded_stream_count=_safe_int(cleartext.get("decoded_stream_count")),
            mismatch_class=str(mismatch_class) if mismatch_class else None,
            overlap_count=_safe_int(overlap.get("overlap_count")),
            dynamic_only_count=len(overlap.get("dynamic_only") or []) if overlap else None,
            static_only_count=len(overlap.get("static_only") or []) if overlap else None,
            overlap_ratio=_safe_float(overlap.get("overlap_ratio")),
            has_interaction_timeline=has_timeline,
            phase_cleartext_steps=_phase_cleartext_steps(run_dir) if has_timeline else 0,
        )
        summary.rows.append(row)
        if package_name:
            app_buckets[package_name].append(row)

    if tls_ratios:
        summary.transport_tls_median = float(statistics.median(tls_ratios))
    if quic_ratios:
        summary.transport_quic_median = float(statistics.median(quic_ratios))
    summary.top_cohort_domains_dns = dns_domain_hits.most_common(25)
    summary.top_cohort_domains_sni = sni_domain_hits.most_common(25)
    summary.top_dynamic_only_domains = dynamic_only_hits.most_common(25)
    summary.domain_context_rollups = _domain_context_rollups(
        dns_domain_hits,
        sni_domain_hits,
        domain_package_hints,
    )

    for package, rows in sorted(app_buckets.items()):
        app_label = next((r.app_label for r in rows if r.app_label), package)
        tls_vals = [r.tls_ratio for r in rows if r.tls_ratio is not None]
        quic_vals = [r.quic_ratio for r in rows if r.quic_ratio is not None]
        summary.app_rollups.append(
            {
                "package": package,
                "app_label": app_label,
                "runs": len(rows),
                "valid_runs": sum(1 for r in rows if r.valid_dataset_run),
                "pcap_bytes_total": sum(r.pcap_bytes or 0 for r in rows),
                "cleartext_surface_runs": sum(1 for r in rows if r.visibility_class == "cleartext_surface_present"),
                "xmpp_runs": sum(1 for r in rows if "xmpp" in r.plaintext_protocols),
                "denied_but_observed_runs": sum(1 for r in rows if r.mismatch_class == "denied_but_observed"),
                "tls_alert_runs": sum(1 for r in rows if (r.tls_alert_count or 0) > 0),
                "median_tls_ratio": round(float(statistics.median(tls_vals)), 3) if tls_vals else None,
                "median_quic_ratio": round(float(statistics.median(quic_vals)), 3) if quic_vals else None,
                "median_unique_sni": round(float(statistics.median([r.unique_sni or 0 for r in rows])), 1),
                "median_unique_dns": round(float(statistics.median([r.unique_dns or 0 for r in rows])), 1),
                "avg_overlap_ratio": round(
                    sum(r.overlap_ratio or 0 for r in rows) / float(len(rows)),
                    3,
                )
                if rows
                else None,
                "avg_dynamic_only": round(
                    sum(r.dynamic_only_count or 0 for r in rows) / float(len(rows)),
                    1,
                )
                if rows
                else None,
            }
        )
    return summary


def _domain_context_rollups(
    dns_hits: Counter[str],
    sni_hits: Counter[str],
    package_hints: dict[str, str],
) -> list[dict[str, Any]]:
    try:
        from scytaledroid.DynamicAnalysis import domain_context, service_context

        service_rows = tuple(service_context.default_service_catalog_seed_rows())
        map_rows = tuple(service_context.default_service_domain_map_seed_rows())
    except Exception:
        service_rows = ()
        map_rows = ()
        domain_context = None
        service_context = None

    domains = sorted(set(dns_hits) | set(sni_hits), key=lambda d: (-(dns_hits[d] + sni_hits[d]), d))
    rows: list[dict[str, Any]] = []
    for domain in domains:
        package_name = package_hints.get(domain) or ""
        domain_row: dict[str, Any] = {}
        service_row: dict[str, Any] = {}
        if domain_context is not None and package_name:
            domain_row = domain_context.classify_domain(domain, package_name=package_name)
        if service_context is not None and package_name:
            service_row = service_context.resolve_service_for_domain(
                domain,
                package_name=package_name,
                service_rows=service_rows,
                map_rows=map_rows,
            )
        rows.append(
            {
                "domain": domain,
                "package_name": package_name,
                "dns_run_hits": dns_hits.get(domain, 0),
                "sni_run_hits": sni_hits.get(domain, 0),
                "total_run_hits": dns_hits.get(domain, 0) + sni_hits.get(domain, 0),
                "owner_class": domain_row.get("owner_class"),
                "role_class": domain_row.get("role_class"),
                "service_key": service_row.get("service_key"),
                "service_category": service_row.get("service_category"),
                "confidence": domain_row.get("confidence") or service_row.get("confidence"),
            }
        )
    return rows


def render_cohort_understanding_md(summary: CohortUnderstanding) -> str:
    gib = summary.total_pcap_bytes / (1024**3) if summary.total_pcap_bytes else 0
    lines = [
        "# Cohort PCAP Understanding (metadata synthesis)",
        "",
        f"Generated: {summary.generated_at}",
        f"Evidence: `{summary.evidence_root}`",
        "",
        "## Executive summary",
        f"- **{summary.runs_scanned}** evidence packs scanned · **{summary.valid_runs}** valid dataset runs",
        f"- **{summary.runs_with_surface}** with security surface · **{gib:.2f} GB** PCAP total",
        f"- Transport median: TLS ratio **{summary.transport_tls_median or 'n/a'}**, QUIC ratio **{summary.transport_quic_median or 'n/a'}**",
        f"- Cleartext surface: **{summary.cleartext_surface_runs}** runs (HTTP metadata: **{summary.http_metadata_runs}**, XMPP signals: **{summary.xmpp_runs}**)",
        f"- Static denies cleartext but dynamic observed: **{summary.denied_but_observed}** runs",
        f"- TLS alert-bearing runs: **{summary.tls_alert_runs}** · high DNS entropy runs: **{summary.high_dns_entropy_runs}**",
        f"- Scripted interaction timelines: **{summary.scripted_runs}**",
        "",
        "## Cleartext interpretation",
    ]
    if summary.http_metadata_runs == 0:
        lines.append("- No literal HTTP host/path metadata was observed in the selected evidence.")
    else:
        lines.append(f"- HTTP metadata was observed in **{summary.http_metadata_runs}** run(s).")
    if summary.xmpp_runs:
        lines.append("- XMPP-decoded cleartext-surface runs are present; validate handshake/STARTTLS staging before treating as payload exposure.")
        lines.append("- XMPP hits commonly use standard port **5222** with sparse frame counts in this corpus.")
    elif summary.cleartext_surface_runs:
        lines.append("- Cleartext-surface runs are present, but no XMPP signals were observed.")
    else:
        lines.append("- No decoded plaintext protocol surface was observed in the selected evidence.")
    lines.extend(["", "## Plaintext protocol prevalence"])
    if summary.plaintext_protocol_counts:
        for protocol, count in sorted(summary.plaintext_protocol_counts.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"- `{protocol}`: {count} run(s)")
    else:
        lines.append("- none")
    lines.extend(["", "## Static↔dynamic cleartext posture"])
    for key, count in sorted(summary.mismatch_counts.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"- `{key}`: {count}")
    lines.extend(["", "## Top cohort DNS names (unique per-run inventories aggregated)"])
    if summary.top_cohort_domains_dns:
        for domain, count in summary.top_cohort_domains_dns[:15]:
            lines.append(f"- `{domain}`: seen in {count} run(s)")
    else:
        lines.append("- none")
    lines.extend(["", "## Top cohort SNI names"])
    if summary.top_cohort_domains_sni:
        for domain, count in summary.top_cohort_domains_sni[:15]:
            lines.append(f"- `{domain}`: seen in {count} run(s)")
    else:
        lines.append("- none")
    lines.extend(["", "## Domain/service context"])
    if summary.domain_context_rollups:
        for row in summary.domain_context_rollups[:15]:
            lines.append(
                f"- `{row['domain']}`: DNS {row['dns_run_hits']}, SNI {row['sni_run_hits']} · "
                f"{row.get('owner_class') or 'unknown'} / {row.get('role_class') or 'unknown'}"
            )
    else:
        lines.append("- none")
    lines.extend(["", "## Frequent dynamic-only destinations (not in static plan)"])
    if summary.top_dynamic_only_domains:
        for domain, count in summary.top_dynamic_only_domains[:15]:
            lines.append(f"- `{domain}`: {count} run(s)")
    else:
        lines.append("- none")
    lines.extend(["", "## Per-app rollup (transport + visibility)"])
    for app in summary.app_rollups:
        lines.append(
            f"- **{app['app_label']}** (`{app['package']}`): {app['runs']} runs, "
            f"median TLS {app.get('median_tls_ratio')}, QUIC {app.get('median_quic_ratio')}, "
            f"cleartext-surface {app.get('cleartext_surface_runs')}, XMPP {app.get('xmpp_runs')}, "
            f"denied-but-observed {app.get('denied_but_observed_runs')}, "
            f"avg overlap {app.get('avg_overlap_ratio')}, avg dynamic-only domains {app.get('avg_dynamic_only')}"
        )
    lines.extend(["", "## Top risk flags"])
    for flag, count in sorted(summary.risk_flag_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:12]:
        lines.append(f"- `{flag}`: {count}")
    lines.extend(["", "## Manual follow-ups"])
    if summary.xmpp_runs:
        lines.append("- Validate XMPP cleartext dissector hits on affected runs (handshake vs payload exposure).")
    if summary.tls_alert_runs:
        lines.append("- Review TLS alert runs for pinning/mitm or benign close-notify patterns.")
    if summary.top_dynamic_only_domains:
        lines.append("- Curate dynamic-only domains against Permission Intel / domain-context seeds.")
    unknown_context = [
        row
        for row in summary.domain_context_rollups
        if not row.get("owner_class") or row.get("owner_class") == "unknown"
    ]
    if unknown_context:
        lines.append("- Research unresolved domain/service context rows in `domain_context_rollup.csv`.")
    if summary.scripted_runs:
        lines.append("- Cross-check scripted phases with `phase_packet_transport_summary` for step-local cleartext.")
    if not any([summary.xmpp_runs, summary.tls_alert_runs, summary.top_dynamic_only_domains, unknown_context, summary.scripted_runs]):
        lines.append("- No immediate PCAP metadata follow-up was identified by this report.")
    lines.append("")
    return "\n".join(lines)


__all__ = ["CohortUnderstanding", "RunUnderstandingRow", "build_cohort_understanding", "render_cohort_understanding_md"]
