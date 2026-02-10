"""Network trends/audit report over dynamic evidence packs (Paper #2).

This is intentionally DB-optional and evidence-pack-only (air-gapped friendly).
It does not attempt payload inspection or decryption. It summarizes:
- transport mix proxies (TLS/QUIC/TCP/UDP ratios)
- intensity proxies (bytes/sec, packets/sec)
- endpoint hints (top DNS / top SNI) and stability across runs
- baseline vs interactive comparisons

Outputs are written under: output/batches/dynamic/
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config


def _utcnow_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _dynamic_evidence_root() -> Path:
    return Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"


def _batches_root() -> Path:
    return Path(app_config.OUTPUT_DIR) / "batches" / "dynamic"


def _coerce_float(v: object) -> float | None:
    try:
        return float(v)  # type: ignore[arg-type]
    except Exception:
        return None


def _coerce_int(v: object) -> int | None:
    try:
        return int(v)  # type: ignore[arg-type]
    except Exception:
        return None


def _safe_median(values: list[float]) -> float | None:
    if not values:
        return None
    try:
        return float(statistics.median(values))
    except Exception:
        return None


def _safe_p95(values: list[float]) -> float | None:
    if not values:
        return None
    try:
        xs = sorted(values)
        # Deterministic percentile index (nearest-rank, inclusive).
        k = max(0, min(len(xs) - 1, int(round(0.95 * (len(xs) - 1)))))
        return float(xs[k])
    except Exception:
        return None


def _safe_min(values: list[float]) -> float | None:
    return float(min(values)) if values else None


def _safe_max(values: list[float]) -> float | None:
    return float(max(values)) if values else None


def _fmt_bytes(n: int | None) -> str:
    if n is None:
        return "—"
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n / 1024.0:.1f}KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024.0 * 1024.0):.1f}MB"
    return f"{n / (1024.0 * 1024.0 * 1024.0):.1f}GB"


def _profile_bucket(run_profile: str | None) -> str:
    if not run_profile:
        return "unknown"
    p = run_profile.lower()
    if "baseline" in p or "idle" in p or "minimal" in p:
        return "baseline"
    if "interactive" in p:
        return "interactive"
    return "other"


def _load_app_labels(packages: set[str], *, enrich_db_labels: bool) -> dict[str, str]:
    if not packages or not enrich_db_labels:
        return {}
    from scytaledroid.Database.db_func.apps.app_labels import fetch_display_name_map

    return fetch_display_name_map(packages)


def _top_values(report: dict[str, Any] | None, key: str, *, limit: int = 10) -> list[str]:
    if not isinstance(report, dict):
        return []
    items = report.get(key)
    if not isinstance(items, list):
        return []
    out: list[str] = []
    for e in items:
        if not isinstance(e, dict):
            continue
        v = e.get("value")
        if isinstance(v, str) and v.strip():
            out.append(v.strip())
        if len(out) >= limit:
            break
    return out


def _jaccard(a: set[str], b: set[str]) -> float | None:
    if not a and not b:
        return None
    u = a | b
    if not u:
        return None
    return float(len(a & b) / len(u))


@dataclass(frozen=True)
class RunAudit:
    run_id: str
    package_name: str
    display_name: str
    ended_at: str
    run_profile: str
    bucket: str
    interaction_level: str
    valid_dataset_run: bool | None
    invalid_reason_code: str | None
    countable: bool | None
    sampling_duration_s: float | None
    pcap_size_bytes: int | None
    bytes_per_sec: float | None
    packets_per_sec: float | None
    tls_ratio: float | None
    quic_ratio: float | None
    tcp_ratio: float | None
    udp_ratio: float | None
    unique_sni_topn: float | None
    unique_dns_topn: float | None
    sni_concentration: float | None
    dns_concentration: float | None
    domains_per_min: float | None
    unique_dst_ip_count: float | None
    unique_dst_port_count: float | None
    burstiness_bytes_p95_over_p50: float | None
    burstiness_packets_p95_over_p50: float | None
    top_sni: list[str]
    top_dns: list[str]
    notes: list[str]


def _load_run_audit(run_dir: Path, *, display_name: str, package_name: str) -> RunAudit | None:
    mf = _read_json(run_dir / "run_manifest.json") or {}
    ds = mf.get("dataset") if isinstance(mf.get("dataset"), dict) else {}
    op = mf.get("operator") if isinstance(mf.get("operator"), dict) else {}
    ended_at = str(mf.get("ended_at") or "")
    # Dataset block is authoritative for Paper #2. Operator is legacy mirror.
    run_profile = str(ds.get("run_profile") or op.get("run_profile") or "")
    interaction_level = str(ds.get("interaction_level") or op.get("interaction_level") or "")

    # metrics/proxies are the canonical derived inputs for Paper #2 ML.
    features = _read_json(run_dir / "analysis" / "pcap_features.json") or {}
    metrics = features.get("metrics") if isinstance(features.get("metrics"), dict) else {}
    proxies = features.get("proxies") if isinstance(features.get("proxies"), dict) else {}

    report = _read_json(run_dir / "analysis" / "pcap_report.json") or {}

    # Best-effort PCAP byte count (prefer report/capinfos; fall back to manifest artifact size).
    pcap_size_bytes = _coerce_int(ds.get("pcap_size_bytes"))
    if pcap_size_bytes is None:
        pcap_size_bytes = _coerce_int(report.get("pcap_size_bytes")) or _coerce_int(report.get("bytes_total"))
    if pcap_size_bytes is None:
        for art in mf.get("artifacts") or []:
            if not isinstance(art, dict):
                continue
            if art.get("type") == "pcapdroid_capture":
                pcap_size_bytes = _coerce_int(art.get("size_bytes"))
                break

    notes: list[str] = []
    if (report.get("report_status") or "").lower() not in ("ok", "success", ""):
        notes.append(f"pcap_report_status:{report.get('report_status')}")
    missing_tools = report.get("missing_tools")
    if isinstance(missing_tools, list) and missing_tools:
        notes.append("missing_tools:" + ",".join(str(x) for x in missing_tools))

    return RunAudit(
        run_id=str(mf.get("dynamic_run_id") or run_dir.name),
        package_name=package_name,
        display_name=display_name,
        ended_at=ended_at,
        run_profile=run_profile,
        bucket=_profile_bucket(run_profile),
        interaction_level=interaction_level,
        valid_dataset_run=ds.get("valid_dataset_run"),
        invalid_reason_code=ds.get("invalid_reason_code"),
        countable=ds.get("countable"),
        sampling_duration_s=_coerce_float(ds.get("sampling_duration_seconds")),
        pcap_size_bytes=pcap_size_bytes,
        bytes_per_sec=_coerce_float(metrics.get("bytes_per_sec")),
        packets_per_sec=_coerce_float(metrics.get("packets_per_sec")),
        tls_ratio=_coerce_float(proxies.get("tls_ratio")),
        quic_ratio=_coerce_float(proxies.get("quic_ratio")),
        tcp_ratio=_coerce_float(proxies.get("tcp_ratio")),
        udp_ratio=_coerce_float(proxies.get("udp_ratio")),
        unique_sni_topn=_coerce_float(proxies.get("unique_sni_topn")),
        unique_dns_topn=_coerce_float(proxies.get("unique_dns_topn")),
        sni_concentration=_coerce_float(proxies.get("sni_concentration")),
        dns_concentration=_coerce_float(proxies.get("dns_concentration")),
        domains_per_min=_coerce_float(proxies.get("domains_per_min")),
        unique_dst_ip_count=_coerce_float(proxies.get("unique_dst_ip_count")),
        unique_dst_port_count=_coerce_float(proxies.get("unique_dst_port_count")),
        burstiness_bytes_p95_over_p50=_coerce_float(metrics.get("burstiness_bytes_p95_over_p50")),
        burstiness_packets_p95_over_p50=_coerce_float(metrics.get("burstiness_packets_p95_over_p50")),
        top_sni=_top_values(report, "top_sni", limit=10),
        top_dns=_top_values(report, "top_dns", limit=10),
        notes=notes,
    )


def run_dynamic_evidence_network_audit(
    *,
    enrich_db_labels: bool = True,
    write_outputs: bool = True,
) -> dict[str, Any]:
    root = _dynamic_evidence_root()
    run_dirs = sorted([p for p in root.iterdir()] if root.exists() else [], key=lambda p: p.name)

    packages: set[str] = set()
    manifests: list[tuple[Path, dict[str, Any]]] = []
    for rd in run_dirs:
        if not rd.is_dir():
            continue
        mf = _read_json(rd / "run_manifest.json")
        if not mf:
            continue
        target = mf.get("target") if isinstance(mf.get("target"), dict) else {}
        pkg = target.get("package_name") if isinstance(target, dict) else None
        if isinstance(pkg, str) and pkg.strip():
            packages.add(pkg.strip())
        manifests.append((rd, mf))

    labels = _load_app_labels(packages, enrich_db_labels=enrich_db_labels)

    per_app: dict[str, list[RunAudit]] = {}
    for rd, mf in manifests:
        target = mf.get("target") if isinstance(mf.get("target"), dict) else {}
        pkg = str((target or {}).get("package_name") or "").strip()
        if not pkg:
            continue
        name = labels.get(pkg, pkg)
        ra = _load_run_audit(rd, display_name=name, package_name=pkg)
        if not ra:
            continue
        per_app.setdefault(pkg, []).append(ra)

    apps_out: list[dict[str, Any]] = []
    for pkg in sorted(per_app.keys(), key=lambda p: labels.get(p, p).lower()):
        runs = sorted(per_app[pkg], key=lambda r: (r.ended_at or "", r.run_id))
        name = labels.get(pkg, pkg)

        # Stability based on top SNI/DNS sets (top10 only).
        sni_sets = [set(r.top_sni) for r in runs if r.top_sni]
        dns_sets = [set(r.top_dns) for r in runs if r.top_dns]
        sni_j = []
        dns_j = []
        for i in range(len(sni_sets)):
            for j in range(i + 1, len(sni_sets)):
                v = _jaccard(sni_sets[i], sni_sets[j])
                if v is not None:
                    sni_j.append(v)
        for i in range(len(dns_sets)):
            for j in range(i + 1, len(dns_sets)):
                v = _jaccard(dns_sets[i], dns_sets[j])
                if v is not None:
                    dns_j.append(v)

        def _bucket_vals(bucket: str, key: str) -> list[float]:
            xs: list[float] = []
            for r in runs:
                if r.bucket != bucket:
                    continue
                v = getattr(r, key)
                if isinstance(v, (int, float)):
                    xs.append(float(v))
            return xs

        baseline_bps = _bucket_vals("baseline", "bytes_per_sec")
        interactive_bps = _bucket_vals("interactive", "bytes_per_sec")
        baseline_quic = _bucket_vals("baseline", "quic_ratio")
        interactive_quic = _bucket_vals("interactive", "quic_ratio")
        baseline_pps = _bucket_vals("baseline", "packets_per_sec")
        interactive_pps = _bucket_vals("interactive", "packets_per_sec")
        baseline_domains_per_min = _bucket_vals("baseline", "domains_per_min")
        interactive_domains_per_min = _bucket_vals("interactive", "domains_per_min")

        def _pct_delta(a: float | None, b: float | None) -> float | None:
            if a is None or b is None:
                return None
            if a == 0:
                return None
            try:
                return float((b - a) / a)
            except Exception:
                return None

        baseline_bps_med = _safe_median(baseline_bps)
        interactive_bps_med = _safe_median(interactive_bps)
        baseline_pps_med = _safe_median(baseline_pps)
        interactive_pps_med = _safe_median(interactive_pps)

        apps_out.append(
            {
                "package_name": pkg,
                "display_name": name,
                "runs_total": len(runs),
                "runs_valid_dataset": sum(1 for r in runs if r.valid_dataset_run is True),
                "runs_invalid_dataset": sum(1 for r in runs if r.valid_dataset_run is False),
                "stability": {
                    "top_sni_pairwise_jaccard_median": _safe_median(sni_j),
                    "top_sni_pairwise_jaccard_p95": _safe_p95(sni_j),
                    "top_dns_pairwise_jaccard_median": _safe_median(dns_j),
                    "top_dns_pairwise_jaccard_p95": _safe_p95(dns_j),
                },
                "baseline": {
                    "runs": sum(1 for r in runs if r.bucket == "baseline"),
                    "bytes_per_sec_min": _safe_min(baseline_bps),
                    "bytes_per_sec_median": baseline_bps_med,
                    "bytes_per_sec_max": _safe_max(baseline_bps),
                    "quic_ratio_median": _safe_median(baseline_quic),
                    "packets_per_sec_median": baseline_pps_med,
                    "domains_per_min_median": _safe_median(baseline_domains_per_min),
                },
                "interactive": {
                    "runs": sum(1 for r in runs if r.bucket == "interactive"),
                    "bytes_per_sec_min": _safe_min(interactive_bps),
                    "bytes_per_sec_median": interactive_bps_med,
                    "bytes_per_sec_max": _safe_max(interactive_bps),
                    "quic_ratio_median": _safe_median(interactive_quic),
                    "packets_per_sec_median": interactive_pps_med,
                    "domains_per_min_median": _safe_median(interactive_domains_per_min),
                },
                "highlights": {
                    "delta_bytes_per_sec_median_pct": _pct_delta(baseline_bps_med, interactive_bps_med),
                    "delta_packets_per_sec_median_pct": _pct_delta(baseline_pps_med, interactive_pps_med),
                    "baseline_invalid_runs": sum(1 for r in runs if r.bucket == "baseline" and r.valid_dataset_run is False),
                    "interactive_invalid_runs": sum(
                        1 for r in runs if r.bucket == "interactive" and r.valid_dataset_run is False
                    ),
                },
                "runs": [
                    {
                        "run_id": r.run_id,
                        "ended_at": r.ended_at,
                        "run_profile": r.run_profile,
                        "bucket": r.bucket,
                        "interaction_level": r.interaction_level,
                        "valid_dataset_run": r.valid_dataset_run,
                        "invalid_reason_code": r.invalid_reason_code,
                        "countable": r.countable,
                        "sampling_duration_s": r.sampling_duration_s,
                        "pcap_size_bytes": r.pcap_size_bytes,
                        "pcap_size": _fmt_bytes(r.pcap_size_bytes),
                        "bytes_per_sec": r.bytes_per_sec,
                        "packets_per_sec": r.packets_per_sec,
                        "tls_ratio": r.tls_ratio,
                        "quic_ratio": r.quic_ratio,
                        "tcp_ratio": r.tcp_ratio,
                        "udp_ratio": r.udp_ratio,
                        "unique_sni_topn": r.unique_sni_topn,
                        "unique_dns_topn": r.unique_dns_topn,
                        "sni_concentration": r.sni_concentration,
                        "dns_concentration": r.dns_concentration,
                        "domains_per_min": r.domains_per_min,
                        "unique_dst_ip_count": r.unique_dst_ip_count,
                        "unique_dst_port_count": r.unique_dst_port_count,
                        "burstiness_bytes_p95_over_p50": r.burstiness_bytes_p95_over_p50,
                        "burstiness_packets_p95_over_p50": r.burstiness_packets_p95_over_p50,
                        "top_sni": r.top_sni,
                        "top_dns": r.top_dns,
                        "notes": r.notes,
                    }
                    for r in runs
                ],
            }
        )

    out = {
        "generated_at": _utcnow_iso(),
        "evidence_root": str(root),
        "packs_total": len(manifests),
        "apps_total": len(apps_out),
        "apps": apps_out,
        "notes": [
            "This report is metadata-only. It does not inspect payload content or decrypt TLS/QUIC.",
            "Top DNS/SNI lists are capped to top-10 per run for operator readability.",
        ],
    }

    if write_outputs:
        _batches_root().mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        json_path = _batches_root() / f"audit-network-{stamp}.json"
        md_path = _batches_root() / f"audit-network-{stamp}.md"
        json_path.write_text(json.dumps(out, indent=2, sort_keys=True), encoding="utf-8")
        md_path.write_text(_render_markdown(out), encoding="utf-8")
        out["report_paths"] = {"json": str(json_path), "md": str(md_path)}

    return out


def _render_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Dynamic Network Audit (Evidence Packs)")
    lines.append("")
    lines.append(f"- Generated at: `{report.get('generated_at')}`")
    lines.append(f"- Evidence root: `{report.get('evidence_root')}`")
    lines.append(f"- Packs: `{report.get('packs_total')}`")
    lines.append(f"- Apps: `{report.get('apps_total')}`")
    lines.append("")

    for app in report.get("apps") or []:
        if not isinstance(app, dict):
            continue
        name = str(app.get("display_name") or app.get("package_name") or "<?>")
        pkg = str(app.get("package_name") or "<?>")
        lines.append(f"## {name}")
        if name != pkg:
            lines.append(f"- Package: `{pkg}`")
        lines.append(
            f"- Runs: total={app.get('runs_total')} valid={app.get('runs_valid_dataset')} invalid={app.get('runs_invalid_dataset')}"
        )
        stab = app.get("stability") if isinstance(app.get("stability"), dict) else {}
        lines.append(
            "- Stability (top-10 sets): "
            f"SNI jaccard median={stab.get('top_sni_pairwise_jaccard_median')} "
            f"DNS jaccard median={stab.get('top_dns_pairwise_jaccard_median')}"
        )
        b = app.get("baseline") if isinstance(app.get("baseline"), dict) else {}
        i = app.get("interactive") if isinstance(app.get("interactive"), dict) else {}
        h = app.get("highlights") if isinstance(app.get("highlights"), dict) else {}
        lines.append(
            "- Baseline: "
            f"runs={b.get('runs')} bytes/sec median={b.get('bytes_per_sec_median')} "
            f"pps median={b.get('packets_per_sec_median')} quic median={b.get('quic_ratio_median')}"
        )
        lines.append(
            "- Interactive: "
            f"runs={i.get('runs')} bytes/sec median={i.get('bytes_per_sec_median')} "
            f"pps median={i.get('packets_per_sec_median')} quic median={i.get('quic_ratio_median')}"
        )
        if h:
            lines.append(
                "- Highlights: "
                f"delta bytes/sec median={h.get('delta_bytes_per_sec_median_pct')} "
                f"delta pps median={h.get('delta_packets_per_sec_median_pct')} "
                f"invalid baseline={h.get('baseline_invalid_runs')} invalid interactive={h.get('interactive_invalid_runs')}"
            )
        lines.append("")
        lines.append("| run_id | bucket | profile | valid | sampling_s | pcap | bps | pps | tls | quic | top_sni_1 | top_dns_1 |")
        lines.append("|---|---|---|---|---:|---:|---:|---:|---:|---:|---|---|")
        for r in app.get("runs") or []:
            if not isinstance(r, dict):
                continue
            valid = r.get("valid_dataset_run")
            valid_s = "VALID" if valid is True else ("INVALID" if valid is False else "—")
            sni = (r.get("top_sni") or [])
            dns = (r.get("top_dns") or [])
            sni1 = sni[0] if isinstance(sni, list) and sni else "—"
            dns1 = dns[0] if isinstance(dns, list) and dns else "—"
            lines.append(
                f"| `{str(r.get('run_id') or '')[:8]}`"
                f" | {r.get('bucket') or '—'}"
                f" | {r.get('run_profile') or '—'}"
                f" | {valid_s}"
                f" | {r.get('sampling_duration_s') or '—'}"
                f" | {r.get('pcap_size') or '—'}"
                f" | {r.get('bytes_per_sec') if r.get('bytes_per_sec') is not None else '—'}"
                f" | {r.get('packets_per_sec') if r.get('packets_per_sec') is not None else '—'}"
                f" | {r.get('tls_ratio') if r.get('tls_ratio') is not None else '—'}"
                f" | {r.get('quic_ratio') if r.get('quic_ratio') is not None else '—'}"
                f" | {sni1}"
                f" | {dns1}"
                " |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


__all__ = ["run_dynamic_evidence_network_audit"]
