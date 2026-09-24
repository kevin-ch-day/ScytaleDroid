"""Versioned, offline hostname relations; never overwrite legacy overlap output."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
from urllib.parse import urlsplit

import idna
from publicsuffixlist import PublicSuffixList
from scytaledroid.Utils.domain_identity import registrable_domain_resolver_metadata

CONTRACT = "hostname_overlap_v2"
_PSL = PublicSuffixList(accept_unknown=False)
_SYNTHETIC = {"localhost", "local", "invalid", "test", "example"}


def normalize_host(value: object) -> dict:
    """Preserve every raw input and an explicit normalization/exclusion reason."""
    row = {
        "raw": value,
        "host": None,
        "kind": "MALFORMED",
        "reason": None,
        "registrable_domain": None,
    }
    if not isinstance(value, str) or not value.strip():
        row["reason"] = "empty_or_nonstring"
        return row
    raw = value.strip()
    if raw.startswith("*."):
        raw = raw[2:]
        row["wildcard_removed"] = True
    try:
        # Plain IPv6 is an address, never a URL authority split into a hostname.
        try:
            ipaddress.ip_address(raw.strip("[]"))
            row.update(kind="IP_ADDRESS", host=raw.lower(), reason="excluded_ip_literal")
            return row
        except ValueError:
            pass
        parsed = urlsplit(raw if "://" in raw else "//" + raw)
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("userinfo_not_a_host")
        host = parsed.hostname
        _ = parsed.port  # Validate port syntax/range even though not part of host identity.
        if not host or any(c.isspace() for c in host):
            raise ValueError("missing_or_spaced_host")
        if host.endswith("."):
            host = host[:-1]
        host = (
            idna.encode(host, uts46=True, transitional=False, std3_rules=True)
            .decode("ascii")
            .lower()
        )
        if len(host) > 253:
            raise ValueError("host_too_long")
        try:
            ipaddress.ip_address(host)
            row.update(kind="IP_ADDRESS", host=host, reason="excluded_ip_literal")
            return row
        except ValueError:
            pass
        if all(c.isdigit() or c == "." for c in host):
            raise ValueError("ambiguous_numeric_address")
        row["host"] = host
        if _PSL.publicsuffix(host) == host and host.rsplit(".", 1)[-1] not in _SYNTHETIC:
            row.update(kind="PUBLIC_SUFFIX_ONLY", reason="no_registrant_label")
            return row
        if "." not in host or host.rsplit(".", 1)[-1] in _SYNTHETIC:
            row.update(kind="SYNTHETIC_OR_LOCAL", reason="not_public_dns_host")
            return row
        registrable = _PSL.privatesuffix(host)
        if registrable:
            row.update(kind="DNS_HOST", registrable_domain=str(registrable), reason=None)
        elif _PSL.publicsuffix(host) == host:
            row.update(kind="PUBLIC_SUFFIX_ONLY", reason="no_registrant_label")
        else:
            row.update(kind="UNKNOWN_SUFFIX", reason="exact_and_relation_only_no_psl_fallback")
        return row
    except (ValueError, UnicodeError, idna.IDNAError) as exc:
        row["reason"] = str(exc) or type(exc).__name__
        return row


def correlate_hosts(static_values, dynamic_values) -> dict:
    static = [normalize_host(v) for v in static_values]
    dynamic = [normalize_host(v) for v in dynamic_values]
    eligible = {"DNS_HOST", "UNKNOWN_SUFFIX"}
    s = {r["host"] for r in static if r["kind"] in eligible}
    d = {r["host"] for r in dynamic if r["kind"] in eligible}
    exact = sorted(s & d)
    pairs = [
        {
            "static_host": a,
            "dynamic_host": b,
            "relation": "equal" if a == b else "dynamic_descendant",
        }
        for a in sorted(s)
        for b in sorted(d)
        if b == a or b.endswith("." + a)
    ]
    sr = {r["registrable_domain"] for r in static if r["kind"] == "DNS_HOST"}
    dr = {r["registrable_domain"] for r in dynamic if r["kind"] == "DNS_HOST"}
    common = sorted(sr & dr)

    def ratio(n, total):
        return n / total if total else None

    meta = registrable_domain_resolver_metadata().copy()
    meta["unknown_suffix_fallback"] = "none"
    return {
        "contract": CONTRACT,
        "normalization": "IDNA_UTS46_nontransitional_STD3_lowercase_one_trailing_root_dot_v2",
        "psl": meta,
        "inputs": {"static": static, "dynamic": dynamic},
        "exact_host_overlap_v2": {
            "count": len(exact),
            "hosts": exact,
            "static_denominator": len(s),
            "dynamic_denominator": len(d),
            "static_coverage": ratio(len(exact), len(s)),
            "dynamic_coverage": ratio(len(exact), len(d)),
        },
        "subdomain_relation_overlap_v2": {
            "direction": "static_equal_or_parent_of_dynamic",
            "pairs": pairs,
            "matched_static_count": len({x["static_host"] for x in pairs}),
            "matched_dynamic_count": len({x["dynamic_host"] for x in pairs}),
            "static_denominator": len(s),
            "dynamic_denominator": len(d),
            "static_coverage": ratio(len({x["static_host"] for x in pairs}), len(s)),
            "dynamic_coverage": ratio(len({x["dynamic_host"] for x in pairs}), len(d)),
        },
        "registrable_domain_overlap_v2": {
            "count": len(common),
            "domains": common,
            "static_denominator": len(sr),
            "dynamic_denominator": len(dr),
            "static_coverage": ratio(len(common), len(sr)),
            "dynamic_coverage": ratio(len(common), len(dr)),
        },
        "interpretation": "Relations are not ownership, app attribution, safety or correctness verdicts; excluded inputs remain explicit.",
    }


def _dynamic_raw_values(report: dict) -> list:
    """Keep malformed/empty values explicit instead of using the lossy V1 set."""
    values = []
    for key in ("top_dns", "top_sni"):
        for item in report.get(key) or []:
            if isinstance(item, dict) and "value" in item:
                values.append(item["value"])
            elif not isinstance(item, dict):
                values.append(item)
    surface = report.get("security_surface")
    inventory = surface.get("domain_inventory") if isinstance(surface, dict) else None
    if isinstance(inventory, dict):
        for key in ("dns_names", "sni_names"):
            values.extend(inventory.get(key) or [])
    return values


def write_hostname_overlap_v2(manifest, run_dir: Path):
    """Prospective additive output; sealed packs and existing v2 files are refused."""
    from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord
    from scytaledroid.DynamicAnalysis.utils.path_utils import resolve_contained_path

    run_dir = Path(run_dir)
    if (run_dir / "run_manifest.json").exists():
        raise RuntimeError("Cannot analyze into sealed pack")
    plan_rel = manifest.target.get("static_plan_path")
    if not plan_rel:
        return None
    plan_path = resolve_contained_path(run_dir, str(plan_rel))
    report_path = run_dir / "analysis/pcap_report.json"
    if plan_path is None or not plan_path.is_file() or not report_path.is_file():
        return None
    plan = json.loads(plan_path.read_text())
    report = json.loads(report_path.read_text())
    result = correlate_hosts(
        (plan.get("network_targets") or {}).get("domains") or [], _dynamic_raw_values(report)
    )
    result["input_sha256"] = {
        "static_plan": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
        "pcap_report": hashlib.sha256(report_path.read_bytes()).hexdigest(),
    }
    path = run_dir / "analysis/hostname_overlap_v2.json"
    with path.open("x") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")
    return ArtifactRecord(
        "analysis/hostname_overlap_v2.json",
        CONTRACT,
        CONTRACT,
        hashlib.sha256(path.read_bytes()).hexdigest(),
        path.stat().st_size,
        origin="host",
        pull_status="n/a",
    )
