"""Formatter-backed views for static analysis CLI output.

These helpers render RUN START and RUN SUMMARY blocks using the shared
forensic formatter so downstream code does not duplicate text/layout.
"""

from __future__ import annotations

from typing import Mapping, Sequence

from scytaledroid.Utils.DisplayUtils import status_messages


def render_run_start(
    *,
    run_id: str,
    profile_label: str,
    target: str,
    modules: Sequence[str],
    workers_desc: str,
    cache_desc: str,
    log_level: str,
    perm_cache_desc: str,
    trace_ids: Sequence[str] | None = None,
) -> None:
    status_messages.print_strip(
        "Static Analysis · Configuration",
        [
            ("Type", "static"),
            ("Target", target),
            ("Profile", profile_label),
            ("Run ID", run_id),
        ],
    )
    print()

    meta_pairs = [
        ("Workers", workers_desc),
        ("Cache", cache_desc),
        ("Log level", log_level.upper()),
        ("Perm cache", perm_cache_desc),
    ]
    if modules:
        meta_pairs.append(("Detectors", ", ".join(modules)))
    if trace_ids:
        meta_pairs.append(("Trace IDs", ", ".join(trace_ids)))

    status_messages.print_strip("Static Analysis · Settings", meta_pairs)
    print()


def render_run_summary(
    *,
    run_id: str,
    profile_label: str,
    target: str,
    detectors_count: int,
    findings_total: int,
    sev_counts: Mapping[str, int],
    failed_masvs: Sequence[str],
    perm_stats: Mapping[str, int],
    evidence_root: str | None = None,
) -> None:
    status_messages.print_strip(
        "Static Analysis · Complete",
        [
            ("Run ID", run_id),
            ("Target", target),
            ("Profile", profile_label),
        ],
    )
    print()

    masvs_summary = f"{len(failed_masvs)} controls failed"
    if failed_masvs:
        masvs_summary += f" (e.g., {', '.join(list(failed_masvs)[:2])})"

    severity = (
        f"High={sev_counts.get('high', 0)}  "
        f"Medium={sev_counts.get('medium', 0)}  "
        f"Low={sev_counts.get('low', 0)}"
    )
    perm_summary = (
        f"Dangerous={perm_stats.get('dangerous', 0)}  "
        f"Signature={perm_stats.get('signature', 0)}  "
        f"Custom={perm_stats.get('custom', 0)}"
    )

    status_messages.print_strip(
        "Static Analysis · Results",
        [
            ("Detectors run", f"{detectors_count} modules"),
            ("Total findings", str(findings_total)),
            ("Severity", severity),
            ("MASVS coverage", masvs_summary),
            ("Permissions", perm_summary),
        ],
    )
    print()

    if evidence_root:
        status_messages.print_strip(
            "Static Analysis · Evidence",
            [("Evidence root", evidence_root)],
        )
        print()
