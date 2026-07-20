"""One-per-run operator notes for multi-app profile/all cohorts (skipped stubs, string rollup)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from scytaledroid.Utils.DisplayUtils import status_messages

from ..core.models import AppRunResult, RunOutcome, RunParameters
from ..core.run_context import StaticRunContext
from .scan_report import _summarize_app_pipeline


def suppress_per_app_cohort_echoes(params: RunParameters, app_total: int | None) -> bool:
    """When True, per-app CLI blocks defer to the cohort footer printed once at end of scan."""
    return bool(
        params.scope in {"all", "profile", "research_cohort"}
        and (app_total or 0) >= 2
        and not params.verbose_output
    )


def emit_post_scan_cohort_notes(
    outcome: RunOutcome,
    params: RunParameters,
    *,
    run_ctx: StaticRunContext | None = None,
) -> None:
    """Print skipped-detector and string-rollup cohort summaries once (non-verbose multi-app)."""
    if run_ctx is not None and run_ctx.quiet and run_ctx.batch:
        return
    if outcome.aborted:
        return
    if params.scope not in {"all", "profile", "research_cohort"}:
        return
    if len(outcome.results) < 2:
        return
    if params.verbose_output:
        return

    apps = list(outcome.results)
    _emit_uniform_placeholder_skips(apps)
    _emit_string_rollup_cohort_line(apps, total=len(apps))


def _detector_key(row: Mapping[str, object]) -> str:
    det = str(row.get("detector") or row.get("section") or "").strip()
    return det or "?"


def _emit_uniform_placeholder_skips(apps: Sequence[AppRunResult]) -> None:
    sigs: list[frozenset[str]] = []
    for app in apps:
        summary = _summarize_app_pipeline(app)
        raw = summary.get("placeholder_detectors")
        if not isinstance(raw, list):
            sigs.append(frozenset())
            continue
        keys: set[str] = set()
        for row in raw:
            if not isinstance(row, Mapping):
                continue
            keys.add(_detector_key(row))
        sigs.append(frozenset(keys))

    if not sigs or not sigs[0]:
        return
    first = sigs[0]
    if not all(s == first for s in sigs):
        print(
            status_messages.status(
                "Skipped detectors differ by app for this cohort — see each app's report JSON or run_health.json.",
                level="info",
                show_icon=False,
                show_prefix=False,
            )
        )
        return

    ordered = sorted(first)
    if not ordered:
        return
    # Placeholder/stub skips share long reason text; list ids only for readability.
    lines = "\n".join(f"  • {name}" for name in ordered)
    print()
    print(
        status_messages.status(
            (
                f"Skipped detectors (same for all {len(apps)} apps)\n"
                f"{lines}\n"
                "Reason: placeholder / not implemented in current pipeline build."
            ),
            level="info",
            show_icon=False,
            show_prefix=False,
        )
    )


def _emit_string_rollup_cohort_line(apps: Sequence[AppRunResult], *, total: int) -> None:
    split_apps = [
        a for a in apps if int(getattr(a, "discovered_artifacts", 0) or 0) > 1
    ]
    if not split_apps:
        return
    merged_apps = sum(
        1
        for app in split_apps
        if str(
            (getattr(app, "base_string_data", {}) or {}).get("aggregation_scope") if isinstance(getattr(app, "base_string_data", None), Mapping) else ""
        ).strip().lower()
        == "artifact_merged"
    )
    print(
        status_messages.status(
            (
                "String rollup summary: split APKs were scanned per configuration and post-run "
                "string payloads are merged per app when artifact payload coverage is available.\n"
                f"Split-app coverage: merged={merged_apps}/{len(split_apps)} across {total} app(s) in this cohort."
            ),
            level="info",
            show_icon=False,
            show_prefix=False,
        )
    )


__all__ = [
    "emit_post_scan_cohort_notes",
    "suppress_per_app_cohort_echoes",
]
