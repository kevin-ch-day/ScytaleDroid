"""Formatting helpers for static analysis scan execution."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path

from ..core.models import AppRunResult, RunOutcome, ScopeSelection
from ..flows.profile_prior_session import format_grain_integrity_session_command
from .run_health.rollup import rollup_parse_fallback_signals

# Column widths for plain-text progress (terminal-friendly; no box drawing).
_KV_W_TOP = 16
_KV_W_SUB = 18

# Align continuation heartbeat under typical ``ℹ [INFO] `` prefix width.
_HEARTBEAT_CONTINUATION_INDENT = "         "

PIPELINE_EVENTS_SECTION_TITLE = "Detector-stage events so far"


def _pipeline_counts_five(agg_checks: Counter[str]) -> tuple[int, int, int, int, int]:
    """Return (ok, warn, policy_gate_failures, finding_gate_failures, execution_errors)."""

    ok = int(agg_checks.get("ok", 0) or 0)
    warn = int(agg_checks.get("warn", 0) or 0)
    pol = int(agg_checks.get("policy_fail", 0) or 0)
    fnd = int(agg_checks.get("finding_fail", 0) or 0)
    err = int(agg_checks.get("error", 0) or 0)
    legacy = int(agg_checks.get("fail", 0) or 0)
    if pol == 0 and fnd == 0 and legacy > 0:
        # Older callers only incremented ``fail`` (policy + finding combined).
        pol, fnd = legacy, 0
    return ok, warn, pol, fnd, err


def _append_pipeline_events_table(
    lines: list[str],
    agg_checks: Counter[str],
    *,
    concise: bool,
    verbose_metrics: bool = False,
    section_title: str | None = None,
) -> None:
    """Append live detector-stage roll-up rows (session totals across completed packages)."""

    ok, warn, pol, fnd, err = _pipeline_counts_five(agg_checks)
    skip = int(agg_checks.get("skipped_stages", 0) or 0)
    parse_est = int(agg_checks.get("parse_signals_est", 0) or 0)
    label_w = 30
    lines.append(str(section_title or PIPELINE_EVENTS_SECTION_TITLE).strip() or PIPELINE_EVENTS_SECTION_TITLE)
    if verbose_metrics:
        rows: tuple[tuple[str, int], ...] = (
            ("OK detector stages", ok),
            ("WARN detector stages", warn),
            ("Policy gate failures", pol),
            ("Finding gate failures", fnd),
            ("Execution errors", err),
            ("Skipped detector stages", skip),
            ("Parse / resource signals (est.)", parse_est),
        )
        valw = max((len(str(v)) for _, v in rows), default=1)
        mw = max(valw, len("Count"))
        rule_w = 2 + label_w + 2 + mw
        lines.append("-" * rule_w)
        lines.append(f"  {'Metric':<{label_w}}  {'Count':>{mw}}")
        lines.append("-" * rule_w)
        for label, val in rows:
            lines.append(f"  {label:<{label_w}}  {val:>{mw}}")
    else:
        rows_min: list[tuple[str, int]] = [
            ("Warnings", warn),
            ("Policy failures", pol),
            ("Finding failures", fnd),
            ("Execution errors", err),
        ]
        if parse_est > 0:
            rows_min.append(("Parse / resource signals (est.)", parse_est))
        valw = max((len(str(v)) for _, v in rows_min), default=1)
        mw = max(valw, len("Count"))
        rule_w = 2 + label_w + 2 + mw
        lines.append("-" * rule_w)
        lines.append(f"  {'Metric':<{label_w}}  {'Count':>{mw}}")
        lines.append("-" * rule_w)
        for label, val in rows_min:
            lines.append(f"  {label:<{label_w}}  {val:>{mw}}")
        if skip > 0:
            lines.append(
                f"  {'Skipped stages (cumulative)':<{label_w}}  {skip:>{mw}}  "
                "(profile/applicability skips — normal when detectors do not apply)"
            )
    if err == 0:
        lines.append(
            "  (no execution errors — analyzer/pipeline did not throw)"
            if concise
            else "  (no execution errors — these are not policy/finding gate failures)"
        )
    else:
        lines.append(
            "  → see logs for execution_errors (not the same as gate failures)"
            if concise
            else "  → investigate logs: execution_errors are analyzer/pipeline exceptions, not gates"
        )
    if skip and verbose_metrics and concise:
        lines.append("  (skipped = detector stages not run; see per-app completion for reasons)")
    elif skip and verbose_metrics and not concise:
        lines.append(
            "  (skipped stages = profile/policy omitted detectors; reasons on verbose per-app cards)"
        )
    if parse_est and verbose_metrics:
        lines.append(
            "  (parse est. ≈ resource fallback + ARSC bounds + label/parse hints across artifacts)"
            if concise
            else (
                "  (parse / resource estimate bundles fallback parsers, bounds warnings, "
                "and label-parse hints — see run_health docs)"
            )
        )


def aggregate_session_skip_reasons_from_results(
    results: Sequence[AppRunResult],
    *,
    limit: int = 8,
) -> list[tuple[str, int]]:
    """Read-only: count merged skip ``reason`` strings across finished artifact pipeline summaries."""

    reason_ctr: Counter[str] = Counter()
    for app in results:
        for art in getattr(app, "artifacts", ()) or ():
            rep = getattr(art, "report", None)
            meta = getattr(rep, "metadata", None)
            if not isinstance(meta, Mapping):
                continue
            ps = meta.get("pipeline_summary")
            if not isinstance(ps, Mapping):
                continue
            skips = ps.get("skipped_detectors")
            if not isinstance(skips, list):
                continue
            for row in skips:
                if not isinstance(row, Mapping):
                    continue
                r = str(row.get("reason") or "unspecified").strip() or "unspecified"
                if len(r) > 96:
                    r = r[:93] + "..."
                reason_ctr[r] += 1
    return reason_ctr.most_common(limit)


def aggregate_parse_signals_by_package(
    results: Sequence[AppRunResult],
    *,
    limit: int = 5,
) -> list[tuple[str, int]]:
    """Sum parse / resource pressure per package for top-N display.

    Prefer ``pipeline_summary.parse_fallback_events_est`` on each saved report when
    present; otherwise fall back to :func:`rollup_parse_fallback_signals` so this table
    stays aligned with the session ``parse_signals_est`` heartbeat (artifact-level
    fallback / bounds / label signals).
    """

    pkg_parse: Counter[str] = Counter()
    for app in results:
        pkg = str(getattr(app, "package_name", "") or "").strip() or "?"
        total = 0
        for art in getattr(app, "artifacts", ()) or ():
            rep = getattr(art, "report", None)
            meta = getattr(rep, "metadata", None)
            if not isinstance(meta, Mapping):
                continue
            ps = meta.get("pipeline_summary")
            if isinstance(ps, Mapping):
                total += int(ps.get("parse_fallback_events_est", 0) or 0)
        if total == 0:
            total = int(rollup_parse_fallback_signals(app).get("parse_fallback_events_est", 0) or 0)
        if total > 0:
            pkg_parse[pkg] += total
    return pkg_parse.most_common(limit)


def _format_last_saved_phrase(seconds_ago: int | None) -> str:
    if seconds_ago is None:
        return "—"
    if seconds_ago <= 0:
        return "just now"
    if seconds_ago == 1:
        return "1s ago"
    return f"{seconds_ago}s ago"


def _eta_compact_for_heartbeat(eta_text: str) -> str:
    """Short ETA token for dense heartbeat lines (~1h21m style)."""

    raw = str(eta_text or "").strip()
    if not raw or raw == "--":
        return "pending"
    had_tilde = raw.startswith("~")
    core = raw[1:].strip() if had_tilde else raw
    for old, new in (
        (" mins", "m"),
        (" min", "m"),
        (" hrs", "h"),
        (" hr", "h"),
        (" secs", "s"),
        (" sec", "s"),
    ):
        core = core.replace(old, new)
    core = core.replace(" ", "")
    return f"~{core}"


def format_scan_progress_heartbeat_lines(
    *,
    apps_completed: int,
    total_apps: int,
    artifacts_done: int,
    total_artifacts: int,
    current_app_label: str | None,
    current_package_name: str | None,
    agg_checks: Counter[str],
    eta_text: str,
    archive_reports_written: int | None = None,
    eta_preliminary: bool = False,
) -> tuple[str, str]:
    """Two-line heartbeat: progress + current app (line 1), ETA / reports / errors (line 2)."""

    cur_pkg = str(current_package_name or "").strip()
    cur_lbl = str(current_app_label or "").strip()
    if cur_lbl and cur_pkg and cur_lbl.lower() != cur_pkg.lower():
        cur_tok = cur_lbl
    elif cur_lbl:
        cur_tok = cur_lbl
    elif cur_pkg:
        cur_tok = cur_pkg
    else:
        cur_tok = "—"
    _ok, _warn, _pol, _fnd, err = _pipeline_counts_five(agg_checks)
    _ = _ok, _warn, _pol, _fnd
    eta_raw = str(eta_text or "").strip()
    eta_core = _eta_compact_for_heartbeat(eta_raw)
    if eta_core == "pending" or eta_raw in {"", "--"}:
        eta_disp = "warming up" if eta_preliminary and total_artifacts > 0 else "pending"
    else:
        eta_disp = eta_core
        if eta_preliminary and total_artifacts > 0:
            eta_disp = f"{eta_disp} preliminary"
    if archive_reports_written is not None and total_artifacts > 0:
        rep = f"{int(archive_reports_written)}/{total_artifacts}"
    elif total_artifacts > 0:
        rep = f"0/{total_artifacts}"
    else:
        rep = "—"
    line1 = (
        f"{artifacts_done}/{total_artifacts} APKs · {apps_completed}/{total_apps} pkgs · {cur_tok}"
    )
    line2 = f"ETA {eta_disp} · APK reports {rep} · execution errors {err}"
    return line1, line2


def format_scan_progress_heartbeat(
    *,
    apps_completed: int,
    total_apps: int,
    artifacts_done: int,
    total_artifacts: int,
    current_app_label: str | None,
    current_package_name: str | None,
    agg_checks: Counter[str],
    eta_text: str,
    archive_reports_written: int | None = None,
    eta_preliminary: bool = False,
) -> str:
    """Return line 1 only (backward compat). Use :func:`format_scan_progress_heartbeat_lines` for both."""

    line1, _line2 = format_scan_progress_heartbeat_lines(
        apps_completed=apps_completed,
        total_apps=total_apps,
        artifacts_done=artifacts_done,
        total_artifacts=total_artifacts,
        current_app_label=current_app_label,
        current_package_name=current_package_name,
        agg_checks=agg_checks,
        eta_text=eta_text,
        archive_reports_written=archive_reports_written,
        eta_preliminary=eta_preliminary,
    )
    return line1


def format_scan_progress_checkpoint_card(
    *,
    apps_completed: int,
    total_apps: int,
    artifacts_done: int,
    total_artifacts: int,
    current_app_label: str | None,
    current_package_name: str | None,
    agg_checks: Counter[str],
    eta_text: str,
    archive_reports_written: int | None,
    elapsed_text: str,
    split_heavy_note: str | None = None,
    verbose_metrics: bool = False,
    eta_preliminary: bool = False,
) -> str:
    """Multiline progress checkpoint for periodic / stride updates (compact all-apps runs)."""

    def _kv_top(label: str, value: str) -> str:
        return f"{label:<{_KV_W_TOP}}: {value}"

    def _kv_sub(label: str, value: str) -> str:
        return f"  {label:<{_KV_W_SUB}}: {value}"

    cur_pkg = str(current_package_name or "").strip()
    cur_lbl = str(current_app_label or "").strip() or cur_pkg or "—"
    disp_line = cur_lbl if (cur_lbl and cur_lbl != "—") else "—"
    id_line = cur_pkg if cur_pkg else "—"
    eta_raw = str(eta_text or "").strip()
    if eta_raw and eta_raw != "--":
        eta_line = f"~{eta_raw}"
        if eta_preliminary and total_artifacts > 0:
            eta_line += " (preliminary)"
    else:
        eta_line = "warming up" if eta_preliminary and total_artifacts > 0 else "pending"
    arch_line = "—"
    if total_artifacts > 0:
        ac = 0 if archive_reports_written is None else int(archive_reports_written)
        arch_line = f"{ac} / {total_artifacts}"
    pkg_done = min(max(apps_completed, 0), total_apps) if total_apps > 0 else 0
    lines = [
        "Static progress",
        "---------------",
        _kv_top("Current package", disp_line),
        _kv_top("Package id", id_line),
        "",
        "Progress",
        _kv_sub("Packages", f"{pkg_done} / {total_apps}"),
        _kv_sub("APK artifacts", f"{artifacts_done} / {total_artifacts}"),
        _kv_sub("APK reports saved", arch_line),
        _kv_sub("Elapsed", elapsed_text),
        _kv_sub("ETA", eta_line),
    ]
    lines.append("")
    _append_pipeline_events_table(
        lines,
        agg_checks,
        concise=True,
        verbose_metrics=verbose_metrics,
    )
    if split_heavy_note:
        lines.extend(["", "Split note", f"  {split_heavy_note}"])
    return "\n".join(lines)


def _append_final_pipeline_digest(
    lines: list[str],
    outcome: RunOutcome,
    agg_checks: Counter[str],
) -> None:
    """Append full session detector-stage roll-up, top skip reasons, and parse-by-package hints."""

    lines.append("")
    lines.append("Session pipeline totals (detector-stage roll-up)")
    lines.append("--------------------------------------------")
    _append_pipeline_events_table(
        lines,
        agg_checks,
        concise=False,
        verbose_metrics=True,
        section_title="Full detector-stage counts (session)",
    )
    lines.append("")
    lines.append(
        "Parse estimate bundles per-artifact resource fallback use, resource-bounds warnings, "
        "and label/parse hints (rollup_parse_fallback_signals); not a gate failure count."
    )
    skip_rows = aggregate_session_skip_reasons_from_results(outcome.results, limit=12)
    lines.append("")
    if skip_rows:
        lines.append("Top skip reasons (artifact pipeline_summary.skipped_detectors)")
        for reason, count in skip_rows:
            lines.append(f"  {count:>5}  {reason}")
        attn = sum(
            c
            for r, c in skip_rows
            if any(
                tok in r.lower()
                for tok in (
                    "error",
                    "failed",
                    "exception",
                    "missing",
                    "corrupt",
                    "broken",
                    "parse",
                )
            )
        )
        total_shown = sum(c for _, c in skip_rows)
        lines.append(
            f"  (heuristic: {attn} of {total_shown} listed rows mention error/missing/parse/corrupt "
            "— inspect artifacts for the rest; most skips are profile/applicability)"
        )
    else:
        lines.append(
            "Skip reasons: no skipped_detectors detail in finished artifact metadata "
            "(session skipped_stages counter may still be >0 from roll-up totals)."
        )
    parse_top = aggregate_parse_signals_by_package(outcome.results, limit=8)
    lines.append("")
    if parse_top:
        lines.append("Top packages by parse / resource signal estimate")
        for pkg, total in parse_top:
            lines.append(f"  {total:>5}  {pkg}")
    else:
        session_pe = int(agg_checks.get("parse_signals_est", 0) or 0)
        lines.append(
            "Top packages by parse signals: no per-package table "
            f"(session parse / resource estimate = {session_pe}; "
            "matches heartbeat roll-up — see metric row above)."
        )


def _workflow_completion_token(outcome: RunOutcome) -> str:
    """High-level scan/workflow completion (distinct from detector posture)."""

    if outcome.aborted:
        return "ABORTED"
    if not outcome.results:
        return "NO RESULTS"
    statuses = [str(getattr(r, "final_status", "") or "").strip() for r in outcome.results]
    if not statuses:
        return "NO RESULTS"
    if all(s == "failed" for s in statuses):
        return "FAILED"
    if all(s == "skipped" for s in statuses):
        return "SKIPPED"
    return "COMPLETE"


def _detector_posture_readable(run_agg: str) -> str:
    """Explain package-level aggregate (complete / partial / failed) without implying scan abort."""

    t = str(run_agg or "").strip().lower()
    if t == "complete":
        return "CLEAR — no partial/failed package aggregate"
    if t == "clean":
        return "CLEAN — no detector warnings, gates, or execution errors"
    if t == "warnings":
        return "WARNINGS — detector warn-stage issues only (workflow still finished)"
    if t == "policy_or_finding_gates":
        return "POLICY / FINDING GATES — workflow still finished"
    if t == "execution_errors":
        return "EXECUTION ERRORS — analyzer/pipeline exceptions occurred"
    if t == "partial":
        return "PARTIAL — warnings or finding/policy gates (workflow still finished)"
    if t == "failed":
        return "FAILED — one or more packages failed"
    if t == "skipped":
        return "SKIPPED — all packages skipped"
    if not t or t == "—":
        return "—"
    return t.upper()


def format_static_run_final_summary_block(
    outcome: RunOutcome,
    *,
    session_display: str | None,
    archive_reports_written: int | None,
    persistence_ready: bool,
    dry_run: bool,
    agg_checks: Counter[str] | None = None,
) -> str:
    """Plain multiline end-of-run summary for compact static scans (no detector/DB changes)."""

    def _kv(label: str, value: str) -> str:
        return f"{label:<18}: {value}"

    stamp = (
        str(session_display or "").strip()
        or str(getattr(outcome.scope, "label", "") or "").strip()
        or "—"
    )
    status_ctr: Counter[str] = Counter()
    for r in outcome.results:
        st = str(getattr(r, "final_status", None) or "").strip()
        if st:
            status_ctr[st] += 1
    total_pkgs = len(outcome.results)
    parts = [f"{status_ctr[k]} {k}" for k in sorted(status_ctr.keys())]
    pkg_roll = ", ".join(parts) if parts else "—"

    total_art = int(outcome.total_artifacts or 0)
    if total_art > 0:
        ar = 0 if archive_reports_written is None else int(archive_reports_written)
        rpt = f"{ar} / {total_art}"
        if not dry_run and ar == total_art:
            evidence_disp = "OK (all APK reports saved)"
        else:
            evidence_disp = rpt
    else:
        rpt = "—"
        evidence_disp = "—"

    if dry_run:
        persist = "dry-run (DB/evidence writes skipped as configured)"
    elif not persistence_ready:
        persist = "off (persistence not ready)"
    elif outcome.persistence_failed:
        persist = "ERROR (session reported persistence failure)"
    else:
        persist = "OK"

    agg = str(outcome.run_aggregate_status or "—").strip() or "—"
    workflow = _workflow_completion_token(outcome)
    posture = _detector_posture_readable(agg)
    execution_errs = "—"
    if agg_checks is not None:
        execution_errs = str(int(agg_checks.get("error", 0) or 0))

    audit = "PYTHONPATH=. python scripts/db/audit_static_session.py --session <session_stamp>"
    grain = (
        "PYTHONPATH=. python scripts/db/report_static_session_grain_integrity.py "
        "--session-stamp <session_stamp> --count-archive-json"
    )
    if stamp and stamp != "—":
        safe = stamp.replace("'", "'\"'\"'")
        audit = f"PYTHONPATH=. python scripts/db/audit_static_session.py --session '{safe}'"
        grain = format_grain_integrity_session_command(stamp, count_archive=True, aggregate_json=False)

    menu_hints = "Post-run diagnostics → 11 · Database Tools → 9 (Static & registry diagnostics)"
    lines = [
        "Static run summary",
        "------------------",
        _kv("Session", stamp),
        _kv("Packages", f"{total_pkgs} in scope ({pkg_roll})"),
        _kv("Run completion", workflow),
        _kv("DB persistence", persist),
        _kv("Evidence (reports)", evidence_disp),
        _kv("Detector posture", posture),
        _kv("Execution errors", execution_errs),
        _kv("Audit", audit),
        _kv("Grain / split triage", grain),
        _kv("DB check menus", menu_hints),
    ]
    if outcome.aborted:
        lines.insert(
            3,
            _kv("Run state", f"aborted ({str(outcome.abort_reason or '').strip() or 'signal'})"),
        )
    if agg_checks is not None:
        _append_final_pipeline_digest(lines, outcome, agg_checks)
    return "\n".join(lines)


def format_scan_progress_single_line(
    *,
    apps_completed: int,
    total_apps: int,
    artifacts_done: int,
    total_artifacts: int,
    current_app_label: str | None,
    current_package_name: str | None,
    agg_checks: Counter[str],
    last_report_seconds_ago: int | None,
    last_report_package: str | None,
    last_report_app_label: str | None = None,
    eta_text: str,
    activity: str = "active",
    archive_reports_written: int | None = None,
) -> str:
    """Return one physical line combining heartbeat line 1 and line 2 for narrow log sinks.

    ``last_report_*`` / ``activity`` are ignored; persistence lag belongs on checkpoint
    cards or verbose paths, not on every heartbeat.
    """

    _ = activity
    _ = last_report_seconds_ago
    _ = last_report_package
    _ = last_report_app_label
    line1, line2 = format_scan_progress_heartbeat_lines(
        apps_completed=apps_completed,
        total_apps=total_apps,
        artifacts_done=artifacts_done,
        total_artifacts=total_artifacts,
        current_app_label=current_app_label,
        current_package_name=current_package_name,
        agg_checks=agg_checks,
        eta_text=eta_text,
        archive_reports_written=archive_reports_written,
        eta_preliminary=False,
    )
    return f"{line1} · {line2}"


def _format_compact_progress_text(
    *,
    apps_completed: int,
    total_apps: int,
    artifacts_done: int,
    total_artifacts: int,
    agg_checks: Counter[str],
    elapsed_text: str,
    eta_text: str,
    current_app_label: str | None = None,
    current_package_name: str | None = None,
    recent_completions: list[str] | None = None,
    last_report_seconds_ago: int | None = None,
    last_report_package: str | None = None,
    archive_reports_written: int | None = None,
    eta_preliminary: bool = False,
    session_display: str | None = None,
    profile_display: str | None = None,
    scope_display: str | None = None,
    workers_display: str | None = None,
    dry_run: bool = False,
    include_legend: bool = True,
    include_run_context: bool = True,
    stale_persist_seconds: int = 180,
    concise: bool = True,
    include_recent_apps: bool | None = None,
    verbose_metrics: bool | None = None,
) -> str:
    """Return the compact multi-line operator progress text."""

    vm = bool(verbose_metrics) if verbose_metrics is not None else (not concise)
    if include_recent_apps is None:
        show_recent = bool(recent_completions) and (not concise)
    else:
        show_recent = bool(recent_completions) and bool(include_recent_apps)

    lines: list[str] = []

    if include_run_context:
        lines.append("Run context")
        lines.append("-----------")
        lines.append(f"Session: {str(session_display or '').strip() or '-'}")
        lines.append(f"Preset: {str(profile_display or '').strip() or '-'}")
        lines.append(f"Scope: {str(scope_display or '').strip() or '-'}")
        lines.append(f"Workers: {str(workers_display or '').strip() or '-'}")
        if dry_run:
            lines.append("Mode: DRY-RUN (reports not persisted to DB/evidence paths as configured)")
        lines.append(f"Packages in run: {total_apps}")
        lines.append(f"APKs in run: {total_artifacts}")
        lines.append("")

    lines.append("Current package")
    lines.append("-----------------")
    app_disp = str(current_app_label or "").strip() or "—"
    pkg_disp = str(current_package_name or "").strip() or "—"
    lines.append(f"Display name: {app_disp}")
    lines.append(f"Package: {pkg_disp}")
    if total_apps > 0:
        ordinal = min(max(apps_completed, 0) + 1, total_apps)
        lines.append(f"Package progress: {ordinal} / {total_apps} selected")
    else:
        lines.append("Package progress: -")
    lines.append(f"APK artifact progress: {artifacts_done} / {total_artifacts} completed")
    lines.append(f"Elapsed: {elapsed_text}")
    eta_raw = str(eta_text or "").strip()
    no_eta = eta_raw in {"", "--"}
    if concise:
        if no_eta:
            eta_line = "ETA: pending (needs a few completed APKs)"
            if eta_preliminary and total_artifacts > 0:
                eta_line += " · preliminary"
        else:
            eta_line = f"ETA: ~{eta_raw}"
            if eta_preliminary and total_artifacts > 0:
                eta_line += " (preliminary)"
    elif no_eta:
        eta_line = "ETA: waiting for completed APKs (rate stabilizes after first few)"
        if eta_preliminary and total_artifacts > 0:
            eta_line += "; split-heavy apps skew early estimates"
    else:
        eta_line = f"ETA: ~{eta_raw}"
        if eta_preliminary and total_artifacts > 0:
            eta_line += " (preliminary; split-heavy apps may skew)"
    lines.append(eta_line)

    arch = archive_reports_written
    if total_artifacts > 0:
        ac = 0 if arch is None else int(arch)
        lines.append(f"APK reports saved: {ac} / {total_artifacts}")
    else:
        lines.append("APK reports saved: —")

    if (
        last_report_seconds_ago is not None
        and last_report_seconds_ago >= int(stale_persist_seconds)
        and last_report_package
    ):
        saved_pkg = str(last_report_package or "").strip() or "—"
        age = _format_last_saved_phrase(last_report_seconds_ago)
        lines.append(f"Last report persist: {saved_pkg}, {age} (lag — check disk/DB if unexpected)")
    elif last_report_seconds_ago is not None and last_report_package:
        # Fresh persistence window: omit noisy per-save line; counts are above.
        pass

    lines.append("")
    _append_pipeline_events_table(lines, agg_checks, concise=bool(concise), verbose_metrics=vm)

    if recent_completions and show_recent:
        lines.append("")
        lines.append("Recent apps")
        lines.append("-----------")
        lines.extend(f"  {completion}" for completion in recent_completions[-2:])

    if include_legend:
        lines.append("")
        lines.append("Legend")
        lines.append("----------------------")
        if concise and not vm:
            lines.extend(
                (
                    "Live table = detector-stage roll-ups from finished packages (not DB canonical findings).",
                    "Warnings / policy / finding / execution columns match session heartbeat semantics.",
                    "Parse signals ≈ resource fallback + ARSC bounds + label-parse hints (artifact roll-up).",
                    "Use --verbose for full OK + skipped-stage columns; end-of-run summary lists totals + top skips.",
                )
            )
        elif concise:
            lines.extend(
                (
                    "OK = detector stages that finished OK (worst badge per detector per package)",
                    "WARN = detector WARN stages (same roll-up; summed across packages in session)",
                    "Policy / Finding gates = FAIL stages from policy vs finding detectors",
                    "Execution errors = analyzer/pipeline exceptions (not DB canonical findings)",
                    "Skipped stages = detector SKIPPED outcomes summed from each finished package",
                    "Parse est. ≈ resource fallback + ARSC bounds + label-parse hints (artifact roll-up)",
                    "Session table = sums of per-package pipeline_summary after each app completes",
                )
            )
        else:
            lines.extend(
                (
                    "OK = detector stages completed without WARN/FAIL/ERROR for that detector",
                    "WARN = medium/hygiene detector outcomes (rolled up per detector per package)",
                    "Policy gate failures = FAIL where the detector marked a policy gate",
                    "Finding gate failures = FAIL from finding severity / non-policy gates",
                    "Execution errors = thrown analyzer errors (distinct from gate FAIL)",
                    "Skipped detector stages = stages omitted by profile/policy (reasons on verbose cards)",
                    "Parse / resource estimate = heuristic coverage pressure (not a gate failure count)",
                )
            )

    return "\n".join(lines)


def _load_v3_catalog_label_overrides(selection: ScopeSelection) -> dict[str, str]:
    """Return per-package display-name overrides for Profile v3 scans.

    Cohort-facing labels from the v3 catalog should appear in pipeline output
    even when APK metadata contains a different app label.
    """
    if selection.scope != "profile":
        return {}

    if not str(selection.label or "").strip().lower().startswith("profile v3"):
        return {}

    catalog_path = Path("profiles") / "profile_v3_app_catalog.json"

    try:
        payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    except Exception:
        return {}

    if not isinstance(payload, dict):
        return {}

    overrides: dict[str, str] = {}

    for pkg, meta in payload.items():
        if not isinstance(pkg, str) or not pkg.strip():
            continue

        if not isinstance(meta, Mapping):
            continue

        label = meta.get("app")
        if isinstance(label, str) and label.strip():
            overrides[pkg.strip().lower()] = label.strip()

    return overrides


def _artifact_label(artifact, *, display_name: str | None = None) -> str:
    """Return the operator-facing label for an artifact."""
    label = getattr(artifact, "artifact_label", None) or getattr(artifact, "display_path", None)

    if isinstance(label, str) and label.strip():
        split_label = label.strip()
    else:
        split_label = "base"

    package = getattr(artifact, "package_name", None)
    app_label = None
    metadata = getattr(artifact, "metadata", None)

    if isinstance(metadata, Mapping):
        app_label = metadata.get("app_label") or metadata.get("display_name")

    display = None

    if isinstance(app_label, str) and app_label.strip():
        display = app_label.strip()
    elif isinstance(display_name, str) and display_name.strip():
        display = display_name.strip()
    elif isinstance(package, str) and package.strip():
        display = package.strip()

    if display:
        return f"{display} • {split_label}"

    return split_label


def format_elapsed_for_progress(seconds: float) -> str:
    """Human-friendly elapsed time for live progress (avoid noisy sub-second ms)."""

    if seconds <= 0:
        return "starting"
    if seconds < 1.0:
        return "<1s"
    return format_duration(seconds)


def format_duration(seconds: float) -> str:
    """Format elapsed seconds for scan progress output."""
    if seconds <= 0:
        return "0 ms"

    if seconds < 1:
        millis = max(1, int(round(seconds * 1000)))
        return f"{millis} ms"

    if seconds < 60:
        whole = max(1, int(round(seconds)))
        sec_label = "sec" if whole == 1 else "secs"
        return f"{whole} {sec_label}"

    minutes = int(seconds // 60)
    remaining = int(round(seconds - minutes * 60))

    if remaining == 60:
        minutes += 1
        remaining = 0

    if minutes < 60:
        min_label = "min" if minutes == 1 else "mins"
        sec_label = "sec" if remaining == 1 else "secs"
        return f"{minutes} {min_label} {remaining} {sec_label}"

    hours = minutes // 60
    minutes = minutes % 60
    hr_label = "hr" if hours == 1 else "hrs"
    min_label = "min" if minutes == 1 else "mins"

    return f"{hours} {hr_label} {minutes} {min_label}"


__all__ = [
    "_artifact_label",
    "_detector_posture_readable",
    "_format_compact_progress_text",
    "_load_v3_catalog_label_overrides",
    "_workflow_completion_token",
    "format_duration",
    "format_elapsed_for_progress",
    "format_scan_progress_checkpoint_card",
    "format_scan_progress_heartbeat",
    "format_scan_progress_heartbeat_lines",
    "format_scan_progress_single_line",
    "format_static_run_final_summary_block",
]
