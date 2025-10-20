"""Result rendering helpers for static analysis CLI."""

from __future__ import annotations

from pathlib import Path

from collections import Counter
from typing import Mapping, MutableMapping, Sequence

from scytaledroid.Utils.DisplayUtils import (
    prompt_utils,
    severity,
    status_messages,
    summary_cards,
    table_utils,
)

from ...core import StaticAnalysisReport
from ...engine.strings import analyse_strings
from ..db_persist import persist_run_summary
from ..detail import (
    SEVERITY_TOKEN_ORDER,
    app_detail_loop,
    render_app_detail,
)
from ..masvs_summary import fetch_db_masvs_summary
from ..models import RunOutcome, RunParameters
from ..renderer import render_app_result, write_baseline_json
from ...persistence.ingest import ingest_baseline_payload
from .scan_flow import format_duration
from scytaledroid.Database.db_core import db_queries as core_q


def _derive_highlight_stats(outcome: RunOutcome) -> dict[str, int]:
    stats = {"providers": 0, "nsc_guard": 0, "secrets_suppressed": 0}
    for app_result in outcome.results:
        base_report = app_result.base_report()
        if base_report is None:
            continue
        try:
            providers = getattr(base_report.exported_components, "providers", ())
            stats["providers"] += len(providers)
        except Exception:
            pass

        metadata = base_report.metadata if isinstance(base_report.metadata, Mapping) else {}
        nsc_payload: Mapping[str, object] | None = None
        if isinstance(metadata, Mapping):
            candidate = metadata.get("network_security_config")
            if isinstance(candidate, Mapping):
                nsc_payload = candidate
            else:
                repro = metadata.get("repro_bundle")
                if isinstance(repro, Mapping):
                    repro_candidate = repro.get("network_security_config")
                    if isinstance(repro_candidate, Mapping):
                        nsc_payload = repro_candidate

        base_flag = base_report.manifest_flags.uses_cleartext_traffic
        if isinstance(nsc_payload, Mapping):
            base_cleartext = nsc_payload.get("base_cleartext")
            domain_policies = nsc_payload.get("domain_policies")
            has_domains = bool(domain_policies)
            if base_cleartext is False or (base_flag is False and not has_domains):
                stats["nsc_guard"] += 1
        elif base_flag is False:
            stats["nsc_guard"] += 1

        for result in getattr(base_report, "detector_results", ()):  # type: ignore[attr-defined]
            if getattr(result, "detector_id", "") == "secrets_credentials":
                metrics = getattr(result, "metrics", {})
                if isinstance(metrics, Mapping):
                    secret_types = metrics.get("secret_types")
                    if isinstance(secret_types, Mapping):
                        for data in secret_types.values():
                            if isinstance(data, Mapping):
                                stats["secrets_suppressed"] += int(data.get("validator_dropped") or 0)
                break
    return stats


def _format_highlight_tokens(
    stats: Mapping[str, int], totals: Mapping[str, int], app_count: int
) -> list[str]:
    tokens: list[str] = []
    providers = stats.get("providers", 0)
    if providers:
        tokens.append(
            f"{providers} exported provider{'s' if providers != 1 else ''} lacking strong guards"
        )
    guard = stats.get("nsc_guard", 0)
    if guard:
        tokens.append(
            f"NSC blocks cleartext in {guard}/{app_count} app{'s' if guard != 1 else ''}"
        )
    suppressed = stats.get("secrets_suppressed", 0)
    if suppressed:
        tokens.append(
            f"{suppressed} secret hit{'s' if suppressed != 1 else ''} auto-suppressed"
        )
    if not tokens:
        high = totals.get("high", 0) + totals.get("critical", 0)
        if high:
            tokens.append(
                f"{high} high-severity finding{'s' if high != 1 else ''} require review"
            )
        else:
            tokens.append("No high-severity findings detected")
    return tokens


def render_run_results(outcome: RunOutcome, params: RunParameters) -> None:
    """Pretty-print run results and optionally drill into per-app details."""

    aggregated: Counter[str] = Counter()
    artifact_count = 0
    for app_result in outcome.results:
        aggregated.update(app_result.severity_totals())
        artifact_count += len(app_result.artifacts)

    totals = severity.normalise_counts(aggregated)
    highlight_stats = _derive_highlight_stats(outcome)
    total_findings = sum(totals.values())
    overview_items = [
        summary_cards.summary_item("Duration", format_duration(outcome.duration_seconds), value_style="emphasis"),
        summary_cards.summary_item("Applications", len(outcome.results)),
        summary_cards.summary_item("Artifacts", artifact_count),
        summary_cards.summary_item("Findings", total_findings, value_style="severity_high" if totals.get("high") or totals.get("critical") else "emphasis"),
    ]
    overview_items.extend(severity.severity_summary_items(totals))
    subtitle_parts = [params.profile_label]
    if params.scope_label:
        subtitle_parts.append(f"Scope: {params.scope_label}")
    if params.session_stamp:
        subtitle_parts.append(f"Session: {params.session_stamp}")
    subtitle = " • ".join(subtitle_parts)
    print(
        summary_cards.format_summary_card(
            "Static analysis summary",
            overview_items,
            subtitle=subtitle,
            footer="Use the prompts below to drill into per-app findings.",
            width=90,
        )
    )
    highlight_tokens = _format_highlight_tokens(
        highlight_stats,
        totals,
        len(outcome.results),
    )
    if highlight_tokens:
        print(status_messages.highlight("; ".join(highlight_tokens), show_icon=True))
    print()

    persistence_errors: list[str] = []
    persist_enabled = not params.dry_run

    for index, app_result in enumerate(outcome.results, start=1):
        base_report = app_result.base_report()
        if base_report is None:
            warning = f"No report generated for {app_result.package_name}."
            print(status_messages.status(warning, level="warn"))
            continue

        string_data = analyse_strings(
            base_report.file_path,
            mode=params.strings_mode,
            min_entropy=params.string_min_entropy,
            max_samples=params.string_max_samples,
            cleartext_only=params.string_cleartext_only,
        )

        total_duration = sum(artifact.duration_seconds for artifact in app_result.artifacts)
        lines, payload, finding_totals = render_app_result(
            base_report,
            signer=app_result.signer,
            split_count=len(app_result.artifacts),
            string_data=string_data,
            duration_seconds=total_duration,
        )

        if persist_enabled:
            try:
                outcome_status = persist_run_summary(
                    base_report,
                    string_data,
                    app_result.package_name,
                    session_stamp=params.session_stamp,
                    scope_label=params.scope_label,
                    finding_totals=finding_totals,
                    baseline_payload=payload,
                    dry_run=params.dry_run,
                )
                if outcome_status and not outcome_status.success:
                    persistence_errors.extend(outcome_status.errors)
            except Exception as exc:
                warning = (
                    f"Failed to persist run summary for {app_result.package_name}: {exc}"
                )
                print(status_messages.status(warning, level="warn"))
                persistence_errors.append(str(exc))

            try:
                ingest_payload = _build_ingest_payload(payload, base_report, params)
                if not ingest_baseline_payload(ingest_payload):
                    warning = (
                        f"Failed to record canonical snapshot for {app_result.package_name}."
                    )
                    print(status_messages.status(warning, level="warn"))
                    persistence_errors.append(warning)
            except Exception as exc:
                warning = (
                    f"Failed to ingest baseline snapshot for {app_result.package_name}: {exc}"
                )
                print(status_messages.status(warning, level="warn"))
                persistence_errors.append(str(exc))

        report_reference = None
        base_artifact = app_result.base_artifact_outcome()
        if base_artifact and base_artifact.saved_path:
            try:
                report_reference = f"report://{Path(base_artifact.saved_path).name}"
            except Exception:
                report_reference = None

        for line in lines:
            print(line)

        if persist_enabled:
            try:
                saved_path = write_baseline_json(
                    payload,
                    package=app_result.package_name,
                    profile=params.profile,
                    scope=params.scope,
                )
                print(f"  Saved baseline JSON → {saved_path.name}")
            except Exception as exc:
                warning = (
                    f"Failed to write baseline JSON for {app_result.package_name}: {exc}"
                )
                print(status_messages.status(warning, level="warn"))

        if report_reference:
            print(f"  Report reference    → {report_reference}")

        if index < len(outcome.results):
            print()

    session_stamp = params.session_stamp
    if outcome.results:
        printed_db_table = False
        if session_stamp and persist_enabled:
            printed_db_table = _render_db_severity_table(session_stamp)
        if not printed_db_table:
            from ..detail import render_app_table  # local import to avoid cycle

            render_app_table(outcome.results)
        if session_stamp and persist_enabled:
            _render_persistence_footer(session_stamp, had_errors=bool(persistence_errors))
            if persistence_errors:
                print(status_messages.status("Persistence issues detected:", level="error"))
                for message in persistence_errors:
                    print(f"  - {message}")
        _interactive_detail_loop(outcome, params)

    if outcome.warnings:
        for message in sorted(set(outcome.warnings)):
            print(status_messages.status(message, level="warn"))
    if outcome.failures:
        for message in sorted(set(outcome.failures)):
            print(status_messages.status(message, level="error"))

    if persist_enabled:
        _render_db_masvs_summary()


def _build_ingest_payload(
    payload: Mapping[str, object],
    report: StaticAnalysisReport,
    params: RunParameters,
) -> Mapping[str, object]:
    app_section = payload.get("app")
    app_copy: MutableMapping[str, object]
    if isinstance(app_section, Mapping):
        app_copy = dict(app_section)
    else:
        app_copy = {}

    baseline_section = payload.get("baseline")
    baseline_copy: MutableMapping[str, object] = {}
    findings_list: list[Mapping[str, object]] = []
    if isinstance(baseline_section, Mapping):
        baseline_copy.update(baseline_section)
        findings_raw = baseline_section.get("findings")
        if isinstance(findings_raw, Sequence) and not isinstance(
            findings_raw, (str, bytes)
        ):
            findings_list = [
                dict(entry)
                for entry in findings_raw
                if isinstance(entry, Mapping)
            ]

    app_copy.setdefault("package", report.manifest.package_name or app_copy.get("package"))
    if report.manifest.version_name and not app_copy.get("version_name"):
        app_copy["version_name"] = report.manifest.version_name
    if report.manifest.version_code and not app_copy.get("version_code"):
        app_copy["version_code"] = report.manifest.version_code
    if report.manifest.min_sdk and not app_copy.get("min_sdk"):
        app_copy["min_sdk"] = report.manifest.min_sdk
    if report.manifest.target_sdk and not app_copy.get("target_sdk"):
        app_copy["target_sdk"] = report.manifest.target_sdk

    metadata_map: MutableMapping[str, object] = {}
    if isinstance(report.metadata, Mapping):
        metadata_map.update(report.metadata)
    if params.session_stamp and not metadata_map.get("session_stamp"):
        metadata_map["session_stamp"] = params.session_stamp
    if params.scope_label and not metadata_map.get("run_scope_label"):
        metadata_map["run_scope_label"] = params.scope_label
    if params.scope and not metadata_map.get("run_scope"):
        metadata_map["run_scope"] = params.scope

    ingest_payload: MutableMapping[str, object] = {}
    ingest_payload["generated_at"] = payload.get("generated_at")
    ingest_payload["app"] = app_copy
    ingest_payload["baseline"] = baseline_copy
    ingest_payload["findings"] = findings_list
    ingest_payload["hashes"] = dict(report.hashes)
    ingest_payload["analysis_version"] = report.analysis_version
    ingest_payload["scan_profile"] = params.profile
    ingest_payload["detector_metrics"] = dict(report.detector_metrics)
    ingest_payload["metadata"] = metadata_map
    analytics_section = payload.get("analytics")
    if isinstance(analytics_section, Mapping):
        ingest_payload["analytics"] = dict(analytics_section)

    return ingest_payload


def _interactive_detail_loop(outcome: RunOutcome, params: RunParameters) -> None:
    while True:
        resp = prompt_utils.prompt_text(
            "View details for app # (Enter to skip)", default="", required=False
        ).strip()
        if not resp:
            break
        if not resp.isdigit():
            print(status_messages.status("Invalid selection.", level="warn"))
            continue
        idx = int(resp)
        if idx < 1 or idx > len(outcome.results):
            print(status_messages.status("Selection out of range.", level="warn"))
            continue
        selected = outcome.results[idx - 1]
        app_detail_loop(
            selected,
            params.evidence_lines,
            set(SEVERITY_TOKEN_ORDER),
            params.finding_limit,
            render_app_detail,
        )


def _render_db_masvs_summary() -> None:
    try:
        summary = fetch_db_masvs_summary()
        if not summary:
            return
        run_id, rows = summary
        print()
        print(f"DB MASVS Summary (run_id={run_id})")
        print("Area       High  Med   Low   Info  Status  Worst CVSS")
        for area in ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE"):
            entry = next((row for row in rows if row["area"] == area), None)
            if entry is None:
                print(f"{area.title():<9}  0     0     0     0     PASS   —")
            else:
                high = entry.get("high", 0)
                medium = entry.get("medium", 0)
                if high:
                    status = "FAIL"
                elif medium:
                    status = "WARN"
                else:
                    status = "PASS"
                print(
                    f"{area.title():<9}  {high:<5} {medium:<5} {entry['low']:<5} {entry['info']:<6}"
                    f"{status:<6} {entry['worst']}"
                )
    except Exception:
        pass


__all__ = ["render_run_results"]


def _render_db_severity_table(session_stamp: str) -> bool:
    try:
        rows = core_q.run_sql(
            """
            SELECT s.package_name, COALESCE(r.target_sdk, '—') AS target_sdk,
                   s.high, s.med, s.low, s.info
            FROM static_findings_summary s
            LEFT JOIN runs r
              ON r.package = s.package_name
             AND r.session_stamp = s.session_stamp
            WHERE s.session_stamp = %s
            ORDER BY s.package_name
            """,
            (session_stamp,),
            fetch="all",
            dictionary=True,
        ) or []
    except Exception:
        return False

    if not rows:
        return False

    table_rows = []
    for idx, row in enumerate(rows, start=1):
        table_rows.append(
            [
                str(idx),
                row.get("package_name", "—"),
                str(row.get("target_sdk", "—")),
                str(int(row.get("high") or 0)),
                str(int(row.get("med") or 0)),
                str(int(row.get("low") or 0)),
                str(int(row.get("info") or 0)),
            ]
        )

    print()
    table_utils.render_table(
        ["#", "Package", "targetSdk", "High", "Medium", "Low", "Information"],
        table_rows,
    )
    return True


def _render_persistence_footer(session_stamp: str, *, had_errors: bool = False) -> None:
    try:
        run_rows = core_q.run_sql(
            "SELECT run_id FROM runs WHERE session_stamp = %s",
            (session_stamp,),
            fetch="all",
        ) or []
    except Exception:
        return

    run_ids = [int(row[0]) for row in run_rows if row and row[0] is not None]

    def _count(sql: str, params: tuple[object, ...]) -> int:
        try:
            row = core_q.run_sql(sql, params, fetch="one")
        except Exception:
            return 0
        if not row:
            return 0
        value = row[0] if not isinstance(row, dict) else next(iter(row.values()), 0)
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    def _count_total(sql: str) -> int:
        try:
            row = core_q.run_sql(sql, fetch="one")
        except Exception:
            return 0
        if not row:
            return 0
        value = row[0] if not isinstance(row, dict) else next(iter(row.values()), 0)
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    findings_summary = _count(
        "SELECT COUNT(*) FROM static_findings_summary WHERE session_stamp = %s",
        (session_stamp,),
    )
    findings_summary_total = _count_total("SELECT COUNT(*) FROM static_findings_summary")
    findings_detail = _count(
        """
        SELECT COUNT(*)
        FROM static_findings f
        JOIN static_findings_summary s ON s.id = f.summary_id
        WHERE s.session_stamp = %s
        """,
        (session_stamp,),
    )
    findings_detail_total = _count_total("SELECT COUNT(*) FROM static_findings")
    strings_summary = _count(
        "SELECT COUNT(*) FROM static_string_summary WHERE session_stamp = %s",
        (session_stamp,),
    )
    strings_summary_total = _count_total("SELECT COUNT(*) FROM static_string_summary")
    string_samples = _count(
        """
        SELECT COUNT(*)
        FROM static_string_samples x
        JOIN static_findings_summary s ON s.id = x.summary_id
        WHERE s.session_stamp = %s
        """,
        (session_stamp,),
    )
    string_samples_total = _count_total("SELECT COUNT(*) FROM static_string_samples")
    fileproviders = _count(
        "SELECT COUNT(*) FROM static_fileproviders WHERE session_stamp = %s",
        (session_stamp,),
    )
    fileproviders_total = _count_total("SELECT COUNT(*) FROM static_fileproviders")
    provider_acl = _count(
        "SELECT COUNT(*) FROM static_provider_acl WHERE session_stamp = %s",
        (session_stamp,),
    )
    provider_acl_total = _count_total("SELECT COUNT(*) FROM static_provider_acl")

    buckets = metrics = findings = contributors = 0
    if run_ids:
        placeholders = ",".join(["%s"] * len(run_ids))
        params = tuple(run_ids)
        buckets = _count(
            f"SELECT COUNT(*) FROM buckets WHERE run_id IN ({placeholders})",
            params,
        )
        metrics = _count(
            f"SELECT COUNT(*) FROM metrics WHERE run_id IN ({placeholders})",
            params,
        )
        findings = _count(
            f"SELECT COUNT(*) FROM findings WHERE run_id IN ({placeholders})",
            params,
        )
        contributors = _count(
            f"SELECT COUNT(*) FROM contributors WHERE run_id IN ({placeholders})",
            params,
        )

    runs_total = _count_total("SELECT COUNT(*) FROM runs")
    buckets_total = _count_total("SELECT COUNT(*) FROM buckets")
    metrics_total = _count_total("SELECT COUNT(*) FROM metrics")
    findings_total = _count_total("SELECT COUNT(*) FROM findings")
    contributors_total = _count_total("SELECT COUNT(*) FROM contributors")

    print()
    print("Persisted")
    print("==========")
    lines = [
        ("runs", f"{len(run_ids)} (total={runs_total})"),
        ("static_findings_summary", f"{findings_summary} (total={findings_summary_total})"),
        ("static_findings", f"{findings_detail} (total={findings_detail_total})"),
        ("static_string_summary", f"{strings_summary} (total={strings_summary_total})"),
        ("static_string_samples", f"{string_samples} (total={string_samples_total})"),
        ("static_fileproviders", f"{fileproviders} (total={fileproviders_total})"),
        ("static_provider_acl", f"{provider_acl} (total={provider_acl_total})"),
        ("buckets", f"{buckets} (total={buckets_total})"),
        ("metrics", f"{metrics} (total={metrics_total})"),
        ("findings", f"{findings} (total={findings_total})"),
        ("contributors", f"{contributors} (total={contributors_total})"),
    ]
    width = max(len(name) for name, _ in lines) if lines else 0
    for name, detail in lines:
        print(f"  {name.ljust(width)} : {detail}")
    if had_errors:
        print(f"  {'status'.ljust(width)} : ERROR (see logs)")
