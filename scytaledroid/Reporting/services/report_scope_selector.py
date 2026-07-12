"""Scope and evidence-basis helpers for study-oriented reports."""

from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_func.research_cohorts import (
    list_active_research_cohorts,
    resolve_research_cohort_context,
)
from scytaledroid.Reporting.models import ReportRequest

RunSql = Callable[..., Any]


@dataclass(slots=True)
class StaticRunCandidate:
    static_run_id: int
    package_name: str
    display_name: str
    version_code: str
    version_name: str
    base_apk_sha256: str
    split_count: int
    static_session_stamp: str
    run_started_at_utc: str
    created_at: str
    identity_valid: int
    canonical_status: str
    status: str
    app_category: str = ""
    source_lineage: str = ""


@dataclass(slots=True)
class StaticEvidenceResolution:
    request: ReportRequest
    selected_runs: list[StaticRunCandidate]
    exclusions: list[dict[str, Any]] = field(default_factory=list)
    basis_label: str = ""
    reproduction_status: str = ""
    selection_rule: str = ""


def _rows(sql: str, params: Sequence[Any] | Mapping[str, Any] | None = None, *, run_sql_fn: RunSql | None = None) -> list[dict[str, Any]]:
    runner = run_sql_fn or core_q.run_sql
    return runner(sql, params or (), fetch="all_dict") or []


def _row_to_candidate(row: Mapping[str, Any], *, source_lineage: str) -> StaticRunCandidate:
    return StaticRunCandidate(
        static_run_id=int(row.get("static_run_id") or row.get("id") or 0),
        package_name=str(row.get("package_name") or "").strip().lower(),
        display_name=str(row.get("display_name") or row.get("package_name") or "").strip(),
        version_code=str(row.get("version_code") or ""),
        version_name=str(row.get("version_name") or ""),
        base_apk_sha256=str(row.get("base_apk_sha256") or "").strip().lower(),
        split_count=int(row.get("split_count") or 0),
        static_session_stamp=str(row.get("static_session_stamp") or row.get("session_stamp") or ""),
        run_started_at_utc=str(row.get("run_started_at_utc") or ""),
        created_at=str(row.get("created_at") or ""),
        identity_valid=int(row.get("identity_valid") or 0),
        canonical_status=str(row.get("canonical_status") or row.get("run_class") or ""),
        status=str(row.get("status") or ""),
        app_category=str(row.get("app_category") or row.get("category") or ""),
        source_lineage=source_lineage,
    )


def list_named_research_cohorts(*, run_sql_fn: RunSql | None = None) -> list[dict[str, Any]]:
    return list_active_research_cohorts(run_sql_fn=run_sql_fn)


def resolve_named_research_cohort_scope(cohort_key: str, *, run_sql_fn: RunSql | None = None) -> tuple[str, str, list[str]]:
    ctx = resolve_research_cohort_context(cohort_key, run_sql_fn=run_sql_fn)
    packages = [str(pkg).strip().lower() for pkg in ctx.get("packages", []) if str(pkg).strip()]
    display = str(ctx.get("display_name") or cohort_key)
    return str(ctx.get("cohort_key") or cohort_key), display, sorted(set(packages))


def list_application_categories(*, run_sql_fn: RunSql | None = None) -> list[dict[str, Any]]:
    rows = _rows(
        """
        SELECT
          COALESCE(NULLIF(cat.category_name, ''), NULLIF(a.profile_key, ''), 'Uncategorized') AS category_name,
          COUNT(DISTINCT LOWER(a.package_name)) AS app_count
        FROM apps a
        LEFT JOIN android_app_categories cat
          ON cat.category_id = a.category_id
        GROUP BY COALESCE(NULLIF(cat.category_name, ''), NULLIF(a.profile_key, ''), 'Uncategorized')
        HAVING app_count > 0
        ORDER BY category_name
        """,
        run_sql_fn=run_sql_fn,
    )
    return [
        {
            "category_name": str(row.get("category_name") or "Uncategorized"),
            "app_count": int(row.get("app_count") or 0),
        }
        for row in rows
    ]


def resolve_application_category_scope(category_name: str, *, run_sql_fn: RunSql | None = None) -> tuple[str, str, list[str]]:
    category = str(category_name or "").strip()
    if not category:
        raise ValueError("application category is required")
    rows = _rows(
        """
        SELECT DISTINCT LOWER(a.package_name) AS package_name
        FROM apps a
        LEFT JOIN android_app_categories cat
          ON cat.category_id = a.category_id
        WHERE LOWER(COALESCE(NULLIF(cat.category_name, ''), NULLIF(a.profile_key, ''), 'Uncategorized')) = LOWER(%s)
        ORDER BY package_name
        """,
        (category,),
        run_sql_fn=run_sql_fn,
    )
    packages = [str(row.get("package_name") or "").strip().lower() for row in rows if row.get("package_name")]
    return category.lower().replace(" ", "_"), category, sorted(set(packages))


def find_static_application_matches(query: str, *, run_sql_fn: RunSql | None = None, limit: int = 20) -> list[dict[str, Any]]:
    search = str(query or "").strip()
    if not search:
        return []
    like = f"%{search}%"
    prefix = f"{search}%"
    rows = _rows(
        """
        SELECT
          LOWER(a.package_name) AS package_name,
          COALESCE(NULLIF(a.display_name, ''), a.package_name) AS display_name,
          COALESCE(NULLIF(cat.category_name, ''), NULLIF(a.profile_key, ''), '') AS app_category
        FROM apps a
        LEFT JOIN android_app_categories cat
          ON cat.category_id = a.category_id
        WHERE LOWER(a.package_name) = LOWER(%s)
           OR LOWER(COALESCE(NULLIF(a.display_name, ''), a.package_name)) = LOWER(%s)
           OR LOWER(a.package_name) LIKE LOWER(%s)
           OR LOWER(COALESCE(NULLIF(a.display_name, ''), a.package_name)) LIKE LOWER(%s)
        ORDER BY
          CASE
            WHEN LOWER(a.package_name) = LOWER(%s) THEN 0
            WHEN LOWER(COALESCE(NULLIF(a.display_name, ''), a.package_name)) = LOWER(%s) THEN 1
            WHEN LOWER(COALESCE(NULLIF(a.display_name, ''), a.package_name)) LIKE LOWER(%s) THEN 2
            WHEN LOWER(a.package_name) LIKE LOWER(%s) THEN 3
            ELSE 4
          END,
          COALESCE(NULLIF(a.display_name, ''), a.package_name),
          a.package_name
        LIMIT %s
        """,
        (search, search, like, like, search, search, prefix, prefix, int(limit)),
        run_sql_fn=run_sql_fn,
    )
    return [
        {
            "package_name": str(row.get("package_name") or "").strip().lower(),
            "display_name": str(row.get("display_name") or "").strip(),
            "app_category": str(row.get("app_category") or "").strip(),
        }
        for row in rows
        if row.get("package_name")
    ]


def resolve_static_social_media_2025_scope() -> tuple[str, str, list[str]]:
    packages = [
        "com.facebook.katana",
        "com.instagram.android",
        "com.facebook.orca",
        "com.snapchat.android",
        "com.zhiliaoapp.musically",
        "com.twitter.android",
    ]
    return "static_social_media_2025", "Static social media six-app method-compatible scope", packages


def eligible_static_packages_for_basis(
    *,
    evidence_basis_type: str,
    evidence_basis_key: str,
    as_of_utc: str | None = None,
    window_start_utc: str | None = None,
    window_end_utc: str | None = None,
    run_sql_fn: RunSql | None = None,
) -> list[str]:
    if evidence_basis_type == "selected_publication_manifest":
        return _packages_from_manifest(Path(evidence_basis_key))
    if evidence_basis_type == "named_static_session":
        rows = _rows(
            """
            SELECT DISTINCT LOWER(a.package_name) AS package_name
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            WHERE sar.session_stamp = %s
              AND UPPER(COALESCE(sar.status, '')) = 'COMPLETED'
              AND UPPER(COALESCE(sar.run_class, '')) = 'CANONICAL'
              AND COALESCE(sar.identity_valid, 0) = 1
            ORDER BY package_name
            """,
            (evidence_basis_key,),
            run_sql_fn=run_sql_fn,
        )
    elif evidence_basis_type == "latest_valid_as_of":
        if not as_of_utc:
            raise ValueError("latest_valid_as_of requires as_of_utc")
        rows = _rows(
            """
            SELECT DISTINCT LOWER(a.package_name) AS package_name
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            WHERE UPPER(COALESCE(sar.status, '')) = 'COMPLETED'
              AND UPPER(COALESCE(sar.run_class, '')) = 'CANONICAL'
              AND COALESCE(sar.identity_valid, 0) = 1
              AND COALESCE(sar.run_started_at_utc, sar.created_at) <= %s
            ORDER BY package_name
            """,
            (as_of_utc,),
            run_sql_fn=run_sql_fn,
        )
    elif evidence_basis_type == "fixed_recent_window":
        if not window_start_utc or not window_end_utc:
            raise ValueError("fixed_recent_window requires window_start_utc and window_end_utc")
        rows = _rows(
            """
            SELECT DISTINCT LOWER(a.package_name) AS package_name
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            WHERE UPPER(COALESCE(sar.status, '')) = 'COMPLETED'
              AND UPPER(COALESCE(sar.run_class, '')) = 'CANONICAL'
              AND COALESCE(sar.identity_valid, 0) = 1
              AND COALESCE(sar.run_started_at_utc, sar.created_at) >= %s
              AND COALESCE(sar.run_started_at_utc, sar.created_at) <= %s
            ORDER BY package_name
            """,
            (window_start_utc, window_end_utc),
            run_sql_fn=run_sql_fn,
        )
    else:
        rows = _rows(
            """
            SELECT DISTINCT LOWER(a.package_name) AS package_name
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            WHERE UPPER(COALESCE(sar.status, '')) = 'COMPLETED'
              AND UPPER(COALESCE(sar.run_class, '')) = 'CANONICAL'
              AND COALESCE(sar.identity_valid, 0) = 1
            ORDER BY package_name
            """,
            run_sql_fn=run_sql_fn,
        )
    return [str(row.get("package_name") or "").strip().lower() for row in rows if row.get("package_name")]


def build_report_request(
    *,
    study_profile_key: str,
    scope_type: str,
    scope_key: str,
    scope_label: str,
    package_names: list[str],
    evidence_basis_type: str,
    evidence_basis_key: str,
    output_contract: str,
    as_of_utc: str | None = None,
    window_start_utc: str | None = None,
    window_end_utc: str | None = None,
    operator_notes: str = "",
    scope_exclusions: list[dict[str, Any]] | None = None,
    requested_formats: list[str] | None = None,
) -> ReportRequest:
    return ReportRequest(
        study_profile_key=study_profile_key,
        study_profile_version="1.0",
        scope_type=scope_type,
        scope_key=scope_key,
        scope_label=scope_label,
        package_names=package_names,
        evidence_basis_type=evidence_basis_type,
        evidence_basis_key=evidence_basis_key,
        as_of_utc=as_of_utc,
        window_start_utc=window_start_utc,
        window_end_utc=window_end_utc,
        output_contract=output_contract,
        requested_formats=requested_formats or ["csv", "json", "txt", "figures"],
        operator_notes=operator_notes,
        scope_exclusions=scope_exclusions or [],
    )


def resolve_static_evidence(request: ReportRequest, *, run_sql_fn: RunSql | None = None) -> StaticEvidenceResolution:
    if request.study_profile_key != "static_exposure_privacy":
        raise ValueError("static evidence resolution only supports static_exposure_privacy")
    if request.evidence_basis_type == "exact_historical_freeze":
        manifest_path = Path(request.evidence_basis_key)
        if not manifest_path.exists():
            raise FileNotFoundError(f"Historical freeze manifest not found: {manifest_path}")
        rows = _static_runs_from_manifest(manifest_path, request.package_names, run_sql_fn=run_sql_fn)
        status = "EXACT HISTORICAL REPRODUCTION"
        rule = "Exact static run IDs are read from the historical manifest; missing or mismatched runs fail closed."
    elif request.evidence_basis_type == "selected_publication_manifest":
        manifest_path = Path(request.evidence_basis_key)
        if not manifest_path.exists():
            raise FileNotFoundError(f"Selected manifest not found: {manifest_path}")
        rows = _static_runs_from_manifest(manifest_path, request.package_names, run_sql_fn=run_sql_fn)
        status = "SELECTED MANIFEST REGENERATION"
        rule = "Static run IDs are read from the selected manifest; one latest matching run per package/build contributes metrics."
    elif request.evidence_basis_type == "named_static_session":
        rows = _static_runs_from_session(request.evidence_basis_key, request.package_names, run_sql_fn=run_sql_fn)
        status = "METHOD-COMPATIBLE REGENERATION"
        rule = "Within the named session, select the latest completed canonical identity-valid run per package."
    elif request.evidence_basis_type == "latest_valid_as_of":
        if not request.as_of_utc:
            raise ValueError("latest_valid_as_of requires as_of_utc")
        rows = _static_runs_latest_as_of(request.package_names, request.as_of_utc, run_sql_fn=run_sql_fn)
        status = "CONTEMPORARY ANALYSIS"
        rule = "Select the latest completed canonical identity-valid run per package with run time <= as_of_utc."
    elif request.evidence_basis_type == "fixed_recent_window":
        if not request.window_start_utc or not request.window_end_utc:
            raise ValueError("fixed_recent_window requires window_start_utc and window_end_utc")
        rows = _static_runs_recent_window(
            request.package_names,
            request.window_start_utc,
            request.window_end_utc,
            run_sql_fn=run_sql_fn,
        )
        status = "CURRENT WINDOW ANALYSIS"
        rule = "Select the latest completed canonical identity-valid run per package inside the configured recent evidence window."
    else:
        raise ValueError(f"Unsupported static evidence basis: {request.evidence_basis_type}")

    keeps_version_history = (
        request.evidence_basis_type == "fixed_recent_window"
        and (
            request.evidence_basis_key.startswith("single_app_history_")
            or request.evidence_basis_key.startswith("app_version_history_")
        )
    )
    if keeps_version_history:
        wanted_packages = {package.lower() for package in request.package_names}
        selected, exclusions = _dedupe_static_runs_by_build(
            [row for row in rows if row.package_name in wanted_packages],
        )
    else:
        selected, exclusions = _dedupe_static_runs(rows, request.package_names)
    return StaticEvidenceResolution(
        request=request,
        selected_runs=selected,
        exclusions=exclusions,
        basis_label=request.evidence_basis_type,
        reproduction_status=status,
        selection_rule=rule,
    )


def _packages_from_manifest(path: Path) -> list[str]:
    return [str(row.get("package_name") or "").strip().lower() for row in _read_manifest_rows(path) if row.get("package_name")]


def _read_manifest_rows(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".json":
        import json

        payload = json.loads(path.read_text(encoding="utf-8"))
        rows = payload.get("apps") if isinstance(payload, dict) else payload
        return [dict(row) for row in rows if isinstance(row, Mapping)]
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _dedupe_static_runs_by_build(rows: Sequence[StaticRunCandidate]) -> tuple[list[StaticRunCandidate], list[dict[str, Any]]]:
    """Select the latest static run for each package/version/base APK build."""

    grouped: dict[tuple[str, str, str, str], list[StaticRunCandidate]] = defaultdict(list)
    for row in rows:
        grouped[(row.package_name, row.version_code, row.version_name, row.base_apk_sha256)].append(row)
    selected: list[StaticRunCandidate] = []
    exclusions: list[dict[str, Any]] = []
    for key in sorted(grouped):
        candidates = sorted(grouped[key], key=lambda item: (item.run_started_at_utc or item.created_at, item.static_run_id), reverse=True)
        contributor = candidates[0]
        selected.append(contributor)
        for extra in candidates[1:]:
            exclusions.append(
                {
                    "package_name": extra.package_name,
                    "static_run_id": extra.static_run_id,
                    "reason": "duplicate_same_build_static_analysis_not_history_contributor",
                    "contributing_static_run_id": contributor.static_run_id,
                    "excluded_version_code": extra.version_code,
                    "excluded_base_apk_sha256": extra.base_apk_sha256,
                }
            )
    selected.sort(key=lambda item: (item.package_name, item.run_started_at_utc or item.created_at, item.static_run_id))
    return selected, exclusions


def _static_runs_from_manifest(path: Path, packages: Sequence[str], *, run_sql_fn: RunSql | None = None) -> list[StaticRunCandidate]:
    wanted = {pkg.lower() for pkg in packages}
    manifest_rows = [row for row in _read_manifest_rows(path) if not wanted or str(row.get("package_name") or "").lower() in wanted]
    static_ids = sorted({
        int(part)
        for row in manifest_rows
        for part in str(row.get("selected_static_run_ids") or row.get("static_run_ids") or "").replace(";", ",").split(",")
        if part.strip().isdigit()
    })
    if not static_ids:
        return []
    run_rows = _static_runs_by_ids(static_ids, run_sql_fn=run_sql_fn)
    manifest_by_pkg = {str(row.get("package_name") or "").lower(): row for row in manifest_rows}
    out: list[StaticRunCandidate] = []
    for candidate in run_rows:
        mrow = manifest_by_pkg.get(candidate.package_name, {})
        expected_sha = str(mrow.get("selected_base_apk_sha256") or mrow.get("base_apk_sha256") or "").lower()
        if expected_sha and candidate.base_apk_sha256 != expected_sha:
            raise ValueError(f"Static run {candidate.static_run_id} hash mismatch for {candidate.package_name}")
        out.append(candidate)
    return out


def _static_runs_by_ids(static_ids: Sequence[int], *, run_sql_fn: RunSql | None = None) -> list[StaticRunCandidate]:
    placeholders = ",".join(["%s"] * len(static_ids))
    rows = _rows(f"{_static_run_select_sql()} WHERE sar.id IN ({placeholders}) ORDER BY a.package_name, sar.id", tuple(static_ids), run_sql_fn=run_sql_fn)
    return [_row_to_candidate(row, source_lineage="selected_static_run_ids") for row in rows]


def _static_runs_from_session(session_stamp: str, packages: Sequence[str], *, run_sql_fn: RunSql | None = None) -> list[StaticRunCandidate]:
    package_filter, params = _package_filter(packages)
    rows = _rows(
        f"""
        {_static_run_select_sql()}
        WHERE sar.session_stamp = %s
          AND UPPER(COALESCE(sar.status, '')) = 'COMPLETED'
          AND UPPER(COALESCE(sar.run_class, '')) = 'CANONICAL'
          AND COALESCE(sar.identity_valid, 0) = 1
          {package_filter}
        ORDER BY a.package_name, COALESCE(sar.run_started_at_utc, sar.created_at), sar.id
        """,
        (session_stamp, *params),
        run_sql_fn=run_sql_fn,
    )
    return [_row_to_candidate(row, source_lineage=f"static_session:{session_stamp}") for row in rows]


def _static_runs_latest_as_of(packages: Sequence[str], as_of_utc: str, *, run_sql_fn: RunSql | None = None) -> list[StaticRunCandidate]:
    package_filter, params = _package_filter(packages)
    rows = _rows(
        f"""
        {_static_run_select_sql()}
        WHERE UPPER(COALESCE(sar.status, '')) = 'COMPLETED'
          AND UPPER(COALESCE(sar.run_class, '')) = 'CANONICAL'
          AND COALESCE(sar.identity_valid, 0) = 1
          AND COALESCE(sar.run_started_at_utc, sar.created_at) <= %s
          {package_filter}
        ORDER BY a.package_name, COALESCE(sar.run_started_at_utc, sar.created_at), sar.id
        """,
        (as_of_utc, *params),
        run_sql_fn=run_sql_fn,
    )
    return [_row_to_candidate(row, source_lineage=f"latest_valid_as_of:{as_of_utc}") for row in rows]


def _static_runs_recent_window(
    packages: Sequence[str],
    window_start_utc: str,
    window_end_utc: str,
    *,
    run_sql_fn: RunSql | None = None,
) -> list[StaticRunCandidate]:
    package_filter, params = _package_filter(packages)
    rows = _rows(
        f"""
        {_static_run_select_sql()}
        WHERE UPPER(COALESCE(sar.status, '')) = 'COMPLETED'
          AND UPPER(COALESCE(sar.run_class, '')) = 'CANONICAL'
          AND COALESCE(sar.identity_valid, 0) = 1
          AND COALESCE(sar.run_started_at_utc, sar.created_at) >= %s
          AND COALESCE(sar.run_started_at_utc, sar.created_at) <= %s
          {package_filter}
        ORDER BY a.package_name, COALESCE(sar.run_started_at_utc, sar.created_at), sar.id
        """,
        (window_start_utc, window_end_utc, *params),
        run_sql_fn=run_sql_fn,
    )
    return [
        _row_to_candidate(row, source_lineage=f"fixed_recent_window:{window_start_utc}:{window_end_utc}")
        for row in rows
    ]


def _package_filter(packages: Sequence[str]) -> tuple[str, tuple[str, ...]]:
    wanted = tuple(sorted({pkg.lower() for pkg in packages if pkg}))
    if not wanted:
        return "", ()
    placeholders = ",".join(["%s"] * len(wanted))
    return f"AND LOWER(a.package_name) IN ({placeholders})", wanted


def _static_run_select_sql() -> str:
    return """
        SELECT
          sar.id AS static_run_id,
          LOWER(a.package_name) AS package_name,
          COALESCE(NULLIF(a.display_name, ''), a.package_name) AS display_name,
          COALESCE(NULLIF(cat.category_name, ''), NULLIF(a.profile_key, ''), '') AS app_category,
          av.version_code,
          av.version_name,
          sar.base_apk_sha256,
          sar.session_stamp AS static_session_stamp,
          sar.run_started_at_utc,
          sar.created_at,
          sar.status,
          sar.run_class AS canonical_status,
          sar.identity_valid,
          COALESCE(apks.split_count, 0) AS split_count
        FROM static_analysis_runs sar
        JOIN app_versions av ON av.id = sar.app_version_id
        JOIN apps a ON a.id = av.app_id
        LEFT JOIN android_app_categories cat ON cat.category_id = a.category_id
        LEFT JOIN apk_sets apks ON apks.apk_set_id = sar.apk_set_id
    """


def _dedupe_static_runs(rows: Sequence[StaticRunCandidate], requested_packages: Sequence[str]) -> tuple[list[StaticRunCandidate], list[dict[str, Any]]]:
    by_pkg: dict[str, list[StaticRunCandidate]] = {}
    for row in rows:
        by_pkg.setdefault(row.package_name, []).append(row)
    selected: list[StaticRunCandidate] = []
    exclusions: list[dict[str, Any]] = []
    for package, candidates in sorted(by_pkg.items()):
        candidates = sorted(candidates, key=lambda item: (item.run_started_at_utc or item.created_at, item.static_run_id))
        winner = candidates[-1]
        selected.append(winner)
        for duplicate in candidates[:-1]:
            same_build = duplicate.base_apk_sha256 == winner.base_apk_sha256 and duplicate.version_code == winner.version_code
            exclusions.append(
                {
                    "package_name": package,
                    "static_run_id": duplicate.static_run_id,
                    "reason": (
                        "duplicate_selected_build_static_analysis_not_app_level_contributor"
                        if same_build
                        else "older_or_different_build_static_analysis_not_app_level_contributor"
                    ),
                    "contributing_static_run_id": winner.static_run_id,
                    "excluded_version_code": duplicate.version_code,
                    "excluded_base_apk_sha256": duplicate.base_apk_sha256,
                }
            )
    for package in sorted(set(requested_packages) - set(by_pkg)):
        exclusions.append({"package_name": package, "static_run_id": "", "reason": "no_completed_canonical_identity_valid_static_run"})
    return selected, exclusions


def default_as_of_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()
