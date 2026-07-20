#!/usr/bin/env python3
"""Read-only audit for local canonical APK blobs that could move to cold storage."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scytaledroid.Config import app_config  # noqa: E402
from scytaledroid.Utils.System import mercury_storage  # noqa: E402

DEFAULT_COLD_ROOT = mercury_storage.configured_cold_apk_store_root()
RECENT_STATIC_DAYS = 14
YES = "yes"
NO = "no"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class ReceiptLineage:
    sha256: str
    package_name: str
    version_code: str
    version_name: str
    session_label: str
    observed_at: str
    split_role: str
    split_name: str
    is_base: bool
    base_sha256: str
    capture_key: str


@dataclass(frozen=True)
class StaticLineage:
    static_run_id: str
    package_name: str
    version_code: str
    base_apk_sha256: str
    scope_label: str
    status: str
    run_started_at_utc: str


@dataclass(frozen=True)
class DynamicLineage:
    dynamic_run_id: str
    static_run_id: str
    package_name: str
    version_code: str
    base_apk_sha256: str
    valid_dataset_run: bool | None
    quota_state: str
    started_at_utc: str


@dataclass(frozen=True)
class ColdPromotionRow:
    sha256: str
    size_bytes: int
    local_canonical_path: str
    proposed_mercury_cold_path: str
    package_name: str
    version_code: str
    version_name: str
    split_role: str
    split_name: str
    first_seen: str
    last_seen: str
    static_run_ids: str
    dynamic_run_ids: str
    receipt_count: int
    db_lineage_count: int
    data_android_apks_indexed: str
    referenced_by_current_research_dataset_beta: str
    referenced_by_paper_freeze_target: str
    referenced_by_current_dynamic_target: str
    referenced_by_current_installed_build: str
    referenced_by_active_dynamic_lineage: str
    referenced_by_recent_static_run: str
    current_active_build: bool
    referenced_only_by_older_harvests: bool
    promotion_class: str
    safe_to_promote: bool
    reason: str


@dataclass(frozen=True)
class PackageSummaryRow:
    package_name: str
    versions_observed: int
    versions_byte_available: int
    versions_metadata_only: int
    versions_hot: int
    versions_cold_candidate: int
    current_paper_protected_versions: int
    total_bytes: int
    promotable_bytes: int
    blocked_or_hot_bytes: int
    blob_count: int
    promotable_blob_count: int
    blocked_or_hot_blob_count: int


@dataclass
class ReceiptIndex:
    by_sha: dict[str, list[ReceiptLineage]] = field(default_factory=lambda: defaultdict(list))
    versions_by_package: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    shas_by_capture: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    captures_by_base_sha: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    base_sha_by_capture: dict[str, str] = field(default_factory=dict)


@dataclass
class LibraryIndex:
    shas: set[str] = field(default_factory=set)
    split_sets: set[tuple[str, str, str]] = field(default_factory=set)
    versions_by_package: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))


@dataclass
class DependencyContext:
    cohort_key: str
    cohort_packages: set[str]
    current_installed_versions: dict[str, str]
    current_research_base_shas: set[str]
    current_research_capture_keys: set[str]
    paper_base_shas: set[str]
    paper_capture_keys: set[str]
    current_dynamic_base_shas: set[str]
    current_dynamic_capture_keys: set[str]
    active_dynamic_base_shas: set[str]
    active_dynamic_capture_keys: set[str]
    recent_static_base_shas: set[str]
    recent_static_capture_keys: set[str]
    static_by_base_sha: dict[str, list[StaticLineage]]
    dynamic_by_base_sha: dict[str, list[DynamicLineage]]
    source_status: dict[str, str]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=Path(app_config.DATA_DIR), help="Data root; default DATA_DIR.")
    parser.add_argument("--cold-root", type=Path, default=DEFAULT_COLD_ROOT, help="Proposed Mercury cold store root.")
    parser.add_argument("--package", dest="packages", action="append", default=[], help="Limit to package; repeatable.")
    parser.add_argument("--cohort-key", default=None, help="Research cohort key; default active cohort.")
    parser.add_argument("--limit", type=int, default=0, help="Limit rows printed/emitted.")
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout.")
    parser.add_argument("--csv", type=Path, default=None, help="Optional legacy candidates CSV output path.")
    parser.add_argument("--output-dir", type=Path, default=None, help="Output directory; default output/audit/apk_cold_promotion/<stamp>.")
    parser.add_argument("--no-output", action="store_true", help="Do not write summary/candidate CSV artifacts.")
    parser.add_argument("--no-db", action="store_true", help="Do not query MariaDB lineage/read-model tables.")
    return parser


def build_audit(
    *,
    data_root: Path,
    cold_root: Path,
    packages: set[str] | None = None,
    limit: int = 0,
    cohort_key: str | None = None,
    use_db: bool = True,
) -> dict[str, Any]:
    root = data_root.expanduser()
    canonical_root = root / "store" / "apk" / "sha256"
    receipt_index = _receipt_lineage(root / "receipts" / "harvest")
    library = _library_index(root / "android_apks")
    dependencies = _dependency_context(
        data_root=root,
        receipt_index=receipt_index,
        cohort_key=cohort_key,
        use_db=use_db,
    )
    latest_by_package = _latest_version_by_package(receipt_index.by_sha)
    package_filter = {_norm_package(pkg) for pkg in packages or set() if _norm_package(pkg)}

    rows: list[ColdPromotionRow] = []
    total_local_regular = 0
    for path in sorted(canonical_root.rglob("*.apk")) if canonical_root.exists() else []:
        if not path.is_file() or path.is_symlink():
            continue
        sha = path.stem.lower()
        if len(sha) != 64:
            continue
        total_local_regular += 1
        lineages = receipt_index.by_sha.get(sha, [])
        if package_filter and not any(item.package_name in package_filter for item in lineages):
            continue
        row = _classify_blob(
            path=path,
            sha=sha,
            cold_root=cold_root,
            lineages=lineages,
            library=library,
            latest_by_package=latest_by_package,
            dependencies=dependencies,
        )
        rows.append(row)
        if limit > 0 and len(rows) >= limit:
            break

    package_summary = _package_summary(rows, receipt_index)
    blocked = [row for row in rows if not row.safe_to_promote]
    candidates = [row for row in rows if row.safe_to_promote]
    seed_alignment = _seed_alignment(rows, receipt_index, library)

    return {
        "schema_version": "apk_cold_promotion_audit_v2",
        "mode": "read_only",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "data_root": root.as_posix(),
        "canonical_root": canonical_root.as_posix(),
        "proposed_cold_root": cold_root.as_posix(),
        "cohort_key": dependencies.cohort_key,
        "source_status": dict(dependencies.source_status),
        "summary": {
            "local_regular_canonical_blobs": total_local_regular,
            "rows_emitted": len(rows),
            "safe_to_promote": len(candidates),
            "blocked_or_keep_hot": len(blocked),
            "safe_to_promote_bytes": sum(row.size_bytes for row in candidates),
            "blocked_or_keep_hot_bytes": sum(row.size_bytes for row in blocked),
            "unknown_current_research_dataset_beta": sum(
                1 for row in rows if row.referenced_by_current_research_dataset_beta == UNKNOWN
            ),
            "protected_current_research_dataset_beta": sum(
                1 for row in rows if row.referenced_by_current_research_dataset_beta == YES
            ),
            "protected_current_installed": sum(1 for row in rows if row.referenced_by_current_installed_build == YES),
            "protected_paper_freeze": sum(1 for row in rows if row.referenced_by_paper_freeze_target == YES),
            "protected_current_dynamic": sum(1 for row in rows if row.referenced_by_current_dynamic_target == YES),
            "promotion_class_counts": _count_by(row.promotion_class for row in rows),
        },
        "apk_library_seed_alignment": seed_alignment,
        "top_25_largest_promotable_packages": [
            asdict(row) for row in sorted(package_summary, key=lambda item: item.promotable_bytes, reverse=True)[:25]
        ],
        "top_25_safest_promotion_candidates": [
            asdict(row) for row in sorted(candidates, key=lambda item: (-item.size_bytes, item.package_name, item.sha256))[:25]
        ],
        "rows": [asdict(row) for row in rows],
        "package_summary": [asdict(row) for row in package_summary],
        "blocked": [asdict(row) for row in blocked],
    }


def _classify_blob(
    *,
    path: Path,
    sha: str,
    cold_root: Path,
    lineages: list[ReceiptLineage],
    library: LibraryIndex,
    latest_by_package: dict[str, tuple[int, str]],
    dependencies: DependencyContext,
) -> ColdPromotionRow:
    packages = sorted({item.package_name for item in lineages if item.package_name})
    version_codes = sorted({item.version_code for item in lineages if item.version_code}, key=_version_sort_tuple)
    version_names = sorted({item.version_name for item in lineages if item.version_name})
    split_roles = sorted({item.split_role for item in lineages if item.split_role})
    split_names = sorted({item.split_name for item in lineages if item.split_name})
    capture_keys = {item.capture_key for item in lineages if item.capture_key}
    base_shas = {item.base_sha256 for item in lineages if item.base_sha256}
    package_name = ";".join(packages)
    version_code = ";".join(version_codes)
    version_name = ";".join(version_names)

    static_lineage = _unique_static(base_shas, dependencies.static_by_base_sha)
    dynamic_lineage = _unique_dynamic(base_shas, dependencies.dynamic_by_base_sha)
    static_run_ids = sorted({row.static_run_id for row in static_lineage if row.static_run_id}, key=_numeric_text_key)
    dynamic_run_ids = sorted({row.dynamic_run_id for row in dynamic_lineage if row.dynamic_run_id})

    current_research_known = _known_source(dependencies.source_status.get("current_research_dataset_beta"))
    paper_known = _known_source(dependencies.source_status.get("paper_freeze"))
    current_dynamic_known = _known_source(dependencies.source_status.get("current_dynamic"))
    inventory_known = _known_source(dependencies.source_status.get("inventory"))

    current_research_hit = bool(
        (base_shas & dependencies.current_research_base_shas)
        or (capture_keys & dependencies.current_research_capture_keys)
    )
    paper_hit = bool((base_shas & dependencies.paper_base_shas) or (capture_keys & dependencies.paper_capture_keys))
    current_dynamic_hit = bool(
        (base_shas & dependencies.current_dynamic_base_shas)
        or (capture_keys & dependencies.current_dynamic_capture_keys)
    )
    active_dynamic_hit = bool(
        (base_shas & dependencies.active_dynamic_base_shas)
        or (capture_keys & dependencies.active_dynamic_capture_keys)
    )
    recent_static_hit = bool(
        (base_shas & dependencies.recent_static_base_shas)
        or (capture_keys & dependencies.recent_static_capture_keys)
    )
    installed_hit = _matches_installed(lineages, dependencies.current_installed_versions)
    indexed = sha in library.shas
    active = _is_latest_known_version(lineages, latest_by_package)
    older_only = bool(lineages) and not active

    flag_current_research = _flag(current_research_hit, current_research_known)
    flag_paper = _flag(paper_hit, paper_known)
    flag_current_dynamic = _flag(current_dynamic_hit, current_dynamic_known)
    flag_installed = _flag(installed_hit, inventory_known)
    flag_active_dynamic = _flag(active_dynamic_hit, _known_source(dependencies.source_status.get("active_dynamic")))
    flag_recent_static = _flag(recent_static_hit, _known_source(dependencies.source_status.get("recent_static")))

    promotion_class, reason = _promotion_decision(
        sha=sha,
        lineages=lineages,
        packages=packages,
        version_codes=version_codes,
        current_research=flag_current_research,
        current_installed=flag_installed,
        paper=flag_paper,
        current_dynamic=flag_current_dynamic,
        active_dynamic=flag_active_dynamic,
        recent_static=flag_recent_static,
    )

    return ColdPromotionRow(
        sha256=sha,
        size_bytes=path.stat().st_size,
        local_canonical_path=path.as_posix(),
        proposed_mercury_cold_path=(cold_root / "data" / "store" / "apk" / "sha256" / sha[:2] / f"{sha}.apk").as_posix(),
        package_name=package_name,
        version_code=version_code,
        version_name=version_name,
        split_role=";".join(split_roles),
        split_name=";".join(split_names),
        first_seen=_min_text(item.observed_at for item in lineages),
        last_seen=_max_text(item.observed_at for item in lineages),
        static_run_ids=";".join(static_run_ids),
        dynamic_run_ids=";".join(dynamic_run_ids),
        receipt_count=len(lineages),
        db_lineage_count=len(static_lineage) + len(dynamic_lineage),
        data_android_apks_indexed=YES if indexed else NO,
        referenced_by_current_research_dataset_beta=flag_current_research,
        referenced_by_paper_freeze_target=flag_paper,
        referenced_by_current_dynamic_target=flag_current_dynamic,
        referenced_by_current_installed_build=flag_installed,
        referenced_by_active_dynamic_lineage=flag_active_dynamic,
        referenced_by_recent_static_run=flag_recent_static,
        current_active_build=active,
        referenced_only_by_older_harvests=older_only,
        promotion_class=promotion_class,
        safe_to_promote=promotion_class == "PROMOTE_COLD_PRIOR_VERSION_CANDIDATE",
        reason=reason,
    )


def _dependency_context(
    *,
    data_root: Path,
    receipt_index: ReceiptIndex,
    cohort_key: str | None,
    use_db: bool,
) -> DependencyContext:
    source_status: dict[str, str] = {}
    resolved_cohort_key, cohort_packages = _active_cohort(cohort_key)
    source_status["cohort"] = "ok" if cohort_packages else "unknown"
    inventory_versions = _current_installed_versions(data_root)
    source_status["inventory"] = "ok" if inventory_versions else "unknown"

    static_by_base: dict[str, list[StaticLineage]] = defaultdict(list)
    dynamic_by_base: dict[str, list[DynamicLineage]] = defaultdict(list)
    web_static_ids: set[str] = set()
    web_current_versions: dict[str, str] = {}
    web_dynamic_ids: set[str] = set()
    db_ok = False
    if use_db:
        try:
            db_payload = _db_dependency_payload(resolved_cohort_key, cohort_packages)
            static_by_base = db_payload["static_by_base_sha"]
            dynamic_by_base = db_payload["dynamic_by_base_sha"]
            web_static_ids = db_payload["web_static_run_ids"]
            web_current_versions = db_payload["web_current_versions"]
            web_dynamic_ids = db_payload["web_dynamic_run_ids"]
            db_ok = True
        except Exception as exc:
            source_status["db"] = f"unavailable:{type(exc).__name__}"
    if db_ok:
        source_status["db"] = "ok"
    elif not use_db:
        source_status["db"] = "disabled"

    paper_base_shas, paper_status = _paper_freeze_base_shas()
    source_status["paper_freeze"] = paper_status

    active_dynamic_base_shas: set[str] = set()
    current_dynamic_base_shas: set[str] = set()
    current_research_base_shas: set[str] = set()
    recent_static_base_shas: set[str] = set()

    recent_cutoff = datetime.now(UTC) - timedelta(days=RECENT_STATIC_DAYS)
    for base_sha, rows in static_by_base.items():
        for row in rows:
            if row.static_run_id in web_static_ids:
                current_research_base_shas.add(base_sha)
            if _is_recent(row.run_started_at_utc, recent_cutoff):
                recent_static_base_shas.add(base_sha)
    for base_sha, rows in dynamic_by_base.items():
        for row in rows:
            if row.valid_dataset_run is True:
                active_dynamic_base_shas.add(base_sha)
            if row.dynamic_run_id in web_dynamic_ids:
                current_dynamic_base_shas.add(base_sha)
            elif row.package_name in web_current_versions and row.version_code == web_current_versions.get(row.package_name):
                current_dynamic_base_shas.add(base_sha)

    current_research_capture_keys = _capture_keys_for_base_shas(current_research_base_shas, receipt_index)
    paper_capture_keys = _capture_keys_for_base_shas(paper_base_shas, receipt_index)
    current_dynamic_capture_keys = _capture_keys_for_base_shas(current_dynamic_base_shas, receipt_index)
    active_dynamic_capture_keys = _capture_keys_for_base_shas(active_dynamic_base_shas, receipt_index)
    recent_static_capture_keys = _capture_keys_for_base_shas(recent_static_base_shas, receipt_index)

    source_status["current_research_dataset_beta"] = "ok" if db_ok and (web_static_ids or current_research_base_shas) else "unknown"
    source_status["current_dynamic"] = "ok" if db_ok and (web_dynamic_ids or current_dynamic_base_shas) else "unknown"
    source_status["active_dynamic"] = "ok" if db_ok else "unknown"
    source_status["recent_static"] = "ok" if db_ok else "unknown"

    return DependencyContext(
        cohort_key=resolved_cohort_key,
        cohort_packages=cohort_packages,
        current_installed_versions=inventory_versions,
        current_research_base_shas=current_research_base_shas,
        current_research_capture_keys=current_research_capture_keys,
        paper_base_shas=paper_base_shas,
        paper_capture_keys=paper_capture_keys,
        current_dynamic_base_shas=current_dynamic_base_shas,
        current_dynamic_capture_keys=current_dynamic_capture_keys,
        active_dynamic_base_shas=active_dynamic_base_shas,
        active_dynamic_capture_keys=active_dynamic_capture_keys,
        recent_static_base_shas=recent_static_base_shas,
        recent_static_capture_keys=recent_static_capture_keys,
        static_by_base_sha=static_by_base,
        dynamic_by_base_sha=dynamic_by_base,
        source_status=source_status,
    )


def _db_dependency_payload(cohort_key: str, cohort_packages: set[str]) -> dict[str, Any]:
    from scytaledroid.Database.db_core import run_sql

    params: list[Any] = []
    package_filter = ""
    if cohort_packages:
        placeholders = ", ".join(["%s"] * len(cohort_packages))
        package_filter = f"WHERE h.package_name_lc IN ({placeholders})"
        params.extend(sorted(cohort_packages))
    static_rows = run_sql(
        f"""
        SELECT
          h.static_run_id,
          h.package_name_lc AS package_name,
          CAST(h.version_code AS CHAR) AS version_code,
          LOWER(TRIM(h.base_apk_sha256)) AS base_apk_sha256,
          COALESCE(s.scope_label, '') AS scope_label,
          COALESCE(s.status, '') AS status,
          COALESCE(CAST(s.run_started_at_utc AS CHAR), CAST(s.created_at AS CHAR), '') AS run_started_at_utc
        FROM v_static_handoff_v1 h
        LEFT JOIN static_analysis_runs s ON s.id = h.static_run_id
        {package_filter}
        """,
        tuple(params),
        fetch="all",
        dictionary=True,
    ) or []
    static_by_base: dict[str, list[StaticLineage]] = defaultdict(list)
    for row in static_rows:
        base = _norm_sha(row.get("base_apk_sha256"))
        if not base:
            continue
        static_by_base[base].append(
            StaticLineage(
                static_run_id=_norm_text(row.get("static_run_id")),
                package_name=_norm_package(row.get("package_name")),
                version_code=_norm_text(row.get("version_code")),
                base_apk_sha256=base,
                scope_label=_norm_text(row.get("scope_label")),
                status=_norm_text(row.get("status")),
                run_started_at_utc=_norm_text(row.get("run_started_at_utc")),
            )
        )

    dyn_params: list[Any] = []
    dyn_filter = ""
    if cohort_packages:
        placeholders = ", ".join(["%s"] * len(cohort_packages))
        dyn_filter = f"WHERE package_name_lc IN ({placeholders})"
        dyn_params.extend(sorted(cohort_packages))
    dynamic_rows = run_sql(
        f"""
        SELECT
          dynamic_run_id,
          COALESCE(CAST(effective_static_run_id AS CHAR), CAST(static_run_id AS CHAR), '') AS static_run_id,
          package_name_lc AS package_name,
          CAST(version_code AS CHAR) AS version_code,
          LOWER(TRIM(base_apk_sha256)) AS base_apk_sha256,
          valid_dataset_run,
          COALESCE(quota_state, '') AS quota_state,
          COALESCE(CAST(started_at_utc AS CHAR), '') AS started_at_utc
        FROM v_dynamic_run_context_v1
        {dyn_filter}
        """,
        tuple(dyn_params),
        fetch="all",
        dictionary=True,
    ) or []
    dynamic_by_base: dict[str, list[DynamicLineage]] = defaultdict(list)
    for row in dynamic_rows:
        base = _norm_sha(row.get("base_apk_sha256"))
        if not base:
            continue
        dynamic_by_base[base].append(
            DynamicLineage(
                dynamic_run_id=_norm_text(row.get("dynamic_run_id")),
                static_run_id=_norm_text(row.get("static_run_id")),
                package_name=_norm_package(row.get("package_name")),
                version_code=_norm_text(row.get("version_code")),
                base_apk_sha256=base,
                valid_dataset_run=_tri_bool(row.get("valid_dataset_run")),
                quota_state=_norm_text(row.get("quota_state")),
                started_at_utc=_norm_text(row.get("started_at_utc")),
            )
        )

    web_sql = """
        SELECT
          package_name,
          latest_static_run_id,
          latest_version_code,
          latest_dynamic_run_id
        FROM v_web_dynamic_app_queue_v1
    """
    web_params: tuple[Any, ...] = ()
    if cohort_key:
        web_sql += " WHERE LOWER(cohort_key) = LOWER(%s)"
        web_params = (cohort_key,)
    web_rows = run_sql(web_sql, web_params, fetch="all", dictionary=True) or []
    web_static_ids = {_norm_text(row.get("latest_static_run_id")) for row in web_rows if _norm_text(row.get("latest_static_run_id"))}
    web_dynamic_ids = {_norm_text(row.get("latest_dynamic_run_id")) for row in web_rows if _norm_text(row.get("latest_dynamic_run_id"))}
    web_current_versions = {
        _norm_package(row.get("package_name")): _norm_text(row.get("latest_version_code"))
        for row in web_rows
        if _norm_package(row.get("package_name")) and _norm_text(row.get("latest_version_code"))
    }
    return {
        "static_by_base_sha": static_by_base,
        "dynamic_by_base_sha": dynamic_by_base,
        "web_static_run_ids": web_static_ids,
        "web_dynamic_run_ids": web_dynamic_ids,
        "web_current_versions": web_current_versions,
    }


def _receipt_lineage(receipts_root: Path) -> ReceiptIndex:
    index = ReceiptIndex()
    if not receipts_root.exists():
        return index
    for receipt in sorted(receipts_root.glob("*/*.json")):
        try:
            payload = json.loads(receipt.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        package = payload.get("package") if isinstance(payload.get("package"), dict) else {}
        execution = payload.get("execution") if isinstance(payload.get("execution"), dict) else {}
        observed = execution.get("observed_artifacts")
        if not isinstance(observed, list):
            continue
        package_name = _norm_package(package.get("package_name"))
        version_code = _norm_text(package.get("version_code"))
        version_name = _norm_text(package.get("version_name"))
        session_label = _norm_text(package.get("session_label") or receipt.parent.name)
        capture_key = _capture_key(package_name, version_code, session_label)
        base_sha = ""
        for item in observed:
            if isinstance(item, dict) and item.get("is_base") is True:
                base_sha = _norm_sha(item.get("sha256"))
                break
        if not base_sha:
            for item in observed:
                if isinstance(item, dict):
                    label = _norm_text(item.get("split_label")).lower()
                    if label == "base":
                        base_sha = _norm_sha(item.get("sha256"))
                        break
        if package_name and version_code:
            index.versions_by_package[package_name].add(version_code)
        for item in observed:
            if not isinstance(item, dict):
                continue
            sha = _norm_sha(item.get("sha256"))
            if not sha:
                continue
            split_name = _norm_text(item.get("split_label") or item.get("file_name"))
            is_base = item.get("is_base") is True or split_name.lower() == "base"
            lineage = ReceiptLineage(
                sha256=sha,
                package_name=package_name,
                version_code=version_code,
                version_name=version_name,
                session_label=session_label,
                observed_at=_norm_text(payload.get("generated_at_utc") or item.get("pulled_at")),
                split_role="base" if is_base else "split",
                split_name=split_name or ("base" if is_base else ""),
                is_base=is_base,
                base_sha256=base_sha or (sha if is_base else ""),
                capture_key=capture_key,
            )
            index.by_sha[sha].append(lineage)
            index.shas_by_capture[capture_key].add(sha)
        if base_sha:
            index.captures_by_base_sha[base_sha].add(capture_key)
            index.base_sha_by_capture[capture_key] = base_sha
    return index


def _library_index(root: Path) -> LibraryIndex:
    out = LibraryIndex()
    if not root.exists():
        return out
    for manifest in root.glob("packages/*/*/split_sets/*/package_manifest.json"):
        try:
            payload = json.loads(manifest.read_text(encoding="utf-8"))
        except Exception:
            continue
        package_name = _norm_package(payload.get("package_name"))
        version_code = _norm_text(payload.get("version_code"))
        split_hash = _norm_text(payload.get("planned_split_set_hash") or payload.get("split_set_hash"))
        if package_name and version_code:
            out.versions_by_package[package_name].add(version_code)
        if package_name and version_code and split_hash:
            out.split_sets.add((package_name, version_code, split_hash))
        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, list):
            continue
        for item in artifacts:
            if isinstance(item, dict):
                sha = _norm_sha(item.get("sha256"))
                if sha:
                    out.shas.add(sha)
    return out


def _active_cohort(cohort_key: str | None) -> tuple[str, set[str]]:
    try:
        from scytaledroid.DynamicAnalysis.research_cohort_runtime import (
            active_research_cohort_key,
            active_research_cohort_packages,
        )

        key = _norm_text(cohort_key or active_research_cohort_key() or "research_dataset_beta").lower()
        packages = {_norm_package(pkg) for pkg in active_research_cohort_packages(key) if _norm_package(pkg)}
        return key, packages
    except Exception:
        return _norm_text(cohort_key or "research_dataset_beta").lower(), set()


def _current_installed_versions(data_root: Path) -> dict[str, str]:
    path = data_root / "state" / "active_device.json"
    serial = ""
    try:
        serial = _norm_text(json.loads(path.read_text(encoding="utf-8")).get("last_serial"))
    except Exception:
        serial = ""
    inventory = data_root / "state" / serial / "inventory" / "latest.json" if serial else None
    if not inventory or not inventory.exists():
        return {}
    try:
        payload = json.loads(inventory.read_text(encoding="utf-8"))
    except Exception:
        return {}
    packages = payload.get("packages")
    if not isinstance(packages, list):
        return {}
    out: dict[str, str] = {}
    for row in packages:
        if not isinstance(row, dict):
            continue
        pkg = _norm_package(row.get("package_name"))
        version = _norm_text(row.get("version_code"))
        if pkg and version:
            out[pkg] = version
    return out


def _paper_freeze_base_shas() -> tuple[set[str], str]:
    try:
        from scytaledroid.DynamicAnalysis.services.paper_freeze_readiness import (
            build_paper_freeze_manifest,
        )

        manifest = build_paper_freeze_manifest()
    except Exception as exc:
        return set(), f"unavailable:{type(exc).__name__}"
    rows = manifest.get("apps") if isinstance(manifest, dict) else None
    if not isinstance(rows, list):
        return set(), "unknown"
    shas = {_norm_sha(row.get("selected_base_apk_sha256")) for row in rows if isinstance(row, dict)}
    shas = {sha for sha in shas if sha}
    return shas, "ok" if shas else "unknown"


def _package_summary(rows: list[ColdPromotionRow], receipt_index: ReceiptIndex) -> list[PackageSummaryRow]:
    by_pkg: dict[str, list[ColdPromotionRow]] = defaultdict(list)
    for row in rows:
        for pkg in _split_semicolon(row.package_name) or ["unknown"]:
            by_pkg[pkg].append(row)
    out: list[PackageSummaryRow] = []
    for pkg, pkg_rows in sorted(by_pkg.items()):
        observed_versions = set(receipt_index.versions_by_package.get(pkg, set()))
        byte_versions = {_version for row in pkg_rows for _version in _split_semicolon(row.version_code)}
        hot_versions = {
            _version
            for row in pkg_rows
            if not row.safe_to_promote
            for _version in _split_semicolon(row.version_code)
        }
        cold_versions = {
            _version
            for row in pkg_rows
            if row.safe_to_promote
            for _version in _split_semicolon(row.version_code)
        }
        protected_versions = {
            _version
            for row in pkg_rows
            if row.referenced_by_current_research_dataset_beta == YES
            or row.referenced_by_paper_freeze_target == YES
            or row.referenced_by_current_installed_build == YES
            or row.referenced_by_current_dynamic_target == YES
            for _version in _split_semicolon(row.version_code)
        }
        promotable = [row for row in pkg_rows if row.safe_to_promote]
        blocked = [row for row in pkg_rows if not row.safe_to_promote]
        out.append(
            PackageSummaryRow(
                package_name=pkg,
                versions_observed=len(observed_versions | byte_versions),
                versions_byte_available=len(byte_versions),
                versions_metadata_only=len(observed_versions - byte_versions),
                versions_hot=len(hot_versions),
                versions_cold_candidate=len(cold_versions),
                current_paper_protected_versions=len(protected_versions),
                total_bytes=sum(row.size_bytes for row in pkg_rows),
                promotable_bytes=sum(row.size_bytes for row in promotable),
                blocked_or_hot_bytes=sum(row.size_bytes for row in blocked),
                blob_count=len(pkg_rows),
                promotable_blob_count=len(promotable),
                blocked_or_hot_blob_count=len(blocked),
            )
        )
    return out


def _seed_alignment(rows: list[ColdPromotionRow], receipt_index: ReceiptIndex, library: LibraryIndex) -> dict[str, Any]:
    packages_with_multi_versions = {
        pkg for pkg, versions in receipt_index.versions_by_package.items() if len(versions) >= 2
    }
    row_versions: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        for pkg in _split_semicolon(row.package_name):
            for version in _split_semicolon(row.version_code):
                row_versions[pkg].add(version)
    return {
        "blobs_already_indexed": sum(1 for row in rows if row.data_android_apks_indexed == YES),
        "blobs_missing_from_index": sum(1 for row in rows if row.data_android_apks_indexed == NO),
        "package_version_entries_seedable_from_receipts": sum(len(versions) for versions in receipt_index.versions_by_package.values()),
        "packages_seedable_from_receipts": len(receipt_index.versions_by_package),
        "split_sets_seedable_from_receipts": len(receipt_index.shas_by_capture),
        "multi_version_apps_ready_for_static_comparison": len(
            [pkg for pkg, versions in row_versions.items() if len(versions) >= 2]
        ),
        "multi_version_apps_receipt_metadata_available": len(packages_with_multi_versions),
        "library_indexed_blobs": len(library.shas),
        "library_indexed_package_versions": sum(len(versions) for versions in library.versions_by_package.values()),
        "library_indexed_split_sets": len(library.split_sets),
    }


def write_outputs(audit: dict[str, Any], output_dir: Path | None = None) -> dict[str, str]:
    out = output_dir or _default_output_dir()
    out.mkdir(parents=True, exist_ok=True)
    summary = {key: value for key, value in audit.items() if key not in {"rows", "package_summary", "blocked"}}
    paths = {
        "summary_json": (out / "summary.json").as_posix(),
        "candidates_csv": (out / "candidates.csv").as_posix(),
        "package_summary_csv": (out / "package_summary.csv").as_posix(),
        "blocked_csv": (out / "blocked.csv").as_posix(),
    }
    Path(paths["summary_json"]).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_csv(Path(paths["candidates_csv"]), [row for row in audit["rows"] if row.get("safe_to_promote") is True])
    _write_csv(Path(paths["package_summary_csv"]), list(audit["package_summary"]))
    _write_csv(Path(paths["blocked_csv"]), list(audit["blocked"]))
    return paths


def _default_output_dir() -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Path(app_config.OUTPUT_DIR) / "audit" / "apk_cold_promotion" / stamp


def _promotion_decision(
    *,
    sha: str,
    lineages: list[ReceiptLineage],
    packages: list[str],
    version_codes: list[str],
    current_research: str,
    current_installed: str,
    paper: str,
    current_dynamic: str,
    active_dynamic: str,
    recent_static: str,
) -> tuple[str, str]:
    if not lineages:
        return "BLOCKED_MISSING_LINEAGE", "canonical blob has no harvest receipt lineage"
    if len(packages) > 1 or len(version_codes) > 1:
        return "BLOCKED_HASH_OR_PATH_CONFLICT", "hash maps to multiple package/version identities"
    if current_research == YES:
        return "KEEP_HOT_CURRENT_RESEARCH_DATASET_BETA", "referenced by current Research Dataset Beta static/queue target"
    if current_installed == YES:
        return "KEEP_HOT_CURRENT_INSTALLED_BUILD", "matches current installed device build"
    if paper == YES:
        return "KEEP_HOT_SELECTED_PAPER_TARGET", "referenced by selected paper-freeze target build"
    if current_dynamic == YES:
        return "KEEP_HOT_CURRENT_DYNAMIC_TARGET", "referenced by current dynamic target build"
    if active_dynamic == YES:
        return "KEEP_HOT_ACTIVE_DYNAMIC_LINEAGE", "referenced by valid dynamic evidence lineage"
    if recent_static == YES:
        return "KEEP_HOT_RECENT_STATIC_RUN", f"referenced by static run in last {RECENT_STATIC_DAYS} days"
    if current_research == UNKNOWN:
        return "BLOCKED_UNKNOWN_RESEARCH_STATUS", "current Research Dataset Beta dependency could not be resolved"
    if not packages or not version_codes:
        return "BLOCKED_METADATA_INCOMPLETE", "receipt lineage is missing package/version metadata"
    return "PROMOTE_COLD_PRIOR_VERSION_CANDIDATE", "prior-version receipt-backed blob with no current/paper/dynamic protection"


def _latest_version_by_package(index: dict[str, list[ReceiptLineage]]) -> dict[str, tuple[int, str]]:
    latest: dict[str, tuple[int, str]] = {}
    for rows in index.values():
        for row in rows:
            pkg = row.package_name
            if not pkg:
                continue
            key = (_version_sort_key(row.version_code), row.version_name)
            if pkg not in latest or key > latest[pkg]:
                latest[pkg] = key
    return latest


def _is_latest_known_version(rows: list[ReceiptLineage], latest: dict[str, tuple[int, str]]) -> bool:
    for row in rows:
        pkg = row.package_name
        if pkg and (_version_sort_key(row.version_code), row.version_name) == latest.get(pkg):
            return True
    return False


def _matches_installed(rows: list[ReceiptLineage], installed: dict[str, str]) -> bool:
    for row in rows:
        if row.package_name and row.version_code and installed.get(row.package_name) == row.version_code:
            return True
    return False


def _capture_keys_for_base_shas(base_shas: set[str], receipt_index: ReceiptIndex) -> set[str]:
    out: set[str] = set()
    for sha in base_shas:
        out.update(receipt_index.captures_by_base_sha.get(sha, set()))
    return out


def _unique_static(base_shas: set[str], by_base: dict[str, list[StaticLineage]]) -> list[StaticLineage]:
    seen: set[tuple[str, str]] = set()
    out: list[StaticLineage] = []
    for sha in base_shas:
        for row in by_base.get(sha, []):
            key = (row.static_run_id, row.base_apk_sha256)
            if key not in seen:
                seen.add(key)
                out.append(row)
    return out


def _unique_dynamic(base_shas: set[str], by_base: dict[str, list[DynamicLineage]]) -> list[DynamicLineage]:
    seen: set[tuple[str, str]] = set()
    out: list[DynamicLineage] = []
    for sha in base_shas:
        for row in by_base.get(sha, []):
            key = (row.dynamic_run_id, row.base_apk_sha256)
            if key not in seen:
                seen.add(key)
                out.append(row)
    return out


def _known_source(status: str | None) -> bool:
    return _norm_text(status).lower() == "ok"


def _flag(hit: bool, known: bool) -> str:
    if hit:
        return YES
    return NO if known else UNKNOWN


def _is_recent(value: str, cutoff: datetime) -> bool:
    text = _norm_text(value)
    if not text:
        return False
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt >= cutoff


def _capture_key(package_name: str, version_code: str, session_label: str) -> str:
    return f"{package_name}|{version_code}|{session_label}"


def _tri_bool(value: Any) -> bool | None:
    if value is True or value == 1 or str(value).strip() == "1":
        return True
    if value is False or value == 0 or str(value).strip() == "0":
        return False
    return None


def _version_sort_key(value: object) -> int:
    text = _norm_text(value)
    try:
        return int(text)
    except ValueError:
        return -1


def _version_sort_tuple(value: str) -> tuple[int, str]:
    return (_version_sort_key(value), value)


def _numeric_text_key(value: str) -> tuple[int, str]:
    return (_version_sort_key(value), value)


def _min_text(values: Iterable[Any]) -> str:
    filtered = sorted(str(value) for value in values if str(value or "").strip())
    return filtered[0] if filtered else ""


def _max_text(values: Iterable[Any]) -> str:
    filtered = sorted(str(value) for value in values if str(value or "").strip())
    return filtered[-1] if filtered else ""


def _count_by(values: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for value in values:
        out[value] = out.get(value, 0) + 1
    return dict(sorted(out.items()))


def _split_semicolon(value: str) -> list[str]:
    return [part for part in str(value or "").split(";") if part]


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _norm_package(value: Any) -> str:
    return _norm_text(value).lower()


def _norm_sha(value: Any) -> str:
    text = _norm_text(value).lower()
    return text if len(text) == 64 else ""


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fieldnames})


def _print_human(audit: dict[str, Any]) -> None:
    summary = audit["summary"]
    print("APK cold-promotion audit")
    print(f"  Mode                    : {audit['mode']}")
    print(f"  Cohort                  : {audit['cohort_key']}")
    print(f"  Canonical root          : {audit['canonical_root']}")
    print(f"  Proposed cold root      : {audit['proposed_cold_root']}")
    print(f"  Rows                    : {summary['rows_emitted']}")
    print(f"  Local regular blobs      : {summary['local_regular_canonical_blobs']}")
    print(f"  Safe to promote          : {summary['safe_to_promote']}")
    print(f"  Blocked / keep hot       : {summary['blocked_or_keep_hot']}")
    print(f"  Safe bytes               : {summary['safe_to_promote_bytes']}")
    print(f"  Blocked / hot bytes      : {summary['blocked_or_keep_hot_bytes']}")
    print(f"  Unknown RDB status       : {summary['unknown_current_research_dataset_beta']}")
    print("  Promotion classes:")
    for key, value in summary["promotion_class_counts"].items():
        print(f"    {key}: {value}")
    print()
    for row in audit["rows"][:25]:
        print(
            f"{'PROMOTE' if row['safe_to_promote'] else 'KEEP'} "
            f"{row['sha256'][:12]}... {row['size_bytes']} bytes "
            f"{row['package_name'] or 'unknown'} {row['version_code'] or 'unknown'} "
            f"class={row['promotion_class']}"
        )


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    audit = build_audit(
        data_root=args.data_root,
        cold_root=args.cold_root,
        packages=set(args.packages),
        limit=args.limit,
        cohort_key=args.cohort_key,
        use_db=not args.no_db,
    )
    output_paths: dict[str, str] = {}
    if not args.no_output:
        output_paths = write_outputs(audit, args.output_dir)
        audit["output_paths"] = output_paths
    if args.csv:
        _write_csv(args.csv, [row for row in audit["rows"] if row.get("safe_to_promote") is True])
    if args.json:
        print(json.dumps(audit, indent=2, sort_keys=True))
    else:
        _print_human(audit)
        if output_paths:
            print()
            print("Output:")
            for key, value in output_paths.items():
                print(f"  {key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
