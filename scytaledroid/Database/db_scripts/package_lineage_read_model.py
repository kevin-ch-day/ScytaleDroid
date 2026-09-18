"""Shared package/version/hash lineage read model for DB operator scripts.

This module intentionally contains no CLI rendering and performs no writes.
Scripts under ``scripts/db`` use it to keep package lineage, byte
availability, static coverage, dynamic coverage, and target-state semantics in
one place while preserving stable script entrypoint paths.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from scytaledroid.Database.db_queries.sql_typed_reads import resolved_dynamic_session_static_run_id


def fetch_base_rows(core_q: Any, *, package_name: str | None) -> list[dict[str, Any]]:
    params: list[Any] = []
    package_filter = ""
    if package_name:
        package_filter = "AND LOWER(TRIM(r.package_name)) = %s"
        params.append(str(package_name).strip().lower())
    return list(
        core_q.run_sql(
            f"""
            SELECT
              r.apk_id,
              LOWER(TRIM(r.package_name)) AS package_name,
              COALESCE(NULLIF(a.display_name, ''), LOWER(TRIM(r.package_name))) AS display_name,
              r.version_code,
              r.version_name,
              LOWER(TRIM(r.sha256)) AS base_apk_sha256,
              h.storage_root_id,
              h.local_rel_path,
              sr.data_root
            FROM android_apk_repository r
            LEFT JOIN apps a ON LOWER(TRIM(a.package_name)) = LOWER(TRIM(r.package_name))
            LEFT JOIN harvest_artifact_paths h ON h.apk_id = r.apk_id
            LEFT JOIN harvest_storage_roots sr ON sr.root_id = h.storage_root_id
            WHERE r.sha256 IS NOT NULL
              AND COALESCE(r.is_split_member, 0) = 0
              {package_filter}
            GROUP BY
              r.apk_id,
              LOWER(TRIM(r.package_name)),
              COALESCE(NULLIF(a.display_name, ''), LOWER(TRIM(r.package_name))),
              r.version_code,
              r.version_name,
              LOWER(TRIM(r.sha256)),
              h.storage_root_id,
              h.local_rel_path,
              sr.data_root
            """,
            tuple(params),
            fetch="all",
            dictionary=True,
            query_name="package_lineage_read_model.base_rows",
        )
        or []
    )


def fetch_static_coverage(core_q: Any) -> dict[str, dict[str, Any]]:
    rows = core_q.run_sql(
        """
        SELECT
          LOWER(TRIM(base_apk_sha256)) AS base_apk_sha256,
          COUNT(*) AS static_runs,
          SUM(CASE
                WHEN status='COMPLETED'
                 AND run_class='CANONICAL'
                 AND COALESCE(identity_valid,0)=1
                THEN 1 ELSE 0
              END) AS canonical_completed_identity_valid,
          MAX(static_session_id) AS latest_static_session
        FROM static_analysis_runs
        WHERE base_apk_sha256 IS NOT NULL
        GROUP BY LOWER(TRIM(base_apk_sha256))
        """,
        fetch="all",
        dictionary=True,
        query_name="package_lineage_read_model.static_coverage",
    ) or []
    return {str(row.get("base_apk_sha256") or "").lower(): dict(row) for row in rows}


def fetch_dynamic_coverage(core_q: Any) -> dict[str, dict[str, Any]]:
    resolved_static_run_id = resolved_dynamic_session_static_run_id("ds")
    rows = core_q.run_sql(
        f"""
        SELECT
          LOWER(TRIM(ds.base_apk_sha256)) AS base_apk_sha256,
          COUNT(*) AS dynamic_sessions,
          SUM(CASE WHEN {resolved_static_run_id} IS NULL THEN 1 ELSE 0 END) AS dynamic_unlinked_sessions,
          SUM(CASE
                 WHEN sar.id IS NOT NULL
                  AND LOWER(TRIM(sar.base_apk_sha256)) = LOWER(TRIM(ds.base_apk_sha256))
                  AND sar.status = 'COMPLETED'
                  AND sar.run_class = 'CANONICAL'
                  AND COALESCE(sar.identity_valid, 0) = 1
                 THEN 1 ELSE 0
               END) AS dynamic_linked_sessions
        FROM dynamic_sessions ds
        LEFT JOIN static_analysis_runs sar ON sar.id = {resolved_static_run_id}
        WHERE ds.base_apk_sha256 IS NOT NULL
        GROUP BY LOWER(TRIM(ds.base_apk_sha256))
        """,
        fetch="all",
        dictionary=True,
        query_name="package_lineage_read_model.dynamic_coverage",
    ) or []
    return {str(row.get("base_apk_sha256") or "").lower(): dict(row) for row in rows}


def fetch_apk_sets_by_hash(core_q: Any) -> dict[str, tuple[dict[str, Any], ...]]:
    """Return every coherent install set grouped by base hash.

    A base APK hash can occur in more than one install set.  The returned
    sequence preserves each set's own ID, artifact digest, counts, and
    provenance; callers must never choose independent aggregate fields from
    sibling sets.
    """

    if not table_exists(core_q, "apk_sets"):
        return {}
    rows = core_q.run_sql(
        """
        SELECT
          apk_set_id,
          LOWER(TRIM(base_apk_sha256)) AS base_apk_sha256,
          LOWER(TRIM(artifact_set_hash)) AS artifact_set_hash,
          artifact_set_hash_version,
          LOWER(TRIM(package_name)) AS package_name,
          version_code,
          version_name,
          base_apk_id,
          member_count,
          split_count,
          completeness_state,
          source_kind
        FROM apk_sets
        WHERE base_apk_sha256 IS NOT NULL
        ORDER BY LOWER(TRIM(base_apk_sha256)), apk_set_id
        """,
        fetch="all",
        dictionary=True,
        query_name="package_lineage_read_model.apk_sets",
    ) or []
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for raw_row in rows:
        row = dict(raw_row)
        base_hash = norm_sha(row.get("base_apk_sha256"))
        artifact_hash = norm_sha(row.get("artifact_set_hash"))
        try:
            apk_set_id = int(row.get("apk_set_id"))
        except (TypeError, ValueError):
            continue
        if not base_hash or not artifact_hash:
            continue
        row["apk_set_id"] = apk_set_id
        row["base_apk_sha256"] = base_hash
        row["artifact_set_hash"] = artifact_hash
        row["member_manifest"] = tuple()
        grouped[base_hash].append(row)
    return {
        base_hash: tuple(sorted(items, key=lambda item: int(item["apk_set_id"])))
        for base_hash, items in grouped.items()
    }


def summarize_install_set_presence_by_base_hash(
    install_sets_by_hash: Mapping[str, Sequence[Mapping[str, Any]]],
) -> dict[str, dict[str, Any]]:
    """Collapse sibling sets to presence/counts without hybrid identity.

    A unique base keeps its ``apk_set_id`` and artifact digest. Bases with
    more than one coherent set keep counts only; identity fields stay unset so
    callers cannot treat MIN(id)/MAX(member_count) as one install set.
    """

    result: dict[str, dict[str, Any]] = {}
    for raw_base, items in install_sets_by_hash.items():
        base_hash = norm_sha(raw_base)
        if not base_hash:
            continue
        rows = [dict(item) for item in items]
        if not rows:
            continue
        complete = sum(
            1 for item in rows if str(item.get("completeness_state") or "unknown") == "complete"
        )
        member_counts = [int(item.get("member_count") or 0) for item in rows]
        split_counts = [int(item.get("split_count") or 0) for item in rows]
        summary: dict[str, Any] = {
            "base_apk_sha256": base_hash,
            "install_sets_seen": len(rows),
            "complete_sets": complete,
            "member_count": max(member_counts) if member_counts else 0,
            "split_count": max(split_counts) if split_counts else 0,
        }
        if len(rows) == 1:
            item = rows[0]
            summary["apk_set_id"] = item.get("apk_set_id")
            summary["artifact_set_hash"] = item.get("artifact_set_hash")
            summary["completeness_state"] = str(item.get("completeness_state") or "unknown")
        else:
            summary["apk_set_id"] = None
            summary["artifact_set_hash"] = None
            if complete == len(rows):
                summary["completeness_state"] = "complete"
            elif complete == 0:
                summary["completeness_state"] = "none_complete"
            else:
                summary["completeness_state"] = "mixed"
        result[base_hash] = summary
    return result


def attach_install_set_members(
    core_q: Any,
    install_sets_by_hash: dict[str, tuple[dict[str, Any], ...]],
) -> dict[str, tuple[dict[str, Any], ...]]:
    """Attach ordered member metadata without changing install-set identity.

    The set row's artifact digest remains the membership identity.  Member
    records are returned for diagnostics and target receipts, not inferred from
    a base hash.
    """

    set_ids = sorted(
        {
            int(item["apk_set_id"])
            for items in install_sets_by_hash.values()
            for item in items
        }
    )
    if not set_ids or not table_exists(core_q, "apk_set_members"):
        return install_sets_by_hash
    placeholders = ", ".join(["%s"] * len(set_ids))
    rows = core_q.run_sql(
        f"""
        SELECT apk_set_id, role, split_name, LOWER(TRIM(sha256)) AS sha256,
               ordinal, member_status
        FROM apk_set_members
        WHERE apk_set_id IN ({placeholders})
        ORDER BY apk_set_id, ordinal, role, split_name, sha256
        """,
        tuple(set_ids),
        fetch="all",
        dictionary=True,
        query_name="package_lineage_read_model.apk_set_members",
    ) or []
    members_by_set: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for raw_row in rows:
        row = dict(raw_row)
        try:
            set_id = int(row.get("apk_set_id"))
        except (TypeError, ValueError):
            continue
        members_by_set[set_id].append(
            {
                "role": str(row.get("role") or ""),
                "split_name": str(row.get("split_name") or ""),
                "sha256": norm_sha(row.get("sha256")),
                "ordinal": int(row.get("ordinal") or 0),
                "member_status": str(row.get("member_status") or ""),
            }
        )
    return {
        base_hash: tuple(
            {
                **item,
                "member_manifest": tuple(members_by_set.get(int(item["apk_set_id"]), [])),
            }
            for item in items
        )
        for base_hash, items in install_sets_by_hash.items()
    }


def exact_identity_key(apk_set_id: Any, artifact_set_hash: Any) -> tuple[int, str] | None:
    """Return the only key that authorizes split-aware evidence attachment."""

    try:
        set_id = int(apk_set_id)
    except (TypeError, ValueError):
        return None
    digest = norm_sha(artifact_set_hash)
    return (set_id, digest) if set_id > 0 and digest else None


def expand_identity_rows(
    base_rows: list[dict[str, Any]],
    install_sets_by_hash: dict[str, tuple[dict[str, Any], ...]],
) -> list[dict[str, Any]]:
    """Expand repository bases into exact-set rows or explicit base-only rows.

    Known install sets are emitted one per set.  A repository base that has no
    known set remains a base-only historical identity and does not acquire a
    guessed split configuration.
    """

    result: list[dict[str, Any]] = []
    seen_exact: set[tuple[int, str]] = set()
    seen_base_only: set[tuple[str, str, str, str]] = set()
    for base_row in base_rows:
        base = norm_sha(base_row.get("base_apk_sha256"))
        package = str(base_row.get("package_name") or "").strip().lower()
        if not base or not package:
            continue
        install_sets = install_sets_by_hash.get(base, tuple())
        if install_sets:
            for set_row in install_sets:
                key = exact_identity_key(set_row.get("apk_set_id"), set_row.get("artifact_set_hash"))
                if key is None or key in seen_exact:
                    continue
                seen_exact.add(key)
                result.append(
                    {
                        **base_row,
                        **set_row,
                        "package_name": str(set_row.get("package_name") or package).strip().lower(),
                        "version_code": set_row.get("version_code") if set_row.get("version_code") is not None else base_row.get("version_code"),
                        "version_name": set_row.get("version_name") if set_row.get("version_name") is not None else base_row.get("version_name"),
                        "identity_kind": "exact_install_set",
                        "identity_key": key,
                    }
                )
            continue
        base_key = (
            package,
            str(base_row.get("version_code") or ""),
            str(base_row.get("version_name") or ""),
            base,
        )
        if base_key in seen_base_only:
            continue
        seen_base_only.add(base_key)
        result.append(
            {
                **base_row,
                "apk_set_id": None,
                "artifact_set_hash": None,
                "member_count": 0,
                "split_count": 0,
                "member_manifest": tuple(),
                "identity_kind": "base_only_legacy",
                "identity_key": None,
            }
        )
    return sorted(
        result,
        key=lambda item: (
            str(item.get("package_name") or ""),
            str(item.get("version_code") or ""),
            str(item.get("base_apk_sha256") or ""),
            int(item.get("apk_set_id") or 0),
        ),
    )


def fetch_exact_static_coverage(core_q: Any) -> dict[tuple[int, str], dict[str, Any]]:
    """Read canonical static coverage keyed by the complete install-set identity."""

    rows = core_q.run_sql(
        """
        SELECT apk_set_id, LOWER(TRIM(artifact_set_hash)) AS artifact_set_hash,
               COUNT(*) AS static_runs,
               SUM(CASE WHEN status='COMPLETED' AND run_class='CANONICAL'
                         AND COALESCE(identity_valid, 0)=1 THEN 1 ELSE 0 END)
                 AS canonical_completed_identity_valid,
               MAX(static_session_id) AS latest_static_session
        FROM static_analysis_runs
        WHERE apk_set_id IS NOT NULL AND artifact_set_hash IS NOT NULL
        GROUP BY apk_set_id, LOWER(TRIM(artifact_set_hash))
        """,
        fetch="all",
        dictionary=True,
        query_name="package_lineage_read_model.exact_static_coverage",
    ) or []
    return {
        key: dict(row)
        for row in rows
        if (key := exact_identity_key(row.get("apk_set_id"), row.get("artifact_set_hash"))) is not None
    }


def fetch_exact_dynamic_coverage(core_q: Any) -> dict[tuple[int, str], dict[str, Any]]:
    """Read dynamic coverage keyed by the complete install-set identity.

    A dynamic row may omit ``apk_set_id`` while retaining an artifact digest and
    an immutable link to a static run that carries the complete matching set
    identity.  That linked pair is sufficient evidence to recover the exact
    key.  A base hash alone remains legacy-only and conflicting dynamic/static
    identity fields are excluded from exact coverage.
    """

    resolved_static_run_id = resolved_dynamic_session_static_run_id("ds")
    rows = core_q.run_sql(
        f"""
        SELECT identity_rows.apk_set_id, identity_rows.artifact_set_hash,
               COUNT(*) AS dynamic_sessions,
               SUM(CASE WHEN identity_rows.resolved_static_run_id IS NULL THEN 1 ELSE 0 END)
                 AS dynamic_unlinked_sessions,
               SUM(CASE WHEN identity_rows.static_identity_is_canonical = 1
                        THEN 1 ELSE 0 END) AS dynamic_linked_sessions
        FROM (
          SELECT
            {resolved_static_run_id} AS resolved_static_run_id,
            COALESCE(ds.apk_set_id, sar.apk_set_id) AS apk_set_id,
            LOWER(TRIM(COALESCE(NULLIF(ds.artifact_set_hash, ''), sar.artifact_set_hash)))
              AS artifact_set_hash,
            CASE WHEN sar.id IS NOT NULL
                       AND sar.status='COMPLETED' AND sar.run_class='CANONICAL'
                       AND COALESCE(sar.identity_valid, 0)=1
                       AND sar.apk_set_id = COALESCE(ds.apk_set_id, sar.apk_set_id)
                       AND LOWER(TRIM(sar.artifact_set_hash)) =
                           LOWER(TRIM(COALESCE(NULLIF(ds.artifact_set_hash, ''), sar.artifact_set_hash)))
                 THEN 1 ELSE 0 END AS static_identity_is_canonical
          FROM dynamic_sessions ds
          LEFT JOIN static_analysis_runs sar ON sar.id = {resolved_static_run_id}
          WHERE (ds.apk_set_id IS NULL OR sar.apk_set_id IS NULL OR ds.apk_set_id = sar.apk_set_id)
            AND (ds.artifact_set_hash IS NULL OR ds.artifact_set_hash = ''
                 OR sar.artifact_set_hash IS NULL OR sar.artifact_set_hash = ''
                 OR LOWER(TRIM(ds.artifact_set_hash)) = LOWER(TRIM(sar.artifact_set_hash)))
        ) AS identity_rows
        WHERE identity_rows.apk_set_id IS NOT NULL
          AND identity_rows.artifact_set_hash IS NOT NULL
          AND identity_rows.artifact_set_hash <> ''
        GROUP BY identity_rows.apk_set_id, identity_rows.artifact_set_hash
        """,
        fetch="all",
        dictionary=True,
        query_name="package_lineage_read_model.exact_dynamic_coverage",
    ) or []
    return {
        key: dict(row)
        for row in rows
        if (key := exact_identity_key(row.get("apk_set_id"), row.get("artifact_set_hash"))) is not None
    }


def fetch_legacy_base_static_coverage(core_q: Any) -> dict[str, dict[str, Any]]:
    """Read coverage that cannot establish a complete install-set identity."""

    rows = core_q.run_sql(
        """
        SELECT LOWER(TRIM(base_apk_sha256)) AS base_apk_sha256,
               COUNT(*) AS static_runs,
               SUM(CASE WHEN status='COMPLETED' AND run_class='CANONICAL'
                         AND COALESCE(identity_valid, 0)=1 THEN 1 ELSE 0 END)
                 AS canonical_completed_identity_valid,
               MAX(static_session_id) AS latest_static_session
        FROM static_analysis_runs
        WHERE base_apk_sha256 IS NOT NULL
          AND (apk_set_id IS NULL OR artifact_set_hash IS NULL)
        GROUP BY LOWER(TRIM(base_apk_sha256))
        """,
        fetch="all",
        dictionary=True,
        query_name="package_lineage_read_model.legacy_base_static_coverage",
    ) or []
    return {norm_sha(row.get("base_apk_sha256")): dict(row) for row in rows}


def fetch_legacy_base_dynamic_coverage(core_q: Any) -> dict[str, dict[str, Any]]:
    """Read dynamic evidence that lacks a complete install-set identity."""

    resolved_static_run_id = resolved_dynamic_session_static_run_id("ds")
    rows = core_q.run_sql(
        f"""
        SELECT LOWER(TRIM(ds.base_apk_sha256)) AS base_apk_sha256,
               COUNT(*) AS dynamic_sessions,
               SUM(CASE WHEN {resolved_static_run_id} IS NULL THEN 1 ELSE 0 END)
                 AS dynamic_unlinked_sessions,
               SUM(CASE WHEN sar.id IS NOT NULL
                          AND LOWER(TRIM(sar.base_apk_sha256)) = LOWER(TRIM(ds.base_apk_sha256))
                          AND sar.status='COMPLETED' AND sar.run_class='CANONICAL'
                          AND COALESCE(sar.identity_valid, 0)=1
                        THEN 1 ELSE 0 END) AS dynamic_linked_sessions
        FROM dynamic_sessions ds
        LEFT JOIN static_analysis_runs sar ON sar.id = {resolved_static_run_id}
        WHERE ds.base_apk_sha256 IS NOT NULL
          AND (
            COALESCE(ds.apk_set_id, sar.apk_set_id) IS NULL
            OR COALESCE(NULLIF(ds.artifact_set_hash, ''), sar.artifact_set_hash) IS NULL
            OR COALESCE(NULLIF(ds.artifact_set_hash, ''), sar.artifact_set_hash) = ''
            OR (ds.apk_set_id IS NOT NULL AND sar.apk_set_id IS NOT NULL AND ds.apk_set_id <> sar.apk_set_id)
            OR (ds.artifact_set_hash IS NOT NULL AND ds.artifact_set_hash <> ''
                AND sar.artifact_set_hash IS NOT NULL AND sar.artifact_set_hash <> ''
                AND LOWER(TRIM(ds.artifact_set_hash)) <> LOWER(TRIM(sar.artifact_set_hash)))
          )
        GROUP BY LOWER(TRIM(ds.base_apk_sha256))
        """,
        fetch="all",
        dictionary=True,
        query_name="package_lineage_read_model.legacy_base_dynamic_coverage",
    ) or []
    return {norm_sha(row.get("base_apk_sha256")): dict(row) for row in rows}


def coverage_for_identity(
    row: dict[str, Any],
    *,
    exact_coverage: dict[tuple[int, str], dict[str, Any]],
    legacy_base_coverage: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Select exact coverage for exact rows and labeled fallback coverage otherwise."""

    key = exact_identity_key(row.get("apk_set_id"), row.get("artifact_set_hash"))
    if row.get("identity_kind") == "exact_install_set" and key is not None:
        return dict(exact_coverage.get(key) or {})
    return dict(legacy_base_coverage.get(norm_sha(row.get("base_apk_sha256"))) or {})


def fetch_same_version_hash_drift_keys(core_q: Any) -> set[tuple[str, str, str]]:
    rows = core_q.run_sql(
        """
        SELECT
          LOWER(TRIM(package_name)) AS package_name,
          COALESCE(CAST(version_code AS CHAR), '') AS version_code,
          COALESCE(version_name, '') AS version_name,
          COUNT(DISTINCT LOWER(TRIM(sha256))) AS hashes
        FROM android_apk_repository
        WHERE sha256 IS NOT NULL
          AND COALESCE(is_split_member, 0) = 0
        GROUP BY
          LOWER(TRIM(package_name)),
          COALESCE(CAST(version_code AS CHAR), ''),
          COALESCE(version_name, '')
        HAVING hashes > 1
        """,
        fetch="all",
        dictionary=True,
        query_name="package_lineage_read_model.same_version_drift",
    ) or []
    return {
        (
            str(row.get("package_name") or "").lower(),
            str(row.get("version_code") or ""),
            str(row.get("version_name") or ""),
        )
        for row in rows
    }


def table_exists(core_q: Any, table_name: str) -> bool:
    row = core_q.run_sql(
        """
        SELECT COUNT(*) AS n
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
          AND table_name = %s
        """,
        (table_name,),
        fetch="one_dict",
        query_name="package_lineage_read_model.table_exists",
    )
    return int((row or {}).get("n") or 0) > 0


def recorded_abs_path(row: dict[str, Any]) -> Path | None:
    raw = str(row.get("local_rel_path") or "").strip()
    if not raw:
        return None
    local = Path(raw).expanduser()
    if local.is_absolute():
        return local
    root = str(row.get("data_root") or "").strip()
    if root:
        return Path(root).expanduser() / local
    return Path.cwd() / local


def path_exists(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text and Path(text).expanduser().exists())


def norm_sha(value: Any) -> str:
    return str(value or "").strip().lower()


def byte_status(
    *,
    recorded_exists: bool,
    canonical_exists: bool,
    recorded_root_exists: bool,
    recorded_location_known: bool,
) -> str:
    if recorded_exists and canonical_exists:
        return "available_recorded_and_canonical"
    if canonical_exists:
        return "available_canonical"
    if recorded_exists:
        return "available_recorded"
    if not recorded_location_known:
        return "missing_no_recorded_location"
    if recorded_root_exists:
        return "missing_current_root_file"
    return "missing_old_root"


def split_status(*, set_info: dict[str, Any], byte_status: str) -> str:
    if set_info:
        return "install_set_known"
    if byte_status.startswith("available"):
        return "base_only_or_split_context_missing"
    return "unknown_until_bytes_restored"


def target_reason(
    *,
    exact_static: int,
    byte_status: str,
    dynamic_sessions: int,
    dynamic_unlinked: int,
    same_version_hash_drift: bool,
) -> str:
    if exact_static > 0 and dynamic_unlinked > 0:
        return "dynamic_static_gap"
    if exact_static > 0 and not byte_status.startswith("available"):
        return "artifact_lifecycle_gap"
    if exact_static > 0 and byte_status == "available_recorded":
        return "artifact_lifecycle_gap"
    if exact_static == 0 and dynamic_sessions > 0:
        return "dynamic_static_gap"
    if same_version_hash_drift:
        return "same_version_hash_drift_review"
    if exact_static == 0:
        return "new_hash_seen"
    return "covered"


def target_status(
    *,
    exact_static: int,
    byte_status: str,
    split_status: str,
    dynamic_unlinked: int,
    same_version_hash_drift: bool,
) -> str:
    if exact_static > 0 and dynamic_unlinked > 0:
        return "link_repair_preview_available"
    if exact_static > 0 and byte_status == "available_recorded":
        return "rebuild_canonical_store"
    if exact_static > 0 and byte_status == "missing_old_root":
        return "blocked_missing_bytes"
    if exact_static > 0 and byte_status in {"missing_current_root_file", "missing_no_recorded_location"}:
        return "artifact_lifecycle_gap"
    if exact_static > 0 and not same_version_hash_drift:
        return "covered"
    if same_version_hash_drift and exact_static > 0:
        return "review"
    if byte_status == "missing_old_root":
        return "blocked_missing_bytes"
    if byte_status in {"missing_current_root_file", "missing_no_recorded_location"}:
        return "needs_reharvest"
    if split_status == "base_only_or_split_context_missing":
        return "blocked_split_context"
    if byte_status.startswith("available"):
        return "ready"
    return "blocked_missing_bytes"


def target_priority(*, reason: str, target_status: str, dynamic_sessions: int) -> int:
    if target_status == "ready" and reason == "dynamic_static_gap":
        return 10
    if target_status == "link_repair_preview_available":
        return 20
    if target_status == "blocked_missing_bytes" and reason == "dynamic_static_gap":
        return 30
    if target_status == "needs_reharvest" and reason == "dynamic_static_gap":
        return 35
    if target_status == "ready":
        return 40
    if target_status == "review":
        return 50
    if target_status == "rebuild_canonical_store":
        return 55
    if target_status == "artifact_lifecycle_gap":
        return 56
    if target_status.startswith("blocked"):
        return 60 if dynamic_sessions else 70
    return 90


def operator_action(target_status: str) -> str:
    return {
        "ready": "Run exact static analysis",
        "blocked_missing_bytes": "Restore old root",
        "needs_reharvest": "Reharvest current app",
        "artifact_lifecycle_gap": "Restore or reharvest bytes",
        "blocked_split_context": "Restore split context or use explicit base-only mode",
        "link_repair_preview_available": "Preview dynamic link repair",
        "rebuild_canonical_store": "Rebuild canonical SHA store",
        "covered": "No action needed",
        "review": "Review same-version hash drift",
    }.get(target_status, "Review target state")
