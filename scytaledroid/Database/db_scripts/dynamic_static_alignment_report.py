"""Read-only SQL helpers for ``report_dynamic_static_alignment`` (core analyst DB).

Hash joins use explicit ``CONVERT(... COLLATE utf8mb4_unicode_ci)`` because
``android_apk_repository`` hash columns may differ in collation from
``dynamic_sessions`` / ``static_analysis_runs`` in some deployments.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "HASH_EQ_DS_REPO",
    "HASH_EQ_DS_SAR",
    "SAR_QUALIFYING_SQL",
    "bucket_sql_exact_static_run_linked",
    "bucket_sql_static_run_id_points_to_bad_static_run",
    "bucket_sql_dynamic_missing_base_apk_hash",
    "bucket_sql_dynamic_hash_missing_from_repository",
    "bucket_sql_static_run_id_missing_exact_hash_exists",
    "bucket_sql_package_exists_but_hash_differs",
    "bucket_sql_repository_hash_known_static_run_missing",
    "sql_link_preview_count",
    "sql_schema_collation_sample",
    "sql_worklist",
    "sql_worklist_distinct_hash_count",
    "run_scalar",
    "run_all_bucket_counts",
]


def _hash_eq(left: str, right: str) -> str:
    return (
        f"CONVERT({left} USING utf8mb4) COLLATE utf8mb4_unicode_ci = "
        f"CONVERT({right} USING utf8mb4) COLLATE utf8mb4_unicode_ci"
    )


HASH_EQ_DS_REPO = _hash_eq("ds.base_apk_sha256", "r.sha256")
HASH_EQ_DS_SAR = _hash_eq("ds.base_apk_sha256", "sar.base_apk_sha256")
PKG_EQ_DS_APP = (
    "CONVERT(ds.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci = "
    "CONVERT(a.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci"
)


def _pkg_match_ds(alias: str) -> str:
    return (
        f"CONVERT(ds.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci = "
        f"CONVERT({alias}.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci"
    )

SAR_QUALIFYING_SQL = """
  UPPER(TRIM(COALESCE(sar.status, ''))) = 'COMPLETED'
  AND UPPER(TRIM(COALESCE(sar.run_class, ''))) = 'CANONICAL'
  AND COALESCE(sar.identity_valid, 0) = 1
  AND sar.base_apk_sha256 IS NOT NULL
  AND TRIM(sar.base_apk_sha256) <> ''
""".strip()


def _ds_base_valid() -> str:
    return "ds.base_apk_sha256 IS NOT NULL AND TRIM(ds.base_apk_sha256) <> ''"


def _exists_repo() -> str:
    return f"""
EXISTS (
  SELECT 1 FROM android_apk_repository r
  WHERE {HASH_EQ_DS_REPO}
    AND {_pkg_match_ds('r')}
)
""".strip()


def _exists_exact_sar() -> str:
    return f"""
EXISTS (
  SELECT 1 FROM static_analysis_runs sar
  WHERE {HASH_EQ_DS_SAR}
    AND {SAR_QUALIFYING_SQL}
)
""".strip()


def _exists_package_any_sar() -> str:
    return f"""
EXISTS (
  SELECT 1
  FROM static_analysis_runs sar
  JOIN app_versions av ON av.id = sar.app_version_id
  JOIN apps a ON a.id = av.app_id
  WHERE {PKG_EQ_DS_APP}
    AND {SAR_QUALIFYING_SQL}
)
""".strip()


def bucket_sql_exact_static_run_linked() -> str:
    return f"""
SELECT COUNT(*) AS c
FROM dynamic_sessions ds
INNER JOIN static_analysis_runs sar ON sar.id = ds.static_run_id
WHERE ds.static_run_id IS NOT NULL
  AND {_hash_eq('ds.base_apk_sha256', 'sar.base_apk_sha256')}
  AND {SAR_QUALIFYING_SQL}
""".strip()


def bucket_sql_static_run_id_points_to_bad_static_run() -> str:
    return f"""
SELECT COUNT(*) AS c
FROM dynamic_sessions ds
WHERE ds.static_run_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1
    FROM static_analysis_runs sar
    WHERE sar.id = ds.static_run_id
      AND {_hash_eq('ds.base_apk_sha256', 'sar.base_apk_sha256')}
      AND {SAR_QUALIFYING_SQL}
  )
""".strip()


def bucket_sql_dynamic_missing_base_apk_hash() -> str:
    return """
SELECT COUNT(*) AS c
FROM dynamic_sessions ds
WHERE ds.static_run_id IS NULL
  AND (ds.base_apk_sha256 IS NULL OR TRIM(ds.base_apk_sha256) = '')
""".strip()


def bucket_sql_dynamic_hash_missing_from_repository() -> str:
    return f"""
SELECT COUNT(*) AS c
FROM dynamic_sessions ds
WHERE ds.static_run_id IS NULL
  AND {_ds_base_valid()}
  AND NOT ({_exists_repo()})
""".strip()


def bucket_sql_static_run_id_missing_exact_hash_exists() -> str:
    return f"""
SELECT COUNT(*) AS c
FROM dynamic_sessions ds
WHERE ds.static_run_id IS NULL
  AND {_ds_base_valid()}
  AND ({_exists_repo()})
  AND ({_exists_exact_sar()})
""".strip()


def bucket_sql_package_exists_but_hash_differs() -> str:
    return f"""
SELECT COUNT(*) AS c
FROM dynamic_sessions ds
WHERE ds.static_run_id IS NULL
  AND {_ds_base_valid()}
  AND ({_exists_repo()})
  AND NOT ({_exists_exact_sar()})
  AND ({_exists_package_any_sar()})
""".strip()


def bucket_sql_repository_hash_known_static_run_missing() -> str:
    return f"""
SELECT COUNT(*) AS c
FROM dynamic_sessions ds
WHERE ds.static_run_id IS NULL
  AND {_ds_base_valid()}
  AND ({_exists_repo()})
  AND NOT ({_exists_exact_sar()})
  AND NOT ({_exists_package_any_sar()})
""".strip()


def sql_worklist(limit: int) -> str:
    """Rows grouped by package + base hash; dynamic sessions still unlinked."""
    lim = max(1, min(int(limit), 5000))
    harvest_ok = f"""
EXISTS (
  SELECT 1 FROM android_apk_repository r0
  WHERE {_hash_eq('ds.base_apk_sha256', 'r0.sha256')}
    AND {_pkg_match_ds('r0')}
    AND (
      EXISTS (SELECT 1 FROM harvest_artifact_paths h0 WHERE h0.apk_id = r0.apk_id)
      OR EXISTS (SELECT 1 FROM harvest_source_paths s0 WHERE s0.apk_id = r0.apk_id)
    )
)
""".strip()

    no_exact = f"""
NOT EXISTS (
  SELECT 1 FROM static_analysis_runs sar2
  WHERE {_hash_eq('ds.base_apk_sha256', 'sar2.base_apk_sha256')}
    AND UPPER(TRIM(COALESCE(sar2.status, ''))) = 'COMPLETED'
    AND UPPER(TRIM(COALESCE(sar2.run_class, ''))) = 'CANONICAL'
    AND COALESCE(sar2.identity_valid, 0) = 1
    AND sar2.base_apk_sha256 IS NOT NULL
    AND TRIM(sar2.base_apk_sha256) <> ''
)
""".strip()

    apk_sub = f"""(SELECT MIN(r.apk_id) FROM android_apk_repository r
  WHERE {_hash_eq('ds.base_apk_sha256', 'r.sha256')} AND {_pkg_match_ds('r')})"""

    path_hap = f"""(SELECT MIN(hap.local_rel_path)
  FROM harvest_artifact_paths hap
  INNER JOIN android_apk_repository rx ON rx.apk_id = hap.apk_id
  WHERE {_hash_eq('ds.base_apk_sha256', 'rx.sha256')} AND {_pkg_match_ds('rx')})"""

    path_hsp = f"""(SELECT MIN(hsp.source_path)
  FROM harvest_source_paths hsp
  INNER JOIN android_apk_repository ry ON ry.apk_id = hsp.apk_id
  WHERE {_hash_eq('ds.base_apk_sha256', 'ry.sha256')} AND {_pkg_match_ds('ry')})"""

    return f"""
SELECT
  ds.package_name,
  ds.base_apk_sha256,
  {apk_sub} AS apk_id,
  {path_hap} AS local_rel_path,
  {path_hsp} AS source_path,
  COUNT(*) AS dynamic_runs,
  SUM(CASE WHEN UPPER(TRIM(COALESCE(ds.status, ''))) = 'SUCCESS' THEN 1 ELSE 0 END)
    AS success_dynamic_runs,
  SUM(CASE WHEN UPPER(TRIM(COALESCE(ds.status, ''))) = 'DEGRADED' THEN 1 ELSE 0 END)
    AS degraded_dynamic_runs,
  MIN(ds.started_at_utc) AS first_dynamic_started,
  MAX(ds.started_at_utc) AS last_dynamic_started,
  'analyze_exact_dynamic_apk_hash' AS recommended_action
FROM dynamic_sessions ds
WHERE ds.static_run_id IS NULL
  AND {_ds_base_valid()}
  AND ({harvest_ok})
  AND ({no_exact})
GROUP BY ds.package_name, ds.base_apk_sha256
ORDER BY dynamic_runs DESC, ds.package_name
LIMIT {lim}
""".strip()


def sql_worklist_distinct_hash_count() -> str:
    """How many distinct (package, base_apk_sha256) pairs match the worklist predicate."""
    harvest_ok = f"""
EXISTS (
  SELECT 1 FROM android_apk_repository r0
  WHERE {_hash_eq('ds.base_apk_sha256', 'r0.sha256')}
    AND {_pkg_match_ds('r0')}
    AND (
      EXISTS (SELECT 1 FROM harvest_artifact_paths h0 WHERE h0.apk_id = r0.apk_id)
      OR EXISTS (SELECT 1 FROM harvest_source_paths s0 WHERE s0.apk_id = r0.apk_id)
    )
)
""".strip()
    no_exact = f"""
NOT EXISTS (
  SELECT 1 FROM static_analysis_runs sar2
  WHERE {_hash_eq('ds.base_apk_sha256', 'sar2.base_apk_sha256')}
    AND UPPER(TRIM(COALESCE(sar2.status, ''))) = 'COMPLETED'
    AND UPPER(TRIM(COALESCE(sar2.run_class, ''))) = 'CANONICAL'
    AND COALESCE(sar2.identity_valid, 0) = 1
    AND sar2.base_apk_sha256 IS NOT NULL
    AND TRIM(sar2.base_apk_sha256) <> ''
)
""".strip()
    return f"""
SELECT COUNT(*) AS c
FROM (
  SELECT DISTINCT ds.package_name, ds.base_apk_sha256
  FROM dynamic_sessions ds
  WHERE ds.static_run_id IS NULL
    AND {_ds_base_valid()}
    AND ({harvest_ok})
    AND ({no_exact})
) t
""".strip()


def sql_link_preview_count() -> str:
    """Dynamic rows still unlinked but an exact qualifying static run exists today."""
    hash_ds_sar = _hash_eq("ds.base_apk_sha256", "sar.base_apk_sha256")
    return f"""
SELECT COUNT(*) AS c
FROM dynamic_sessions ds
WHERE ds.static_run_id IS NULL
  AND {_ds_base_valid()}
  AND EXISTS (
    SELECT 1 FROM static_analysis_runs sar
    WHERE {hash_ds_sar}
      AND {SAR_QUALIFYING_SQL}
  )
""".strip()


def sql_schema_collation_sample() -> str:
    return """
SELECT table_name, column_name, collation_name
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND (
       (table_name = 'dynamic_sessions' AND column_name IN ('base_apk_sha256', 'package_name'))
    OR (table_name = 'static_analysis_runs' AND column_name = 'base_apk_sha256')
    OR (table_name = 'android_apk_repository' AND column_name IN ('sha256', 'package_name'))
    OR (table_name = 'apps' AND column_name = 'package_name')
  )
ORDER BY table_name, column_name
""".strip()


def run_scalar(core_q: Any, sql: str, *, query_name: str) -> int:
    row = core_q.run_sql(
        sql,
        (),
        fetch="one",
        dictionary=True,
        query_name=query_name,
    )
    if not row:
        return 0
    v = row.get("c")
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def run_all_bucket_counts(core_q: Any) -> dict[str, int]:
    specs: list[tuple[str, str]] = [
        ("exact_static_run_linked", bucket_sql_exact_static_run_linked()),
        ("static_run_id_points_to_bad_static_run", bucket_sql_static_run_id_points_to_bad_static_run()),
        ("dynamic_missing_base_apk_hash", bucket_sql_dynamic_missing_base_apk_hash()),
        ("dynamic_hash_missing_from_repository", bucket_sql_dynamic_hash_missing_from_repository()),
        (
            "static_run_id_missing_but_exact_static_hash_exists",
            bucket_sql_static_run_id_missing_exact_hash_exists(),
        ),
        ("package_exists_but_hash_differs", bucket_sql_package_exists_but_hash_differs()),
        (
            "static_run_id_missing_repository_hash_known_static_run_missing",
            bucket_sql_repository_hash_known_static_run_missing(),
        ),
    ]
    out: dict[str, int] = {}
    for name, sql in specs:
        out[name] = run_scalar(core_q, sql, query_name=f"dynamic_static_alignment.bucket.{name}")
    return out
