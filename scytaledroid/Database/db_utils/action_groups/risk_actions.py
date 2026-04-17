"""Risk, coverage, and governance actions for Database Tools."""

from __future__ import annotations


def backfill_static_permission_risk_vnext(*, core_q, prompt_utils, status_messages) -> None:
    """Backfill canonical risk tables from legacy/static artifacts."""
    from scytaledroid.Database.db_func.static_analysis import static_permission_risk as spr_db

    print()
    print("Backfill Static Permission Risk (vNext)")
    print("--------------------------------------")
    print("Idempotent operation:")
    print("1) Fill missing risk_scores rows from static run metrics.")
    print("2) Fill missing risk_scores rows from legacy static_permission_risk.")
    print("3) Fill missing static_permission_risk_vnext rows from permission matrix + risk_scores.")
    print()

    if not prompt_utils.prompt_yes_no("Run backfill now?", default=False):
        print(status_messages.status("Backfill cancelled.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    if not spr_db.ensure_table_vnext():
        print(status_messages.status("static_permission_risk_vnext table unavailable.", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    def _scalar(sql: str) -> int:
        row = core_q.run_sql(sql, fetch="one")
        return int((row or [0])[0] or 0)

    before_scores = _scalar("SELECT COUNT(*) FROM risk_scores")
    before_vnext = _scalar("SELECT COUNT(*) FROM static_permission_risk_vnext")

    core_q.run_sql_write(
        """
        INSERT INTO risk_scores (
          package_name, app_label, session_stamp, scope_label,
          risk_score, risk_grade, dangerous, signature, vendor
        )
        SELECT
          a.package_name,
          a.display_name AS app_label,
          sar.session_stamp,
          COALESCE(NULLIF(sar.scope_label, ''), a.package_name) AS scope_label,
          ROUND(ms.value_num, 3) AS risk_score,
          COALESCE(NULLIF(mg.value_text, ''), 'A') AS risk_grade,
          CAST(COALESCE(md.value_num, 0) AS SIGNED) AS dangerous,
          CAST(COALESCE(msig.value_num, 0) AS SIGNED) AS signature,
          CAST(COALESCE(mv.value_num, 0) AS SIGNED) AS vendor
        FROM static_analysis_runs sar
        JOIN app_versions av ON av.id = sar.app_version_id
        JOIN apps a ON a.id = av.app_id
        JOIN metrics ms
          ON ms.run_id = sar.id
         AND ms.feature_key = 'permissions.risk_score'
        LEFT JOIN metrics mg
          ON mg.run_id = sar.id
         AND mg.feature_key = 'permissions.risk_grade'
        LEFT JOIN metrics md
          ON md.run_id = sar.id
         AND md.feature_key = 'permissions.dangerous_count'
        LEFT JOIN metrics msig
          ON msig.run_id = sar.id
         AND msig.feature_key = 'permissions.signature_count'
        LEFT JOIN metrics mv
          ON mv.run_id = sar.id
         AND mv.feature_key = 'permissions.oem_count'
        LEFT JOIN risk_scores rs
          ON rs.package_name COLLATE utf8mb4_unicode_ci = a.package_name COLLATE utf8mb4_unicode_ci
         AND rs.session_stamp COLLATE utf8mb4_unicode_ci = sar.session_stamp COLLATE utf8mb4_unicode_ci
         AND rs.scope_label COLLATE utf8mb4_unicode_ci = COALESCE(NULLIF(sar.scope_label, ''), a.package_name) COLLATE utf8mb4_unicode_ci
        WHERE rs.id IS NULL
          AND sar.session_stamp IS NOT NULL
          AND sar.session_stamp <> ''
        """,
        query_name="db_utils.backfill.risk_scores_from_metrics",
    )

    core_q.run_sql_write(
        """
        INSERT INTO risk_scores (
          package_name, app_label, session_stamp, scope_label,
          risk_score, risk_grade, dangerous, signature, vendor
        )
        SELECT
          spr.package_name,
          a.display_name AS app_label,
          spr.session_stamp,
          spr.scope_label,
          spr.risk_score,
          spr.risk_grade,
          spr.dangerous,
          spr.signature,
          spr.vendor
        FROM static_permission_risk spr
        LEFT JOIN apps a
          ON (
            (spr.app_id IS NOT NULL AND a.id = spr.app_id)
            OR (spr.app_id IS NULL AND a.package_name COLLATE utf8mb4_general_ci = spr.package_name COLLATE utf8mb4_general_ci)
          )
        LEFT JOIN risk_scores rs
          ON rs.package_name COLLATE utf8mb4_general_ci = spr.package_name COLLATE utf8mb4_general_ci
         AND rs.session_stamp COLLATE utf8mb4_general_ci = spr.session_stamp COLLATE utf8mb4_general_ci
         AND rs.scope_label COLLATE utf8mb4_general_ci = spr.scope_label COLLATE utf8mb4_general_ci
        WHERE rs.id IS NULL
        """,
        query_name="db_utils.backfill.risk_scores_from_legacy",
    )

    core_q.run_sql_write(
        """
        INSERT INTO static_permission_risk_vnext (
          run_id, permission_name, risk_score, risk_class, rationale_code
        )
        SELECT
          spm.run_id,
          LOWER(spm.permission_name) AS permission_name,
          rs.risk_score,
          CASE
            WHEN spm.is_runtime_dangerous = 1 AND LOWER(COALESCE(spm.guard_strength, '')) IN ('weak', 'unknown') THEN 'HIGH'
            WHEN spm.is_runtime_dangerous = 1 THEN 'MEDIUM'
            WHEN spm.is_flagged_normal = 1 THEN 'LOW'
            ELSE NULL
          END AS risk_class,
          CASE
            WHEN spm.is_runtime_dangerous = 1 AND LOWER(COALESCE(spm.guard_strength, '')) IN ('weak', 'unknown') THEN 'RUNTIME_DANGEROUS_WEAK_GUARD'
            WHEN spm.is_runtime_dangerous = 1 THEN 'RUNTIME_DANGEROUS'
            WHEN spm.is_flagged_normal = 1 THEN 'FLAGGED_NORMAL_PERMISSION'
            ELSE NULL
          END AS rationale_code
        FROM static_permission_matrix spm
        JOIN static_analysis_runs sar ON sar.id = spm.run_id
        JOIN app_versions av ON av.id = sar.app_version_id
        JOIN apps a ON a.id = av.app_id
        JOIN risk_scores rs
          ON rs.package_name COLLATE utf8mb4_unicode_ci = a.package_name COLLATE utf8mb4_unicode_ci
         AND rs.session_stamp COLLATE utf8mb4_unicode_ci = sar.session_stamp COLLATE utf8mb4_unicode_ci
         AND rs.scope_label COLLATE utf8mb4_unicode_ci = sar.scope_label COLLATE utf8mb4_unicode_ci
        LEFT JOIN static_permission_risk_vnext v
          ON v.run_id = spm.run_id
         AND v.permission_name COLLATE utf8mb4_general_ci = LOWER(spm.permission_name) COLLATE utf8mb4_general_ci
        WHERE v.id IS NULL
          AND spm.permission_name IS NOT NULL
          AND spm.permission_name <> ''
        """,
        query_name="db_utils.backfill.permission_risk_vnext",
    )

    after_scores = _scalar("SELECT COUNT(*) FROM risk_scores")
    after_vnext = _scalar("SELECT COUNT(*) FROM static_permission_risk_vnext")

    print(status_messages.status("Backfill complete.", level="success"))
    print(f"risk_scores: {before_scores} -> {after_scores} (inserted={max(0, after_scores - before_scores)})")
    print(
        "static_permission_risk_vnext: "
        f"{before_vnext} -> {after_vnext} (inserted={max(0, after_vnext - before_vnext)})"
    )
    print("note: inserted counts are derived from before/after totals.")
    prompt_utils.press_enter_to_continue()


def audit_static_risk_coverage(*, core_q, prompt_utils, status_messages) -> None:
    """Audit coverage gaps for risk_scores and static_permission_risk_vnext."""
    print()
    print("Static Risk Coverage Audit")
    print("--------------------------")

    def _scalar(sql: str) -> int:
        row = core_q.run_sql(sql, fetch="one")
        return int((row or [0])[0] or 0)

    runs_total = _scalar("SELECT COUNT(*) FROM static_analysis_runs")
    runs_with_risk = _scalar(
        """
        SELECT COUNT(*) FROM (
          SELECT sar.id
          FROM static_analysis_runs sar
          JOIN app_versions av ON av.id = sar.app_version_id
          JOIN apps a ON a.id = av.app_id
          JOIN risk_scores rs
            ON rs.package_name COLLATE utf8mb4_unicode_ci = a.package_name COLLATE utf8mb4_unicode_ci
           AND rs.session_stamp COLLATE utf8mb4_unicode_ci = sar.session_stamp COLLATE utf8mb4_unicode_ci
           AND rs.scope_label COLLATE utf8mb4_unicode_ci = sar.scope_label COLLATE utf8mb4_unicode_ci
          GROUP BY sar.id
        ) x
        """
    )
    runs_without_risk = max(0, runs_total - runs_with_risk)
    spm_total = _scalar("SELECT COUNT(*) FROM static_permission_matrix")
    vnext_total = _scalar("SELECT COUNT(*) FROM static_permission_risk_vnext")
    spm_missing_vnext = _scalar(
        """
        SELECT COUNT(*)
        FROM static_permission_matrix spm
        LEFT JOIN static_permission_risk_vnext v
          ON v.run_id = spm.run_id
         AND v.permission_name COLLATE utf8mb4_general_ci = LOWER(spm.permission_name) COLLATE utf8mb4_general_ci
        WHERE v.id IS NULL
        """
    )
    runs_missing_metric = _scalar(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs sar
        LEFT JOIN metrics m
          ON m.run_id = sar.id
         AND m.feature_key = 'permissions.risk_score'
        WHERE m.run_id IS NULL
        """
    )
    missing_status_rows = core_q.run_sql(
        """
        SELECT sar.status, COUNT(*)
        FROM static_analysis_runs sar
        JOIN app_versions av ON av.id = sar.app_version_id
        JOIN apps a ON a.id = av.app_id
        LEFT JOIN risk_scores rs
          ON rs.package_name COLLATE utf8mb4_unicode_ci = a.package_name COLLATE utf8mb4_unicode_ci
         AND rs.session_stamp COLLATE utf8mb4_unicode_ci = sar.session_stamp COLLATE utf8mb4_unicode_ci
         AND rs.scope_label COLLATE utf8mb4_unicode_ci = sar.scope_label COLLATE utf8mb4_unicode_ci
        WHERE rs.id IS NULL
        GROUP BY sar.status
        ORDER BY sar.status
        """,
        fetch="all",
    ) or []
    unresolved_sample = core_q.run_sql(
        """
        SELECT sar.id, a.package_name, sar.session_stamp, sar.scope_label, sar.status
        FROM static_analysis_runs sar
        JOIN app_versions av ON av.id = sar.app_version_id
        JOIN apps a ON a.id = av.app_id
        LEFT JOIN risk_scores rs
          ON rs.package_name COLLATE utf8mb4_unicode_ci = a.package_name COLLATE utf8mb4_unicode_ci
         AND rs.session_stamp COLLATE utf8mb4_unicode_ci = sar.session_stamp COLLATE utf8mb4_unicode_ci
         AND rs.scope_label COLLATE utf8mb4_unicode_ci = sar.scope_label COLLATE utf8mb4_unicode_ci
        WHERE rs.id IS NULL
        ORDER BY sar.id DESC
        LIMIT 10
        """,
        fetch="all",
    ) or []

    print(f"runs: total={runs_total} with_risk_scores={runs_with_risk} without_risk_scores={runs_without_risk}")
    print(f"permission_matrix rows={spm_total} vnext rows={vnext_total} missing vnext rows={spm_missing_vnext}")
    print(f"runs missing permissions.risk_score metric={runs_missing_metric}")
    if missing_status_rows:
        status_detail = ", ".join(f"{row[0] or '<null>'}:{int(row[1] or 0)}" for row in missing_status_rows)
        print(f"missing risk_scores by run status: {status_detail}")
    if unresolved_sample:
        print("sample unresolved runs (id, package, session, scope, status):")
        for row in unresolved_sample:
            print(f"  {row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]}")
    if runs_without_risk or spm_missing_vnext:
        print(status_messages.status("Coverage gaps remain.", level="warn"))
    else:
        print(status_messages.status("Coverage complete for current DB snapshot.", level="success"))
    prompt_utils.press_enter_to_continue()


def show_governance_snapshot_status(*, core_q, prompt_utils, status_messages) -> None:
    """Show high-level governance snapshot status and import guidance."""

    def _section(title: str) -> None:
        print(title)
        print("-" * len(title))

    _section("Governance Snapshot Status")
    version = None
    sha = None
    row_count = 0
    try:
        row = core_q.run_sql(
            """
            SELECT s.governance_version, s.snapshot_sha256, COUNT(r.permission_string) AS row_count
            FROM permission_governance_snapshots s
            LEFT JOIN permission_governance_snapshot_rows r
              ON r.governance_version = s.governance_version
            GROUP BY s.governance_version, s.snapshot_sha256
            ORDER BY s.created_at_utc DESC
            LIMIT 1
            """,
            fetch="one",
        )
        if row:
            version = row[0]
            sha = row[1]
            row_count = int(row[2] or 0)
    except Exception as exc:
        print(status_messages.status(f"Unable to read governance snapshot: {exc}", level="warn"))

    if version:
        print(f"    Version : {version}")
        print(f"    SHA-256 : {sha or '<unknown>'}")
        print(f"    Rows    : {row_count}")
    else:
        print("    Status  : missing")
        print("    Rows    : 0")

    print()
    _section("Import (required for research-grade runs)")
    print(
        "    python -m scytaledroid.Database.tools.permission_governance_import \\"
    )
    print("      /path/to/governance_snapshot.csv \\")
    print("      --version gov_vYYYYMMDD --source EREBUS")
    print()
    prompt_utils.press_enter_to_continue()


__all__ = [
    "audit_static_risk_coverage",
    "backfill_static_permission_risk_vnext",
    "show_governance_snapshot_status",
]
