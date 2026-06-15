"""Canonical DB-backed research cohort helpers."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
import os

try:  # optional DB access
    from scytaledroid.Database.db_core import run_sql, run_sql_many
except Exception:  # pragma: no cover - offline mode
    run_sql = None
    run_sql_many = None


ALPHA_COHORT_KEY = "research_dataset_alpha"
BETA_COHORT_KEY = "research_dataset_beta"
DEFAULT_RESEARCH_COHORT_KEY = ALPHA_COHORT_KEY


@dataclass(frozen=True)
class ResearchCohortMemberSeed:
    package_name: str
    member_source: str = "manual"
    source_cohort_key: str | None = None
    sort_order: int = 0
    notes: str | None = None


def _norm_text(value: object) -> str:
    return str(value or "").strip()


def _norm_package(value: object) -> str:
    return _norm_text(value).lower()


def normalize_research_cohort_key(value: object) -> str | None:
    key = _norm_text(value).lower()
    return key or None


def profile_key_for_research_cohort(cohort_key: str | None) -> str | None:
    normalized = normalize_research_cohort_key(cohort_key)
    if not normalized:
        return None
    return normalized.upper()


def _resolve_run_sql(run_sql_fn):
    return run_sql_fn or run_sql


def _resolve_run_sql_many(run_sql_many_fn):
    return run_sql_many_fn or run_sql_many


def list_active_research_cohorts(*, run_sql_fn=None) -> list[dict[str, object]]:
    sql_runner = _resolve_run_sql(run_sql_fn)
    if sql_runner is None:
        return []
    try:
        rows = sql_runner(
            """
            SELECT
              rc.cohort_key,
              rc.display_name,
              rc.description,
              rc.intended_use,
              rc.selection_rule,
              rc.is_active,
              COUNT(CASE WHEN rcm.is_active = 1 THEN 1 END) AS active_member_count
            FROM research_cohorts rc
            LEFT JOIN research_cohort_members rcm
              ON rcm.cohort_id = rc.cohort_id
            WHERE rc.is_active = 1
            GROUP BY
              rc.cohort_id,
              rc.cohort_key,
              rc.display_name,
              rc.description,
              rc.intended_use,
              rc.selection_rule,
              rc.is_active
            ORDER BY rc.display_name, rc.cohort_key
            """,
            (),
            fetch="all",
            dictionary=True,
        ) or []
    except Exception:
        return []
    return [dict(row) for row in rows if isinstance(row, dict)]


def fetch_research_cohort(cohort_key: str, *, run_sql_fn=None) -> dict[str, object] | None:
    key = _norm_text(cohort_key)
    sql_runner = _resolve_run_sql(run_sql_fn)
    if not key or sql_runner is None:
        return None
    try:
        row = sql_runner(
            """
            SELECT
              cohort_id,
              cohort_key,
              display_name,
              description,
              intended_use,
              selection_rule,
              is_active
            FROM research_cohorts
            WHERE cohort_key = %s
            LIMIT 1
            """,
            (key,),
            fetch="one",
            dictionary=True,
        )
    except Exception:
        return None
    return dict(row) if isinstance(row, dict) else None


def fetch_active_research_cohort_members(cohort_key: str, *, run_sql_fn=None) -> list[dict[str, object]]:
    key = _norm_text(cohort_key)
    sql_runner = _resolve_run_sql(run_sql_fn)
    if not key or sql_runner is None:
        return []
    try:
        rows = sql_runner(
            """
            SELECT
              rc.cohort_key,
              rc.display_name,
              rcm.package_name,
              rcm.member_source,
              rcm.source_cohort_key,
              rcm.sort_order,
              rcm.is_active,
              rcm.notes
            FROM research_cohorts rc
            JOIN research_cohort_members rcm
              ON rcm.cohort_id = rc.cohort_id
            WHERE rc.cohort_key = %s
              AND rc.is_active = 1
              AND rcm.is_active = 1
            ORDER BY rcm.sort_order ASC, rcm.package_name ASC
            """,
            (key,),
            fetch="all",
            dictionary=True,
        ) or []
    except Exception:
        return []
    return [dict(row) for row in rows if isinstance(row, dict)]


def fetch_active_research_cohort_packages(cohort_key: str, *, run_sql_fn=None) -> list[str]:
    return [
        _norm_package(row.get("package_name"))
        for row in fetch_active_research_cohort_members(cohort_key, run_sql_fn=run_sql_fn)
        if _norm_package(row.get("package_name"))
    ]


def resolve_research_cohort_packages(
    cohort_key: str | None,
    *,
    fallback_profile_key: str | None = None,
    run_sql_fn=None,
) -> list[str]:
    packages: list[str] = []
    if cohort_key:
        try:
            packages = fetch_active_research_cohort_packages(cohort_key, run_sql_fn=run_sql_fn)
        except Exception:
            packages = []
        if packages:
            return sorted(dict.fromkeys(packages))
    if fallback_profile_key:
        try:
            from scytaledroid.DynamicAnalysis.profile_loader import load_profile_packages

            packages = [str(pkg).strip().lower() for pkg in load_profile_packages(fallback_profile_key) if str(pkg).strip()]
        except Exception:
            packages = []
    return sorted(dict.fromkeys(packages))


def configured_research_cohort_key(*, env: dict[str, str] | None = None) -> str | None:
    source = env if env is not None else os.environ
    return normalize_research_cohort_key(source.get("SCYTALEDROID_RESEARCH_COHORT_KEY"))


def resolve_preferred_research_cohort_key(
    preferred_key: str | None = None,
    *,
    run_sql_fn=None,
    env: dict[str, str] | None = None,
) -> str | None:
    active_rows = list_active_research_cohorts(run_sql_fn=run_sql_fn)
    active_keys = {
        normalize_research_cohort_key(row.get("cohort_key"))
        for row in active_rows
        if normalize_research_cohort_key(row.get("cohort_key"))
    }
    candidates = [
        normalize_research_cohort_key(preferred_key),
        configured_research_cohort_key(env=env),
        DEFAULT_RESEARCH_COHORT_KEY,
    ]
    for candidate in candidates:
        if candidate and candidate in active_keys:
            return candidate
    if active_rows:
        first = normalize_research_cohort_key(active_rows[0].get("cohort_key"))
        if first:
            return first
    for candidate in candidates:
        if candidate:
            return candidate
    return None


def resolve_research_cohort_context(
    preferred_key: str | None = None,
    *,
    fallback_profile_key: str | None = None,
    run_sql_fn=None,
    env: dict[str, str] | None = None,
) -> dict[str, object]:
    cohort_key = resolve_preferred_research_cohort_key(
        preferred_key,
        run_sql_fn=run_sql_fn,
        env=env,
    )
    profile_key = fallback_profile_key or profile_key_for_research_cohort(cohort_key)
    cohort = fetch_research_cohort(cohort_key or "", run_sql_fn=run_sql_fn) if cohort_key else None
    display_name = str((cohort or {}).get("display_name") or "").strip()
    if not display_name and profile_key:
        display_name = profile_key.replace("_", " ").title()
    if not display_name and cohort_key:
        display_name = cohort_key.replace("_", " ").title()
    packages = resolve_research_cohort_packages(
        cohort_key,
        fallback_profile_key=profile_key,
        run_sql_fn=run_sql_fn,
    )
    return {
        "cohort_key": cohort_key,
        "profile_key": profile_key,
        "display_name": display_name or "Research cohort",
        "packages": tuple(packages),
        "cohort": cohort,
    }


def upsert_research_cohort(
    *,
    cohort_key: str,
    display_name: str,
    description: str | None,
    intended_use: str = "research",
    selection_rule: str = "newest_harvest_capture_per_package",
    is_active: bool = True,
    run_sql_fn=None,
) -> int:
    sql_runner = _resolve_run_sql(run_sql_fn)
    key = _norm_text(cohort_key)
    name = _norm_text(display_name)
    if not key or not name or sql_runner is None:
        raise ValueError("cohort_key and display_name are required")
    sql_runner(
        """
        INSERT INTO research_cohorts (
          cohort_key,
          display_name,
          description,
          intended_use,
          selection_rule,
          is_active
        ) VALUES (%s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
          display_name = VALUES(display_name),
          description = VALUES(description),
          intended_use = VALUES(intended_use),
          selection_rule = VALUES(selection_rule),
          is_active = VALUES(is_active),
          updated_at_utc = CURRENT_TIMESTAMP
        """,
        (key, name, description, _norm_text(intended_use) or "research", _norm_text(selection_rule) or "newest_harvest_capture_per_package", 1 if is_active else 0),
    )
    row = sql_runner(
        "SELECT cohort_id FROM research_cohorts WHERE cohort_key = %s LIMIT 1",
        (key,),
        fetch="one",
        dictionary=True,
    )
    if not isinstance(row, dict) or row.get("cohort_id") is None:
        raise RuntimeError(f"failed to resolve cohort_id for {key}")
    return int(row["cohort_id"])


def replace_research_cohort_members(
    *,
    cohort_id: int,
    members: Sequence[ResearchCohortMemberSeed],
    run_sql_fn=None,
    run_sql_many_fn=None,
) -> int:
    sql_runner = _resolve_run_sql(run_sql_fn)
    sql_runner_many = _resolve_run_sql_many(run_sql_many_fn)
    if cohort_id <= 0 or sql_runner is None or sql_runner_many is None:
        return 0

    normalized: list[tuple[str, str, str | None, int, int, str | None]] = []
    seen: set[str] = set()
    for member in members:
        pkg = _norm_package(member.package_name)
        if not pkg or pkg in seen:
            continue
        seen.add(pkg)
        normalized.append(
            (
                pkg,
                _norm_text(member.member_source) or "manual",
                _norm_text(member.source_cohort_key) or None,
                int(member.sort_order),
                1,
                _norm_text(member.notes) or None,
            )
        )

    if normalized:
        payload = [
            (cohort_id, pkg, source, source_key, sort_order, is_active, notes)
            for pkg, source, source_key, sort_order, is_active, notes in normalized
        ]
        sql_runner_many(
            """
            INSERT INTO research_cohort_members (
              cohort_id,
              package_name,
              member_source,
              source_cohort_key,
              sort_order,
              is_active,
              notes
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
              member_source = VALUES(member_source),
              source_cohort_key = VALUES(source_cohort_key),
              sort_order = VALUES(sort_order),
              is_active = VALUES(is_active),
              notes = VALUES(notes),
              updated_at_utc = CURRENT_TIMESTAMP
            """,
            payload,
        )

        placeholders = ", ".join(["%s"] * len(normalized))
        params: list[object] = [cohort_id]
        params.extend(pkg for pkg, *_rest in normalized)
        sql_runner(
            f"""
            UPDATE research_cohort_members
            SET is_active = 0,
                updated_at_utc = CURRENT_TIMESTAMP
            WHERE cohort_id = %s
              AND package_name NOT IN ({placeholders})
            """,
            tuple(params),
        )
    else:
        sql_runner(
            """
            UPDATE research_cohort_members
            SET is_active = 0,
                updated_at_utc = CURRENT_TIMESTAMP
            WHERE cohort_id = %s
            """,
            (cohort_id,),
        )
    return len(normalized)


def make_member_seeds(rows: Iterable[tuple[str, str, str | None, int, str | None]]) -> list[ResearchCohortMemberSeed]:
    seeds: list[ResearchCohortMemberSeed] = []
    for package_name, member_source, source_cohort_key, sort_order, notes in rows:
        pkg = _norm_package(package_name)
        if not pkg:
            continue
        seeds.append(
            ResearchCohortMemberSeed(
                package_name=pkg,
                member_source=_norm_text(member_source) or "manual",
                source_cohort_key=_norm_text(source_cohort_key) or None,
                sort_order=int(sort_order),
                notes=_norm_text(notes) or None,
            )
        )
    return seeds


__all__ = [
    "ALPHA_COHORT_KEY",
    "BETA_COHORT_KEY",
    "DEFAULT_RESEARCH_COHORT_KEY",
    "ResearchCohortMemberSeed",
    "configured_research_cohort_key",
    "fetch_active_research_cohort_members",
    "fetch_active_research_cohort_packages",
    "fetch_research_cohort",
    "list_active_research_cohorts",
    "make_member_seeds",
    "normalize_research_cohort_key",
    "profile_key_for_research_cohort",
    "replace_research_cohort_members",
    "resolve_preferred_research_cohort_key",
    "resolve_research_cohort_context",
    "resolve_research_cohort_packages",
    "upsert_research_cohort",
]
