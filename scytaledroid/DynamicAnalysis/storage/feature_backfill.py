"""Backfill derived dynamic network feature rows from local evidence packs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.DynamicAnalysis.storage.index_from_evidence import (
    _ensure_dynamic_network_features_columns,
    build_dynamic_network_features_row_from_evidence_pack,
    upsert_dynamic_network_features_row,
)


@dataclass(frozen=True)
class FeatureBackfillCandidate:
    dynamic_run_id: str
    package_name: str
    evidence_path: Path
    tier: str | None
    status: str | None
    countable: bool | None
    evidence_exists: bool
    manifest_exists: bool
    features_artifact_exists: bool
    report_artifact_exists: bool

    @property
    def can_build(self) -> bool:
        return self.evidence_exists and self.manifest_exists


@dataclass(frozen=True)
class FeatureBackfillResult:
    scanned: int
    buildable: int
    upserted: int
    missing_evidence: int
    low_signal_upserted: int
    dry_run: bool
    errors: tuple[str, ...]


def list_missing_feature_candidates(*, limit: int | None = None) -> list[FeatureBackfillCandidate]:
    """Return DB sessions that lack `dynamic_network_features` rows."""
    sql = """
        SELECT ds.dynamic_run_id,
               ds.package_name,
               ds.evidence_path,
               ds.tier,
               ds.status,
               ds.countable
        FROM dynamic_sessions ds
        LEFT JOIN dynamic_network_features nf
          ON nf.dynamic_run_id = ds.dynamic_run_id
        WHERE nf.dynamic_run_id IS NULL
        ORDER BY ds.started_at_utc DESC, ds.dynamic_run_id DESC
    """
    params: tuple[Any, ...] = ()
    if limit is not None:
        sql += " LIMIT %s"
        params = (max(1, int(limit)),)
    rows = core_q.run_sql(sql, params, fetch="all") or []
    candidates: list[FeatureBackfillCandidate] = []
    for row in rows:
        evidence_path = Path(str(row[2] or ""))
        candidates.append(
            FeatureBackfillCandidate(
                dynamic_run_id=str(row[0] or ""),
                package_name=str(row[1] or ""),
                evidence_path=evidence_path,
                tier=str(row[3]) if row[3] is not None else None,
                status=str(row[4]) if row[4] is not None else None,
                countable=bool(row[5]) if row[5] is not None else None,
                evidence_exists=evidence_path.exists(),
                manifest_exists=(evidence_path / "run_manifest.json").exists(),
                features_artifact_exists=(evidence_path / "analysis" / "pcap_features.json").exists(),
                report_artifact_exists=(evidence_path / "analysis" / "pcap_report.json").exists(),
            )
        )
    return candidates


def backfill_missing_dynamic_network_features(
    *,
    limit: int | None = None,
    dry_run: bool = True,
) -> FeatureBackfillResult:
    """Build and optionally upsert missing feature rows from local evidence."""
    candidates = list_missing_feature_candidates(limit=limit)
    buildable = 0
    upserted = 0
    low_signal_upserted = 0
    errors: list[str] = []
    if not dry_run:
        _ensure_dynamic_network_features_columns()

    for candidate in candidates:
        if not candidate.can_build:
            continue
        buildable += 1
        row = build_dynamic_network_features_row_from_evidence_pack(candidate.evidence_path)
        if not row:
            errors.append(f"{candidate.dynamic_run_id}: unable_to_build_feature_row")
            continue
        if dry_run:
            if row.get("low_signal") == 1:
                low_signal_upserted += 1
            continue
        try:
            upsert_dynamic_network_features_row(row)
            upserted += 1
            if row.get("low_signal") == 1:
                low_signal_upserted += 1
        except Exception as exc:
            errors.append(f"{candidate.dynamic_run_id}: {exc}")

    return FeatureBackfillResult(
        scanned=len(candidates),
        buildable=buildable,
        upserted=upserted,
        missing_evidence=sum(1 for candidate in candidates if not candidate.evidence_exists),
        low_signal_upserted=low_signal_upserted,
        dry_run=dry_run,
        errors=tuple(errors[:20]),
    )


__all__ = [
    "FeatureBackfillCandidate",
    "FeatureBackfillResult",
    "backfill_missing_dynamic_network_features",
    "list_missing_feature_candidates",
]
