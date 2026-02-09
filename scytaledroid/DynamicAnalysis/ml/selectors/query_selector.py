"""Query selector (Phase F1).

DB may be used for candidate discovery only. Evidence packs are authoritative:
every selected run is validated by reading its evidence-pack run_manifest.json.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

try:  # optional DB access for candidate discovery
    from scytaledroid.Database.db_core import db_queries as core_q
except Exception:  # pragma: no cover
    core_q = None

from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_preflight import derive_run_mode, load_run_inputs

from .models import QueryParams, RunRef, SelectionResult


def _sha256_stream(path: Path) -> str:
    h = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.strip())
    except Exception:
        return None


@dataclass(frozen=True)
class QuerySelector:
    evidence_root: Path
    params: QueryParams
    grouping_key: str = "base_apk_sha256"
    allow_db_index: bool = True

    def _candidate_run_ids(self) -> list[str]:
        # Prefer DB for discovery if allowed and present; otherwise scan filesystem.
        if self.allow_db_index and core_q is not None:
            where: list[str] = []
            args: list[Any] = []
            if self.params.tier:
                where.append("tier = %s")
                args.append(self.params.tier)
            if self.params.package_name:
                where.append("package_name = %s")
                args.append(self.params.package_name)
            if self.params.base_apk_sha256 and not self.params.pool_versions:
                where.append("base_apk_sha256 = %s")
                args.append(self.params.base_apk_sha256)
            if self.params.started_at_utc_from:
                where.append("started_at_utc >= %s")
                args.append(self.params.started_at_utc_from)
            if self.params.started_at_utc_to:
                where.append("started_at_utc <= %s")
                args.append(self.params.started_at_utc_to)
            if self.params.ended_at_utc_from:
                where.append("ended_at_utc >= %s")
                args.append(self.params.ended_at_utc_from)
            if self.params.ended_at_utc_to:
                where.append("ended_at_utc <= %s")
                args.append(self.params.ended_at_utc_to)
            clause = f"WHERE {' AND '.join(where)}" if where else ""
            rows = core_q.run_sql(
                f"SELECT dynamic_run_id FROM dynamic_sessions {clause} ORDER BY started_at_utc ASC",
                tuple(args),
                fetch="all",
            )
            return [str(r[0]) for r in (rows or []) if r and r[0]]

        # Filesystem scan fallback (DB-free).
        if not self.evidence_root.exists():
            return []
        out: list[str] = []
        for p in sorted(self.evidence_root.iterdir(), key=lambda x: x.name):
            if not p.is_dir():
                continue
            if (p / "run_manifest.json").exists():
                out.append(p.name)
        return out

    def select(self) -> SelectionResult:
        included: list[RunRef] = []
        excluded: dict[str, dict[str, Any]] = {}

        for rid in self._candidate_run_ids():
            run_dir = self.evidence_root / rid
            if not run_dir.exists():
                excluded[rid] = {"reason": "missing_evidence_dir", "evidence_dir": str(run_dir)}
                continue
            manifest_path = run_dir / "run_manifest.json"
            if not manifest_path.exists():
                excluded[rid] = {"reason": "missing_run_manifest", "evidence_dir": str(run_dir)}
                continue

            inputs = load_run_inputs(run_dir)
            if not inputs:
                excluded[rid] = {"reason": "invalid_run_manifest", "evidence_dir": str(run_dir)}
                continue

            pkg = inputs.package_name
            if self.params.package_name and pkg != self.params.package_name:
                excluded[rid] = {"reason": "package_filter_mismatch", "package_name": pkg}
                continue

            # Tier filter is evidence-pack-authoritative.
            ds = inputs.manifest.get("dataset") if isinstance(inputs.manifest.get("dataset"), dict) else {}
            tier = str(ds.get("tier") or "") if ds else ""
            if self.params.tier and tier and tier != self.params.tier:
                excluded[rid] = {"reason": "tier_filter_mismatch", "tier": tier}
                continue
            if self.params.require_valid_dataset_run:
                if ds.get("valid_dataset_run") is not True:
                    excluded[rid] = {"reason": "invalid_dataset_run"}
                    continue

            mode, mode_source = derive_run_mode(inputs)
            if self.params.mode and mode != self.params.mode:
                excluded[rid] = {"reason": "mode_filter_mismatch", "mode": mode}
                continue
            if mode == "unknown" and not self.params.include_unknown_mode:
                excluded[rid] = {"reason": "unknown_mode_excluded"}
                continue

            started = inputs.manifest.get("started_at")
            ended = inputs.manifest.get("ended_at")
            if self.params.started_at_utc_from and _parse_iso(started) and _parse_iso(started) < _parse_iso(self.params.started_at_utc_from):
                excluded[rid] = {"reason": "started_at_before_range"}
                continue
            if self.params.started_at_utc_to and _parse_iso(started) and _parse_iso(started) > _parse_iso(self.params.started_at_utc_to):
                excluded[rid] = {"reason": "started_at_after_range"}
                continue
            if self.params.ended_at_utc_from and _parse_iso(ended) and _parse_iso(ended) < _parse_iso(self.params.ended_at_utc_from):
                excluded[rid] = {"reason": "ended_at_before_range"}
                continue
            if self.params.ended_at_utc_to and _parse_iso(ended) and _parse_iso(ended) > _parse_iso(self.params.ended_at_utc_to):
                excluded[rid] = {"reason": "ended_at_after_range"}
                continue

            base_sha = None
            if isinstance(inputs.plan, dict):
                ident = inputs.plan.get("run_identity") if isinstance(inputs.plan.get("run_identity"), dict) else {}
                base_sha = ident.get("base_apk_sha256")
            base_sha_str = str(base_sha) if isinstance(base_sha, str) and base_sha else None
            if self.params.base_apk_sha256 and not self.params.pool_versions and base_sha_str != self.params.base_apk_sha256:
                excluded[rid] = {"reason": "base_sha_filter_mismatch", "base_apk_sha256": base_sha_str}
                continue

            included.append(
                RunRef(
                    run_id=rid,
                    evidence_dir=run_dir,
                    manifest_path=manifest_path,
                    manifest_sha256=_sha256_stream(manifest_path),
                    package_name=pkg,
                    base_apk_sha256=base_sha_str,
                    mode=mode,
                    mode_source=mode_source,
                    run_profile=inputs.run_profile,
                    started_at_utc=str(started) if isinstance(started, str) and started else None,
                    ended_at_utc=str(ended) if isinstance(ended, str) and ended else None,
                )
            )

        # Stable ordering: base_sha, package, mode, ended_at, run_id
        def _sort_key(r: RunRef) -> tuple[str, str, int, float, str]:
            mode_rank = 0 if r.mode == "baseline" else (1 if r.mode == "interactive" else 2)
            ended_dt = _parse_iso(r.ended_at_utc)
            ended = ended_dt.timestamp() if ended_dt else 0.0
            return (str(r.base_apk_sha256 or ""), str(r.package_name or ""), mode_rank, float(ended), r.run_id)

        included = sorted(included, key=_sort_key)

        return SelectionResult(
            selector_type="query",
            query_params=json.loads(json.dumps(self.params.__dict__, sort_keys=True)),
            grouping_key=self.grouping_key,
            pool_versions=bool(self.params.pool_versions),
            included=included,
            excluded=excluded,
        )


__all__ = ["QuerySelector"]
