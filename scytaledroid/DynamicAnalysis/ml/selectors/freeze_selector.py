"""Freeze selector (Phase E reproduction) as a first-class selector.

This must reproduce the Phase E "1 baseline + 2 interactive" selection exactly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_preflight import derive_run_mode, load_run_inputs

from .models import RunRef, SelectionResult


def _sha256_stream(path: Path) -> str:
    h = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_iso_to_epoch(value: object) -> float | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.strip()).timestamp()
    except Exception:
        return None


@dataclass(frozen=True)
class FreezeSelector:
    evidence_root: Path
    freeze_manifest_path: Path
    grouping_key: str = "base_apk_sha256"

    def select(self) -> SelectionResult:
        payload = json.loads(self.freeze_manifest_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError(f"Freeze manifest is not an object: {self.freeze_manifest_path}")
        apps = payload.get("apps") if isinstance(payload.get("apps"), dict) else None
        checksums = payload.get("included_run_checksums") if isinstance(payload.get("included_run_checksums"), dict) else None
        included = payload.get("included_run_ids") if isinstance(payload.get("included_run_ids"), list) else None
        if apps is None or checksums is None or included is None:
            raise RuntimeError(f"Freeze manifest missing required fields: {self.freeze_manifest_path}")
        included_set = {str(x) for x in included}

        included_refs: list[RunRef] = []
        excluded: dict[str, dict[str, Any]] = {}

        for pkg in sorted(apps.keys()):
            ent = apps.get(pkg)
            if not isinstance(ent, dict):
                continue
            base_ids = ent.get("baseline_run_ids") or []
            inter_ids = ent.get("interactive_run_ids") or []
            if not (isinstance(base_ids, list) and isinstance(inter_ids, list)):
                continue
            if len(base_ids) < 1 or len(inter_ids) < 2:
                continue

            baseline_id = str(base_ids[0])
            interactive_ids = [str(x) for x in inter_ids[:2]]
            interactive_ids = sorted(
                interactive_ids,
                key=lambda rid: (_parse_iso_to_epoch((checksums.get(rid) or {}).get("ended_at")), rid),
            )
            run_ids = [baseline_id] + interactive_ids

            for rid in run_ids:
                if rid not in included_set:
                    raise RuntimeError(f"Freeze manifest inconsistency: {rid} not in included_run_ids")
                run_dir = self.evidence_root / rid
                mf = run_dir / "run_manifest.json"
                if not mf.exists():
                    excluded[rid] = {"reason": "missing_run_manifest", "evidence_dir": str(run_dir)}
                    continue
                inputs = load_run_inputs(run_dir)
                if not inputs:
                    excluded[rid] = {"reason": "invalid_run_manifest", "evidence_dir": str(run_dir)}
                    continue
                mode, mode_source = derive_run_mode(inputs)
                base_sha = None
                if isinstance(inputs.plan, dict):
                    ident = inputs.plan.get("run_identity") if isinstance(inputs.plan.get("run_identity"), dict) else {}
                    base_sha = ident.get("base_apk_sha256")
                included_refs.append(
                    RunRef(
                        run_id=rid,
                        evidence_dir=run_dir,
                        manifest_path=mf,
                        manifest_sha256=_sha256_stream(mf),
                        package_name=inputs.package_name,
                        base_apk_sha256=str(base_sha) if isinstance(base_sha, str) and base_sha else None,
                        mode=mode,
                        mode_source=mode_source,
                        run_profile=inputs.run_profile,
                        started_at_utc=str(inputs.manifest.get("started_at") or "") or None,
                        ended_at_utc=str(inputs.manifest.get("ended_at") or "") or None,
                    )
                )

        # Stable ordering: package, base_sha, mode, ended_at, run_id
        def _sort_key(r: RunRef) -> tuple[str, str, int, float, str]:
            mode_rank = 0 if r.mode == "baseline" else (1 if r.mode == "interactive" else 2)
            ended = _parse_iso_to_epoch(r.ended_at_utc) or 0.0
            return (str(r.package_name or ""), str(r.base_apk_sha256 or ""), mode_rank, float(ended), r.run_id)

        included_refs = sorted(included_refs, key=_sort_key)

        return SelectionResult(
            selector_type="freeze",
            query_params={"freeze_manifest_path": str(self.freeze_manifest_path)},
            grouping_key=self.grouping_key,
            pool_versions=False,
            included=included_refs,
            excluded=excluded,
        )


__all__ = ["FreezeSelector"]

