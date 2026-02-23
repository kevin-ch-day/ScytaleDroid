#!/usr/bin/env python3
"""
Evidence-pack hunting utilities for dynamic collection.

Goals:
- Make it easy to understand why runs are excluded (and which run IDs).
- Detect tracker drift vs recomputed evidence-derived eligibility.
- Provide a safe quarantine workflow (move excluded packs out of output/evidence/dynamic).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

# Allow running as a standalone script without installing the package.
_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _iter_run_dirs(evidence_root: Path) -> Iterable[Path]:
    if not evidence_root.exists():
        return []
    return sorted([p for p in evidence_root.iterdir() if p.is_dir()], key=lambda p: p.name)


def _pick(d: dict[str, Any], *path: str, default: Any = None) -> Any:
    cur: Any = d
    for k in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
    return cur if cur is not None else default


def _load_tracker(tracker_path: Path) -> dict[str, Any]:
    payload = _read_json(tracker_path) or {}
    apps = payload.get("apps")
    if not isinstance(apps, dict):
        payload["apps"] = {}
    return payload


def _tracker_rows_by_run_id(tracker_payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    apps = tracker_payload.get("apps") if isinstance(tracker_payload.get("apps"), dict) else {}
    for _pkg, entry in apps.items():
        if not isinstance(entry, dict):
            continue
        runs = entry.get("runs")
        if not isinstance(runs, list):
            continue
        for r in runs:
            if isinstance(r, dict) and r.get("run_id"):
                out[str(r["run_id"])] = r
    return out


@dataclass(frozen=True)
class EligibilityRow:
    run_id: str
    pkg: str
    run_profile: str | None
    template_id: str | None
    valid_dataset_run: bool | None
    invalid_reason: str | None
    paper_eligible: bool
    reason: str | None
    all_reasons: tuple[str, ...]


def _derive_eligibility_rows(
    *,
    evidence_root: Path,
    min_windows: int,
    required_capture_policy_version: int,
    pkg_filter: str | None = None,
) -> list[EligibilityRow]:
    from scytaledroid.DynamicAnalysis.paper_eligibility import derive_paper_eligibility

    rows: list[EligibilityRow] = []
    pkg_filter_lc = pkg_filter.strip().lower() if pkg_filter else None
    for d in _iter_run_dirs(evidence_root):
        man = _read_json(d / "run_manifest.json")
        if not isinstance(man, dict):
            continue
        tgt = man.get("target") if isinstance(man.get("target"), dict) else {}
        pkg = str(tgt.get("package_name") or "").strip().lower()
        if not pkg:
            continue
        if pkg_filter_lc and pkg != pkg_filter_lc:
            continue
        plan = _read_json(d / "inputs" / "static_dynamic_plan.json") or {}
        el = derive_paper_eligibility(
            manifest=man,
            plan=plan if isinstance(plan, dict) else {},
            min_windows=int(min_windows),
            required_capture_policy_version=int(required_capture_policy_version),
        )
        op = man.get("operator") if isinstance(man.get("operator"), dict) else {}
        ds = man.get("dataset") if isinstance(man.get("dataset"), dict) else {}
        template_id = (
            op.get("template_id_actual")
            or op.get("template_id")
            or op.get("scenario_template")
        )
        rows.append(
            EligibilityRow(
                run_id=d.name,
                pkg=pkg,
                run_profile=(op.get("run_profile") or ds.get("run_profile")),
                template_id=str(template_id) if template_id else None,
                valid_dataset_run=(ds.get("valid_dataset_run") if isinstance(ds.get("valid_dataset_run"), bool) else None),
                invalid_reason=(str(ds.get("invalid_reason_code")) if ds.get("invalid_reason_code") else None),
                paper_eligible=bool(el.paper_eligible),
                reason=el.reason_code,
                all_reasons=tuple(el.all_reason_codes),
            )
        )
    return rows


def cmd_summary(args: argparse.Namespace) -> int:
    from scytaledroid.DynamicAnalysis.ml import ml_parameters_paper2 as paper2

    evidence_root = Path(args.evidence_root)
    rows = _derive_eligibility_rows(
        evidence_root=evidence_root,
        min_windows=int(args.min_windows),
        required_capture_policy_version=int(args.policy_version or paper2.PAPER_CONTRACT_VERSION),
        pkg_filter=args.pkg,
    )
    total = len(rows)
    eligible = sum(1 for r in rows if r.paper_eligible)
    excluded = total - eligible
    print(f"evidence_root={evidence_root}")
    if args.pkg:
        print(f"pkg_filter={args.pkg.strip().lower()}")
    print(f"runs_total={total}")
    print(f"paper_eligible={eligible}")
    print(f"excluded={excluded}")

    by_reason = Counter(r.reason or "EXCLUDED_UNKNOWN" for r in rows if not r.paper_eligible)
    if by_reason:
        print("\nTop exclusion reasons:")
        for k, v in by_reason.most_common(25):
            print(f"  {k}: {v}")

    by_pkg = Counter(r.pkg for r in rows)
    print("\nEvidence dirs per package (top 25):")
    for k, v in by_pkg.most_common(25):
        print(f"  {k}: {v}")

    by_tpl = Counter((r.pkg, r.template_id or "<none>") for r in rows)
    print("\nTop templates by package (top 25):")
    for (pkg, tpl), v in by_tpl.most_common(25):
        print(f"  {pkg:28s} {tpl:30s} {v}")

    return 0


def cmd_list_excluded(args: argparse.Namespace) -> int:
    from scytaledroid.DynamicAnalysis.ml import ml_parameters_paper2 as paper2

    reasons_filter = {s.strip() for s in (args.reason or []) if s.strip()}
    evidence_root = Path(args.evidence_root)
    rows = _derive_eligibility_rows(
        evidence_root=evidence_root,
        min_windows=int(args.min_windows),
        required_capture_policy_version=int(args.policy_version or paper2.PAPER_CONTRACT_VERSION),
        pkg_filter=args.pkg,
    )
    excluded = [r for r in rows if not r.paper_eligible]
    if reasons_filter:
        excluded = [r for r in excluded if (r.reason or "") in reasons_filter]
    excluded.sort(key=lambda r: (r.pkg, r.reason or "", r.run_id))
    for r in excluded:
        print(
            json.dumps(
                {
                    "run_id": r.run_id,
                    "pkg": r.pkg,
                    "reason": r.reason,
                    "all_reasons": list(r.all_reasons),
                    "run_profile": r.run_profile,
                    "template_id": r.template_id,
                    "valid_dataset_run": r.valid_dataset_run,
                    "invalid_reason": r.invalid_reason,
                },
                sort_keys=True,
            )
        )
    return 0


def cmd_drift(args: argparse.Namespace) -> int:
    from scytaledroid.DynamicAnalysis.ml import ml_parameters_paper2 as paper2
    from scytaledroid.DynamicAnalysis.paper_eligibility import derive_paper_eligibility

    evidence_root = Path(args.evidence_root)
    tracker_path = Path(args.tracker_path)
    tracker = _load_tracker(tracker_path)
    by_run = _tracker_rows_by_run_id(tracker)

    drift = []
    for d in _iter_run_dirs(evidence_root):
        rid = d.name
        man = _read_json(d / "run_manifest.json")
        if not isinstance(man, dict):
            continue
        tgt = man.get("target") if isinstance(man.get("target"), dict) else {}
        pkg = str(tgt.get("package_name") or "").strip().lower()
        if args.pkg and pkg != args.pkg.strip().lower():
            continue
        plan = _read_json(d / "inputs" / "static_dynamic_plan.json") or {}
        el = derive_paper_eligibility(
            manifest=man,
            plan=plan if isinstance(plan, dict) else {},
            min_windows=int(args.min_windows),
            required_capture_policy_version=int(args.policy_version or paper2.PAPER_CONTRACT_VERSION),
        )
        tr = by_run.get(rid)
        if not tr:
            continue
        t_eligible = tr.get("paper_eligible")
        t_reason = tr.get("paper_exclusion_primary_reason_code")
        if bool(t_eligible) != bool(el.paper_eligible) or (t_reason != el.reason_code):
            drift.append(
                {
                    "run_id": rid,
                    "pkg": pkg,
                    "tracker_paper_eligible": t_eligible,
                    "tracker_reason": t_reason,
                    "recomputed_paper_eligible": el.paper_eligible,
                    "recomputed_reason": el.reason_code,
                }
            )
    print(f"drift_count={len(drift)}")
    for row in drift[: int(args.limit)]:
        print(json.dumps(row, sort_keys=True))
    return 0


def cmd_quarantine(args: argparse.Namespace) -> int:
    """
    Move excluded evidence packs out of output/evidence/dynamic into a quarantine root.

    This is non-destructive (move, not delete). It will change what ScytaleDroid sees,
    because many tools scan output/evidence/dynamic directly.
    """
    from scytaledroid.DynamicAnalysis.ml import ml_parameters_paper2 as paper2

    evidence_root = Path(args.evidence_root)
    quarantine_root = Path(args.quarantine_root)
    quarantine_root.mkdir(parents=True, exist_ok=True)

    reasons_filter = {s.strip() for s in (args.reason or []) if s.strip()}
    rows = _derive_eligibility_rows(
        evidence_root=evidence_root,
        min_windows=int(args.min_windows),
        required_capture_policy_version=int(args.policy_version or paper2.PAPER_CONTRACT_VERSION),
        pkg_filter=args.pkg,
    )
    excluded = [r for r in rows if not r.paper_eligible]
    if reasons_filter:
        excluded = [r for r in excluded if (r.reason or "") in reasons_filter]

    # Deterministic order to make repeated runs stable.
    excluded.sort(key=lambda r: (r.reason or "", r.pkg, r.run_id))

    moved = 0
    skipped = 0
    for r in excluded:
        src = evidence_root / r.run_id
        if not src.exists():
            skipped += 1
            continue
        reason = r.reason or "EXCLUDED_UNKNOWN"
        dst = quarantine_root / reason / r.run_id
        if dst.exists():
            skipped += 1
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        if args.dry_run:
            print(json.dumps({"action": "would_move", "src": str(src), "dst": str(dst), "reason": reason, "pkg": r.pkg}))
            continue
        shutil.move(str(src), str(dst))
        moved += 1
        print(json.dumps({"action": "moved", "src": str(src), "dst": str(dst), "reason": reason, "pkg": r.pkg}))

    print(f"moved={moved} skipped={skipped} dry_run={bool(args.dry_run)}")
    if not args.dry_run and args.reindex_tracker:
        from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig, recompute_dataset_tracker

        recompute_dataset_tracker(config=DatasetTrackerConfig())
        print("tracker_reindexed=true")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    p.add_argument("--evidence-root", default="output/evidence/dynamic")
    p.add_argument("--tracker-path", default="data/archive/dataset_plan.json")
    p.add_argument("--min-windows", type=int, default=20)
    p.add_argument("--policy-version", type=int, default=0, help="0 means use tool default")
    p.add_argument("--pkg", default=None, help="package filter (e.g., com.facebook.orca)")

    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("summary")
    s.set_defaults(fn=cmd_summary)

    l = sub.add_parser("list-excluded")
    l.add_argument("--reason", action="append", default=[], help="filter exclusion reason (repeatable)")
    l.set_defaults(fn=cmd_list_excluded)

    d = sub.add_parser("drift")
    d.add_argument("--limit", type=int, default=50)
    d.set_defaults(fn=cmd_drift)

    q = sub.add_parser("quarantine")
    q.add_argument("--reason", action="append", default=[], help="only move these exclusion reason(s)")
    q.add_argument("--quarantine-root", default="output/evidence/dynamic_excluded")
    q.add_argument("--dry-run", action="store_true", default=False)
    q.add_argument("--reindex-tracker", action="store_true", default=False)
    q.set_defaults(fn=cmd_quarantine)

    return p


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    if getattr(args, "policy_version", 0) == 0:
        # Use paper2 default without importing at top-level in non-repo contexts.
        try:
            from scytaledroid.DynamicAnalysis.ml import ml_parameters_paper2 as paper2

            args.policy_version = int(paper2.PAPER_CONTRACT_VERSION)
        except Exception:
            args.policy_version = 1
    try:
        return int(args.fn(args))
    except BrokenPipeError:
        # Allow piping to head/grep without noisy stacktraces.
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
