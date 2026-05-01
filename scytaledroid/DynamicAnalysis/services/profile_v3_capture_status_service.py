#!/usr/bin/env python3
"""Profile v3 capture status dashboard (Phase 2 operator aid).

This script scans local dynamic evidence packs under output/evidence/dynamic and
summarizes, per v3 catalog package:
- idle + scripted run availability
- minima compliance (min windows / min pcap bytes) using the same sources as strict manifest build
- required ML artifacts presence (window_scores.csv + baseline_threshold.json)
- version_code presence + mixed-version detection

It is intentionally filesystem-driven (DB is advisory) and emits:
- a one-line [COPY] summary for PM updates
- a CSV for quick sorting/filtering
- a JSON receipt for audit trails
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import signal
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.DynamicAnalysis.run_profile_norm import (  # noqa: E402
    normalize_run_profile,
    phase_from_normalized_profile,
    resolve_run_profile_from_manifest,
)
from scytaledroid.DynamicAnalysis.utils.profile_v3_minima import (  # noqa: E402
    effective_min_pcap_bytes_idle,
    effective_min_pcap_bytes_scripted,
    effective_min_windows_per_run,
)
from scytaledroid.Publication.profile_v3_metrics import load_profile_v3_catalog  # noqa: E402


def _truthy_env(name: str, default: str = "0") -> bool:
    return str(os.environ.get(name) or default).strip().lower() in {"1", "true", "yes", "on"}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_commit(repo_root: Path) -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=str(repo_root),
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        return out or "UNKNOWN"
    except Exception:
        return "UNKNOWN"

def _relpath_under_repo(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except Exception:
        return str(path)


def _rjson(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object: {path}")
    return payload


def _read_run_manifest(evidence_root: Path, run_id: str) -> dict:
    p = evidence_root / run_id / "run_manifest.json"
    if not p.exists():
        raise FileNotFoundError(p)
    return _rjson(p)


def _run_identity(manifest: dict) -> dict:
    tgt = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
    ident = tgt.get("run_identity") if isinstance(tgt.get("run_identity"), dict) else {}
    return ident


def _run_package(manifest: dict) -> str:
    tgt = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
    pkg = str(tgt.get("package_name") or tgt.get("package") or "").strip()
    return pkg


def _pcap_size_bytes(manifest: dict) -> int | None:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return None
    for art in artifacts:
        if not isinstance(art, dict):
            continue
        if str(art.get("type") or "") != "pcapdroid_capture":
            continue
        size = art.get("size_bytes")
        try:
            return int(size) if size is not None else None
        except Exception:
            return None
    return None


def _window_scores_path(evidence_root: Path, run_id: str) -> Path:
    return evidence_root / run_id / "analysis" / "ml" / "v1" / "window_scores.csv"


def _threshold_path(evidence_root: Path, run_id: str) -> Path:
    return evidence_root / run_id / "analysis" / "ml" / "v1" / "baseline_threshold.json"


def _count_windows(window_scores_csv: Path) -> int | None:
    if not window_scores_csv.exists():
        return None
    try:
        with window_scores_csv.open("r", encoding="utf-8", newline="") as f:
            r = csv.DictReader(f)
            n = 0
            for _ in r:
                n += 1
        return int(n)
    except Exception:
        return None


@dataclass
class RunObs:
    run_id: str
    package: str
    run_profile: str
    phase: str
    version_code: str
    windows: int | None
    pcap_bytes: int | None
    has_scores: bool
    has_threshold: bool

    def is_scripted(self, *, accept_manual: bool) -> bool:
        if self.run_profile == "interaction_scripted":
            return True
        if accept_manual and self.run_profile == "interaction_manual":
            return True
        return False

    def is_idle(self) -> bool:
        return self.phase == "idle"

    def artifacts_ok(self) -> bool:
        return self.has_scores and self.has_threshold

    def minima_ok(self, *, min_windows: int, min_pcap_bytes: int) -> bool:
        if self.windows is None or int(self.windows) < int(min_windows):
            return False
        if self.pcap_bytes is None or int(self.pcap_bytes) < int(min_pcap_bytes):
            return False
        return True


def _scan_runs(evidence_root: Path) -> list[RunObs]:
    runs: list[RunObs] = []
    if not evidence_root.exists():
        return runs
    for mf in sorted(evidence_root.glob("*/run_manifest.json")):
        run_id = mf.parent.name
        try:
            man = _rjson(mf)
        except Exception:
            continue
        pkg = _run_package(man)
        if not pkg:
            continue
        try:
            rp = resolve_run_profile_from_manifest(man, strict_conflict=True).normalized
        except Exception:
            rp = ""
        rp = normalize_run_profile(rp)
        phase = phase_from_normalized_profile(rp)
        ident = _run_identity(man)
        vc = str(ident.get("version_code") or ident.get("observed_version_code") or "").strip()
        scores_path = _window_scores_path(evidence_root, run_id)
        thr_path = _threshold_path(evidence_root, run_id)
        runs.append(
            RunObs(
                run_id=run_id,
                package=pkg.strip(),
                run_profile=rp,
                phase=phase,
                version_code=vc,
                windows=_count_windows(scores_path),
                pcap_bytes=_pcap_size_bytes(man),
                has_scores=scores_path.exists(),
                has_threshold=thr_path.exists(),
            )
        )
    return runs


def _phase_blocker_reasons(
    *,
    phase_runs: list[RunObs],
    phase_label: str,
    min_windows: int,
    min_pcap_bytes: int,
) -> list[str]:
    """Return strict-aligned reasons for why no eligible run exists for a phase."""

    reasons: list[str] = []
    if not phase_runs:
        # Strict manifest enforces idle>=1 and scripted>=1 per package.
        # Mirror that language here so dashboard blockers map 1:1 to strict failures.
        reasons.append(f"missing_required_phase_{phase_label.lower()}")
        return reasons

    if not any(o.version_code for o in phase_runs):
        reasons.append("missing_version_code")

    if not any(o.has_scores for o in phase_runs):
        reasons.append(f"missing_window_scores_csv:{phase_label.lower()}")
    if not any(o.has_threshold for o in phase_runs):
        reasons.append(f"missing_baseline_threshold_json:{phase_label.lower()}")

    # Minima checks: only flag under-minima when at least one run has the corresponding measurement.
    windows = [o.windows for o in phase_runs if o.windows is not None]
    if windows and min(int(w) for w in windows) < int(min_windows):
        reasons.append(f"insufficient_windows:{phase_label.lower()}")
    pcap_sizes = [o.pcap_bytes for o in phase_runs if o.pcap_bytes is not None]
    if pcap_sizes and min(int(b) for b in pcap_sizes) < int(min_pcap_bytes):
        reasons.append(f"insufficient_pcap_bytes:{phase_label.lower()}")

    # If we have runs but no pcap sizes, surface it (strict manifest would fail-closed).
    if not pcap_sizes:
        reasons.append(f"pcap_size_unavailable:{phase_label.lower()}")
    if not windows:
        reasons.append(f"window_count_unavailable:{phase_label.lower()}")

    return reasons


def main(argv: list[str] | None = None) -> int:
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except Exception:
        pass

    p = argparse.ArgumentParser(description="Profile v3 capture status dashboard (Phase 2)")
    p.add_argument(
        "--catalog",
        default=str(REPO_ROOT / "profiles" / "profile_v3_app_catalog.json"),
        help="v3 app catalog (21 packages).",
    )
    p.add_argument(
        "--evidence-root",
        default=str(REPO_ROOT / "output" / "evidence" / "dynamic"),
        help="Dynamic evidence root containing run dirs.",
    )
    p.add_argument(
        "--out-dir",
        default=str(REPO_ROOT / "output" / "audit" / "profile_v3"),
        help="Output directory for CSV + JSON receipt.",
    )
    p.add_argument(
        "--write-audit",
        action="store_true",
        help="Write CSV + JSON receipt under --out-dir.",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Strict/paper mode: exit non-zero if any catalog package lacks idle+scripted minima/artifacts.",
    )
    args = p.parse_args(argv)

    strict_env = str(os.environ.get("SCYTALEDROID_PAPER_STRICT") or "").strip().lower() in {"1", "true", "yes", "on"}
    strict = bool(args.strict or strict_env)
    accept_manual_interaction = _truthy_env("SCYTALEDROID_V3_ACCEPT_MANUAL_INTERACTIVE", default="0")
    mixed_versions_policy = str(os.environ.get("SCYTALEDROID_V3_MIXED_VERSIONS_POLICY") or "").strip().lower() or "warn"
    if mixed_versions_policy not in {"warn", "block"}:
        mixed_versions_policy = "warn"

    # Optional operator-quality target: how many *eligible* runs per package.
    # This does not change strict manifest requirements (idle>=1 + scripted>=1); it's a Phase 2
    # capture-day target so you can average/robustify against misruns.
    try:
        env_idle = str(os.environ.get("SCYTALEDROID_V3_IDLE_ELIGIBLE_TARGET") or "").strip()
        idle_target = int(env_idle or ("3" if strict else "1"))
    except Exception:
        idle_target = 3 if strict else 1
    if idle_target < 1:
        idle_target = 1

    # Default in strict is 3 for redundancy; override via env to keep scripted lighter.
    try:
        env_scripted = str(os.environ.get("SCYTALEDROID_V3_SCRIPTED_ELIGIBLE_TARGET") or "").strip()
        scripted_target = int(env_scripted or ("3" if strict else "1"))
    except Exception:
        scripted_target = 3 if strict else 1
    if scripted_target < 1:
        scripted_target = 1

    catalog_path = Path(args.catalog)
    catalog = load_profile_v3_catalog(catalog_path)
    pkgs = sorted(catalog.keys())

    evidence_root = Path(args.evidence_root)
    runs = _scan_runs(evidence_root)

    min_windows = int(effective_min_windows_per_run())
    min_pcap_bytes_idle = int(effective_min_pcap_bytes_idle())
    min_pcap_bytes_scripted = int(effective_min_pcap_bytes_scripted())

    def _min_pcap_for_obs(o: RunObs) -> int:
        if o.is_idle():
            return int(min_pcap_bytes_idle)
        if o.is_scripted(accept_manual=accept_manual_interaction):
            return int(min_pcap_bytes_scripted)
        # Conservative default: treat non-idle as interactive.
        return int(min_pcap_bytes_scripted)

    by_pkg: dict[str, list[RunObs]] = {pkg: [] for pkg in pkgs}
    for r in runs:
        if r.package in by_pkg:
            by_pkg[r.package].append(r)

    # Build per-package summary rows.
    rows: list[dict[str, str]] = []
    blockers: list[str] = []
    warnings: list[str] = []
    idle_gap_n = 0
    scripted_gap_n = 0
    targets_met_n = 0

    for pkg in pkgs:
        meta = catalog.get(pkg) or {}
        app = str(meta.get("app") or "").strip()
        cat = str(meta.get("app_category") or "").strip()

        obs = by_pkg.get(pkg, [])
        # Define "eligible run" for Phase 2 planning: strict-manifest-aligned.
        eligible = [
            o
            for o in obs
            if o.artifacts_ok()
            and o.minima_ok(min_windows=min_windows, min_pcap_bytes=_min_pcap_for_obs(o))
            and bool(o.version_code)
        ]
        elig_idle = [o for o in eligible if o.is_idle()]
        elig_scripted = [o for o in eligible if o.is_scripted(accept_manual=accept_manual_interaction)]

        idle_ok = len(elig_idle) > 0
        scripted_ok = len(elig_scripted) > 0
        idle_gap = max(0, int(idle_target) - int(len(elig_idle)))
        if idle_gap > 0:
            idle_gap_n += 1
        scripted_gap = max(0, int(scripted_target) - int(len(elig_scripted)))
        if scripted_gap > 0:
            scripted_gap_n += 1

        # Diagnostics for "best seen" values (even if not eligible).
        idle_all = [o for o in obs if o.is_idle()]
        scripted_all = [o for o in obs if o.is_scripted(accept_manual=accept_manual_interaction)]

        def _min_int(vals: list[int]) -> str:
            return str(min(vals)) if vals else ""

        idle_wc_min = _min_int([o.windows for o in idle_all if o.windows is not None])
        scr_wc_min = _min_int([o.windows for o in scripted_all if o.windows is not None])
        idle_pcap_min = _min_int([o.pcap_bytes for o in idle_all if o.pcap_bytes is not None])
        scr_pcap_min = _min_int([o.pcap_bytes for o in scripted_all if o.pcap_bytes is not None])

        versions = sorted({o.version_code for o in obs if o.version_code})
        mixed_versions = "1" if len(versions) > 1 else "0"

        status = "PASS"
        reasons: list[str] = []
        if mixed_versions == "1":
            reasons.append("MIXED_VERSIONS")
            if mixed_versions_policy == "block":
                status = "BLOCK"
            else:
                warnings.append(f"{pkg}:MIXED_VERSIONS:{'|'.join(versions)}")

        if not idle_ok:
            status = "BLOCK"
            reasons.extend(
                _phase_blocker_reasons(
                    phase_runs=idle_all,
                    phase_label="IDLE",
                    min_windows=min_windows,
                    min_pcap_bytes=min_pcap_bytes_idle,
                )
            )
        if not scripted_ok:
            status = "BLOCK"
            reasons.extend(
                _phase_blocker_reasons(
                    phase_runs=scripted_all,
                    phase_label="SCRIPTED",
                    min_windows=min_windows,
                    min_pcap_bytes=min_pcap_bytes_scripted,
                )
            )

        if status != "PASS":
            blockers.append(f"{pkg}:{','.join(reasons) if reasons else 'BLOCK'}")
        else:
            if idle_gap == 0 and scripted_gap == 0:
                targets_met_n += 1

        rows.append(
            {
                "package": pkg,
                "app": app,
                "app_category": cat,
                "status": status,
                "reasons": ",".join(dict.fromkeys(reasons)),  # stable de-dupe, preserve order
                "idle_runs_total": str(len(idle_all)),
                "scripted_runs_total": str(len(scripted_all)),
                "idle_runs_eligible": str(len(elig_idle)),
                "scripted_runs_eligible": str(len(elig_scripted)),
                "idle_runs_eligible_target": str(idle_target),
                "idle_runs_eligible_gap": str(idle_gap),
                "scripted_runs_eligible_target": str(scripted_target),
                "scripted_runs_eligible_gap": str(scripted_gap),
                "idle_windows_min": idle_wc_min,
                "scripted_windows_min": scr_wc_min,
                "idle_pcap_bytes_min": idle_pcap_min,
                "scripted_pcap_bytes_min": scr_pcap_min,
                "version_codes": "|".join(versions),
                "mixed_versions": mixed_versions,
                "min_windows_required": str(min_windows),
                "min_pcap_bytes_required_idle": str(min_pcap_bytes_idle),
                "min_pcap_bytes_required_scripted": str(min_pcap_bytes_scripted),
            }
        )

    total = len(pkgs)
    ok_n = sum(1 for r in rows if r["status"] == "PASS")
    block_n = total - ok_n
    # Action taxonomy (matches guided capture UI labels).
    need_both = 0
    need_idle = 0
    need_scripted = 0
    for r in rows:
        if (r.get("status") or "").strip().upper() == "PASS":
            continue
        reasons = r.get("reasons") or ""
        miss_idle = "missing_required_phase_idle" in reasons
        miss_scripted = "missing_required_phase_scripted" in reasons
        if miss_idle and miss_scripted:
            need_both += 1
        elif miss_idle:
            need_idle += 1
        elif miss_scripted:
            need_scripted += 1

    # One-line PM copy/paste summary.
    print(
        "[COPY] v3_capture_status "
        f"git_commit={_git_commit(REPO_ROOT)} strict={int(strict)} accept_manual_interaction={int(accept_manual_interaction)} "
        f"catalog_packages={total} pass={ok_n} blockers={block_n} "
        f"min_windows={min_windows} min_pcap_bytes_idle={min_pcap_bytes_idle} min_pcap_bytes_scripted={min_pcap_bytes_scripted} "
        f"idle_target={idle_target} scripted_target={scripted_target} "
        f"idle_gap_apps={idle_gap_n} scripted_gap_apps={scripted_gap_n} targets_met={targets_met_n} "
        f"need_both={need_both} need_idle={need_idle} need_scripted={need_scripted} "
        f"evidence_root='{_relpath_under_repo(evidence_root)}'"
    )

    if warnings:
        print("Warnings (first 10):")
        for w in warnings[:10]:
            print(f"- {w}")
        if len(warnings) > 10:
            print(f"- ... ({len(warnings) - 10} more)")

    # Print a small actionable recap (top blockers only).
    if blockers:
        print("Blockers (first 15):")
        for b in blockers[:15]:
            print(f"- {b}")
        if len(blockers) > 15:
            print(f"- ... ({len(blockers) - 15} more)")

    if args.write_audit:
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        csv_path = out_dir / f"capture_status_{ts}.csv"
        json_path = out_dir / f"capture_status_{ts}.json"

        with csv_path.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [])
            w.writeheader()
            for r in rows:
                w.writerow(r)

        receipt = {
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "profile_id": "profile_v3_structural",
            "git_commit": _git_commit(REPO_ROOT),
            "strict": bool(strict),
            "inputs": {
                "catalog_path": str(catalog_path),
                "catalog_sha256": _sha256_file(catalog_path) if catalog_path.exists() else "",
                "evidence_root": str(evidence_root),
                "min_windows_required": int(min_windows),
                "min_pcap_bytes_required_idle": int(min_pcap_bytes_idle),
                "min_pcap_bytes_required_scripted": int(min_pcap_bytes_scripted),
                "idle_runs_eligible_target": int(idle_target),
                "scripted_runs_eligible_target": int(scripted_target),
                "accept_manual_interaction": bool(accept_manual_interaction),
            },
            "summary": {
                "catalog_packages": total,
                "pass": ok_n,
                "blockers": block_n,
                "targets_met": targets_met_n,
                "need_both": int(need_both),
                "need_idle": int(need_idle),
                "need_scripted": int(need_scripted),
            },
            "warnings": warnings,
            "csv_path": str(csv_path),
            "rows": rows,
        }
        json_path.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
        print(f"[COPY] v3_capture_status_csv path='{csv_path.relative_to(REPO_ROOT)}'")
        print(f"[COPY] v3_capture_status_receipt path='{json_path.relative_to(REPO_ROOT)}'")

        # Recapture plan: ordered, minimal-action suggestions.
        plan_rows: list[dict[str, str]] = []
        for r in rows:
            if r["status"] == "PASS":
                # Optional burn-down: if you want redundancy, keep these in the plan.
                try:
                    idle_gap = int(r.get("idle_runs_eligible_gap") or "0")
                    scr_gap = int(r.get("scripted_runs_eligible_gap") or "0")
                    if int(idle_target) <= 1 and int(scripted_target) <= 1:
                        continue
                    if idle_gap <= 0 and scr_gap <= 0:
                        continue
                except Exception:
                    continue
            pkg = r["package"]
            reasons_s = r.get("reasons") or ""
            reason_set = {x for x in reasons_s.split(",") if x}
            # Priority: missing phase > missing artifacts > under minima > mixed versions.
            priority = 90
            action = "capture_both"
            # Redundancy is lowest priority (quality target only).
            if (r.get("status") or "") == "PASS":
                try:
                    idle_gap = int(r.get("idle_runs_eligible_gap") or "0")
                    scr_gap = int(r.get("scripted_runs_eligible_gap") or "0")
                    if idle_gap > 0 and scr_gap > 0:
                        priority = 95
                        action = "capture_both"
                    elif idle_gap > 0:
                        priority = 95
                        action = "capture_idle"
                    elif scr_gap > 0:
                        priority = 95
                        action = "capture_scripted"
                except Exception:
                    pass
            if "MIXED_VERSIONS" in reason_set:
                # Mixed versions are tracked as an audit warning; do not force churn during Phase 2
                # unless the operator explicitly sets policy=block.
                if mixed_versions_policy == "block":
                    priority = 10
                    action = "reharvest_recapture"
            missing_idle = "missing_required_phase_idle" in reason_set
            missing_scripted = "missing_required_phase_scripted" in reason_set
            if missing_idle and missing_scripted:
                priority = min(priority, 20)
                action = "capture_both"
            elif missing_idle:
                priority = min(priority, 30)
                action = "capture_idle"
            elif missing_scripted:
                priority = min(priority, 30)
                action = "capture_interactive" if accept_manual_interaction else "capture_scripted"
            else:
                # Non-missing blockers: likely artifacts/minima; choose phase-specific action when obvious.
                idle_only = any(":idle" in x for x in reason_set) and not any(":scripted" in x for x in reason_set)
                scripted_only = any(":scripted" in x for x in reason_set) and not any(":idle" in x for x in reason_set)
                if idle_only and not scripted_only:
                    priority = min(priority, 50)
                    action = "recapture_idle"
                elif scripted_only and not idle_only:
                    priority = min(priority, 50)
                    action = "recapture_interactive" if accept_manual_interaction else "recapture_scripted"
                else:
                    priority = min(priority, 60)
                    action = "recapture_both"

            plan_rows.append(
                {
                    "priority": str(priority),
                    "action": action,
                    "package": pkg,
                    "app": r.get("app") or "",
                    "app_category": r.get("app_category") or "",
                    "reasons": reasons_s,
                }
            )

        plan_rows.sort(key=lambda rr: (int(rr["priority"]), rr["app_category"], rr["package"]))
        plan_csv = out_dir / f"recapture_plan_{ts}.csv"
        with plan_csv.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["priority", "action", "package", "app", "app_category", "reasons"])
            w.writeheader()
            for pr in plan_rows:
                w.writerow(pr)
        print(f"[COPY] v3_recapture_plan_csv path='{plan_csv.relative_to(REPO_ROOT)}' items={len(plan_rows)}")

    if strict and block_n > 0:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
