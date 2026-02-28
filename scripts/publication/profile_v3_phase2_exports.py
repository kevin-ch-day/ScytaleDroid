#!/usr/bin/env python3
"""Profile v3 Phase 2 draft exports (uses current runs; no manifest required).

This is a writing-time helper for Paper #3 while Phase 2 capture is still in progress.
It is filesystem-only and reuses existing evidence packs and per-run ML artifacts.

It produces:
- a run-level CSV (one row per selected eligible run)
- a per-app CSV (ISC/BSI + summary stats) for apps that have both phases
- a per-category CSV with n-app counts (total + scripted-only + single-version-only)
- a JSON receipt that records filters, counts, and selected run_ids

It does NOT delete/prune any runs and does NOT modify evidence packs.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys
from collections import defaultdict
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
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
from scytaledroid.Publication.profile_v3_metrics import (  # noqa: E402
    ProfileV3Error,
    compute_profile_v3_per_app,
    env_allow_multi_model,
    load_profile_v3_catalog,
)


def _truthy_env(name: str, default: str = "0") -> bool:
    return str(os.environ.get(name) or default).strip().lower() in {"1", "true", "yes", "on"}


def _git_commit() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=str(REPO_ROOT),
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        return out or "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _rjson(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object: {path}")
    return payload


def _run_identity(manifest: dict) -> dict:
    tgt = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
    ident = tgt.get("run_identity") if isinstance(tgt.get("run_identity"), dict) else {}
    return ident


def _run_package(manifest: dict) -> str:
    tgt = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
    return str(tgt.get("package_name") or tgt.get("package") or "").strip()


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


def _ended_at(manifest: dict) -> str:
    scen = manifest.get("scenario") if isinstance(manifest.get("scenario"), dict) else {}
    return str(scen.get("ended_at") or manifest.get("ended_at") or "").strip()


def _template_id(manifest: dict) -> str:
    op = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
    return str(op.get("script_name") or "").strip()


def _template_hash(manifest: dict) -> str:
    op = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
    return str(op.get("script_hash") or op.get("template_hash") or "").strip()


def _window_scores_path(run_dir: Path) -> Path:
    return run_dir / "analysis" / "ml" / "v1" / "window_scores.csv"


def _threshold_path(run_dir: Path) -> Path:
    return run_dir / "analysis" / "ml" / "v1" / "baseline_threshold.json"


def _count_windows(scores: Path) -> int | None:
    if not scores.exists():
        return None
    try:
        with scores.open("r", encoding="utf-8", newline="") as f:
            r = csv.DictReader(f)
            n = 0
            for _ in r:
                n += 1
        return int(n)
    except Exception:
        return None


def _eligible(
    *,
    run_id: str,
    run_dir: Path,
    manifest: dict,
    min_windows: int,
    min_pcap_idle: int,
    min_pcap_interactive: int,
    accept_manual: bool,
    scripted_only: bool,
) -> tuple[bool, dict[str, object]]:
    """Return (eligible?, run_row_details)."""
    pkg = _run_package(manifest)
    ident = _run_identity(manifest)
    vc = str(ident.get("version_code") or ident.get("observed_version_code") or "").strip()
    vn = str(ident.get("version_name") or "").strip()
    rp = resolve_run_profile_from_manifest(manifest, strict_conflict=False).normalized
    rp = normalize_run_profile(rp)
    phase = phase_from_normalized_profile(rp)
    is_manual = rp == "interaction_manual"
    is_scripted = rp == "interaction_scripted"
    if rp.startswith("interaction"):
        if scripted_only and not is_scripted:
            return False, {}
        if (not accept_manual) and is_manual:
            return False, {}
        min_pcap = int(min_pcap_interactive)
    else:
        min_pcap = int(min_pcap_idle)

    pcap_bytes = _pcap_size_bytes(manifest)
    scores = _window_scores_path(run_dir)
    thr = _threshold_path(run_dir)
    windows = _count_windows(scores)

    ok = True
    reasons: list[str] = []
    if not vc:
        ok = False
        reasons.append("missing_version_code")
    if not scores.exists():
        ok = False
        reasons.append("missing_window_scores_csv")
    if not thr.exists():
        ok = False
        reasons.append("missing_baseline_threshold_json")
    if windows is None:
        ok = False
        reasons.append("window_count_unavailable")
    elif int(windows) < int(min_windows):
        ok = False
        reasons.append("insufficient_windows")
    if pcap_bytes is None:
        ok = False
        reasons.append("pcap_size_unavailable")
    elif int(pcap_bytes) < int(min_pcap):
        ok = False
        reasons.append("insufficient_pcap_bytes")

    row = {
        "run_id": run_id,
        "package": pkg,
        "run_profile": rp,
        "phase": phase,
        "manual_flag": int(is_manual),
        "template_id": _template_id(manifest),
        "template_hash": _template_hash(manifest),
        "ended_at": _ended_at(manifest),
        "version_code": vc,
        "version_name": vn,
        "windows": windows if windows is not None else "",
        "pcap_bytes": pcap_bytes if pcap_bytes is not None else "",
        "min_windows": int(min_windows),
        "min_pcap_bytes": int(min_pcap),
        "eligible": int(ok),
        "ineligible_reasons": ",".join(reasons),
    }
    return ok, row


def _select_runs(
    *,
    evidence_root: Path,
    catalog: dict[str, dict[str, str]],
    accept_manual: bool,
    scripted_only: bool,
    single_version_only: bool,
    target_per_phase: int,
) -> tuple[list[dict[str, object]], dict[str, dict[str, list[str]]]]:
    """Return (run_level_rows, selected_run_ids_by_pkg_phase)."""

    min_windows = int(effective_min_windows_per_run())
    min_pcap_idle = int(effective_min_pcap_bytes_idle())
    min_pcap_inter = int(effective_min_pcap_bytes_scripted())

    run_rows: list[dict[str, object]] = []
    eligible_by_pkg_phase: dict[str, dict[str, list[dict[str, object]]]] = defaultdict(lambda: defaultdict(list))
    version_set: dict[str, set[str]] = defaultdict(set)

    for mf in sorted(evidence_root.glob("*/run_manifest.json")):
        run_id = mf.parent.name
        try:
            man = _rjson(mf)
        except Exception:
            continue
        pkg = _run_package(man)
        if pkg not in catalog:
            continue
        ok, row = _eligible(
            run_id=run_id,
            run_dir=mf.parent,
            manifest=man,
            min_windows=min_windows,
            min_pcap_idle=min_pcap_idle,
            min_pcap_interactive=min_pcap_inter,
            accept_manual=accept_manual,
            scripted_only=scripted_only,
        )
        if not row:
            continue
        row["app"] = catalog[pkg]["app"]
        row["app_category"] = catalog[pkg]["app_category"]
        run_rows.append(row)
        if ok:
            phase = str(row["phase"] or "")
            eligible_by_pkg_phase[pkg][phase].append(row)
            vc = str(row.get("version_code") or "").strip()
            if vc:
                version_set[pkg].add(vc)

    # If single-version-only, drop packages with multiple version codes.
    if single_version_only:
        for pkg in list(eligible_by_pkg_phase.keys()):
            if len(version_set.get(pkg, set())) > 1:
                eligible_by_pkg_phase.pop(pkg, None)

    # Select newest eligible runs per pkg/phase up to target_per_phase.
    selected: dict[str, dict[str, list[str]]] = defaultdict(lambda: {"idle": [], "interactive": []})
    for pkg, by_phase in eligible_by_pkg_phase.items():
        for phase in ("idle", "interactive"):
            rows = list(by_phase.get(phase) or [])
            rows.sort(key=lambda r: str(r.get("ended_at") or ""), reverse=True)
            for r in rows[: max(int(target_per_phase), 1)]:
                selected[pkg][phase].append(str(r["run_id"]))

    return run_rows, selected


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: ("" if r.get(k) is None else r.get(k)) for k in fieldnames})


def _category_counts(catalog: dict[str, dict[str, str]], packages: list[str]) -> dict[str, int]:
    by_cat: dict[str, int] = defaultdict(int)
    for pkg in packages:
        meta = catalog.get(pkg)
        if not meta:
            continue
        by_cat[str(meta["app_category"])] += 1
    return dict(sorted(by_cat.items()))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Profile v3 Phase 2 draft exports (no manifest)")
    p.add_argument("--catalog", default=str(REPO_ROOT / "profiles" / "profile_v3_app_catalog.json"))
    p.add_argument("--evidence-root", default=str(REPO_ROOT / "output" / "evidence" / "dynamic"))
    p.add_argument("--out-dir", default=str(REPO_ROOT / "output" / "audit" / "profile_v3" / "phase2_exports"))
    p.add_argument("--target-per-phase", type=int, default=0, help="How many eligible runs per app per phase to select (default: 3 in strict, else 1).")
    p.add_argument("--scripted-only", action="store_true", help="Interactive must be interaction_scripted only (exclude manual).")
    p.add_argument("--single-version-only", action="store_true", help="Exclude packages with mixed version_code among eligible runs.")
    p.add_argument("--accept-manual-interaction", action="store_true", help="Treat interaction_manual as interactive for selection/metrics.")
    p.add_argument("--allow-degenerate-metrics", action="store_true", help="Allow sigma_idle==0 or mu_idle<=0 (exports null ISC/BSI).")
    args = p.parse_args(argv)

    strict = _truthy_env("SCYTALEDROID_PAPER_STRICT", default="0")
    accept_manual = bool(args.accept_manual_interaction or _truthy_env("SCYTALEDROID_V3_ACCEPT_MANUAL_INTERACTIVE", default="0"))
    if args.scripted_only:
        accept_manual = False

    target = int(args.target_per_phase or 0)
    if target <= 0:
        target = 3 if strict else 1

    # Operators often pass repo-relative paths like output/...; normalize everything to
    # absolute paths under REPO_ROOT so receipts can safely reference repo-relative paths.
    catalog_path = Path(args.catalog)
    if not catalog_path.is_absolute():
        catalog_path = (REPO_ROOT / catalog_path).resolve()
    catalog = load_profile_v3_catalog(catalog_path)
    evidence_root = Path(args.evidence_root)
    if not evidence_root.is_absolute():
        evidence_root = (REPO_ROOT / evidence_root).resolve()
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = (REPO_ROOT / out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")

    # Build four datasets: primary + sensitivity filters.
    datasets = [
        ("primary", dict(scripted_only=False, single_version_only=False, accept_manual=accept_manual)),
        ("scripted_only", dict(scripted_only=True, single_version_only=False, accept_manual=False)),
        ("single_version_only", dict(scripted_only=False, single_version_only=True, accept_manual=accept_manual)),
        ("scripted_and_single_version", dict(scripted_only=True, single_version_only=True, accept_manual=False)),
    ]

    allow_multi = env_allow_multi_model()
    summary: dict[str, object] = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "git_commit": _git_commit(),
        "inputs": {
            "catalog_path": str(catalog_path),
            "catalog_sha256": _sha256_file(catalog_path) if catalog_path.exists() else "",
            "evidence_root": str(evidence_root),
            "strict_env": bool(strict),
            "target_per_phase": int(target),
            "min_windows": int(effective_min_windows_per_run()),
            "min_pcap_idle": int(effective_min_pcap_bytes_idle()),
            "min_pcap_interactive": int(effective_min_pcap_bytes_scripted()),
        },
        "datasets": {},
    }

    # Always write a run-level inventory for debugging (includes eligible flag).
    inventory_rows, _ = _select_runs(
        evidence_root=evidence_root,
        catalog=catalog,
        accept_manual=accept_manual,
        scripted_only=False,
        single_version_only=False,
        target_per_phase=target,
    )
    inv_csv = out_dir / f"profile_v3_run_inventory_{ts}.csv"
    inv_fields = [
        "run_id",
        "package",
        "app",
        "app_category",
        "phase",
        "run_profile",
        "manual_flag",
        "template_id",
        "template_hash",
        "ended_at",
        "version_code",
        "version_name",
        "windows",
        "pcap_bytes",
        "eligible",
        "ineligible_reasons",
    ]
    _write_csv(inv_csv, inv_fields, inventory_rows)

    for name, cfg in datasets:
        run_rows, selected = _select_runs(
            evidence_root=evidence_root,
            catalog=catalog,
            accept_manual=bool(cfg["accept_manual"]),
            scripted_only=bool(cfg["scripted_only"]),
            single_version_only=bool(cfg["single_version_only"]),
            target_per_phase=target,
        )
        pkgs_included = []
        included_run_ids: list[str] = []
        for pkg, by_phase in selected.items():
            if by_phase.get("idle") and by_phase.get("interactive"):
                pkgs_included.append(pkg)
                included_run_ids.extend(list(by_phase["idle"]))
                included_run_ids.extend(list(by_phase["interactive"]))

        # Run-level selected CSV (eligible runs only).
        selected_set = set(included_run_ids)
        selected_rows = [r for r in run_rows if str(r.get("run_id")) in selected_set]
        sel_csv = out_dir / f"profile_v3_selected_runs_{name}_{ts}.csv"
        _write_csv(sel_csv, inv_fields, selected_rows)

        # Per-app metrics (only for apps included with both phases).
        per_app_rows: list[dict[str, object]] = []
        per_cat_rows: list[dict[str, object]] = []
        per_app_csv = out_dir / f"profile_v3_per_app_{name}_{ts}.csv"
        per_cat_csv = out_dir / f"profile_v3_per_category_{name}_{ts}.csv"

        per_app_ok = True
        per_app_err = ""
        try:
            per_app = compute_profile_v3_per_app(
                included_run_ids=list(included_run_ids),
                evidence_root=evidence_root,
                catalog=catalog,
                allow_multi_model=bool(allow_multi),
                allow_manual_interaction=bool(cfg["accept_manual"]),
                allow_degenerate_metrics=bool(args.allow_degenerate_metrics),
            )
            per_app_rows = [asdict(x) for x in per_app]
        except ProfileV3Error as exc:
            per_app_ok = False
            per_app_err = f"{exc.code}:{exc}"

        if per_app_rows:
            _write_csv(per_app_csv, list(per_app_rows[0].keys()), per_app_rows)

            # Per-category aggregation (n apps + medians).
            by_cat: dict[str, list[dict[str, object]]] = defaultdict(list)
            for r in per_app_rows:
                by_cat[str(r["app_category"])].append(r)

            def _median(xs: list[float]) -> float | None:
                xs = sorted(xs)
                if not xs:
                    return None
                mid = len(xs) // 2
                return float(xs[mid]) if len(xs) % 2 == 1 else float((xs[mid - 1] + xs[mid]) / 2.0)

            for cat, rows_cat in sorted(by_cat.items()):
                for m in ("mu_idle_rdi", "mu_interactive_rdi", "delta_rdi", "isc", "bsi"):
                    vals: list[float] = []
                    for rr in rows_cat:
                        v = rr.get(m)
                        if v in (None, ""):
                            continue
                        try:
                            vals.append(float(v))
                        except Exception:
                            continue
                    # write one row per category (medians)
                per_cat_rows.append(
                    {
                        "app_category": cat,
                        "n_apps": int(len(rows_cat)),
                        "median_mu_idle_rdi": _median([float(rr["mu_idle_rdi"]) for rr in rows_cat if rr.get("mu_idle_rdi") not in (None, "")]),
                        "median_mu_interactive_rdi": _median([float(rr["mu_interactive_rdi"]) for rr in rows_cat if rr.get("mu_interactive_rdi") not in (None, "")]),
                        "median_delta_rdi": _median([float(rr["delta_rdi"]) for rr in rows_cat if rr.get("delta_rdi") not in (None, "")]),
                        "median_isc": _median([float(rr["isc"]) for rr in rows_cat if rr.get("isc") not in (None, "")]),
                        "median_bsi": _median([float(rr["bsi"]) for rr in rows_cat if rr.get("bsi") not in (None, "")]),
                    }
                )

            _write_csv(per_cat_csv, list(per_cat_rows[0].keys()) if per_cat_rows else ["app_category", "n_apps"], per_cat_rows)

        summary["datasets"][name] = {
            "filters": cfg,
            "n_apps_total_catalog": int(len(catalog)),
            "n_apps_included": int(len(pkgs_included)),
            "category_counts_included": _category_counts(catalog, pkgs_included),
            "selected_run_ids_total": int(len(included_run_ids)),
            "selected_csv": str(sel_csv.relative_to(REPO_ROOT)),
            "per_app_ok": bool(per_app_ok),
            "per_app_error": per_app_err,
            "per_app_csv": str(per_app_csv.relative_to(REPO_ROOT)) if per_app_rows else "",
            "per_category_csv": str(per_cat_csv.relative_to(REPO_ROOT)) if per_cat_rows else "",
        }

    receipt_path = out_dir / f"profile_v3_phase2_exports_receipt_{ts}.json"
    receipt_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    print(f"[OK] Wrote: {inv_csv}")
    print(f"[OK] Wrote: {receipt_path}")
    # Be resilient if the operator passed an out-dir outside the repo root.
    try:
        out_rel = str(out_dir.relative_to(REPO_ROOT))
    except Exception:
        out_rel = str(out_dir)
    try:
        rec_rel = str(receipt_path.relative_to(REPO_ROOT))
    except Exception:
        rec_rel = str(receipt_path)
    print(f"[COPY] v3_phase2_exports out_dir='{out_rel}' receipt='{rec_rel}'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
