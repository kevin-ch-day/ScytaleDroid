#!/usr/bin/env python3
"""Build a self-contained Profile v3 manifest (no runtime extension).

This is a convenience tool for composing:
- imported runs from an existing freeze (e.g., v2)
- additional run IDs for the new apps

It writes a standalone manifest at the requested output path. It does NOT:
- compute run checksums
- validate ML artifacts
- modify any evidence packs
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import MIN_WINDOWS_PER_RUN  # noqa: E402
from scytaledroid.DynamicAnalysis.run_profile_norm import (  # noqa: E402
    normalize_run_profile,
    phase_from_normalized_profile,
    resolve_run_profile_from_manifest,
)
from scytaledroid.DynamicAnalysis.utils.profile_v3_minima import (  # noqa: E402
    effective_min_pcap_bytes_idle,
    effective_min_pcap_bytes_scripted,
)
from scytaledroid.Publication.paper_mode import PaperModeContext  # noqa: E402


def _sha256_file(path: Path) -> str:
    import hashlib

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


def _load_run_ids_arg(values: list[str]) -> list[str]:
    out: list[str] = []
    for v in values:
        s = str(v).strip()
        if not s:
            continue
        # Allow @file syntax (one run id per line).
        if s.startswith("@"):
            p = Path(s[1:])
            for line in p.read_text(encoding="utf-8").splitlines():
                rid = line.strip()
                if rid and not rid.startswith("#"):
                    out.append(rid)
            continue
        out.append(s)
    return out


def _rjson_file(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object: {path}")
    return payload


def _read_run_manifest(evidence_root: Path, run_id: str) -> dict:
    p = evidence_root / run_id / "run_manifest.json"
    if not p.exists():
        raise SystemExit(f"Missing run_manifest.json for run_id={run_id}: {p}")
    return _rjson_file(p)


def _run_identity(manifest: dict) -> dict:
    tgt = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
    ident = tgt.get("run_identity") if isinstance(tgt.get("run_identity"), dict) else {}
    return ident


def _run_package(manifest: dict) -> str:
    tgt = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
    pkg = str(tgt.get("package_name") or tgt.get("package") or "").strip()
    if not pkg:
        raise SystemExit("run_manifest missing target.package_name")
    return pkg


def _include_run_id(
    *,
    evidence_root: Path,
    run_id: str,
    allow_manual_interaction: bool,
) -> tuple[bool, dict]:
    """Return (include?, metadata) for a run_id."""

    man = _read_run_manifest(evidence_root, run_id)
    pkg = _run_package(man)
    rp = resolve_run_profile_from_manifest(man, strict_conflict=True).normalized
    rp = normalize_run_profile(rp)
    phase = phase_from_normalized_profile(rp)
    if rp == "interaction_manual" and not allow_manual_interaction:
        return False, {
            "run_id": run_id,
            "package": pkg,
            "run_profile": rp,
            "phase": phase,
            "excluded_reason": "manual_interaction_excluded",
        }
    ident = _run_identity(man)
    meta = {
        "run_id": run_id,
        "package": pkg,
        "run_profile": rp,
        "phase": phase,
        "version_code": str(ident.get("version_code") or ident.get("observed_version_code") or "").strip(),
        "version_name": str(ident.get("version_name") or "").strip(),
        "base_apk_sha256": str(ident.get("base_apk_sha256") or "").strip(),
        "device_serial": str((man.get("environment") or {}).get("device_serial") or "").strip(),
        "build_fingerprint": str((man.get("environment") or {}).get("build_fingerprint") or "").strip(),
    }
    return True, meta


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
        import csv

        with window_scores_csv.open("r", encoding="utf-8", newline="") as f:
            r = csv.DictReader(f)
            n = 0
            for _ in r:
                n += 1
        return int(n)
    except Exception:
        return None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build profile v3 structural manifest (standalone)")
    p.add_argument(
        "--base-freeze",
        default=str(REPO_ROOT / "data" / "archive" / "dataset_freeze.json"),
        help="Path to base freeze (used only for provenance refs + optional imported runs).",
    )
    p.add_argument(
        "--import-from-base",
        action="store_true",
        help="If set, import baseline + interactive runs from the base freeze apps map (deterministic).",
    )
    p.add_argument(
        "--add-run-id",
        action="append",
        default=[],
        help="Additional run IDs to include. Repeat flag, or use @file.txt (one per line).",
    )
    p.add_argument(
        "--evidence-root",
        default=str(REPO_ROOT / "output" / "evidence" / "dynamic"),
        help="Dynamic evidence root containing run directories.",
    )
    p.add_argument(
        "--allow-manual-interaction",
        action="store_true",
        help="Allow interaction_manual runs in the composed v3 manifest (default: excluded).",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Paper/demo strict mode: fail-closed unless all catalog apps meet minima and required artifacts exist.",
    )
    p.add_argument(
        "--allow-mixed-versions",
        action="store_true",
        help="Allow a package to appear with multiple version_code values across included runs (default: fail-closed).",
    )
    p.add_argument(
        "--catalog",
        default=str(REPO_ROOT / "profiles" / "profile_v3_app_catalog.json"),
        help="Optional: v3 app catalog path for coverage diagnostics (unknown package reporting only).",
    )
    p.add_argument(
        "--out",
        default=str(REPO_ROOT / "data" / "archive" / "profile_v3_manifest.json"),
        help="Output manifest path.",
    )
    args = p.parse_args(argv)

    mode = PaperModeContext.detect(repo_root=REPO_ROOT, strict_arg=bool(args.strict))
    mode.apply_env()
    mode.assert_clean_if_required()
    strict = bool(mode.strict)
    if strict and bool(args.allow_manual_interaction):
        raise SystemExit("PROFILE_V3_STRICT_MANUAL_NOT_ALLOWED: strict mode forbids manual interaction runs")

    base_path = Path(args.base_freeze)
    base = _rjson(base_path)
    base_sha = _sha256_file(base_path)
    base_hash = str(base.get("freeze_dataset_hash") or "").strip()
    base_included = base.get("included_run_ids") if isinstance(base.get("included_run_ids"), list) else []
    base_included = [str(r).strip() for r in base_included if str(r).strip()]

    evidence_root = Path(args.evidence_root)

    included: list[str] = []
    if args.import_from_base:
        apps = base.get("apps") if isinstance(base.get("apps"), dict) else {}
        for pkg in sorted(apps.keys()):
            meta = apps[pkg] if isinstance(apps.get(pkg), dict) else {}
            baselines = meta.get("baseline_run_ids") if isinstance(meta.get("baseline_run_ids"), list) else []
            inters = meta.get("interactive_run_ids") if isinstance(meta.get("interactive_run_ids"), list) else []
            for rid in baselines + inters:
                included.append(str(rid).strip())
    included.extend(_load_run_ids_arg(list(args.add_run_id)))

    # De-dup while preserving order.
    seen = set()
    deduped = []
    for r in included:
        if r in seen:
            continue
        seen.add(r)
        deduped.append(r)
    included = deduped

    # Filter / annotate runs.
    include_meta: dict[str, dict] = {}
    excluded: list[dict] = []
    for rid in included:
        ok, meta = _include_run_id(
            evidence_root=evidence_root,
            run_id=rid,
            allow_manual_interaction=bool(args.allow_manual_interaction),
        )
        if ok:
            include_meta[rid] = meta
        else:
            excluded.append(meta)

    included = [rid for rid in included if rid in include_meta]

    # Coverage/exclusion diagnostics (visibility only; does not change eligibility).
    catalog_pkgs: set[str] | None = None
    try:
        cat_path = Path(args.catalog)
        if cat_path.exists():
            payload = _rjson(cat_path)
            catalog_pkgs = {str(k).strip() for k in payload.keys() if str(k).strip()}
    except Exception:
        catalog_pkgs = None

    # Strict cohort lock: fail early if catalog is not frozen to the expected paper-grade size.
    EXPECTED_COHORT_N = 21
    if strict:
        if catalog_pkgs is None:
            raise SystemExit("PROFILE_V3_STRICT_MISSING_CATALOG: catalog not found/invalid")
        if len(catalog_pkgs) != int(EXPECTED_COHORT_N):
            raise SystemExit(f"PROFILE_V3_STRICT_CATALOG_SIZE_MISMATCH: catalog={len(catalog_pkgs)} expected={EXPECTED_COHORT_N}")

    diag_counts: dict[str, int] = {}
    diag_examples: dict[str, list[str]] = {}
    # Profile v3 uses phase-specific PCAP minima (centralized for dashboard/post-run/strict consistency).
    min_bytes_idle = int(effective_min_pcap_bytes_idle())
    min_bytes_scripted = int(effective_min_pcap_bytes_scripted())

    def _min_pcap_for_run(*, run_profile: str, phase: str) -> int:
        # Prefer phase when available (derived from normalized run_profile).
        if str(phase or "").strip().lower() == "idle":
            return int(min_bytes_idle)
        # Scripted runs are the paper-grade interactive requirement; apply scripted threshold for
        # any interactive run (including legacy imports) so strict remains conservative.
        if str(run_profile or "").strip().lower() == "interaction_scripted":
            return int(min_bytes_scripted)
        if str(phase or "").strip().lower() == "interactive":
            return int(min_bytes_scripted)
        return int(min_bytes_scripted)

    def _bump(code: str, example: str | None = None) -> None:
        diag_counts[code] = int(diag_counts.get(code, 0)) + 1
        if example:
            diag_examples.setdefault(code, [])
            if len(diag_examples[code]) < 3:
                diag_examples[code].append(example)

    strict_failures: list[str] = []

    # Excluded reasons already computed by _include_run_id (currently only manual interaction).
    for ex in excluded:
        _bump(str(ex.get("excluded_reason") or "excluded_unknown"))

    for rid in included:
        meta = include_meta.get(rid) or {}
        pkg = str(meta.get("package") or "")
        rp = str(meta.get("run_profile") or "")
        phase = str(meta.get("phase") or "")
        if catalog_pkgs is not None and pkg and pkg not in catalog_pkgs:
            _bump("unknown_package_not_in_catalog", f"{pkg} (run_id={rid[:8]})")
            if strict:
                strict_failures.append(f"unknown_package_not_in_catalog\t{pkg}\trun_id={rid}")

        scores_path = _window_scores_path(evidence_root, rid)
        thr_path = _threshold_path(evidence_root, rid)
        if not scores_path.exists():
            _bump("missing_window_scores_csv", f"{pkg} {phase} (run_id={rid[:8]})")
            if strict:
                strict_failures.append(f"missing_window_scores_csv\t{pkg}\t{phase}\trun_id={rid}")
        if not thr_path.exists():
            _bump("missing_baseline_threshold_json", f"{pkg} {phase} (run_id={rid[:8]})")
            if strict:
                strict_failures.append(f"missing_baseline_threshold_json\t{pkg}\t{phase}\trun_id={rid}")

        wc = _count_windows(scores_path)
        if wc is None:
            _bump("window_count_unavailable", f"{pkg} {phase} (run_id={rid[:8]})")
            if strict:
                strict_failures.append(f"window_count_unavailable\t{pkg}\t{phase}\trun_id={rid}")
        elif int(wc) < int(MIN_WINDOWS_PER_RUN):
            _bump("insufficient_windows", f"{pkg} {phase} windows={wc} (min {int(MIN_WINDOWS_PER_RUN)})")
            if strict:
                strict_failures.append(f"insufficient_windows\t{pkg}\t{phase}\twindows={wc}\tmin={int(MIN_WINDOWS_PER_RUN)}\trun_id={rid}")

        # PCAP size is best-effort from run_manifest artifacts.
        man = _read_run_manifest(evidence_root, rid)
        pcap_size = _pcap_size_bytes(man)
        if pcap_size is None:
            _bump("pcap_size_unavailable", f"{pkg} {phase} (run_id={rid[:8]})")
            if strict:
                strict_failures.append(f"pcap_size_unavailable\t{pkg}\t{phase}\trun_id={rid}")
        else:
            min_bytes_req = _min_pcap_for_run(run_profile=rp, phase=phase)
            if int(pcap_size) < int(min_bytes_req):
                _bump("insufficient_pcap_bytes", f"{pkg} {phase} pcap={pcap_size}B (min {min_bytes_req}B)")
                if strict:
                    strict_failures.append(
                        f"insufficient_pcap_bytes\t{pkg}\t{phase}\tpcap={pcap_size}\tmin={min_bytes_req}\trun_id={rid}"
                    )

        # Strict identity: version_code must be present so mixed-version detection is meaningful.
        vc = str(meta.get("version_code") or "").strip()
        if not vc:
            _bump("missing_version_code", f"{pkg} {phase} (run_id={rid[:8]})")
            if strict:
                strict_failures.append(f"missing_version_code\t{pkg}\t{phase}\trun_id={rid}")

    # Version consistency (paper-grade default).
    by_pkg: dict[str, set[str]] = {}
    for _rid, meta in include_meta.items():
        pkg = str(meta.get("package") or "")
        vc = str(meta.get("version_code") or "")
        if not vc:
            continue
        by_pkg.setdefault(pkg, set()).add(vc)
    if not bool(args.allow_mixed_versions):
        mixed = {pkg: sorted(list(vs)) for pkg, vs in by_pkg.items() if len(vs) > 1}
        if mixed:
            raise SystemExit(f"PROFILE_V3_MIXED_PACKAGE_VERSIONS: {mixed}")

    # Strict: require full catalog coverage with idle>=1 and scripted_interaction>=1 per package.
    if strict and catalog_pkgs is not None:
        per_pkg: dict[str, dict[str, int]] = {pkg: {"idle": 0, "scripted": 0, "manual": 0} for pkg in catalog_pkgs}
        for _rid, meta in include_meta.items():
            pkg = str(meta.get("package") or "").strip()
            if pkg not in per_pkg:
                continue
            phase = str(meta.get("phase") or "").strip()
            rp = str(meta.get("run_profile") or "").strip()
            if phase == "idle":
                per_pkg[pkg]["idle"] += 1
            if rp == "interaction_scripted":
                per_pkg[pkg]["scripted"] += 1
            if rp == "interaction_manual":
                per_pkg[pkg]["manual"] += 1

        missing_pkgs: list[str] = []
        for pkg in sorted(per_pkg.keys()):
            idle = int(per_pkg[pkg]["idle"])
            scripted = int(per_pkg[pkg]["scripted"])
            if idle < 1 or scripted < 1:
                missing_pkgs.append(pkg)
                strict_failures.append(
                    f"missing_required_phase\t{pkg}\tidle={idle}\tscripted={scripted}"
                )
        if missing_pkgs:
            _bump("strict_missing_phase_coverage", str(len(missing_pkgs)))

    if strict and strict_failures:
        print("[FAIL] Profile v3 manifest build (strict): FAIL")
        print(f"- catalog_packages: {len(catalog_pkgs) if catalog_pkgs is not None else 'unknown'} (expected {EXPECTED_COHORT_N})")
        print(f"- included_run_ids: {len(included)}")
        print()
        print("Strict failures (first 50):")
        for line in strict_failures[:50]:
            print("  " + line)
        if len(strict_failures) > 50:
            print(f"  ... ({len(strict_failures) - 50} more)")
        raise SystemExit("PROFILE_V3_STRICT_NOT_READY")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "profile_id": "profile_v3_structural",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "included_run_ids": included,
        "included_run_checksums": {},
        "included_run_metadata": include_meta,
        "excluded_run_metadata": excluded,
        "package_versions": {pkg: sorted(list(vs)) for pkg, vs in by_pkg.items()},
        "inputs": {
            "base_freeze_refs": [
                {
                    "profile_id": "profile_v2",
                    "freeze_path": str(base_path),
                    "freeze_sha256": base_sha,
                    "freeze_dataset_hash": base_hash or None,
                    "runs_imported": int(len(base_included)) if args.import_from_base else 0,
                }
            ],
            "paper_mode": mode.receipt_fields(),
        },
        "notes": {
            "capture_policy": "personal_account_only_no_mdm",
            "aggregation": "run_balanced_means_pooled_idle_sd_ddof_1",
            "exceedance_operator": ">",
            "primary_engine": "iforest",
            "allow_manual_interaction": bool(args.allow_manual_interaction),
            "allow_mixed_versions": bool(args.allow_mixed_versions),
            "strict": bool(strict),
            "min_windows_per_run": int(MIN_WINDOWS_PER_RUN),
            "min_pcap_bytes_idle": int(min_bytes_idle),
            "min_pcap_bytes_scripted": int(min_bytes_scripted),
        },
    }
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(f"[OK] Wrote: {out_path}")
    print(f"[OK] included_run_ids: {len(included)}")
    if excluded:
        print(f"[WARN] excluded_run_ids: {len(excluded)} (see excluded_run_metadata in manifest)")
    if diag_counts:
        print()
        print("Profile v3 manifest build · exclusion/coverage summary (visibility only)")
        for code in sorted(diag_counts.keys()):
            n = int(diag_counts.get(code) or 0)
            if n <= 0:
                continue
            examples = diag_examples.get(code) or []
            ex = (" e.g., " + "; ".join(examples)) if examples else ""
            print(f"- {code}: {n}{ex}")

    # Per-catalog-package inclusion coverage (visibility only).
    try:
        cat_path = Path(args.catalog)
        if cat_path.exists():
            payload_cat = _rjson(cat_path)
            cat_pkgs = [str(k).strip() for k in payload_cat.keys() if str(k).strip()]
            by_pkg_phase: dict[str, dict[str, int]] = {pkg: {"idle": 0, "interactive": 0, "manual": 0} for pkg in cat_pkgs}
            for _rid, meta in include_meta.items():
                pkg = str(meta.get("package") or "").strip()
                if pkg not in by_pkg_phase:
                    continue
                phase = str(meta.get("phase") or "").strip()
                rp = str(meta.get("run_profile") or "").strip()
                if phase == "idle":
                    by_pkg_phase[pkg]["idle"] += 1
                elif phase == "interactive":
                    by_pkg_phase[pkg]["interactive"] += 1
                if rp == "interaction_manual":
                    by_pkg_phase[pkg]["manual"] += 1
            print()
            print("Per-package included coverage (catalog order):")
            for pkg in cat_pkgs:
                idle = by_pkg_phase[pkg]["idle"]
                inter = by_pkg_phase[pkg]["interactive"]
                manual = by_pkg_phase[pkg]["manual"]
                missing_bits = []
                if idle < 1:
                    missing_bits.append("idle")
                if inter < 1:
                    missing_bits.append("interactive")
                miss = f" missing={','.join(missing_bits)}" if missing_bits else ""
                man = " manual_included=1" if manual else ""
                print(f"- {pkg}: idle={idle} interactive={inter}{miss}{man}")
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
