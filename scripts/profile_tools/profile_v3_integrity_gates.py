#!/usr/bin/env python3
"""Profile v3 integrity gates runner (one-screen summary).

Runs the paper-grade gates in a deterministic order and prints a compact PASS/FAIL
table with next steps. This is intended to be called from the TUI (Reporting ->
Profile v3 -> Run v3 integrity gates).

Gates:
1) catalog freeze check (must be exactly 21 with valid categories)
2) catalog validate (included runs' packages are present in catalog; also catches empty manifest)
3) APK freshness (device inventory version_code matches harvested base APK version_code)
4) scripted coverage (manifest includes >=1 idle and >=1 scripted interaction per catalog package)
5) static readiness (each catalog package has a COMPLETED static run with a static_run_id)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Publication.paper_mode import PaperModeContext  # noqa: E402


@dataclass(frozen=True)
class GateResult:
    name: str
    script: Path
    ok: bool
    exit_code: int
    skipped: bool = False


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


def _load_included_run_ids_count(manifest_path: Path) -> int | None:
    if not manifest_path.exists():
        return None
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        ids = payload.get("included_run_ids") if isinstance(payload, dict) else None
        if isinstance(ids, list):
            return len([str(x).strip() for x in ids if str(x).strip()])
    except Exception:
        return None
    return None


def _run_script(path: Path) -> GateResult:
    name = path.name
    # Use a subprocess to avoid argv bleed-through between gate runner and sub-scripts.
    # Operators may run this with flags; sub-scripts should only see their own argv.
    res = subprocess.run([sys.executable, str(path)], check=False)
    return GateResult(name=name, script=path, ok=(res.returncode == 0), exit_code=int(res.returncode))


def _run_script_with_args(path: Path, extra_argv: list[str]) -> GateResult:
    name = path.name
    res = subprocess.run([sys.executable, str(path), *list(extra_argv)], check=False)
    return GateResult(name=name, script=path, ok=(res.returncode == 0), exit_code=int(res.returncode))

def _skip_script(path: Path) -> GateResult:
    return GateResult(name=path.name, script=path, ok=True, exit_code=0, skipped=True)


def main(argv: list[str] | None = None) -> int:
    # If output is piped (e.g., to `head`), avoid noisy BrokenPipeError messages.
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except Exception:
        pass

    p = argparse.ArgumentParser(description="Run Profile v3 integrity gates (one-screen)")
    p.add_argument(
        "--scripts-root",
        default=str(REPO_ROOT / "scripts" / "profile_tools"),
        help="Root dir containing profile v3 gate scripts.",
    )
    p.add_argument(
        "--catalog",
        default=str(REPO_ROOT / "profiles" / "profile_v3_app_catalog.json"),
        help="Catalog path (used for provenance only).",
    )
    p.add_argument(
        "--manifest",
        default=str(REPO_ROOT / "data" / "archive" / "profile_v3_manifest.json"),
        help="Manifest path (used for provenance only).",
    )
    p.add_argument(
        "--freshness-snapshot",
        default="",
        help="Optional explicit inventory snapshot path to pass to the APK freshness gate (pins device state).",
    )
    p.add_argument(
        "--phase",
        default="full",
        choices=["1", "full"],
        help="Which gate set to run. Phase 1 is static+freshness preflight (skips manifest-based gates).",
    )
    p.add_argument(
        "--write-audit",
        action="store_true",
        help="Write a gate receipt JSON under output/audit/profile_v3/.",
    )
    p.add_argument(
        "--audit-dir",
        default=str(REPO_ROOT / "output" / "audit" / "profile_v3"),
        help="Audit output directory used with --write-audit.",
    )
    args = p.parse_args(argv)

    scripts_root = Path(args.scripts_root)
    catalog_path = Path(args.catalog)
    manifest_path = Path(args.manifest)
    freshness_snapshot = str(args.freshness_snapshot or "").strip()
    freshness_snapshot_sha = ""
    if freshness_snapshot:
        p = Path(freshness_snapshot)
        if p.exists():
            freshness_snapshot_sha = _sha256_file(p)
    scripts = [
        scripts_root / "profile_v3_catalog_freeze_check.py",
        scripts_root / "profile_v3_catalog_validate.py",
        scripts_root / "profile_v3_apk_freshness_check.py",
        scripts_root / "profile_v3_scripted_coverage_audit.py",
        scripts_root / "profile_v3_static_ready_check.py",
    ]
    missing = [s for s in scripts if not s.exists()]
    if missing:
        print("[FAIL] Missing gate scripts:")
        for s in missing:
            print(f"  - {s}")
        return 2

    # Copy/paste provenance line for PM updates (no heavy IO, no gate logic).
    mode = PaperModeContext.detect(repo_root=REPO_ROOT, pinned_snapshot=freshness_snapshot or None)
    mode.apply_env()
    git_commit = mode.commit
    strict_env = "1" if mode.strict else (str(os.environ.get("SCYTALEDROID_PAPER_STRICT") or "").strip() or "0")
    cat_sha = _sha256_file(catalog_path) if catalog_path.exists() else ""
    man_sha = _sha256_file(manifest_path) if manifest_path.exists() else ""
    included_n = _load_included_run_ids_count(manifest_path)
    minima_sha = dict(mode.receipt_fields().get("minima_source_sha256") or {})

    print(
        "[COPY] v3_gates start "
        f"git_commit={git_commit} strict_env={strict_env} "
        f"catalog_sha256={cat_sha} manifest_sha256={man_sha} included_run_ids={included_n if included_n is not None else 'na'} "
        f"minima_sha256={minima_sha}"
        + (f" freshness_snapshot='{freshness_snapshot}' freshness_snapshot_sha256={freshness_snapshot_sha}" if freshness_snapshot else ""),
        flush=True,
    )

    results: list[GateResult] = []
    for s in scripts:
        if args.phase == "1" and s.name in {
            "profile_v3_catalog_validate.py",
            "profile_v3_scripted_coverage_audit.py",
        }:
            results.append(_skip_script(s))
            continue
        if s.name == "profile_v3_apk_freshness_check.py" and str(args.freshness_snapshot or "").strip():
            results.append(_run_script_with_args(s, ["--snapshot", str(args.freshness_snapshot).strip()]))
        else:
            results.append(_run_script(s))

    # One-screen summary (deterministic order).
    print()
    print("Profile v3 Integrity Gates · SUMMARY")
    print("-----------------------------------")
    for r in results:
        if r.skipped:
            print(f"SKIP  {r.name}  (exit=0)")
        else:
            status = "PASS" if r.ok else "FAIL"
            print(f"{status:4}  {r.name}  (exit={r.exit_code})")

    ok = all(r.ok for r in results if not r.skipped)
    print()
    if ok:
        print("[PASS] Profile v3 gates: PASS")
        print(f"[COPY] v3_gates end ok=PASS gates_total={len(results)} gates_failed=0")
        if args.write_audit:
            audit_dir = Path(args.audit_dir)
            audit_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            out = audit_dir / f"integrity_gates_{ts}.json"
            receipt = {
                "generated_at_utc": datetime.now(UTC).isoformat(),
                "profile_id": "profile_v3_structural",
                **mode.receipt_fields(),
                "strict_env": strict_env,
                "inputs": {
                    "catalog_path": str(catalog_path),
                    "catalog_sha256": cat_sha,
                    "manifest_path": str(manifest_path),
                    "manifest_sha256": man_sha,
                    "included_run_ids_count": included_n,
                    "minima_source_sha256": minima_sha,
                    "freshness_snapshot_override": freshness_snapshot or None,
                    "freshness_snapshot_override_sha256": freshness_snapshot_sha or None,
                },
                "gates": [
                    {
                        "name": r.name,
                        "script": str(r.script),
                        "ok": bool(r.ok),
                        "exit_code": int(r.exit_code),
                        "skipped": bool(r.skipped),
                    }
                    for r in results
                ],
                "ok": True,
            }
            out.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
            print(f"[COPY] v3_gates_receipt path='{out.relative_to(REPO_ROOT)}'")
        return 0

    print("[FAIL] Profile v3 gates: FAIL")
    failed = [r for r in results if (not r.ok and not r.skipped)]
    print(f"[COPY] v3_gates end ok=FAIL gates_total={len(results)} gates_failed={len(failed)}")
    print("Next steps (based on failing gates):")
    # Keep this deterministic and operator-actionable (no deep inference).
    names = {r.name for r in failed}
    if "profile_v3_catalog_freeze_check.py" in names:
        print("- Fix v3 catalog freeze: profiles/profile_v3_app_catalog.json must be exactly 21 apps with valid categories.")
        print("- Install missing cohort apps on device, confirm package IDs, then re-run the gate.")
    if "profile_v3_apk_freshness_check.py" in names:
        print("- Sync device inventory (full or scoped v3) and re-pull APKs using the Profile v3 Structural scope (full refresh).")
        print("- Ensure Play auto-updates are paused during the harvest/capture window to prevent version drift.")
    if "profile_v3_catalog_validate.py" in names:
        print("- Build/populate data/archive/profile_v3_manifest.json (included_run_ids) from paper-grade runs.")
        print("- Re-run catalog validate to ensure included packages are catalog-defined only.")
    if "profile_v3_scripted_coverage_audit.py" in names:
        print("- Capture missing baseline_idle and/or interaction_scripted runs for the v3 cohort, then rebuild the v3 manifest.")
    if "profile_v3_static_ready_check.py" in names:
        print("- Run the Profile v3 static batch to completion (21 apps) and confirm static readiness PASS.")
    if not names:
        print("- Re-run with verbose logs; no failing gate names were detected (unexpected).")
    if args.write_audit:
        audit_dir = Path(args.audit_dir)
        audit_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        out = audit_dir / f"integrity_gates_{ts}.json"
        receipt = {
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "profile_id": "profile_v3_structural",
            "git_commit": git_commit,
            "strict_env": strict_env,
            "inputs": {
                "catalog_path": str(catalog_path),
                "catalog_sha256": cat_sha,
                "manifest_path": str(manifest_path),
                "manifest_sha256": man_sha,
                "included_run_ids_count": included_n,
                "minima_source_sha256": minima_sha,
                "freshness_snapshot_override": freshness_snapshot or None,
                "freshness_snapshot_override_sha256": freshness_snapshot_sha or None,
            },
            "gates": [
                {"name": r.name, "script": str(r.script), "ok": bool(r.ok), "exit_code": int(r.exit_code)} for r in results
            ],
            "ok": False,
        }
        out.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
        print(f"[COPY] v3_gates_receipt path='{out.relative_to(REPO_ROOT)}'")
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        # Clean exit when output is piped (e.g., `| head`) and the consumer closes early.
        try:
            sys.stdout.close()
        except Exception:
            pass
        raise SystemExit(0)
