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
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class GateResult:
    name: str
    script: Path
    ok: bool
    exit_code: int


def _run_script(path: Path) -> GateResult:
    name = path.name
    # Use a subprocess to avoid argv bleed-through between gate runner and sub-scripts.
    # Operators may run this with flags; sub-scripts should only see their own argv.
    res = subprocess.run([sys.executable, str(path)], check=False)
    return GateResult(name=name, script=path, ok=(res.returncode == 0), exit_code=int(res.returncode))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run Profile v3 integrity gates (one-screen)")
    p.add_argument(
        "--scripts-root",
        default=str(REPO_ROOT / "scripts" / "profile_tools"),
        help="Root dir containing profile v3 gate scripts.",
    )
    args = p.parse_args(argv)

    scripts_root = Path(args.scripts_root)
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

    results: list[GateResult] = []
    for s in scripts:
        results.append(_run_script(s))

    # One-screen summary (deterministic order).
    print()
    print("Profile v3 Integrity Gates · SUMMARY")
    print("-----------------------------------")
    for r in results:
        status = "PASS" if r.ok else "FAIL"
        print(f"{status:4}  {r.name}  (exit={r.exit_code})")

    ok = all(r.ok for r in results)
    print()
    if ok:
        print("[PASS] Profile v3 gates: PASS")
        return 0

    print("[FAIL] Profile v3 gates: FAIL")
    print("Next steps:")
    print("- Fix catalog freeze (must be exactly 21 apps) before harvest/capture.")
    print("- Sync device inventory before pulling APKs.")
    print("- Pull APKs using the Profile v3 Structural scope (full refresh).")
    print("- Capture scripted dynamic runs and rebuild the v3 manifest.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
