#!/usr/bin/env python3
"""Derive/repair Profile v3 ML artifacts for already-captured runs.

Use case:
- A run has a valid PCAP + run_manifest.json but is missing:
  analysis/ml/v1/window_scores.csv and/or analysis/ml/v1/baseline_threshold.json
- We want to upgrade evidence packs without re-capturing.

This is filesystem-driven and does not require the DB.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.DynamicAnalysis.ml.profile_v3_ml_derive import derive_profile_v3_ml_for_package  # noqa: E402
from scytaledroid.DynamicAnalysis.utils.profile_v3_minima import (  # noqa: E402
    effective_min_pcap_bytes_idle,
    effective_min_pcap_bytes_scripted,
    effective_min_windows_per_run,
)
from scytaledroid.Utils.DisplayUtils import status_messages  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Derive Profile v3 ML artifacts for a package (latest baseline+scripted runs).")
    p.add_argument("--package", required=True, help="Android package name (e.g., com.adobe.reader).")
    p.add_argument(
        "--evidence-root",
        default=str(REPO_ROOT / "output" / "evidence" / "dynamic"),
        help="Dynamic evidence root containing run dirs.",
    )
    args = p.parse_args(argv)

    res = derive_profile_v3_ml_for_package(package=str(args.package).strip(), evidence_root=Path(args.evidence_root))
    ok = not bool(res.errors)
    print(
        "[COPY] v3_ml_derive "
        f"status={'PASS' if ok else 'FAIL'} package={res.package} "
        f"baseline_run_id={res.baseline_run_id or 'na'} scripted_run_id={res.scripted_run_id or 'na'} "
        f"trained={int(res.trained)} wrote_baseline={int(res.wrote_baseline)} wrote_scripted={int(res.wrote_scripted)} "
        f"min_windows={effective_min_windows_per_run()} min_pcap_bytes_idle={effective_min_pcap_bytes_idle()} "
        f"min_pcap_bytes_scripted={effective_min_pcap_bytes_scripted()} "
        f"errors={';'.join(res.errors) if res.errors else ''}"
    )
    if not ok:
        print(status_messages.status("Derivation failed; see errors=... (short) and run logs for details.", level="error"))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

