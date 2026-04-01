"""Headless static analysis runner for a full repository scan.

This is intended for stress/regression verification (no interactive prompts)
and CI-style executions. It uses the same repository discovery and grouping
logic as the interactive menu, but requires explicit parameters.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running as `python scripts/...` without installing the package.
_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.services import artifact_store
from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.cli.flows.selection import _select_latest_groups
from scytaledroid.StaticAnalysis.core.repository import group_artifacts
from scytaledroid.StaticAnalysis.services import static_service
from scytaledroid.StaticAnalysis.session import normalize_session_stamp
from scytaledroid.Utils.System import output_prefs


def _select_latest_per_package(groups):
    by_pkg: dict[str, list] = {}
    order: list[str] = []
    for g in groups:
        pkg = g.package_name
        if pkg not in by_pkg:
            by_pkg[pkg] = []
            order.append(pkg)
        by_pkg[pkg].append(g)

    selected = []
    for pkg in order:
        selected.extend(_select_latest_groups(tuple(by_pkg[pkg])))
    return tuple(selected)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Headless static analysis (all apps)")
    parser.add_argument(
        "--base-dir",
        default=str(artifact_store.harvest_receipts_root()),
        help="Receipt root containing canonical harvest package receipts (default: data/receipts/harvest)",
    )
    parser.add_argument("--session", required=True, help="Session label/stamp for this run")
    parser.add_argument("--profile", default="full", choices=["full", "lightweight", "permissions", "metadata", "split"])
    parser.add_argument("--workers", default="auto", help="Worker count (default: auto)")
    parser.add_argument("--reuse-cache", action="store_true", help="Reuse cache (default: purge)")
    args = parser.parse_args(argv)

    output_prefs.set_noninteractive(True)
    output_prefs.set_run_mode("batch")
    output_prefs.set_quiet(True)

    discovery_root = Path(args.base_dir).expanduser().resolve()
    analysis_root = artifact_store.analysis_apk_root()
    groups = group_artifacts(discovery_root)
    if not groups:
        raise SystemExit(f"No APK artifacts discovered under: {discovery_root}")

    scoped = _select_latest_per_package(groups)
    selection = ScopeSelection(scope="all", label="All apps", groups=scoped)

    session_stamp = normalize_session_stamp(args.session)
    params = RunParameters(
        profile=args.profile,
        scope="all",
        scope_label=selection.label,
        session_stamp=session_stamp,
        workers=args.workers,
        reuse_cache=bool(args.reuse_cache),
        # In headless/stress mode we only care about persistence; keep output compact.
        verbose_output=False,
    )

    static_service.run_scan(selection, params, analysis_root)
    print(f"Static analysis completed: session={session_stamp} apps={len(scoped)}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
