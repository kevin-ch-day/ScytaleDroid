#!/usr/bin/env python3
"""Compare Paper #2 export artifacts against a frozen baseline manifest."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Config import app_config
from scytaledroid.Utils.System.export_manifest import (
    build_manifest_from_artifacts,
    compare_manifest,
    dump_manifest,
    load_manifest,
)
from scytaledroid.Utils.version_utils import get_git_commit


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%d%H%M%SZ")


def _default_diff_path() -> Path:
    return Path("output") / "audit" / "comparators" / "paper2_export" / _stamp() / "diff.json"


def _run_compare(*, manifest_path: Path, artifact_root: Path, output_path: Path) -> int:
    baseline = load_manifest(manifest_path)
    result = compare_manifest(baseline_manifest=baseline, artifact_root=artifact_root, compare_type="paper2_export")

    payload = {
        "tool_semver": app_config.APP_VERSION,
        "git_commit": get_git_commit(),
        "manifest_path": str(manifest_path),
        "artifact_root": str(artifact_root),
        "checked_at_utc": datetime.now(UTC).isoformat(),
        **result.payload,
    }
    dump_manifest(output_path, payload)
    print(
        json.dumps(
            {
                "status": "PASS" if result.passed else "FAIL",
                "output": str(output_path),
                "disallowed_diffs": int(payload["result"]["diff_counts"]["disallowed"]),
                "validation_issues": payload["result"]["validation_issues"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if result.passed else 1


def _run_refresh(*, manifest_path: Path, artifact_root: Path, output_manifest: Path) -> int:
    baseline = load_manifest(manifest_path)
    artifacts = baseline.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise SystemExit("Manifest has no artifact list to refresh.")

    refreshed = build_manifest_from_artifacts(
        artifact_root=artifact_root,
        artifact_specs=[entry for entry in artifacts if isinstance(entry, dict)],
        generated_utc=datetime.now(UTC).isoformat(),
        description=str(
            baseline.get("description")
            or "Frozen Paper #2 export artifact manifest. Update only with approved drift rationale."
        ),
    )
    dump_manifest(output_manifest, refreshed)
    print(json.dumps({"status": "OK", "updated_manifest": str(output_manifest)}, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        default="tests/baseline/paper2_export_manifest.json",
        help="Baseline manifest path.",
    )
    parser.add_argument(
        "--artifact-root",
        default="output/paper",
        help="Root directory containing frozen export artifacts.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Diff artifact output path. Default: output/audit/comparators/paper2_export/<stamp>/diff.json",
    )
    parser.add_argument(
        "--refresh-manifest",
        default=None,
        help="Write a refreshed manifest (same artifact list, recomputed hashes/sizes) to this path.",
    )
    args = parser.parse_args(argv)

    manifest_path = Path(args.manifest).expanduser().resolve()
    artifact_root = Path(args.artifact_root).expanduser().resolve()
    if not manifest_path.exists():
        raise SystemExit(f"Manifest not found: {manifest_path}")
    if not artifact_root.exists():
        raise SystemExit(f"Artifact root not found: {artifact_root}")

    if args.refresh_manifest:
        return _run_refresh(
            manifest_path=manifest_path,
            artifact_root=artifact_root,
            output_manifest=Path(args.refresh_manifest).expanduser().resolve(),
        )
    output_path = Path(args.output).expanduser().resolve() if args.output else _default_diff_path().resolve()
    return _run_compare(manifest_path=manifest_path, artifact_root=artifact_root, output_path=output_path)


if __name__ == "__main__":
    raise SystemExit(main())
