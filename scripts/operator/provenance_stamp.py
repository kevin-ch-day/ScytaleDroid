#!/usr/bin/env python3
"""
Paper/demo provenance stamp (copy/paste friendly).

This is intentionally lightweight and filesystem-driven:
- prints repo root + git commit (if available)
- prints SHA-256 for key cohort definition artifacts (if present)

Use this at the start of paper-grade runs to eliminate "wrong checkout / stale ZIP"
confusion in PM updates and reviewer provenance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Publication.paper_mode import PaperModeContext, sha256_file  # noqa: E402


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


def _git_dirty(repo_root: Path) -> str:
    try:
        out = subprocess.check_output(
            ["git", "status", "--porcelain=v1"],
            cwd=str(repo_root),
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return "true" if out.strip() else "false"
    except Exception:
        return "unknown"


def _json_count_included_run_ids(manifest_path: Path) -> int | None:
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    ids = data.get("included_run_ids")
    if isinstance(ids, list):
        return len(ids)
    return None


def main() -> int:
    repo_root = REPO_ROOT

    ap = argparse.ArgumentParser(description="Print provenance stamp for paper/demo runs.")
    ap.add_argument(
        "--freeze",
        default=str(repo_root / "data" / "archive" / "dataset_freeze.json"),
        help="Path to v2 freeze anchor (optional; printed if present).",
    )
    ap.add_argument(
        "--catalog",
        default=str(repo_root / "profiles" / "profile_v3_app_catalog.json"),
        help="Path to v3 catalog (optional; printed if present).",
    )
    ap.add_argument(
        "--manifest",
        default=str(repo_root / "data" / "archive" / "profile_v3_manifest.json"),
        help="Path to v3 manifest (optional; printed if present).",
    )
    ap.add_argument(
        "--minima-sources",
        nargs="*",
        default=[
            str(repo_root / "scytaledroid" / "DynamicAnalysis" / "ml" / "ml_parameters_profile.py"),
            str(repo_root / "scytaledroid" / "DynamicAnalysis" / "pcap" / "dataset_tracker.py"),
        ],
        help="Python source files that define paper-grade minima (printed if present).",
    )
    ap.add_argument(
        "--tool-sources",
        nargs="*",
        default=[
            str(repo_root / "scripts" / "profile_tools" / "profile_v3_manifest_build.py"),
            str(repo_root / "scripts" / "publication" / "profile_v3_exports.py"),
            str(repo_root / "scripts" / "publication" / "export_profile.py"),
        ],
        help="Key tool scripts to hash for provenance (printed if present).",
    )
    ap.add_argument(
        "--write-audit",
        action="store_true",
        help="Also write a JSON provenance receipt under output/audit/provenance/ (no scientific data changes).",
    )
    ap.add_argument(
        "--audit-dir",
        default=str(repo_root / "output" / "audit" / "provenance"),
        help="Audit output directory used with --write-audit.",
    )
    ap.add_argument(
        "--fail-on-dirty",
        action="store_true",
        help="Fail if git worktree is dirty (can also be enabled via SCYTALEDROID_FAIL_ON_DIRTY=1).",
    )
    args = ap.parse_args()

    freeze_path = Path(args.freeze)
    catalog_path = Path(args.catalog)
    manifest_path = Path(args.manifest)
    minima_sources = [Path(p) for p in (args.minima_sources or [])]
    tool_sources = [Path(p) for p in (args.tool_sources or [])]

    mode = PaperModeContext.detect(repo_root=repo_root, fail_on_dirty_arg=bool(args.fail_on_dirty))
    mode.apply_env()
    commit = mode.commit
    dirty = "true" if mode.dirty else "false"
    strict_env = "1" if mode.strict else (str(os.environ.get("SCYTALEDROID_PAPER_STRICT") or "").strip() or "0")
    fail_on_dirty = bool(mode.fail_on_dirty)

    if fail_on_dirty and dirty == "true":
        raise SystemExit("PROVENANCE_DIRTY_TREE: git worktree is dirty (refuse under fail-on-dirty)")

    stamp: dict[str, object] = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "repo_root": str(repo_root),
        **mode.receipt_fields(),
        "paper_strict_env": strict_env,
        "runtime": {},
        "files": {},
    }

    # Minimal runtime fingerprint (helps explain cross-machine differences).
    runtime: dict[str, object] = {
        "python_version": sys.version.split()[0],
        "python_executable": sys.executable,
        "platform": platform.platform(),
    }
    # Optional dependency versions (best-effort; do not fail).
    deps: dict[str, str] = {}
    for mod in ("numpy", "pandas", "scipy", "sklearn", "matplotlib"):
        try:
            m = __import__(mod)  # noqa: WPS421
            deps[mod] = str(getattr(m, "__version__", "") or "")
        except Exception:
            continue
    if deps:
        runtime["deps"] = deps
    stamp["runtime"] = runtime

    # Single-line copy/paste anchor for PM updates.
    print(
        f"[COPY] provenance repo_root='{repo_root}' git_commit={commit} git_dirty={dirty} "
        f"paper_strict_env={strict_env}"
    )
    if dirty == "true":
        print("[WARN] git worktree is dirty; for paper exports, pin commit + file hashes in the receipt.")

    if freeze_path.exists():
        sha = sha256_file(freeze_path)
        print(f"[COPY] freeze path='{freeze_path}' sha256={sha}")
        stamp["files"]["dataset_freeze.json"] = {"path": str(freeze_path), "sha256": sha}

    if catalog_path.exists():
        try:
            cat = json.loads(catalog_path.read_text(encoding="utf-8"))
            size = len(cat) if isinstance(cat, dict) else None
        except Exception:
            size = None
        size_str = str(size) if size is not None else "unknown"
        sha = sha256_file(catalog_path)
        print(f"[COPY] v3_catalog path='{catalog_path}' sha256={sha} catalog_size={size_str}")
        stamp["files"]["profile_v3_app_catalog.json"] = {
            "path": str(catalog_path),
            "sha256": sha,
            "catalog_size": size,
        }

    if manifest_path.exists():
        n_ids = _json_count_included_run_ids(manifest_path)
        n_str = str(n_ids) if n_ids is not None else "unknown"
        sha = sha256_file(manifest_path)
        print(f"[COPY] v3_manifest path='{manifest_path}' sha256={sha} included_run_ids={n_str}")
        stamp["files"]["profile_v3_manifest.json"] = {
            "path": str(manifest_path),
            "sha256": sha,
            "included_run_ids": n_ids,
        }

    # Lock paper-grade minima sources (prevents "constants drift" ambiguity in PM/reviewer provenance).
    for p in minima_sources:
        if p.exists():
            sha = sha256_file(p)
            rel = str(p.relative_to(repo_root))
            print(f"[COPY] minima_source path='{rel}' sha256={sha}")
            stamp["files"][rel] = {"path": str(p), "sha256": sha}

    for p in tool_sources:
        if p.exists():
            sha = _sha256_file(p)
            rel = str(p.relative_to(repo_root))
            print(f"[COPY] tool_source path='{rel}' sha256={sha}")
            stamp["files"][rel] = {"path": str(p), "sha256": sha}

    if args.write_audit:
        audit_dir = Path(args.audit_dir)
        audit_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        out = audit_dir / f"provenance_{ts}.json"
        out.write_text(json.dumps(stamp, indent=2, sort_keys=True), encoding="utf-8")
        print(f"[COPY] provenance_audit_json path='{out.relative_to(repo_root)}'")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
