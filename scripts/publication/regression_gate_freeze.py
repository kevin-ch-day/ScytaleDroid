#!/usr/bin/env python3
"""Phase E regression gate (no-drift under the pinned paper toolchain).

Goal:
- Same evidence packs + same pinned toolchain => identical *deterministic* artifacts.

This gate:
1) Runs Phase E ML (freeze, DB-free) and writes the Phase E deliverables bundle.
2) Computes canonicalized sha256 hashes for a stable set of artifacts.
3) Compares against a stored reference (or records a new reference explicitly).
"""

from __future__ import annotations

import argparse
import importlib.metadata as md
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT_RESOLVED = REPO_ROOT.resolve()
sys.path.insert(0, str(REPO_ROOT))


def _sha256_bytes(b: bytes) -> str:
    return sha256(b).hexdigest()


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="strict")


def _canonicalize_csv(text: str) -> bytes:
    # Strip only the leading provenance comment header ("# ...") if present.
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if not out and (not line.strip() or line.startswith("#")):
            i += 1
            continue
        out.append(line)
        i += 1
    return ("\n".join(out) + "\n").encode("utf-8")


def _canonicalize_tex(text: str) -> bytes:
    # Strip leading comment lines ("% ...") so generated_at/toolchain notes don't break hashes.
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if not out and (not line.strip() or line.startswith("%")):
            i += 1
            continue
        out.append(line)
        i += 1
    return ("\n".join(out) + "\n").encode("utf-8")


_TIME_KEYS = {
    "created_at",
    "created_at_utc",
    "generated_at",
    "generated_at_utc",
    "finished_at",
    "started_at",
    "started_at_utc",
    "ended_at",
    "ended_at_utc",
}


def _strip_time_keys(obj: Any) -> Any:
    if isinstance(obj, list):
        return [_strip_time_keys(x) for x in obj]
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if str(k) in _TIME_KEYS:
                continue
            out[str(k)] = _strip_time_keys(v)
        return out
    return obj


def _canonicalize_json(text: str, *, filename: str) -> bytes:
    payload = json.loads(text)
    payload = _strip_time_keys(payload)

    # Phase E artifacts manifest includes hashes for PDFs/PNGs/XLSX which can embed metadata and
    # vary across environments. For the regression gate, only hash the deterministic subset.
    if filename == "phase_e_artifacts_manifest.json" and isinstance(payload, dict):
        files = payload.get("files")
        if isinstance(files, dict):
            keep: dict[str, Any] = {}
            for k, v in files.items():
                ks = str(k)
                if ks.startswith("fig_"):
                    continue
                if ks.endswith("_xlsx"):
                    continue
                keep[ks] = v
            payload["files"] = keep

    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return blob


def _sha256_canonical(path: Path) -> str:
    ext = path.suffix.lower()
    raw = _read_text(path)
    if ext == ".csv":
        return _sha256_bytes(_canonicalize_csv(raw))
    if ext == ".tex":
        return _sha256_bytes(_canonicalize_tex(raw))
    if ext == ".json":
        return _sha256_bytes(_canonicalize_json(raw, filename=path.name))
    # Fallback: hash raw bytes (only used for files we deliberately include).
    return _sha256_bytes(path.read_bytes())


def _parse_pins(req_path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in req_path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        # Very small parser: handle "pkg==1.2.3" (ignore extras/markers here).
        m = re.match(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)$", s)
        if not m:
            continue
        pins[m.group(1).lower()] = m.group(2)
    return pins


def _toolchain_matches(pins: dict[str, str]) -> tuple[bool, list[str]]:
    mismatches: list[str] = []
    for pkg, want in sorted(pins.items()):
        try:
            got = md.version(pkg)
        except Exception:
            mismatches.append(f"{pkg}: missing (want {want})")
            continue
        if str(got) != str(want):
            mismatches.append(f"{pkg}: {got} (want {want})")
    return (len(mismatches) == 0), mismatches


def _phase_e_bundle_root() -> Path:
    # Avoid importing app_config early (it can touch env/.env); import lazily inside the gate.
    from scytaledroid.DynamicAnalysis.ml.deliverable_bundle_paths import output_phase_e_bundle_root

    return output_phase_e_bundle_root()


def _collect_hash_targets() -> list[Path]:
    targets: list[Path] = []

    # Deterministic dataset CSVs (written by Phase E ML runner).
    for rel in (
        "data/anomaly_prevalence_per_app_phase.csv",
        "data/model_overlap_per_run.csv",
        "data/transport_mix_by_phase.csv",
        "data/ml_audit_per_app_model.csv",
    ):
        p = REPO_ROOT / rel
        if p.exists():
            targets.append(p)

    # Deterministic paper bundle outputs (exclude .xlsx/.png/.pdf; they may embed metadata).
    bundle = _phase_e_bundle_root()
    tables = bundle / "tables"
    manifest = bundle / "manifest"
    if tables.exists():
        for p in sorted(tables.glob("*")):
            if not p.is_file():
                continue
            if p.suffix.lower() not in {".csv", ".tex"}:
                continue
            targets.append(p)
    if manifest.exists():
        for p in sorted(manifest.glob("*.json")):
            if p.name == "phase_e_closure_record.json":
                continue
            if p.name == "phase_e_artifacts_manifest.json":
                # This file embeds raw SHA256s of PDFs/PNGs/XLSX and the paper tables that
                # include provenance comment headers. We already hash the deterministic
                # artifacts directly, so including this manifest creates false diffs.
                continue
            targets.append(p)
    return sorted(set(targets), key=lambda x: str(x))


@dataclass(frozen=True)
class GateResult:
    ok: bool
    message: str
    mismatches: list[str]
    missing: list[str]


def _hash_snapshot() -> dict[str, str]:
    out: dict[str, str] = {}
    for p in _collect_hash_targets():
        rp = p.resolve()
        rel = str(rp.relative_to(REPO_ROOT_RESOLVED))
        # Output layout migration: normalize legacy keys so older recordings still validate.
        rel = rel.replace("output/paper/paper2/phase_e/", "output/paper/internal/baseline/")
        rel = rel.replace("output/paper/paper2/baseline/", "output/paper/internal/baseline/")
        out[rel] = _sha256_canonical(rp)
    return dict(sorted(out.items()))


def _default_reference_path() -> Path:
    from scytaledroid.Config import app_config

    return Path(app_config.DATA_DIR) / "archive" / "phase_e_reference_hashes.json"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run_phase_e() -> None:
    from scytaledroid.Config import app_config
    from scytaledroid.DynamicAnalysis.ml.artifact_bundle_writer import (
        write_phase_e_deliverables_bundle,
    )
    from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_orchestrator import (
        run_ml_on_evidence_packs,
    )

    run_ml_on_evidence_packs(output_root=Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic")

    # Bundle needs the pinned exemplar (selected during ML run).
    archive_dir = Path(app_config.DATA_DIR) / "archive"
    paper_artifacts = archive_dir / "paper_artifacts.json"
    payload = json.loads(paper_artifacts.read_text(encoding="utf-8"))
    rid = str(payload.get("fig_B1_run_id") or "").strip()
    tag = str(payload.get("interaction_tag") or "").strip() or None
    if not rid:
        raise RuntimeError("paper_artifacts.json missing fig_B1_run_id (run Phase E ML first).")
    write_phase_e_deliverables_bundle(fig_b1_run_id=rid, interaction_tag=tag)


def run_gate(*, reference_path: Path, record: bool, allow_toolchain_mismatch: bool) -> GateResult:
    pins_path = REPO_ROOT / "requirements-paper-toolchain.txt"
    if pins_path.exists():
        pins = _parse_pins(pins_path)
        ok, mismatches = _toolchain_matches(pins)
        if not ok and not allow_toolchain_mismatch:
            return GateResult(
                ok=False,
                message="Paper toolchain pins mismatch (fail-closed).",
                mismatches=mismatches,
                missing=[],
            )

    _run_phase_e()
    snap = _hash_snapshot()

    if record:
        payload = {
            "created_at_utc": datetime.now(UTC).isoformat(),
            "repo_root": str(REPO_ROOT),
            "tool_version_git_sha": os.getenv("SCYTALEDROID_GIT_COMMIT"),
            "hashes": snap,
        }
        _write_json(reference_path, payload)
        return GateResult(ok=True, message=f"Recorded reference: {reference_path}", mismatches=[], missing=[])

    if not reference_path.exists():
        return GateResult(
            ok=False,
            message=f"Reference missing: {reference_path} (run with --record to create it).",
            mismatches=[],
            missing=[str(reference_path)],
        )

    ref = _load_json(reference_path)
    ref_hashes = ref.get("hashes") if isinstance(ref.get("hashes"), dict) else {}
    # Normalize legacy keys in the reference so older recordings still validate.
    if isinstance(ref_hashes, dict):
        norm: dict[str, Any] = {}
        for k, v in ref_hashes.items():
            ks = str(k)
            ks = ks.replace("output/paper/paper2/phase_e/", "output/paper/internal/baseline/")
            ks = ks.replace("output/paper/paper2/baseline/", "output/paper/internal/baseline/")
            norm[ks] = v
        ref_hashes = norm
    mism: list[str] = []
    missing: list[str] = []

    for rel, want in sorted(ref_hashes.items()):
        got = snap.get(rel)
        if got is None:
            missing.append(rel)
            continue
        if str(got) != str(want):
            mism.append(f"{rel}: got {got} want {want}")

    ok = (not mism) and (not missing)
    msg = "PASS" if ok else "FAIL"
    return GateResult(ok=ok, message=msg, mismatches=mism, missing=missing)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--record", action="store_true", help="Record reference hashes instead of verifying.")
    ap.add_argument("--reference", type=str, default="", help="Path to reference JSON (default: data/archive).")
    ap.add_argument(
        "--allow-toolchain-mismatch",
        action="store_true",
        help="Do not fail-closed if requirements-paper-toolchain.txt doesn't match the current environment.",
    )
    args = ap.parse_args(argv)

    ref = Path(args.reference) if args.reference else _default_reference_path()
    res = run_gate(reference_path=ref, record=bool(args.record), allow_toolchain_mismatch=bool(args.allow_toolchain_mismatch))
    print(f"[phase_e_regression_gate] {res.message}")
    if res.missing:
        print("Missing:")
        for m in res.missing:
            print(f"- {m}")
    if res.mismatches:
        print("Mismatches:")
        for m in res.mismatches[:50]:
            print(f"- {m}")
        if len(res.mismatches) > 50:
            print(f"- ... and {len(res.mismatches) - 50} more")
    return 0 if res.ok else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
