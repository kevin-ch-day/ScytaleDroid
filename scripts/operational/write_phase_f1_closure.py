#!/usr/bin/env python3
"""Write Phase F1 closure artifact (non-interactive).

Runs the two acceptance gates:
1) Phase E no-drift regression
2) Query-mode variable-N smoke

If both pass, writes: data/archive/phase_f1_closure.json
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path


@dataclass(frozen=True)
class GateResult:
    name: str
    script: Path
    status: str
    stdout: str
    stderr: str
    snapshot_path: str | None = None


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    h = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _git(args: list[str]) -> str | None:
    try:
        p = subprocess.run(args, cwd=_repo_root(), capture_output=True, text=True)
        if p.returncode != 0:
            return None
        return (p.stdout or "").strip() or None
    except Exception:
        return None


def _run_gate(name: str, script: Path, extra_args: list[str] | None = None) -> GateResult:
    args = [sys.executable, str(script)]
    if extra_args:
        args.extend(extra_args)
    proc = subprocess.run(args, text=True, capture_output=True)
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    status = "PASS" if proc.returncode == 0 else "FAIL"

    snapshot: str | None = None
    if name == "query_mode_smoke":
        # Be tolerant to stream differences: some environments may emit to stderr.
        combined = "\n".join([out, err]).strip()
        # Be tolerant to potential carriage returns in captured output.
        m = re.search(r"^[\\r\\s]*\\-\\s+snapshot:\\s+(\\S+)", combined, flags=re.MULTILINE)
        if m:
            snapshot = m.group(1).strip()
        else:
            # Fallback: avoid regex edge cases by scanning lines.
            for line in combined.splitlines():
                if "snapshot:" in line:
                    snapshot = line.split("snapshot:", 1)[1].strip().split()[0]
                    break

    return GateResult(name=name, script=script, status=status, stdout=out, stderr=err, snapshot_path=snapshot)


def main(argv: list[str]) -> int:
    repo_root = _repo_root()
    # Allow running directly from a git checkout without installation.
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    gate_phase_e = repo_root / "scripts" / "publication" / "regression_gate_freeze.py"
    gate_smoke = repo_root / "scripts" / "operational" / "query_mode_smoke_gate.py"

    if not gate_phase_e.exists():
        print(f"[phase_f1_closure] FAIL missing gate: {gate_phase_e}")
        return 2
    if not gate_smoke.exists():
        print(f"[phase_f1_closure] FAIL missing gate: {gate_smoke}")
        return 2

    r1 = _run_gate("phase_e_regression", gate_phase_e)
    print(f"[phase_f1_closure] Gate phase_e_regression: {r1.status}")
    r2 = _run_gate("query_mode_smoke", gate_smoke)
    print(f"[phase_f1_closure] Gate query_mode_smoke: {r2.status}")

    ok = r1.status == "PASS" and r2.status == "PASS"
    if not ok:
        return 1

    try:
        from scytaledroid.Config import app_config
        from scytaledroid.DynamicAnalysis.ml import ml_parameters_operational as op_cfg
        from scytaledroid.DynamicAnalysis.ml import ml_parameters_paper2 as paper_cfg
        from scytaledroid.Utils.toolchain_versions import gather_toolchain_versions
    except Exception as exc:
        print(f"[phase_f1_closure] FAIL import: {exc}")
        return 2

    created = datetime.now(UTC).isoformat()
    head = _git(["git", "rev-parse", "HEAD"])
    branch = _git(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    dirty = bool(_git(["git", "status", "--porcelain"]))
    tc = gather_toolchain_versions()

    snapshot_path = r2.snapshot_path
    selection_manifest_sha = ""
    f2_tables_present: dict[str, bool] = {}
    if snapshot_path:
        snap = Path(snapshot_path)
        selection_manifest_sha = _sha256_file(snap / "selection_manifest.json") or ""
        tables = snap / "tables"
        f2_tables_present = {
            "anomaly_persistence_per_run.csv": (tables / "anomaly_persistence_per_run.csv").exists(),
            "threshold_stability_per_group_model.csv": (tables / "threshold_stability_per_group_model.csv").exists(),
            "coverage_confidence_per_group.csv": (tables / "coverage_confidence_per_group.csv").exists(),
            "dynamic_math_audit_per_group_model.csv": (tables / "dynamic_math_audit_per_group_model.csv").exists(),
            "risk_summary_per_group.csv": (tables / "risk_summary_per_group.csv").exists(),
        }

    payload = {
        "phase_f1_complete": True,
        "created_at_utc": created,
        "git": {"commit": head, "branch": branch, "dirty": dirty},
        "toolchain": tc,
        "percentile": {
            "paper_np_percentile_method": str(paper_cfg.NP_PERCENTILE_METHOD),
            "operational_np_percentile_method": str(op_cfg.NP_PERCENTILE_METHOD),
        },
        "operational_mode": {
            "feature_log1p": bool(getattr(op_cfg, "FEATURE_LOG1P", False)),
            "feature_robust_scale": bool(getattr(op_cfg, "FEATURE_ROBUST_SCALE", False)),
        },
        "gates": {
            "phase_e_regression": {
                "status": r1.status,
                "script": str(gate_phase_e),
                "stdout_tail": r1.stdout.splitlines()[-1] if r1.stdout else "",
                "stderr_tail": r1.stderr.splitlines()[-1] if r1.stderr else "",
            },
            "query_mode_smoke": {
                "status": r2.status,
                "script": str(gate_smoke),
                "snapshot_path": snapshot_path or "",
                "selection_manifest_sha256": selection_manifest_sha,
                "f2_tables_present": f2_tables_present,
                "stdout_tail": r2.stdout.splitlines()[-1] if r2.stdout else "",
                "stderr_tail": r2.stderr.splitlines()[-1] if r2.stderr else "",
            },
        },
    }

    out_path = Path(app_config.DATA_DIR) / "archive" / "phase_f1_closure.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[phase_f1_closure] Wrote: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
