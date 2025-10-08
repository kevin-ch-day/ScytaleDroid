#!/usr/bin/env python3
"""Lightweight repository health checks for ScytaleDroid."""

from __future__ import annotations

import importlib
import importlib.util
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]

IMPORT_TARGETS: tuple[str, ...] = (
    "main",
    "scytaledroid.StaticAnalysis.core.pipeline",
    "scytaledroid.DeviceAnalysis.device_analysis_menu",
    "scytaledroid.Reporting.menu",
)


@dataclass
class CheckResult:
    name: str
    status: str
    detail: str


def _ensure_path() -> None:
    root_str = str(ROOT)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)


def _measure_import_latency(targets: Sequence[str]) -> list[CheckResult]:
    results: list[CheckResult] = []
    for module_name in targets:
        start = time.perf_counter()
        try:
            importlib.import_module(module_name)
        except Exception as exc:  # pragma: no cover - import errors are reported
            duration = time.perf_counter() - start
            results.append(
                CheckResult(
                    name=module_name,
                    status="error",
                    detail=f"{duration:.3f}s import failed: {exc}",
                )
            )
        else:
            duration = time.perf_counter() - start
            results.append(
                CheckResult(
                    name=module_name,
                    status="ok",
                    detail=f"{duration:.3f}s",
                )
            )
    return results


def _module_available(module_name: str) -> bool:
    return importlib.util.find_spec(module_name) is not None


def _run_optional_tool(
    module_name: str,
    args: Sequence[str],
    description: str,
) -> CheckResult:
    if not _module_available(module_name) and shutil.which(args[0]) is None:
        return CheckResult(
            name=description,
            status="skipped",
            detail=f"Install {module_name} to enable this check.",
        )
    try:
        completed = subprocess.run(
            list(args),
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return CheckResult(
            name=description,
            status="skipped",
            detail=f"Executable for {module_name} not found.",
        )

    output = completed.stdout.strip() or completed.stderr.strip()
    if completed.returncode != 0:
        return CheckResult(
            name=description,
            status="error",
            detail=output or "Command failed without output.",
        )
    return CheckResult(name=description, status="ok", detail=output or "no findings")


def _summarise_requirements(requirements: Iterable[str]) -> CheckResult:
    missing: list[str] = []
    for raw_line in requirements:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        package = re.split(r"[<>=!]", line, maxsplit=1)[0].strip()
        module_name = package.replace("-", "_")
        if not _module_available(module_name):
            missing.append(package)
    if missing:
        detail = "Missing modules: " + ", ".join(sorted(missing))
        return CheckResult(name="requirements", status="warn", detail=detail)
    return CheckResult(name="requirements", status="ok", detail="All requirement imports resolved")


def main() -> int:
    _ensure_path()

    print("== Import latency ==")
    import_results = _measure_import_latency(IMPORT_TARGETS)
    for result in import_results:
        print(f"[{result.status.upper()}] {result.name}: {result.detail}")

    print("\n== Static analysis stubs ==")

    health_checks: list[CheckResult] = []

    vulture_args = ("vulture", "scytaledroid", "scripts", "tests")
    health_checks.append(
        _run_optional_tool("vulture", vulture_args, "dead-code")
    )

    deptry_args = ("deptry", "--config", str(ROOT / "pyproject.toml"))
    health_checks.append(
        _run_optional_tool("deptry", deptry_args, "dependencies")
    )

    req_path = ROOT / "requirements.txt"
    if req_path.exists():
        health_checks.append(
            _summarise_requirements(req_path.read_text(encoding="utf-8").splitlines())
        )

    for check in health_checks:
        print(f"[{check.status.upper()}] {check.name}: {check.detail}")

    errors = [result for result in import_results + health_checks if result.status == "error"]
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
