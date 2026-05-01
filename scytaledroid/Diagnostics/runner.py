"""Diagnostics entrypoints for headless health checks."""
from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "scytaledroid"


@dataclass(frozen=True)
class ScanResults:
    """Container for repository scan metadata."""

    import_smells: list[str]
    io_hotspots: list[str]
    fast_wins: list[str]
    dead_modules: list[str]
    duplicate_helpers: list[str]
    logging_noise: list[str]


def _timed_python(code: str) -> int:
    """Execute *code* in a fresh interpreter and return the printed timing."""

    cp = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    if cp.returncode != 0:
        raise RuntimeError(
            "Timing helper failed: " + (cp.stderr.strip() or cp.stdout.strip() or "unknown error")
        )

    for line in reversed(cp.stdout.splitlines()):
        stripped = line.strip()
        if stripped.isdigit():
            return int(stripped)
    raise ValueError("Timing helper did not emit an integer timing result")


def _time_imports() -> int:
    """Measure end-to-end import time for primary CLI dependencies."""

    code = """
import time
start = time.perf_counter()
import scytaledroid  # noqa: F401
import scytaledroid.StaticAnalysis.core.pipeline  # noqa: F401
print(int((time.perf_counter() - start) * 1000))
"""
    return _timed_python(code)


def _time_menu_init() -> int:
    """Measure the time needed to prime menu dependencies."""

    code = """
import time
start = time.perf_counter()
from scytaledroid.Utils.DisplayUtils import menu_utils  # noqa: F401
from scytaledroid.Utils.DisplayUtils import prompt_utils  # noqa: F401
from scytaledroid.Config import app_config  # noqa: F401
print(int((time.perf_counter() - start) * 1000))
"""
    return _timed_python(code)


def collect_metrics() -> dict[str, int]:
    """Collect timing metrics used by the diagnostics runner."""

    return {
        "import_ms": _time_imports(),
        "menu_init_ms": _time_menu_init(),
    }


def _iter_python_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        yield path


FORBIDDEN_IMPORT_PATTERNS = [
    re.compile(r"scytaledroid\.StaticAnalysis\.core\._androguard"),
    re.compile(r"from\s+\.\s*_androguard\s+import"),
]


def _scan_import_smells(root: Path) -> list[str]:
    offenders: list[str] = []
    for path in _iter_python_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pattern in FORBIDDEN_IMPORT_PATTERNS:
            if pattern.search(text):
                offenders.append(str(path.relative_to(REPO_ROOT)))
                break
    return sorted(set(offenders))


IO_SUSPECT_PATTERNS = ["glob(", "rglob(", "os.walk(", "json.load(", "open("]


def _scan_io_hotspots(root: Path) -> list[str]:
    suspects: set[str] = set()
    for path in _iter_python_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lowered = text.lower()
        if any(token in lowered for token in IO_SUSPECT_PATTERNS):
            suspects.add(str(path.relative_to(REPO_ROOT)))
    return sorted(suspects)


def _scan_dead_modules(root: Path) -> list[str]:
    contents: list[tuple[Path, str]] = []
    for path in _iter_python_files(root):
        try:
            data = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        contents.append((path, data))

    dead: list[str] = []
    for path, _text in contents:
        if path.name == "__init__.py":
            continue
        module_name = ".".join(path.relative_to(root).with_suffix("").parts)
        short_name = path.stem
        referenced_elsewhere = False
        for other_path, other_text in contents:
            if other_path == path:
                continue
            if module_name in other_text or f"from {module_name}" in other_text or f"import {module_name}" in other_text:
                referenced_elsewhere = True
                break
            if short_name and re.search(rf"\b{re.escape(short_name)}\b", other_text):
                referenced_elsewhere = True
                break
        if not referenced_elsewhere:
            dead.append(str(path.relative_to(REPO_ROOT)))
    return sorted(dead)


def _normalise_source(text: str) -> str:
    return "\n".join(line.strip() for line in text.strip().splitlines())


def _scan_duplicate_helpers(root: Path) -> list[str]:
    duplicates: dict[tuple[str, str], set[str]] = {}
    for path in _iter_python_files(root):
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            if len(node.body) > 6:
                continue
            segment = ast.get_source_segment(source, node)
            if not segment:
                continue
            key = (node.name, _normalise_source(segment))
            duplicates.setdefault(key, set()).add(str(path.relative_to(REPO_ROOT)))

    repeated: list[str] = []
    for (_name, _src), files in duplicates.items():
        if len(files) > 1:
            repeated.append(", ".join(sorted(files)))
    return sorted(repeated)


LOGGING_NOISE_PATTERNS = ["logging.debug", "print("]


def _scan_logging_noise(root: Path) -> list[str]:
    offenders: set[str] = set()
    for path in _iter_python_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pattern in LOGGING_NOISE_PATTERNS:
            if pattern in text:
                offenders.add(str(path.relative_to(REPO_ROOT)))
                break
    return sorted(offenders)


def scan_repo() -> ScanResults:
    """Gather static findings across the repository."""

    import_smells = _scan_import_smells(SRC_ROOT)
    io_hotspots = _scan_io_hotspots(SRC_ROOT)
    dead_modules = _scan_dead_modules(SRC_ROOT)
    duplicate_helpers = _scan_duplicate_helpers(SRC_ROOT)
    logging_noise = _scan_logging_noise(SRC_ROOT)

    fast_wins: list[str] = []
    if import_smells:
        fast_wins.append("Resolve shim imports referencing StaticAnalysis.core._androguard")
    if io_hotspots:
        fast_wins.append("Consider caching repeated file reads and tightening glob patterns")
    if dead_modules:
        preview = ", ".join(dead_modules[:3])
        fast_wins.append(f"Review possibly unused modules: {preview}")
    if duplicate_helpers:
        preview = "; ".join(duplicate_helpers[:2])
        fast_wins.append(f"Deduplicate small helper functions: {preview}")
    if logging_noise:
        preview = ", ".join(logging_noise[:3])
        fast_wins.append(f"Reduce print/logging noise in: {preview}")

    return ScanResults(
        import_smells=import_smells,
        io_hotspots=io_hotspots,
        fast_wins=sorted(set(fast_wins)),
        dead_modules=dead_modules,
        duplicate_helpers=duplicate_helpers,
        logging_noise=logging_noise,
    )


def emit_report(data: dict, *, json_mode: bool = False) -> None:
    """Output the diagnostics payload in either human or JSON form."""

    if json_mode:
        print(json.dumps(data, indent=2, sort_keys=True))
        return

    print("# Diagnostics")
    timings = data.get("timings", {})
    print("\n## Timings")
    print(f"- Import time: {timings.get('import_ms', 0)} ms")
    print(f"- Menu init: {timings.get('menu_init_ms', 0)} ms")

    print("\n## Import smells")
    smells = data.get("import_smells", [])
    if smells:
        for item in smells:
            print(f"- {item}")
    else:
        print("- (none)")

    print("\n## I/O hotspots")
    hotspots = data.get("io_hotspots", [])
    if hotspots:
        for item in hotspots:
            print(f"- {item}")
    else:
        print("- (none)")

    print("\n## Fast wins")
    wins = data.get("fast_wins", [])
    if wins:
        for item in wins:
            print(f"- {item}")
    else:
        print("- (none)")

    if data.get("dead_modules"):
        print("\n## Potentially unused modules")
        for item in data["dead_modules"]:
            print(f"- {item}")

    if data.get("duplicate_helpers"):
        print("\n## Duplicate helpers")
        for item in data["duplicate_helpers"]:
            print(f"- {item}")

    if data.get("logging_noise"):
        print("\n## Logging noise")
        for item in data["logging_noise"]:
            print(f"- {item}")


def run(json_mode: bool = False) -> None:
    """Execute diagnostics workflow and emit a report."""

    timings = collect_metrics()
    scan = scan_repo()
    payload = {
        "timings": timings,
        "import_smells": scan.import_smells,
        "io_hotspots": scan.io_hotspots,
        "fast_wins": scan.fast_wins,
        "dead_modules": scan.dead_modules,
        "duplicate_helpers": scan.duplicate_helpers,
        "logging_noise": scan.logging_noise,
    }
    emit_report(payload, json_mode=json_mode)


__all__ = ["collect_metrics", "run", "scan_repo", "emit_report"]
