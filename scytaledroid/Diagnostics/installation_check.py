"""Read-only readiness checks for a newly provisioned ScytaleDroid host."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.Diagnostics.deployment_check import CheckLine, _database_check, _python_check

REQUIRED_SOURCE_PATHS = ("requirements.lock", "scytaledroid", "setup.sh", "run.sh")
RESTORE_ROOTS = ("data/store/apk", "data/evidence/dynamic")
RUNTIME_TOOLS = {
    "adb": "Android device access",
    "tshark": "PCAP analysis",
    "capinfos": "PCAP validation",
    "mariadb": "database smoke checks",
    "mariadb-dump": "database backup/export",
}


@dataclass(frozen=True)
class InstallationState:
    """Compact local state used by the interactive landing screen."""

    level: str
    detail: str


def describe_installation_state(repo_root: Path) -> InstallationState:
    """Describe setup state without probing ADB, the database, or storage."""

    if not (repo_root / ".env").is_file():
        return InstallationState("setup-required", "create .env from .env.example")
    if not _project_venv_exists(repo_root) or not (repo_root / ".setup" / "requirements.sha256").is_file():
        return InstallationState("setup-unverified", "run ./setup.sh, then --new-system-check")
    python = _python_check()
    if python and python.level != "ok":
        return InstallationState("runtime-unvalidated", python.message)
    if not _restore_roots_populated(repo_root):
        return InstallationState("restore-pending", "restore data roots before collection")
    return InstallationState("ready", "run --new-system-check after host changes")


def _restore_roots_populated(repo_root: Path) -> bool:
    """Require entries, not merely setup-created empty directories."""

    for relative in RESTORE_ROOTS:
        root = repo_root / relative
        try:
            if not root.is_dir() or not any(root.iterdir()):
                return False
        except OSError:
            return False
    return True


def _project_venv_exists(repo_root: Path) -> bool:
    return (repo_root / ".venv" / "bin" / "python").is_file()


def _source_check(repo_root: Path) -> CheckLine:
    missing = [relative for relative in REQUIRED_SOURCE_PATHS if not (repo_root / relative).exists()]
    if missing:
        return CheckLine("fail", "source", f"missing required paths: {', '.join(missing)}")
    return CheckLine("ok", "source", "repository entrypoints and requirements present")


def _setup_marker_check(repo_root: Path) -> CheckLine:
    marker = repo_root / ".setup" / "requirements.sha256"
    if marker.is_file() and marker.read_text(encoding="utf-8").strip() and _project_venv_exists(repo_root):
        return CheckLine("ok", "setup", "setup.sh dependency marker present")
    if marker.is_file() and marker.read_text(encoding="utf-8").strip():
        return CheckLine("warn", "setup", "dependency marker present, but project virtual environment is missing")
    return CheckLine("warn", "setup", "setup marker missing; run ./setup.sh")


def _environment_check(repo_root: Path) -> CheckLine:
    if (repo_root / ".env").is_file():
        return CheckLine("ok", "configuration", ".env present (values not inspected)")
    return CheckLine("fail", "configuration", ".env missing; copy .env.example and configure credentials")


def _runtime_tool_checks(tool_resolver: Callable[[str], str | None]) -> list[CheckLine]:
    lines: list[CheckLine] = []
    for tool, purpose in RUNTIME_TOOLS.items():
        if tool_resolver(tool):
            lines.append(CheckLine("ok", tool, purpose))
        else:
            lines.append(CheckLine("warn", tool, f"missing ({purpose})"))
    return lines


def _restore_root_check(repo_root: Path) -> CheckLine:
    populated = [
        relative
        for relative in RESTORE_ROOTS
        if (repo_root / relative).is_dir() and any((repo_root / relative).iterdir())
    ]
    if len(populated) == len(RESTORE_ROOTS):
        return CheckLine("ok", "workspace", "canonical APK and dynamic-evidence roots populated")
    missing = [relative for relative in RESTORE_ROOTS if relative not in populated]
    return CheckLine(
        "warn",
        "workspace",
        f"restore pending for: {', '.join(missing)} (expected on a fresh clone)",
    )


def _cold_apk_store_check(repo_root: Path) -> CheckLine:
    """Verify restored APK symlinks without re-hashing the full APK corpus."""

    sha_root = repo_root / "data" / "store" / "apk" / "sha256"
    if not sha_root.is_dir():
        return CheckLine("warn", "cold APK store", "canonical APK store not restored yet")

    symlink_count = 0
    broken_count = 0
    try:
        for path in sha_root.rglob("*.apk"):
            if path.is_symlink():
                symlink_count += 1
                if not path.exists():
                    broken_count += 1
    except OSError as exc:
        return CheckLine("fail", "cold APK store", f"unable to inspect canonical APK links ({type(exc).__name__})")

    if broken_count:
        return CheckLine(
            "fail",
            "cold APK store",
            f"{broken_count}/{symlink_count} canonical APK symlink(s) are unavailable; mount or restore cold storage",
        )
    if symlink_count:
        return CheckLine("ok", "cold APK store", f"{symlink_count} canonical external APK symlink(s) resolve")
    return CheckLine("ok", "cold APK store", "no external canonical APK symlinks")


def _dynamic_alias_check(repo_root: Path) -> CheckLine:
    """Report legacy output aliases without making them an evidence-validity gate."""

    try:
        from scytaledroid.DynamicAnalysis.utils.path_utils import inspect_legacy_dynamic_aliases

        summary = inspect_legacy_dynamic_aliases(
            canonical_root=repo_root / "data" / "evidence" / "dynamic",
            legacy_root=repo_root / "output" / "evidence" / "dynamic",
        )
    except OSError as exc:
        return CheckLine("warn", "dynamic aliases", f"unable to inspect compatibility aliases ({type(exc).__name__})")

    issues = summary.missing + summary.stale + summary.conflicts + summary.orphaned
    detail = (
        f"canonical={summary.canonical_runs}, valid={summary.valid}, missing={summary.missing}, "
        f"stale={summary.stale}, conflicts={summary.conflicts}, orphaned={summary.orphaned}"
    )
    if issues:
        return CheckLine(
            "warn",
            "dynamic aliases",
            f"{detail}; repair canonical aliases with scripts/dynamic/rebuild_dynamic_evidence_aliases.py --apply",
        )
    return CheckLine("ok", "dynamic aliases", detail)


def _permission_intel_check() -> CheckLine:
    """Report the separate Permission Intel catalog without changing its policy."""

    try:
        from scytaledroid.Database.db_utils.permission_intel_readiness import (
            assess_permission_intel_readiness,
        )

        state = assess_permission_intel_readiness()
    except Exception as exc:  # noqa: BLE001 - diagnostics must remain informative
        return CheckLine("warn", "permission intel", f"readiness unavailable ({type(exc).__name__})")

    if not state.configured:
        return CheckLine("warn", "permission intel", "not configured (required for paper-grade static analysis)")
    if not state.catalog_name_matches_expected or not state.connect_ok or state.missing_tables:
        missing = ", ".join(state.missing_tables) or "connection/catalog mismatch"
        return CheckLine("warn", "permission intel", f"needs repair: {missing}")
    if not state.governance_ok:
        return CheckLine("warn", "permission intel", "reachable, but governance snapshots are not paper-grade ready")
    return CheckLine("ok", "permission intel", "configured, reachable, and governance-ready")


def collect_checks(
    *,
    repo_root: Path,
    require_database: bool,
    tool_resolver: Callable[[str], str | None] = shutil.which,
) -> list[CheckLine]:
    """Collect non-mutating new-system installation checks."""

    lines: list[CheckLine] = []
    python = _python_check()
    if python:
        lines.append(python)
    lines.extend(
        (
            _source_check(repo_root),
            _setup_marker_check(repo_root),
            _environment_check(repo_root),
            _restore_root_check(repo_root),
            _cold_apk_store_check(repo_root),
            _dynamic_alias_check(repo_root),
        )
    )
    lines.extend(_runtime_tool_checks(tool_resolver))
    lines.extend(_database_check(require_database))
    lines.append(_permission_intel_check())
    return lines


def run(*, repo_root: Path, json_mode: bool, require_database: bool) -> int:
    """Print installation readiness and return nonzero only for hard blockers."""

    checks = collect_checks(repo_root=repo_root, require_database=require_database)
    counts: dict[str, int] = {}
    for line in checks:
        counts[line.level] = counts.get(line.level, 0) + 1

    payload = {
        "new_system_check": True,
        "repo_root": str(repo_root),
        "require_database": require_database,
        "setup_state": describe_installation_state(repo_root).__dict__,
        "summary": counts,
        "checks": [{"level": line.level, "topic": line.topic, "message": line.message} for line in checks],
    }
    if json_mode:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("New-System Installation Check")
        for line in checks:
            tag = {"ok": " OK", "warn": " !!", "fail": " XX"}.get(line.level, " ?")
            print(f" {tag}  {line.topic:14} {line.message}")
        print(f"  -> ok={counts.get('ok', 0)} warn={counts.get('warn', 0)} fail={counts.get('fail', 0)}")
        if counts.get("fail"):
            print("  Next: resolve failures, then rerun ./run.sh --new-system-check --require-database.")
        elif counts.get("warn"):
            print("  Next: review warnings before capture, backup, or production use.")
        else:
            print("  Result: host is ready for the configured ScytaleDroid workflows.")
    return 1 if counts.get("fail") else 0


__all__ = ["InstallationState", "collect_checks", "describe_installation_state", "run"]
