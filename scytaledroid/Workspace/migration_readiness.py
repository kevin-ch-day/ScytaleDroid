"""Read-only preflight for moving a ScytaleDroid workspace to a new system.

The Git checkout is not the research corpus.  This module reports the separate
code, filesystem, database, static-to-dynamic, recovery, and paper-freeze
surfaces that must be preserved for a reproducible move.  It never copies,
deletes, modifies database rows, or reads configuration values.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import stat
import subprocess
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Source code moves through Git. These roots are the research corpus that Git
# intentionally does not carry to the destination system.
_REQUIRED_TOOLS = ("git", "python", "rsync", "mysqldump", "adb", "tshark", "capinfos")
_TRANSFER_HEADROOM_RATIO = 1.20


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _directory_size_bytes(path: Path) -> int | None:
    """Return allocated directory size using ``du`` without walking in Python."""

    if not path.exists():
        return None
    try:
        completed = subprocess.run(
            ("du", "-sk", str(path)),
            capture_output=True,
            check=False,
            text=True,
            timeout=180,
        )
        if completed.returncode != 0:
            return None
        token = (completed.stdout or "").strip().split("\t", 1)[0]
        return int(token) * 1024
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def _format_bytes(value: int | None) -> str:
    if value is None:
        return "unknown"
    amount = float(value)
    for suffix in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or suffix == "TiB":
            return f"{amount:.1f} {suffix}" if suffix != "B" else f"{int(amount)} B"
        amount /= 1024
    return f"{amount:.1f} TiB"


def _git_output(repo_root: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(
            ("git", *args),
            cwd=repo_root,
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return (completed.stdout or "").strip()


def collect_git_state(repo_root: Path) -> dict[str, Any]:
    """Collect local Git state only; this intentionally never fetches a remote."""

    branch = _git_output(repo_root, "branch", "--show-current")
    revision = _git_output(repo_root, "rev-parse", "--short=12", "HEAD")
    porcelain = _git_output(repo_root, "status", "--porcelain")
    upstream = _git_output(repo_root, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}")
    divergence = _git_output(repo_root, "rev-list", "--left-right", "--count", "@{upstream}...HEAD")

    ahead: int | None = None
    behind: int | None = None
    if divergence:
        try:
            behind, ahead = (int(part) for part in divergence.split())
        except ValueError:
            pass
    return {
        "repository_detected": bool(revision),
        "branch": branch or "unknown",
        "revision": revision or "unknown",
        "clean": porcelain == "" if porcelain is not None else None,
        "upstream": upstream,
        "ahead": ahead,
        "behind": behind,
        "remote_state_note": "ahead/behind is local last-fetch state; this preflight does not fetch",
    }


def _path_record(path: Path, *, size_resolver: Callable[[Path], int | None]) -> dict[str, Any]:
    exists = path.exists()
    record: dict[str, Any] = {
        "path": str(path),
        "exists": exists,
        "readable": bool(exists and os.access(path, os.R_OK)),
        "size_bytes": size_resolver(path) if exists else None,
    }
    if exists:
        try:
            record["free_bytes"] = shutil.disk_usage(path).free
        except OSError:
            record["free_bytes"] = None
    return record


def _transfer_footprint(roots: list[Mapping[str, Any]], *, external_cold_bytes: int = 0) -> dict[str, Any]:
    """Estimate filesystem-only transfer capacity; the DB dump is separate."""

    sizes = [int(row["size_bytes"]) for row in roots if row.get("size_bytes") is not None]
    root_bytes = sum(sizes) if len(sizes) == len(roots) else None
    source_bytes = root_bytes + external_cold_bytes if root_bytes is not None else None
    return {
        "source_bytes": source_bytes,
        "repository_root_bytes": root_bytes,
        "external_cold_bytes": external_cold_bytes,
        "recommended_free_bytes": math.ceil(source_bytes * _TRANSFER_HEADROOM_RATIO) if source_bytes is not None else None,
        "headroom_ratio": _TRANSFER_HEADROOM_RATIO,
        "database_export_included": False,
        "note": "Filesystem roots only; reserve additional destination capacity for the separately generated database export.",
    }


def _external_cold_store_record(repo_root: Path, *, data_dir: Path | None = None) -> dict[str, Any]:
    """Measure external canonical APK targets not included in ``du data``."""

    if data_dir is None:
        data_dir = _workspace_roots(repo_root)["data"]
    logical_root = data_dir / "store" / "apk" / "sha256"
    if not logical_root.is_dir():
        return {"links": 0, "missing": 0, "bytes": 0, "roots": []}

    targets: dict[str, int] = {}
    roots: set[str] = set()
    missing = 0
    for logical in logical_root.rglob("*.apk"):
        if not logical.is_symlink():
            continue
        target = logical.resolve(strict=False)
        try:
            target.relative_to(repo_root)
            continue
        except ValueError:
            pass
        if not target.is_file():
            missing += 1
            continue
        targets[str(target)] = target.stat().st_size
        cold_root = next((parent for parent in target.parents if parent.name == "cold"), target.parent)
        roots.add(str(cold_root))
    return {
        "links": len(targets) + missing,
        "missing": missing,
        "bytes": sum(targets.values()),
        "roots": sorted(roots),
    }


def _permission_intel_probe() -> dict[str, Any]:
    """Read Permission Intel readiness without changing its catalog."""

    try:
        from scytaledroid.Database.db_utils.permission_intel_readiness import (
            assess_permission_intel_readiness,
        )

        state = assess_permission_intel_readiness()
    except Exception as exc:  # noqa: BLE001 - migration preflight must report failures
        return {"configured": False, "reachable": False, "detail": type(exc).__name__}
    return {
        "configured": state.configured,
        "reachable": state.connect_ok,
        "catalog_ok": state.catalog_name_matches_expected,
        "governance_ok": state.governance_ok,
        "database": state.resolved_database,
        "detail": state.governance_detail or "readiness checked",
    }


_DEFINER_SQL = """
SELECT DISTINCT definer
FROM (
    SELECT DEFINER AS definer FROM information_schema.views WHERE table_schema = DATABASE()
    UNION ALL SELECT DEFINER FROM information_schema.triggers WHERE trigger_schema = DATABASE()
    UNION ALL SELECT DEFINER FROM information_schema.routines WHERE routine_schema = DATABASE()
    UNION ALL SELECT DEFINER FROM information_schema.events WHERE event_schema = DATABASE()
) AS scoped_definers
WHERE definer IS NOT NULL AND definer != ''
ORDER BY definer
"""


def _database_definer_probe() -> dict[str, Any]:
    """Inventory source DB definers that destination restore accounts must satisfy."""

    results: dict[str, Any] = {}
    try:
        from scytaledroid.Database.db_core import db_engine

        with db_engine.connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(_DEFINER_SQL)
                results["core"] = {"available": True, "definers": sorted(str(row[0]) for row in cursor.fetchall())}
    except Exception as exc:  # noqa: BLE001
        results["core"] = {"available": False, "definers": [], "detail": type(exc).__name__}

    try:
        from scytaledroid.Database.db_core import permission_intel

        rows = permission_intel.fetch_database_definers()
        results["permission_intel"] = {
            "available": True,
            "definers": sorted(str(row[0]) for row in rows or ()),
        }
    except Exception as exc:  # noqa: BLE001
        results["permission_intel"] = {"available": False, "definers": [], "detail": type(exc).__name__}
    return results


def _database_export_record(path: Path | str | None, *, catalog: str) -> dict[str, Any]:
    """Verify a caller-supplied database export without reading its contents.

    Dumps can be compressed and can contain sensitive research metadata, so the
    migration preflight only establishes that a non-empty, readable artifact was
    deliberately supplied.  Restore coverage remains an operator smoke test.
    """

    if path is None or not str(path).strip():
        return {
            "catalog": catalog,
            "supplied": False,
            "valid": False,
            "path": None,
            "detail": "not supplied",
        }
    candidate = Path(path).expanduser()
    try:
        stat_result = candidate.stat()
    except OSError as exc:
        return {
            "catalog": catalog,
            "supplied": True,
            "valid": False,
            "path": str(candidate),
            "detail": f"unavailable ({type(exc).__name__})",
        }
    valid = candidate.is_file() and stat_result.st_size > 0 and os.access(candidate, os.R_OK)
    return {
        "catalog": catalog,
        "supplied": True,
        "valid": valid,
        "path": str(candidate),
        "size_bytes": stat_result.st_size,
        "detail": "readable non-empty export; contents intentionally not inspected"
        if valid
        else "path must be a readable non-empty regular file",
    }


def _dynamic_alias_probe(
    repo_root: Path,
    *,
    data_dir: Path | None = None,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    """Inspect transitional output aliases without treating them as evidence truth."""

    try:
        if data_dir is None or output_dir is None:
            configured = _workspace_roots(repo_root)
            data_dir = data_dir or configured["data"]
            output_dir = output_dir or configured["output"]
        from scytaledroid.DynamicAnalysis.utils.path_utils import inspect_legacy_dynamic_aliases

        summary = inspect_legacy_dynamic_aliases(
            canonical_root=(data_dir or repo_root / "data") / "evidence" / "dynamic",
            legacy_root=(output_dir or repo_root / "output") / "evidence" / "dynamic",
        )
    except OSError as exc:
        return {"available": False, "detail": type(exc).__name__}
    return {"available": True, **summary.__dict__}


def _static_manifest_path_probe(repo_root: Path, *, evidence_dir: Path | None = None) -> dict[str, Any]:
    """Count immutable static manifests retaining this workstation's absolute path.

    Static manifests are historical provenance and must not be rewritten during a
    move.  The check makes their source-path residue explicit so operators do not
    mistake a transferred, valid manifest for a broken canonical evidence pack.
    """

    static_root = (evidence_dir or repo_root / "evidence") / "static_runs"
    if not static_root.is_dir():
        return {"available": False, "manifests": 0, "source_path_manifests": 0}

    source_prefix = str(repo_root.resolve()).encode("utf-8")
    manifests = source_path_manifests = 0
    try:
        for manifest in static_root.glob("*/run_manifest.json"):
            manifests += 1
            if source_prefix in manifest.read_bytes():
                source_path_manifests += 1
    except OSError as exc:
        return {
            "available": False,
            "manifests": manifests,
            "source_path_manifests": source_path_manifests,
            "detail": type(exc).__name__,
        }
    return {
        "available": True,
        "manifests": manifests,
        "source_path_manifests": source_path_manifests,
    }


def _destination_record(path: Path | None, footprint: Mapping[str, Any]) -> dict[str, Any]:
    if path is None:
        return {
            "configured": False,
            "path": None,
            "exists": False,
            "writable": False,
            "free_bytes": None,
            "capacity_sufficient": None,
            "detail": "not checked; supply a mounted destination root to validate capacity",
        }
    candidate = path.expanduser().resolve()
    exists = candidate.is_dir()
    writable = bool(exists and os.access(candidate, os.W_OK))
    try:
        free_bytes = shutil.disk_usage(candidate).free if exists else None
    except OSError:
        free_bytes = None
    required = footprint.get("recommended_free_bytes")
    capacity_sufficient = bool(free_bytes is not None and required is not None and free_bytes >= required) if exists else False
    detail = (
        "destination has enough filesystem capacity; database export capacity remains additional"
        if capacity_sufficient
        else "destination is missing, not writable, or lacks the recommended filesystem transfer capacity"
    )
    return {
        "configured": True,
        "path": str(candidate),
        "exists": exists,
        "writable": writable,
        "free_bytes": free_bytes,
        "capacity_sufficient": capacity_sufficient,
        "detail": detail,
    }


def _rsync_command_templates(roots: list[Mapping[str, Any]], destination_root: Path | None) -> list[str]:
    """Return review-only command templates; this function never runs rsync."""

    destination = str(destination_root.expanduser().resolve()) if destination_root else "<destination-root>"
    return [
        "rsync -aHAX --numeric-ids --info=progress2 --partial --protect-args "
        f"'{root['path']}/' '{destination}/ScytaleDroid/{root['name']}/'"
        for root in roots
    ]


def _cold_store_rsync_templates(cold_store: Mapping[str, Any]) -> list[str]:
    """Return review-only transfer commands for APK bytes outside the repository."""

    templates: list[str] = []
    for source in cold_store.get("roots") or ():
        templates.append(
            "rsync -aHAX --numeric-ids --info=progress2 --partial --protect-args "
            f"'{source}/' '<destination-cold-apk-root>/'"
        )
    return templates


def _environment_record(repo_root: Path) -> dict[str, Any]:
    env_path = repo_root / ".env"
    exists = env_path.is_file()
    mode: str | None = None
    private: bool | None = None
    if exists:
        try:
            permission_bits = stat.S_IMODE(env_path.stat().st_mode)
            mode = f"{permission_bits:04o}"
            private = (permission_bits & 0o077) == 0
        except OSError:
            pass
    return {
        "path": str(env_path),
        "present": exists,
        "mode": mode,
        "private": private,
        "note": "configuration values are intentionally never inspected or exported",
    }


def _workspace_roots(repo_root: Path) -> dict[str, Path]:
    """Resolve transfer roots using the same configured paths as runtime setup."""

    from scytaledroid.Config import app_config
    from scytaledroid.Config.environment import resolve_workspace_path

    roots = {
        "data": resolve_workspace_path(app_config.DATA_DIR, repo_root=repo_root),
        "output": resolve_workspace_path(app_config.OUTPUT_DIR, repo_root=repo_root),
        "logs": resolve_workspace_path(app_config.LOGS_DIR, repo_root=repo_root),
        # Static handoff artifacts currently use this repo-relative location.
        "evidence": repo_root / "evidence",
    }
    dynamic_root = resolve_workspace_path(app_config.DYNAMIC_EVIDENCE_ROOT, repo_root=repo_root)
    if not any(dynamic_root == root or root in dynamic_root.parents for root in roots.values()):
        roots["dynamic_evidence"] = dynamic_root
    return roots


def _transfer_root_records(
    repo_root: Path,
    *,
    size_resolver: Callable[[Path], int | None],
) -> tuple[list[dict[str, Any]], dict[str, Path]]:
    configured = _workspace_roots(repo_root)
    records = [
        _path_record(path, size_resolver=size_resolver) | {"name": name}
        for name, path in configured.items()
    ]
    return records, configured


def _workspace_path_portability(repo_root: Path, roots: Mapping[str, Path]) -> tuple[bool, str]:
    """Flag custom roots because older maintenance paths are still repo-relative."""

    defaults = {
        "data": repo_root / "data",
        "output": repo_root / "output",
        "logs": repo_root / "logs",
    }
    changed = [name for name, expected in defaults.items() if roots.get(name) != expected]
    if not changed:
        return True, "repo-local workspace roots in use"
    return (
        False,
        "custom workspace roots configured for "
        f"{', '.join(changed)}; transfer paths are covered here, but legacy maintenance scripts "
        "may still assume repo-local data/output/logs",
    )


def _probe_database() -> dict[str, Any]:
    """Test DB reachability without exposing a DSN or running mutations."""

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core.optional import maybe_get_database

        if not db_config.db_enabled():
            return {"configured": False, "reachable": False, "database": None, "detail": "database disabled"}
        engine = maybe_get_database()
        if engine is None:
            return {"configured": False, "reachable": False, "database": None, "detail": "database disabled"}
        engine.fetch_one("SELECT 1")
        return {
            "configured": True,
            "reachable": True,
            "database": str(db_config.DB_CONFIG.get("database") or "unknown"),
            "detail": "read probe passed",
        }
    except Exception as exc:  # noqa: BLE001 - operational boundary
        return {
            "configured": True,
            "reachable": False,
            "database": None,
            "detail": f"read probe failed: {type(exc).__name__}",
        }


def _latest_static_health(data_dir: Path) -> dict[str, Any] | None:
    candidates = sorted((data_dir / "store" / "apk").glob("*_run_health.json"), key=lambda path: path.stat().st_mtime)
    for path in reversed(candidates):
        payload = _read_json(path)
        if not payload:
            continue
        return {
            "path": str(path),
            "session_stamp": payload.get("session_stamp"),
            "workflow_completion_status": payload.get("workflow_completion_status"),
            "db_persistence_status": payload.get("db_persistence_status"),
            "persistence_requested": payload.get("persistence_requested"),
            "persistence_failed": payload.get("outcome_persistence_failed"),
            "finding_fidelity_status": payload.get("finding_fidelity_status"),
            "detector_posture": payload.get("detector_posture"),
            "execution_errors": (payload.get("counts") or {}).get("execution_errors"),
        }
    return None


def _latest_paper_freeze(output_dir: Path) -> dict[str, Any] | None:
    candidates = sorted((output_dir / "paper").glob("*/summary.json"), key=lambda path: path.stat().st_mtime)
    for summary_path in reversed(candidates):
        manifest_path = summary_path.with_name("paper_freeze_manifest.json")
        payload = _read_json(summary_path)
        if not payload or not manifest_path.is_file():
            continue
        return {
            "path": str(summary_path.parent),
            "manifest_path": str(manifest_path),
            "apps_total": payload.get("apps_total"),
            "paper_usable": (payload.get("evidence_tier_summary") or {}).get("paper_usable"),
            "ready": payload.get("ready"),
            "needs_baseline": payload.get("needs_baseline"),
            "needs_interactive": payload.get("needs_interactive"),
        }
    return None


def _tool_records(tool_resolver: Callable[[str], str | None]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for name in _REQUIRED_TOOLS:
        candidates = ("mysqldump", "mariadb-dump") if name == "mysqldump" else (name,)
        resolved_as = next((candidate for candidate in candidates if tool_resolver(candidate)), None)
        records.append({"name": name, "available": bool(resolved_as), "resolved_as": resolved_as})
    return records


def _check(name: str, status: str, detail: str) -> dict[str, str]:
    return {"name": name, "status": status, "detail": detail}


def build_migration_readiness_report(
    repo_root: Path | str,
    *,
    size_resolver: Callable[[Path], int | None] = _directory_size_bytes,
    tool_resolver: Callable[[str], str | None] = shutil.which,
    git_state_loader: Callable[[Path], dict[str, Any]] = collect_git_state,
    database_probe: Callable[[], dict[str, Any]] = _probe_database,
    cold_store_loader: Callable[[Path], Mapping[str, Any]] = _external_cold_store_record,
    alias_loader: Callable[[Path], Mapping[str, Any]] = _dynamic_alias_probe,
    permission_intel_probe: Callable[[], Mapping[str, Any]] = _permission_intel_probe,
    definer_probe: Callable[[], Mapping[str, Any]] = _database_definer_probe,
    handoff_loader: Callable[[], Mapping[str, Any]] | None = None,
    incomplete_loader: Callable[[], Any] | None = None,
    mercury_loader: Callable[[], Any] | None = None,
    destination_root: Path | str | None = None,
    core_database_dump: Path | str | None = None,
    permission_intel_database_dump: Path | str | None = None,
) -> dict[str, Any]:
    """Build a migration preflight report without changing local or DB state."""

    root = Path(repo_root).resolve()
    roots, configured_roots = _transfer_root_records(root, size_resolver=size_resolver)
    data_dir = configured_roots["data"]
    output_dir = configured_roots["output"]
    try:
        cold_store = dict(cold_store_loader(root))
    except Exception as exc:  # noqa: BLE001 - migration preflight must report unavailable data
        cold_store = {"links": 0, "missing": 0, "bytes": 0, "roots": [], "detail": type(exc).__name__}
    footprint = _transfer_footprint(roots, external_cold_bytes=int(cold_store.get("bytes") or 0))
    destination_path = Path(destination_root) if destination_root else None
    destination = _destination_record(destination_path, footprint)
    git = git_state_loader(root)
    environment = _environment_record(root)
    database = database_probe()
    database_exports = {
        "core": _database_export_record(core_database_dump, catalog="core"),
        "permission_intel": _database_export_record(permission_intel_database_dump, catalog="permission_intel"),
    }
    try:
        permission_intel = dict(permission_intel_probe())
    except Exception as exc:  # noqa: BLE001
        permission_intel = {"configured": False, "reachable": False, "detail": type(exc).__name__}
    try:
        definers = dict(definer_probe())
    except Exception as exc:  # noqa: BLE001
        definers = {"core": {"available": False, "definers": [], "detail": type(exc).__name__}}
    try:
        dynamic_aliases = dict(alias_loader(root))
    except Exception as exc:  # noqa: BLE001
        dynamic_aliases = {"available": False, "detail": type(exc).__name__}
    static_manifest_paths = _static_manifest_path_probe(root, evidence_dir=configured_roots["evidence"])
    static_health = _latest_static_health(data_dir)
    paper_freeze = _latest_paper_freeze(output_dir)

    if handoff_loader is None:
        from scytaledroid.DynamicAnalysis.tools.evidence.state_summary import (
            build_static_handoff_plan_summary,
        )

        handoff_loader = build_static_handoff_plan_summary
    if incomplete_loader is None:
        from scytaledroid.DynamicAnalysis.utils.run_cleanup import (
            summarize_incomplete_dynamic_run_dirs,
        )

        incomplete_loader = summarize_incomplete_dynamic_run_dirs
    if mercury_loader is None:
        from scytaledroid.Utils.System.mercury_storage import mercury_storage_status

        mercury_loader = mercury_storage_status

    try:
        handoff = dict(handoff_loader())
    except Exception as exc:  # noqa: BLE001 - preflight must report unavailable subsystems
        handoff = {"error": type(exc).__name__}
    try:
        incomplete = incomplete_loader()
        incomplete_summary = {
            "total_runs": int(getattr(incomplete, "total_runs", 0)),
            "pre_capture_runs": len(getattr(incomplete, "pre_capture_runs", ()) or ()),
            "pcap_artifact_runs": len(getattr(incomplete, "pcap_artifact_runs", ()) or ()),
        }
    except Exception as exc:  # noqa: BLE001
        incomplete_summary = {"error": type(exc).__name__}
    try:
        mercury = mercury_loader()
        mercury_summary = {
            "mounted": bool(getattr(mercury, "mountpoint_mounted", False) or getattr(mercury, "user_media_mounted", False)),
            "mountpoint": str(getattr(mercury, "mountpoint", "unknown")),
            "compatibility_alias_exists": bool(getattr(mercury, "compatibility_alias_exists", False)),
        }
    except Exception as exc:  # noqa: BLE001
        mercury_summary = {"error": type(exc).__name__}

    checks: list[dict[str, str]] = []
    missing_roots = [record["name"] for record in roots if not record["exists"] or not record["readable"]]
    checks.append(
        _check(
            "research corpus roots",
            "blocker" if missing_roots else "ready",
            f"missing or unreadable: {', '.join(missing_roots)}"
            if missing_roots
            else "configured data/output/log roots and static evidence are readable",
        )
    )
    missing_database_exports = [catalog for catalog, export in database_exports.items() if not export["valid"]]
    checks.append(
        _check(
            "database backup artifacts",
            "blocker" if missing_database_exports else "ready",
            (
                "missing or unreadable export(s): "
                f"{', '.join(missing_database_exports)}; create full catalog dumps with views, triggers, routines, and events "
                "then rerun with --core-database-dump and --permission-intel-database-dump"
            )
            if missing_database_exports
            else "; ".join(
                f"{catalog}: {_format_bytes(int(export.get('size_bytes') or 0))}"
                for catalog, export in database_exports.items()
            ),
        )
    )
    portable_workspace, workspace_portability_detail = _workspace_path_portability(root, configured_roots)
    checks.append(
        _check(
            "workspace path portability",
            "ready" if portable_workspace else "warning",
            workspace_portability_detail,
        )
    )
    if destination["configured"]:
        checks.append(
            _check(
                "destination capacity",
                "ready" if destination["capacity_sufficient"] else "blocker",
                str(destination["detail"]),
            )
        )
    static_complete = bool(static_health) and str(static_health.get("workflow_completion_status") or "").lower() == "complete"
    static_persisted = bool(static_health) and static_health.get("persistence_failed") is not True
    checks.append(
        _check(
            "latest static session",
            "ready" if static_complete and static_persisted else "warning",
            "no static run-health file found"
            if static_health is None
            else "workflow complete; persistence did not report failure"
            if static_complete and static_persisted
            else "latest static session needs review before transfer",
        )
    )
    git_clean = git.get("clean") is True
    ahead = int(git.get("ahead") or 0)
    behind = int(git.get("behind") or 0)
    git_detail = (
        "repository not detected"
        if not git.get("repository_detected")
        else "working tree has uncommitted changes"
        if not git_clean
        else f"local branch differs from upstream (ahead={ahead}, behind={behind})"
        if ahead or behind
        else f"{git.get('branch')} @ {git.get('revision')}"
    )
    checks.append(
        _check(
            "git checkpoint",
            "blocker"
            if not git.get("repository_detected")
            else "warning"
            if not git_clean or ahead or behind
            else "ready",
            git_detail,
        )
    )
    checks.append(
        _check(
            "secure configuration",
            "warning" if not environment["present"] or environment["private"] is False else "ready",
            "provision configuration securely on the destination" if not environment["present"] else "restrict .env before transfer" if environment["private"] is False else ".env present with owner-only permissions",
        )
    )
    checks.append(
        _check(
            "database export source",
            "ready" if database.get("reachable") else "blocker",
            str(database.get("detail") or "unknown"),
        )
    )
    cold_missing = int(cold_store.get("missing") or 0)
    cold_links = int(cold_store.get("links") or 0)
    checks.append(
        _check(
            "external cold APK store",
            "blocker" if cold_missing else "ready",
            f"{cold_missing}/{cold_links} external APK target(s) unavailable"
            if cold_missing
            else f"{cold_links} external APK target(s), {_format_bytes(int(cold_store.get('bytes') or 0))} outside repository corpus roots",
        )
    )
    permission_intel_ready = bool(permission_intel.get("configured")) and bool(permission_intel.get("reachable"))
    checks.append(
        _check(
            "Permission Intel export source",
            "ready" if permission_intel_ready else "warning",
            str(permission_intel.get("detail") or "catalog must be configured and restored separately"),
        )
    )
    definer_sources = [
        f"{catalog}: {', '.join(str(value) for value in detail.get('definers') or ()) or 'none'}"
        for catalog, detail in definers.items()
        if isinstance(detail, Mapping) and detail.get("available")
    ]
    unavailable_definer_sources = [
        catalog
        for catalog, detail in definers.items()
        if not isinstance(detail, Mapping) or not detail.get("available")
    ]
    checks.append(
        _check(
            "database definer prerequisites",
            "warning" if unavailable_definer_sources else "ready",
            f"unavailable source inventory: {', '.join(unavailable_definer_sources)}"
            if unavailable_definer_sources
            else "; ".join(definer_sources) or "no view, trigger, routine, or event definers found",
        )
    )
    alias_issues = sum(int(dynamic_aliases.get(name) or 0) for name in ("missing", "stale", "conflicts", "orphaned"))
    absolute_aliases = int(dynamic_aliases.get("absolute_targets") or 0)
    checks.append(
        _check(
            "dynamic compatibility aliases",
            "warning" if not dynamic_aliases.get("available") or alias_issues or absolute_aliases else "ready",
            str(dynamic_aliases.get("detail") or "alias inspection unavailable")
            if not dynamic_aliases.get("available")
            else (
                f"canonical={dynamic_aliases.get('canonical_runs', 0)}, valid={dynamic_aliases.get('valid', 0)}, "
                f"missing={dynamic_aliases.get('missing', 0)}, stale={dynamic_aliases.get('stale', 0)}, "
                f"conflicts={dynamic_aliases.get('conflicts', 0)}, orphaned={dynamic_aliases.get('orphaned', 0)}, "
                f"absolute_targets={absolute_aliases}; "
                "run scripts/dynamic/rebuild_dynamic_evidence_aliases.py --apply --prune-orphans after restore"
            )
            if alias_issues or absolute_aliases
            else f"{dynamic_aliases.get('canonical_runs', 0)} canonical aliases resolve",
        )
    )
    manifests_with_source_paths = int(static_manifest_paths.get("source_path_manifests") or 0)
    checks.append(
        _check(
            "static manifest path portability",
            "warning" if not static_manifest_paths.get("available") or manifests_with_source_paths else "ready",
            str(static_manifest_paths.get("detail") or "static manifest inspection unavailable")
            if not static_manifest_paths.get("available")
            else (
                f"{manifests_with_source_paths}/{static_manifest_paths.get('manifests', 0)} static manifests retain "
                "source-host paths; preserve them as immutable provenance and use transferred evidence roots for navigation"
            )
            if manifests_with_source_paths
            else f"{static_manifest_paths.get('manifests', 0)} static manifests have no source-host path residue",
        )
    )
    plan_ready = bool(handoff.get("ready_for_guided_dataset_run"))
    checks.append(
        _check(
            "static-to-dynamic handoff",
            "ready" if plan_ready else "warning",
            f"{handoff.get('dataset_packages_with_plan', 0)}/{handoff.get('dataset_packages_total', 0)} cohort plans ready" if "error" not in handoff else f"unavailable: {handoff['error']}",
        )
    )
    pcap_incomplete = int(incomplete_summary.get("pcap_artifact_runs") or 0)
    checks.append(
        _check(
            "incomplete dynamic evidence",
            "warning" if pcap_incomplete else "ready",
            f"{pcap_incomplete} incomplete pack(s) contain PCAP artifacts; preserve and classify before move" if pcap_incomplete else "no incomplete packs with PCAP artifacts",
        )
    )
    checks.append(
        _check(
            "paper-freeze cutoff",
            "warning" if paper_freeze is None else "ready",
            "no paired paper-freeze manifest found" if paper_freeze is None else f"{paper_freeze.get('paper_usable', 0)}/{paper_freeze.get('apps_total', 0)} apps paper-usable in latest freeze",
        )
    )
    unavailable_tools = [row["name"] for row in _tool_records(tool_resolver) if not row["available"]]
    checks.append(
        _check(
            "destination tool baseline",
            "warning" if unavailable_tools else "ready",
            f"missing locally: {', '.join(unavailable_tools)}" if unavailable_tools else "git, transfer, DB dump, ADB, and PCAP tools available",
        )
    )

    blockers = [check["detail"] for check in checks if check["status"] == "blocker"]
    warnings = [check["detail"] for check in checks if check["status"] == "warning"]
    overall_status = "BLOCKED" if blockers else "READY_WITH_WARNINGS" if warnings else "READY"
    return {
        "kind": "scytaledroid_system_migration_readiness_v1",
        "generated_at_utc": _utc_now(),
        "read_only": True,
        "overall_status": overall_status,
        "blockers": blockers,
        "warnings": warnings,
        "checks": checks,
        "repository": git,
        "transfer_roots": roots,
        "transfer_footprint": footprint,
        "destination": destination,
        "rsync_command_templates": _rsync_command_templates(roots, destination_path),
        "cold_store_rsync_command_templates": _cold_store_rsync_templates(cold_store),
        "environment": environment,
        "database": database,
        "database_exports": database_exports,
        "permission_intel": permission_intel,
        "database_definers": definers,
        "external_cold_store": cold_store,
        "dynamic_aliases": dynamic_aliases,
        "static_manifest_paths": static_manifest_paths,
        "tools": _tool_records(tool_resolver),
        "static_health": static_health,
        "static_dynamic_handoff": handoff,
        "incomplete_dynamic_evidence": incomplete_summary,
        "paper_freeze": paper_freeze,
        "mercury": mercury_summary,
        "migration_steps": [
            "Commit and push the checked repository state, then clone the recorded branch/revision on the destination.",
            "Stop active capture/harvest work, then copy data, output, logs, and the external cold APK store with metadata-preserving tooling such as rsync; verify byte totals after transfer.",
            "Export and restore both MariaDB catalogs separately, including views, triggers, routines, and events; pass both dump paths to this report and provision or remap the listed source definer accounts.",
            "Provision destination configuration securely. Preserve the Mercury mount path, or set SCYTALEDROID_EXTERNAL_APK_STORE_MOUNT_ROOTS and use scripts/device_analysis/retarget_cold_apk_symlinks.py in dry-run mode before applying it.",
            "Run ./setup.sh (or SCYTALEDROID_SETUP_ANDROID=1 ./setup.sh for capture hosts), then rebuild dynamic aliases with scripts/dynamic/rebuild_dynamic_evidence_aliases.py --apply --prune-orphans. Existing static manifests are immutable provenance; do not rewrite source-host path fields.",
            "Run ./run.sh --new-system-check --require-database, this preflight, and the paper-freeze report again on the destination.",
        ],
    }


def render_migration_readiness_report(report: Mapping[str, Any]) -> str:
    """Render a compact human-readable migration checkpoint."""

    lines = ["System Migration Readiness (read-only)", "=" * 42, f"Overall: {report.get('overall_status', 'UNKNOWN')}"]
    repository = report.get("repository") or {}
    lines.append(f"Git: {repository.get('branch', 'unknown')} @ {repository.get('revision', 'unknown')} | clean={repository.get('clean', 'unknown')}")
    lines.extend(("", "Research corpus roots to transfer:"))
    for root in report.get("transfer_roots") or []:
        lines.append(f"- {root.get('name')}: {_format_bytes(root.get('size_bytes'))} | {root.get('path')}")
    footprint = report.get("transfer_footprint") or {}
    lines.append(
        "Filesystem transfer estimate: "
        f"{_format_bytes(footprint.get('source_bytes'))} source | "
        f"{_format_bytes(footprint.get('recommended_free_bytes'))} recommended free capacity "
        f"({int(float(footprint.get('headroom_ratio') or 0) * 100)}% headroom; DB export additional)"
    )
    cold_store = report.get("external_cold_store") or {}
    lines.append(
        "External cold APK store: "
        f"{cold_store.get('links', 0)} target(s) | {_format_bytes(cold_store.get('bytes'))} | "
        f"missing={cold_store.get('missing', 0)}"
    )
    destination = report.get("destination") or {}
    if destination.get("configured"):
        lines.append(
            "Destination: "
            f"{destination.get('path')} | free={_format_bytes(destination.get('free_bytes'))} | "
            f"capacity_sufficient={destination.get('capacity_sufficient')}"
        )
    database = report.get("database") or {}
    lines.append(f"Database: {'reachable' if database.get('reachable') else 'not reachable'} | {database.get('detail', 'unknown')}")
    database_exports = report.get("database_exports") or {}
    lines.append(
        "Database exports: "
        + "; ".join(
            f"{catalog}={'ready' if export.get('valid') else 'missing'}"
            for catalog, export in database_exports.items()
        )
    )
    permission_intel = report.get("permission_intel") or {}
    lines.append(
        "Permission Intel: "
        f"{'reachable' if permission_intel.get('reachable') else 'not reachable'} | "
        f"{permission_intel.get('detail', 'unknown')}"
    )
    handoff = report.get("static_dynamic_handoff") or {}
    lines.append(f"Static-to-dynamic: {handoff.get('dataset_packages_with_plan', 0)}/{handoff.get('dataset_packages_total', 0)} plans ready")
    static_health = report.get("static_health") or {}
    if static_health:
        lines.append(
            "Latest static session: "
            f"{static_health.get('session_stamp', 'unknown')} | "
            f"workflow={static_health.get('workflow_completion_status', 'unknown')} | "
            f"fidelity={static_health.get('finding_fidelity_status', 'unknown')} | "
            f"posture={static_health.get('detector_posture', 'unknown')}"
        )
    freeze = report.get("paper_freeze") or {}
    if freeze:
        lines.append(f"Latest paper freeze: {freeze.get('paper_usable', 0)}/{freeze.get('apps_total', 0)} paper-usable apps | {freeze.get('path')}")
    else:
        lines.append("Latest paper freeze: not found")
    for check in report.get("checks") or []:
        if check.get("status") != "ready":
            lines.append(f"{str(check.get('status', 'warning')).upper()}: {check.get('name')} - {check.get('detail')}")
    lines.extend(("", "Rsync command templates (review before use):"))
    lines.extend(f"- {command}" for command in report.get("rsync_command_templates") or [])
    cold_commands = report.get("cold_store_rsync_command_templates") or []
    if cold_commands:
        lines.extend(("", "External cold APK store transfer (choose a destination mount path):"))
        lines.extend(f"- {command}" for command in cold_commands)
    lines.extend(("", "Next steps:"))
    lines.extend(f"- {step}" for step in report.get("migration_steps") or [])
    return "\n".join(lines) + "\n"


__all__ = ["build_migration_readiness_report", "collect_git_state", "render_migration_readiness_report"]
