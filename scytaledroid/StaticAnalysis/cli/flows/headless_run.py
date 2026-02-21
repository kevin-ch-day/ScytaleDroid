"""Headless static analysis entrypoint (non-interactive).

Approved for deterministic runs (CI/demo) without menu interaction.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Database.db_utils import schema_gate
from scytaledroid.DynamicAnalysis.profile_loader import load_profile_packages
from scytaledroid.StaticAnalysis.cli.core.run_specs import build_static_run_spec
from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.cli.flows.run_dispatch import execute_run_spec
from scytaledroid.StaticAnalysis.core.repository import (
    ArtifactGroup,
    RepositoryArtifact,
    group_artifacts,
    _load_metadata,
)
from scytaledroid.StaticAnalysis.session import normalize_session_stamp
from scytaledroid.Utils.System import output_prefs
from scytaledroid.Utils.LoggingUtils import logging_utils as log

try:  # optional during offline runs
    from scytaledroid.Database.db_core import db_queries as core_q
except Exception:  # pragma: no cover - offline mode
    core_q = None


def _artifact_group_from_path(apk_path: Path) -> ArtifactGroup:
    meta = _load_metadata(apk_path)
    artifact = RepositoryArtifact(apk_path, apk_path.name, meta)
    group_key = f"{artifact.package_name}:{artifact.version_display}"
    return ArtifactGroup(
        group_key=group_key,
        package_name=artifact.package_name,
        version_display=artifact.version_display,
        session_stamp=artifact.session_stamp,
        capture_id=artifact.capture_id,
        artifacts=(artifact,),
    )


def _check_session_uniqueness(session_stamp: str, package_name: str, allow_reuse: bool) -> None:
    if allow_reuse or core_q is None:
        return
    try:
        rows = core_q.run_sql(
            """
            SELECT sar.id
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            WHERE sar.session_stamp = %s
              AND a.package_name = %s
            """,
            (session_stamp, package_name),
            fetch="all",
        )
        if rows:
            raise SystemExit(
                f"Session '{session_stamp}' for package '{package_name}' already exists "
                "(static_analysis_runs). Use a new --session or --allow-session-reuse explicitly."
            )
    except SystemExit:
        raise
    except Exception as exc:  # pragma: no cover - DB optional
        log.warning(f"Session uniqueness check failed (skipping): {exc}", category="static")


def _run_single_apk(*, apk_path: Path, session: str | None, scope_label: str | None, profile: str, allow_session_reuse: bool) -> int:
    group = _artifact_group_from_path(apk_path)
    resolved_scope_label = scope_label or group.package_name
    selection = ScopeSelection(scope="app", label=resolved_scope_label, groups=(group,))

    params = RunParameters(
        profile=profile,
        scope="app",
        scope_label=resolved_scope_label,
    )
    if session:
        params = params.__class__(**{**params.__dict__, "session_stamp": session, "session_label": session})
    if params.session_stamp:
        normalized = normalize_session_stamp(params.session_stamp)
        if normalized != params.session_stamp:
            params = params.__class__(**{**params.__dict__, "session_stamp": normalized, "session_label": normalized})

    _check_session_uniqueness(params.session_stamp, group.package_name, allow_session_reuse)
    base_dir = Path(app_config.DATA_DIR) / "device_apks"
    spec = build_static_run_spec(
        selection=selection,
        params=params,
        base_dir=base_dir,
        run_mode="batch",
        quiet=True,
        noninteractive=True,
    )
    execute_run_spec(spec)
    print(f"Static analysis completed: session={params.session_stamp} package={group.package_name}")
    return 0


def _run_dataset_alpha(*, session: str, profile: str, allow_session_reuse: bool) -> int:
    base_dir = Path(app_config.DATA_DIR) / "device_apks"
    groups = tuple(group_artifacts(base_dir))
    dataset_pkgs = {pkg.lower() for pkg in load_profile_packages("RESEARCH_DATASET_ALPHA")}
    if not dataset_pkgs:
        raise SystemExit("Profile RESEARCH_DATASET_ALPHA has no packages.")
    selected: list[ArtifactGroup] = []
    by_pkg: dict[str, ArtifactGroup] = {}
    for group in groups:
        pkg = str(getattr(group, "package_name", "")).lower()
        if not pkg or pkg not in dataset_pkgs:
            continue
        if pkg not in by_pkg:
            by_pkg[pkg] = group
    selected = [by_pkg[pkg] for pkg in sorted(by_pkg.keys())]
    if not selected:
        raise SystemExit(f"No local artifact groups found for RESEARCH_DATASET_ALPHA under {base_dir}")

    failures = 0
    for group in selected:
        pkg = str(group.package_name)
        app_session = normalize_session_stamp(f"{session}-{pkg}")
        _check_session_uniqueness(app_session, pkg, allow_session_reuse)
        selection = ScopeSelection(scope="app", label=pkg, groups=(group,))
        params = RunParameters(
            profile=profile,
            scope="app",
            scope_label=pkg,
            session_stamp=app_session,
            session_label=app_session,
            canonical_action="first_run",
        )
        spec = build_static_run_spec(
            selection=selection,
            params=params,
            base_dir=base_dir,
            run_mode="batch",
            quiet=True,
            noninteractive=True,
        )
        try:
            execute_run_spec(spec)
            print(f"[OK] {pkg} session={app_session}")
        except Exception as exc:
            failures += 1
            print(f"[FAIL] {pkg} session={app_session} error={exc}")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Headless static analysis runner")
    parser.add_argument("--apk", help="Path to APK file")
    parser.add_argument(
        "--profile-key",
        choices=["research_dataset_alpha"],
        help="Run a deterministic cohort profile headlessly.",
    )
    parser.add_argument("--session", help="Session stamp (defaults to generated)")
    parser.add_argument("--scope-label", help="Scope label (defaults to package name)")
    parser.add_argument(
        "--profile",
        default="full",
        choices=["full", "permissions", "metadata", "lightweight", "split"],
        help="Static analysis profile",
    )
    parser.add_argument("--allow-session-reuse", action="store_true", help="Permit reusing an existing session stamp")
    args = parser.parse_args(argv)
    if bool(args.apk) == bool(args.profile_key):
        raise SystemExit("Choose exactly one mode: --apk <path> OR --profile-key research_dataset_alpha")

    ok, message, detail = schema_gate.static_schema_gate()
    if not ok:
        extra = f" ({detail})" if detail else ""
        raise SystemExit(f"Static schema gate failed: {message}{extra}")

    # Headless runs must not prompt for interactive "next view" choices at the end
    # of the scan. This preference is process-local and does not affect the
    # interactive menu UI.
    output_prefs.set_noninteractive(True)
    output_prefs.set_run_mode("batch")
    if args.allow_session_reuse:
        print("⚠ Session reuse enabled — reproducibility risk (may mix previous results).")
    if args.profile_key:
        if not args.session:
            raise SystemExit("--session is required when using --profile-key for deterministic cohort runs.")
        return _run_dataset_alpha(
            session=args.session,
            profile=args.profile,
            allow_session_reuse=args.allow_session_reuse,
        )
    apk_path = Path(str(args.apk)).expanduser().resolve()
    if not apk_path.exists():
        raise SystemExit(f"APK not found: {apk_path}")
    return _run_single_apk(
        apk_path=apk_path,
        session=args.session,
        scope_label=args.scope_label,
        profile=args.profile,
        allow_session_reuse=args.allow_session_reuse,
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
