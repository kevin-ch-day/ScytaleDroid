"""Headless static analysis entrypoint (non-interactive).

Approved for deterministic runs (CI/demo) without menu interaction.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.core.repository import (
    ArtifactGroup,
    RepositoryArtifact,
    _load_metadata,
)
from scytaledroid.StaticAnalysis.services import static_service
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Headless static analysis runner")
    parser.add_argument("--apk", required=True, help="Path to APK file")
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

    # Headless runs must not prompt for interactive "next view" choices at the end
    # of the scan. This preference is process-local and does not affect the
    # interactive menu UI.
    output_prefs.set_noninteractive(True)
    output_prefs.set_run_mode("batch")

    apk_path = Path(args.apk).expanduser().resolve()
    if not apk_path.exists():
        raise SystemExit(f"APK not found: {apk_path}")

    group = _artifact_group_from_path(apk_path)
    scope_label = args.scope_label or group.package_name
    selection = ScopeSelection(scope="app", label=scope_label, groups=(group,))

    params = RunParameters(
        profile=args.profile,
        scope="app",
        scope_label=scope_label,
    )
    if args.session:
        params = params.__class__(**{**params.__dict__, "session_stamp": args.session})

    if params.session_stamp:
        normalized = normalize_session_stamp(params.session_stamp)
        if normalized != params.session_stamp:
            print(
                
                    "⚠ Session label normalized for cross-table compatibility "
                    f"({len(params.session_stamp)}→{len(normalized)} chars): "
                    f"'{params.session_stamp}' → '{normalized}'."
                
            )
            params = params.__class__(**{**params.__dict__, "session_stamp": normalized})

    if args.allow_session_reuse:
        print(
            "⚠ Session reuse enabled — reproducibility risk (may mix previous results)."
        )

    _check_session_uniqueness(params.session_stamp, group.package_name, args.allow_session_reuse)

    base_dir = Path(app_config.DATA_DIR) / "device_apks"
    try:
        static_service.run_scan(selection, params, base_dir)
    except Exception as exc:
        raise SystemExit(f"Static analysis failed: {exc}") from exc
    print(f"Static analysis completed: session={params.session_stamp} package={group.package_name}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
