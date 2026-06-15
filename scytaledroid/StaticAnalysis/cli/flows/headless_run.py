"""Headless static analysis entrypoint (non-interactive).

Approved for deterministic runs (CI/demo) without menu interaction.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
from pathlib import Path
from typing import Any

from scytaledroid.Database.db_utils import schema_gate
from scytaledroid.Database.db_func.research_cohorts import (
    fetch_research_cohort,
    normalize_research_cohort_key,
    profile_key_for_research_cohort,
)
from scytaledroid.DeviceAnalysis.services import artifact_store
from scytaledroid.DynamicAnalysis.profile_loader import load_profile_packages
from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.cli.core.run_specs import build_static_run_spec
from scytaledroid.StaticAnalysis.cli.flows.research_cohort import prepare_research_cohort_scope
from scytaledroid.StaticAnalysis.cli.flows.exact_target import (
    ExactTargetResolutionError,
    count_linkable_dynamic_sessions_for_hash,
    resolve_exact_static_target,
    write_exact_target_receipt,
)
from scytaledroid.StaticAnalysis.cli.flows.run_dispatch import execute_run_spec
from scytaledroid.StaticAnalysis.cli.flows.session_uniqueness import (
    check_session_uniqueness as _check_session_uniqueness,
)
from scytaledroid.StaticAnalysis.core.repository import (
    ArtifactGroup,
    RepositoryArtifact,
    _load_metadata,
    group_artifacts,
)
from scytaledroid.StaticAnalysis.session import normalize_session_stamp
from scytaledroid.Utils.System import output_prefs


def _artifact_group_from_path(apk_path: Path) -> ArtifactGroup:
    meta = _resolve_artifact_metadata(apk_path, _load_metadata(apk_path))
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


def _resolve_artifact_metadata(apk_path: Path, metadata: dict[str, Any] | object) -> dict[str, object]:
    resolved = dict(metadata) if isinstance(metadata, dict) else dict(metadata or {})
    if all(resolved.get(field) for field in ("package_name", "version_code", "version_name")):
        return resolved
    try:
        from scytaledroid.StaticAnalysis.core.resource_fallback import open_apk_with_fallback

        fallback = open_apk_with_fallback(apk_path)
    except Exception:
        return resolved

    apk = getattr(fallback, "apk", None)
    if apk is not None:
        try:
            package_name = apk.get_package()
        except Exception:
            package_name = None
        try:
            version_code = apk.get_androidversion_code()
        except Exception:
            version_code = None
        try:
            version_name = apk.get_androidversion_name()
        except Exception:
            version_name = None
        try:
            app_label = apk.get_app_name()
        except Exception:
            app_label = None
        if package_name and not resolved.get("package_name"):
            resolved["package_name"] = str(package_name)
        if version_code and not resolved.get("version_code"):
            resolved["version_code"] = str(version_code)
        if version_name and not resolved.get("version_name"):
            resolved["version_name"] = str(version_name)
        if app_label and not resolved.get("app_label"):
            resolved["app_label"] = str(app_label)

    fallback_meta = getattr(fallback, "fallback_meta", None) or {}
    for key in ("package_name", "version_code", "version_name", "app_label"):
        value = fallback_meta.get(key)
        if value and not resolved.get(key):
            resolved[key] = str(value)
    return resolved


def _run_single_apk(
    *,
    apk_path: Path,
    session: str | None,
    scope_label: str | None,
    profile: str,
    allow_session_reuse: bool,
    dry_run: bool,
) -> int:
    group = _artifact_group_from_path(apk_path)
    resolved_scope_label = scope_label or group.package_name
    selection = ScopeSelection(scope="app", label=resolved_scope_label, groups=(group,))

    params = RunParameters(
        profile=profile,
        scope="app",
        scope_label=resolved_scope_label,
        dry_run=dry_run,
        paper_grade_requested=False,
    )
    if session:
        params = replace(params, session_stamp=session, session_label=session)
    if params.session_stamp:
        normalized = normalize_session_stamp(params.session_stamp)
        if normalized != params.session_stamp:
            params = replace(params, session_stamp=normalized, session_label=normalized)

    _check_session_uniqueness(
        params.session_stamp,
        group.package_name,
        allow_session_reuse,
        dry_run=params.dry_run,
    )
    base_dir = artifact_store.analysis_apk_root()
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


def _run_exact_target(
    *,
    apk_id: str | None,
    base_apk_sha256: str | None,
    session: str | None,
    scope_label: str | None,
    profile: str,
    include_splits: str,
    allow_session_reuse: bool,
    dry_run: bool,
) -> int:
    try:
        target = resolve_exact_static_target(
            apk_id=apk_id,
            base_apk_sha256=base_apk_sha256,
            include_splits=include_splits,  # type: ignore[arg-type]
        )
    except ExactTargetResolutionError as exc:
        raise SystemExit(f"Exact target resolution failed: {exc}") from exc

    receipt_path = write_exact_target_receipt(
        target,
        source_worklist_bucket="dynamic_static_alignment",
    )
    resolved_scope_label = scope_label or target.selection.label
    selection = ScopeSelection(
        scope=target.selection.scope,
        label=resolved_scope_label,
        groups=target.selection.groups,
        selection_rule_summary=target.selection.selection_rule_summary,
    )
    params = RunParameters(
        profile=profile,
        scope=selection.scope,
        scope_label=selection.label,
        dry_run=dry_run,
        paper_grade_requested=False,
    )
    if session:
        params = replace(params, session_stamp=session, session_label=session)
    if params.session_stamp:
        normalized = normalize_session_stamp(params.session_stamp)
        if normalized != params.session_stamp:
            params = replace(params, session_stamp=normalized, session_label=normalized)

    _check_session_uniqueness(
        params.session_stamp,
        target.package_name,
        allow_session_reuse,
        dry_run=params.dry_run,
    )

    print("Exact static target preflight")
    print(f"  package           : {target.package_name}")
    print(f"  apk_id            : {target.apk_id or 'unknown'}")
    print(f"  expected hash     : {target.expected_base_sha256}")
    print(f"  actual hash       : {target.actual_base_sha256} (verified)")
    print(f"  split mode        : {target.split_mode}")
    print(f"  split members     : {target.split_count}")
    print(f"  artifacts verified: {len(target.artifacts)}")
    print(f"  receipt           : {receipt_path}")

    base_dir = artifact_store.analysis_apk_root()
    spec = build_static_run_spec(
        selection=selection,
        params=params,
        base_dir=base_dir,
        run_mode="batch",
        quiet=True,
        noninteractive=True,
    )
    execute_run_spec(spec)
    linkable = count_linkable_dynamic_sessions_for_hash(target.expected_base_sha256)
    if linkable is not None:
        print(
            f"{linkable} dynamic session(s) may now be linkable by exact hash. "
            "Run dynamic link repair preview to verify."
        )
    print(
        "Static analysis completed: "
        f"session={params.session_stamp} package={target.package_name} exact_hash={target.expected_base_sha256[:12]}..."
    )
    return 0
def _display_name_for_cohort(cohort_key: str, legacy_profile_key: str | None = None) -> str:
    row = fetch_research_cohort(cohort_key)
    if isinstance(row, dict):
        display_name = str(row.get("display_name") or "").strip()
        if display_name:
            return display_name
    profile_key = str(legacy_profile_key or profile_key_for_research_cohort(cohort_key) or "").strip()
    if profile_key:
        return profile_key.replace("_", " ").title()
    return str(cohort_key or "Research cohort").replace("_", " ").title()


def _cohort_key_from_legacy_profile_key(profile_key: str | None) -> str | None:
    normalized = normalize_research_cohort_key(profile_key)
    if normalized and normalized.startswith("research_dataset_"):
        return normalized
    return None


def _run_research_cohort(
    *,
    cohort_key: str,
    session: str,
    profile: str,
    allow_session_reuse: bool,
    dry_run: bool,
    legacy_profile_key: str | None = None,
) -> int:
    base_dir = artifact_store.analysis_apk_root()
    groups = tuple(group_artifacts())
    prepared = prepare_research_cohort_scope(groups, cohort_key)
    fallback_display_name: str | None = None
    if prepared is None and legacy_profile_key:
        dataset_pkgs = {pkg.lower() for pkg in load_profile_packages(legacy_profile_key)}
        if dataset_pkgs:
            by_pkg: dict[str, ArtifactGroup] = {}
            for group in groups:
                pkg = str(getattr(group, "package_name", "")).lower()
                if not pkg or pkg not in dataset_pkgs:
                    continue
                if pkg not in by_pkg:
                    by_pkg[pkg] = group
            selected = tuple(by_pkg[pkg] for pkg in sorted(by_pkg.keys()))
            prepared = ScopeSelection(
                scope="research_cohort",
                label=_display_name_for_cohort(cohort_key, legacy_profile_key),
                groups=selected,
            )
            fallback_display_name = _display_name_for_cohort(cohort_key, legacy_profile_key)
    if prepared is None:
        raise SystemExit(f"Research cohort {cohort_key} is not available.")
    if isinstance(prepared, ScopeSelection):
        selection = prepared
        selection_label = fallback_display_name or prepared.label
    else:
        selection = prepared.selection
        selection_label = str(prepared.display_name)
    selected = tuple(selection.groups)
    if not selected:
        raise SystemExit(
            f"No local artifact groups found for {cohort_key} in the canonical receipt store."
        )

    cohort_session = normalize_session_stamp(session)
    for group in selected:
        pkg = str(group.package_name)
        _check_session_uniqueness(cohort_session, pkg, allow_session_reuse, dry_run=dry_run)

    params = RunParameters(
        profile=profile,
        scope=selection.scope,
        scope_label=selection_label,
        session_stamp=cohort_session,
        session_label=cohort_session,
        canonical_action="first_run",
        dry_run=dry_run,
    )
    spec = build_static_run_spec(
        selection=selection,
        params=params,
        base_dir=base_dir,
        run_mode="batch",
        quiet=True,
        noninteractive=True,
    )
    execute_run_spec(spec)
    print(
        "Static analysis completed: "
        f"session={cohort_session} research_cohort={cohort_key} apps={len(selected)}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Headless static analysis runner")
    parser.add_argument("--apk", help="Path to APK file")
    parser.add_argument("--apk-id", help="android_apk_repository.apk_id for exact-hash static analysis")
    parser.add_argument("--base-apk-sha256", "--exact-hash", dest="base_apk_sha256", help="Exact base APK SHA-256 to analyze")
    parser.add_argument(
        "--include-splits",
        default="auto",
        choices=["auto", "base-only", "require"],
        help="Exact target split handling: auto uses receipt-backed group; base-only must be explicit.",
    )
    parser.add_argument(
        "--profile-key",
        help="Legacy alias for --research-cohort-key <cohort_key>; accepts research_dataset_* values.",
    )
    parser.add_argument(
        "--research-cohort-key",
        help="Run a deterministic DB-backed research cohort headlessly.",
    )
    parser.add_argument("--session", help="Session stamp (defaults to generated)")
    parser.add_argument("--scope-label", help="Scope label (defaults to package name)")
    parser.add_argument(
        "--profile",
        default="full",
        choices=["full", "permissions", "metadata", "lightweight", "split"],
        help="Static analysis profile",
    )
    parser.add_argument("--dry-run", action="store_true", help="Run analysis without database persistence")
    parser.add_argument("--allow-session-reuse", action="store_true", help="Permit reusing an existing session stamp")
    args = parser.parse_args(argv)
    exact_mode = bool(args.apk_id or args.base_apk_sha256)
    selected_modes = sum(
        1 for enabled in (bool(args.apk), bool(args.profile_key), bool(args.research_cohort_key), exact_mode) if enabled
    )
    if selected_modes != 1:
        raise SystemExit(
            "Choose exactly one mode: --apk <path> OR --profile-key research_dataset_* "
            "OR --research-cohort-key <cohort_key> "
            "OR --apk-id/--base-apk-sha256 exact target."
        )

    if not args.dry_run:
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
        cohort_key = _cohort_key_from_legacy_profile_key(str(args.profile_key).strip())
        if not cohort_key:
            raise SystemExit(
                "--profile-key is a legacy research cohort alias and must be a research_dataset_* key."
            )
        return _run_research_cohort(
            cohort_key=cohort_key,
            session=args.session,
            profile=args.profile,
            allow_session_reuse=args.allow_session_reuse,
            dry_run=args.dry_run,
            legacy_profile_key=str(args.profile_key).strip().upper(),
        )
    if args.research_cohort_key:
        if not args.session:
            raise SystemExit("--session is required when using --research-cohort-key for deterministic cohort runs.")
        return _run_research_cohort(
            cohort_key=str(args.research_cohort_key).strip(),
            session=args.session,
            profile=args.profile,
            allow_session_reuse=args.allow_session_reuse,
            dry_run=args.dry_run,
            legacy_profile_key="RESEARCH_DATASET_ALPHA"
            if str(args.research_cohort_key).strip().lower() == "research_dataset_alpha"
            else None,
        )
    if exact_mode:
        return _run_exact_target(
            apk_id=args.apk_id,
            base_apk_sha256=args.base_apk_sha256,
            session=args.session,
            scope_label=args.scope_label,
            profile=args.profile,
            include_splits=args.include_splits,
            allow_session_reuse=args.allow_session_reuse,
            dry_run=args.dry_run,
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
        dry_run=args.dry_run,
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
