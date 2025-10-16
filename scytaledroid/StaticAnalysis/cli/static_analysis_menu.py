"""Interactive menu for APK static analysis workflows."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime
import logging
from pathlib import Path
from time import perf_counter
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence, Tuple

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import (
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
)
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.LoggingUtils.logging_engine import (
    configure_third_party_loggers,
)

from ..core import (
    AnalysisConfig,
    StaticAnalysisError,
    StaticAnalysisReport,
    analyze_apk,
)
from ..engine.strings import analyse_strings
from ..core.findings import EvidencePointer, Finding, SeverityLevel
from ..core.repository import (
    ArtifactGroup,
    RepositoryArtifact,
    group_artifacts,
    list_categories,
    list_packages,
)
from ..persistence import ReportStorageError, save_report
from ..modules.permissions import (
    collect_permissions_and_sdk,
    print_permissions_block,
)
from ..modules.permissions.render_postcard import render as render_permission_postcard
from ..modules.permissions.render_summary import render as render_after_run_summary
from ..modules.permissions.render_matrix import (
    render_signals as render_signal_matrix,
)
from ..modules.permissions.audit import PermissionAuditAccumulator
from .renderer import render_app_result, write_baseline_json
from .sections import SECTION_DEFINITIONS, extract_integrity_profiles


_SECTION_TITLE_LOOKUP = {
    definition.key: definition.title for definition in SECTION_DEFINITIONS
}

_SEVERITY_LABELS: Mapping[SeverityLevel, Tuple[str, str]] = {
    SeverityLevel.P0: ("High", "H"),
    SeverityLevel.P1: ("Med", "M"),
    SeverityLevel.P2: ("Low", "L"),
    SeverityLevel.NOTE: ("Info", "I"),
}

_SEVERITY_TOKEN_ORDER = ("H", "M", "L", "I")

_PROFILE_LABELS: Mapping[str, str] = {
    "metadata": "Metadata",
    "permissions": "Permission analysis",
    "lightweight": "Lightweight",
    "full": "Full",
    "split": "Split-APK composition",
    "custom": "Custom",
}

_MICRO_TESTS: Tuple[Tuple[str, str], ...] = (
    ("manifest", "Manifest-only"),
    ("provider_acl", "Provider ACL only"),
    ("nsc", "NSC only"),
    ("webview", "WebView quick"),
    ("secrets", "Secrets sampler"),
)

_EVIDENCE_STEPS = (1, 2, 4)


@dataclass(frozen=True)
class ScopeSelection:
    """Represents the scope of a static-analysis run."""

    scope: str
    label: str
    groups: Tuple[ArtifactGroup, ...]


@dataclass(frozen=True)
class RunParameters:
    """User-facing configuration for an analysis run."""

    profile: str
    scope: str
    scope_label: str
    selected_tests: Tuple[str, ...] = tuple()
    evidence_lines: int = 2
    finding_limit: int = 25
    secrets_entropy: float = 4.5
    secrets_hits_per_bucket: int = 40
    secrets_scope: str = "resources"
    workers: str = "auto"
    reuse_cache: bool = True
    log_level: str = "info"
    trace_detectors: Tuple[str, ...] = tuple()
    dry_run: bool = False

    @property
    def profile_label(self) -> str:
        return _PROFILE_LABELS.get(self.profile, self.profile.title())


@dataclass
class ArtifactOutcome:
    """Stores report metadata for an analysed artifact."""

    label: str
    report: StaticAnalysisReport
    severity: Counter[str]
    duration_seconds: float
    saved_path: Optional[str]
    started_at: datetime
    finished_at: datetime


@dataclass
class AppRunResult:
    """Aggregated findings for a package across base + splits."""

    package_name: str
    category: str
    artifacts: list[ArtifactOutcome] = field(default_factory=list)
    signer: Optional[str] = None

    def severity_totals(self) -> Counter[str]:
        totals: Counter[str] = Counter()
        for artifact in self.artifacts:
            totals.update(artifact.severity)
        return totals

    def base_report(self) -> Optional[StaticAnalysisReport]:
        for artifact in self.artifacts:
            _, _, artifact_profile, _ = extract_integrity_profiles(artifact.report)
            role = str((artifact_profile or {}).get("role") or "").lower()
            if role == "base":
                return artifact.report
        return self.artifacts[0].report if self.artifacts else None


@dataclass
class RunOutcome:
    """Results captured from a completed scan."""

    results: list[AppRunResult]
    started_at: datetime
    finished_at: datetime
    scope: ScopeSelection
    base_dir: Path
    warnings: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()


def _format_scope_target(selection: ScopeSelection) -> str:
    if selection.scope == "app":
        return f"App={selection.label}"
    if selection.scope == "category":
        return f"Category={selection.label}"
    return "All apps"


def _configure_logging_for_cli(level: str) -> None:
    level = level.strip().lower()
    if level not in {"debug", "info"}:
        level = "info"

    verbosity = "debug" if level == "debug" else "normal"
    configure_third_party_loggers(
        verbosity=verbosity,
        run_id="cli",
        debug_dir=str(Path(app_config.LOGS_DIR).resolve()),
    )

    root_level = logging.DEBUG if level == "debug" else logging.INFO
    logging.getLogger().setLevel(root_level)

    androguard_level = logging.DEBUG if level == "debug" else logging.ERROR
    for name in ("androguard", "androguard.core", "androguard.core.axml"):
        logging.getLogger(name).setLevel(androguard_level)

    quiet_level = logging.DEBUG if level == "debug" else logging.WARNING
    for name in ("zipfile", "urllib3"):
        logging.getLogger(name).setLevel(quiet_level)


def static_analysis_menu() -> None:
    """Render the static analysis menu loop with staged configuration screens."""

    # New ordering and labels (numeric only)
    option_map: Dict[str, str] = {
        "1": "full",          # Full static analysis (all detectors; writes to DB)
        "2": "lightweight",   # Baseline static analysis (paper-aligned; writes to DB)
        "3": "metadata",      # App Metadata (hashes, manifest flags)
        "4": "permissions",   # Permission Analysis (writes to DB)
        "5": "strings",       # String analysis (DEX + resources; writes to DB)
        "6": "split",         # Split-APK composition (base + splits)
        "7": "webview",       # WebView posture (read-only)
        "8": "nsc",           # Network Security Config (read-only)
        "9": "ipc",           # IPC & PendingIntent safety (read-only)
        "10": "crypto",       # Crypto/TLS quick scan (read-only)
        "11": "sdk",          # SDK fingerprints (read-only)
    }

    while True:
        # Clear screen before drawing a new menu screen (optional)
        try:
            from scytaledroid.Utils.DisplayUtils import ui_prefs as _ui
            if _ui.should_clear():
                from scytaledroid.Utils.System.util_actions import clear_screen as _clear
                _clear()
            else:
                print()
        except Exception:
            print()
        menu_utils.print_header("Android APK Static Analysis")
        menu_utils.print_menu(
            [
                ("1", "Full static analysis (all detectors; writes to DB)", "Run all detectors and persist summaries"),
                ("2", "Baseline static analysis (paper-aligned; writes to DB)", "Faster path; key detectors only"),
                ("3", "App Metadata (hashes, manifest flags)", "No DB writes; summary only"),
                ("4", "Permission Analysis (writes to DB)", "Persist detected permissions and audit"),
                ("5", "String analysis (DEX + resources; writes to DB)", "Persist string summary and samples"),
                ("6", "Split-APK composition (base + splits)", "Analyze split grouping and consistency"),
                ("7", "WebView posture (read-only)", "Check JS/mixed-content/JS bridge flags"),
                ("8", "Network Security Config (read-only)", "Parse NSC cleartext/pins/user certs"),
                ("9", "IPC & PendingIntent safety (read-only)", "Exported receivers/permissions; PI flags"),
                ("10", "Crypto/TLS quick scan (read-only)", "Weak hashes/TLS refs in strings"),
                ("11", "SDK fingerprints (read-only)", "Known analytics/ads SDK presence"),
            ],
            is_main=False,
        )
        choice = prompt_utils.get_choice(list(option_map.keys()) + ["0"], default="0")
        if choice == "0":
            break

        profile = option_map[choice]
        _launch_scan_flow(profile)


def _launch_scan_flow(initial_profile: str) -> None:
    base_dir = (Path(app_config.DATA_DIR) / "apks").resolve()
    groups = tuple(group_artifacts(base_dir))
    if not groups:
        print(
            status_messages.status(
                "No harvested APK groups found. Run Device Analysis → 7 to pull artifacts.",
                level="warn",
            )
        )
        prompt_utils.press_enter_to_continue()
        return

    selection = _select_scope(groups)
    profile = initial_profile
    params = RunParameters(profile=profile, scope=selection.scope, scope_label=selection.label)

    scope_target = _format_scope_target(selection)
    print()
    print(f"Running — {params.profile_label} static analysis")
    print(f"Target : {scope_target}")
    print(f"Profile: {params.profile_label}")
    print("-" * 41)

    _configure_logging_for_cli(params.log_level)
    if params.profile == "permissions":
        _execute_permission_scan(selection, params)
        return

    outcome = _execute_scan(selection, params, base_dir)
    _render_run_results(outcome, params)

    # For Full/Baseline profiles, render the same Permission Analysis view
    # used by the standalone menu so output is identical and includes
    # the audit snapshot id.
    if params.profile in {"full", "lightweight"}:
        try:
            from dataclasses import replace as _replace
            perm_params = _replace(params, profile="permissions")
            print()
            print("-- Re-rendering Permission Analysis snapshot for parity --")
            _execute_permission_scan(selection, perm_params, persist_detections=False)
        except Exception:
            pass


def _select_scope(groups: Sequence[ArtifactGroup]) -> ScopeSelection:
    print()
    menu_utils.print_header("Scope", "Select the analysis scope")
    options = {"1": "App", "2": "Category", "3": "All apps"}
    for key, label in options.items():
        print(f" {key}) {label}")
    choice = prompt_utils.get_choice(list(options.keys()), default="1")

    if choice == "1":
        return _select_app_scope(groups)
    if choice == "2":
        return _select_category_scope(groups)
    return ScopeSelection("all", "All apps", tuple(groups))


def _select_app_scope(groups: Sequence[ArtifactGroup]) -> ScopeSelection:
    packages = list_packages(groups)
    if not packages:
        print(status_messages.status("No packages available for analysis.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return ScopeSelection("all", "All apps", tuple(groups))

    print()
    menu_utils.print_header("Scope — App", "Select 1 package")
    rows = []
    for idx, (package, version, _count) in enumerate(packages, start=1):
        rows.append([str(idx), package, version])
    table_utils.render_table(["#", "Package", "Version"], rows)
    choice = prompt_utils.get_choice(
        [str(idx) for idx in range(1, len(packages) + 1)],
        prompt="Select package #: ",
        default="1",
    )
    package_name, _, _ = packages[int(choice) - 1]
    scoped = tuple(group for group in groups if group.package_name == package_name)
    return ScopeSelection("app", package_name, scoped)


def _select_category_scope(groups: Sequence[ArtifactGroup]) -> ScopeSelection:
    categories = list_categories(groups)
    if not categories:
        print(status_messages.status("No category data available.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return ScopeSelection("all", "All apps", tuple(groups))

    print()
    menu_utils.print_header("Scope — Category", "Select 1 category")
    rows = [[str(idx), category, str(count)] for idx, (category, count) in enumerate(categories, start=1)]
    table_utils.render_table(["#", "Category", "Groups"], rows)
    choice = prompt_utils.get_choice(
        [str(idx) for idx in range(1, len(categories) + 1)],
        prompt="Select category #: ",
        default="1",
    )
    category_name, _ = categories[int(choice) - 1]
    scoped = tuple(group for group in groups if group.category == category_name)
    return ScopeSelection("category", category_name, scoped)


def _prompt_tuning(base_params: RunParameters) -> RunParameters:
    params = base_params
    print()
    menu_utils.print_header("Tuning", "Adjust quick parameters")

    if params.profile == "custom":
        tests = _prompt_custom_tests(params.selected_tests)
        params = replace(params, selected_tests=tests)
    else:
        params = replace(params, selected_tests=tuple())

    evidence = _prompt_int("Evidence lines", params.evidence_lines, choices=_EVIDENCE_STEPS)
    findings = _prompt_int("Max findings/test", params.finding_limit, minimum=1)
    entropy = _prompt_float("Secrets sampler entropy ≥", params.secrets_entropy, minimum=0.0)
    hits = _prompt_int("Secrets sampler hits/bucket", params.secrets_hits_per_bucket, minimum=1)
    scope_choice = _prompt_choice(
        "Secrets sampler scope",
        {"1": "resources-only", "2": "dex-strings", "3": "both"},
        default={"resources": "1", "dex": "2", "both": "3"}.get(params.secrets_scope, "1"),
    )
    secrets_scope = {"1": "resources", "2": "dex", "3": "both"}[scope_choice]

    workers = prompt_utils.prompt_text(
        "Workers",
        default=params.workers,
        required=False,
        hint="Use 'auto' to match CPU count.",
    )
    reuse_cache = prompt_utils.prompt_yes_no(
        "Reuse cache", default=params.reuse_cache
    )
    log_level = _prompt_choice("Log level", {"1": "INFO", "2": "DEBUG"}, default="1")
    traces_raw = prompt_utils.prompt_text(
        "Trace detectors",
        default=",".join(params.trace_detectors) if params.trace_detectors else "",
        required=False,
        hint="Comma-separated detector IDs (optional).",
    )
    trace_detectors = tuple(
        token.strip()
        for token in traces_raw.split(",")
        if token.strip()
    )
    dry_run = prompt_utils.prompt_yes_no("Dry-run (no persistence)", default=params.dry_run)

    return replace(
        params,
        evidence_lines=evidence,
        finding_limit=findings,
        secrets_entropy=entropy,
        secrets_hits_per_bucket=hits,
        secrets_scope=secrets_scope,
        workers=workers or "auto",
        reuse_cache=reuse_cache,
        log_level="debug" if log_level == "2" else "info",
        trace_detectors=trace_detectors,
        dry_run=dry_run,
    )


def _prompt_custom_tests(selected: Tuple[str, ...]) -> Tuple[str, ...]:
    rows: list[list[str]] = []
    for idx, (key, label) in enumerate(_MICRO_TESTS, start=1):
        marker = "x" if key in selected else " "
        rows.append([str(idx), f"[{marker}] {label}"])
    table_utils.render_table(["#", "Test"], rows)
    default = ",".join(str(idx) for idx, (key, _) in enumerate(_MICRO_TESTS, start=1) if key in selected)
    response = prompt_utils.prompt_text(
        "Select tests (comma-separated #)",
        default=default,
        required=False,
    )
    if not response.strip():
        return selected if selected else tuple(key for key, _ in _MICRO_TESTS)

    tokens = {token.strip() for token in response.split(",") if token.strip()}
    chosen: list[str] = []
    for token in tokens:
        if not token.isdigit():
            continue
        index = int(token) - 1
        if 0 <= index < len(_MICRO_TESTS):
            chosen.append(_MICRO_TESTS[index][0])
    return tuple(chosen or (key for key, _ in _MICRO_TESTS))


def _prompt_int(label: str, default: int, *, choices: Sequence[int] | None = None, minimum: int = 1) -> int:
    if choices:
        print(f"{label} options: {', '.join(str(value) for value in choices)}")
        default_index = next((idx + 1 for idx, value in enumerate(choices) if value == default), 1)
        keys = [str(idx + 1) for idx in range(len(choices))]
        choice = prompt_utils.get_choice(keys, default=str(default_index))
        selected_index = int(choice) - 1
        selected_index = max(0, min(selected_index, len(choices) - 1))
        return choices[selected_index]

    while True:
        response = prompt_utils.prompt_text(label, default=str(default), required=False)
        if not response.strip():
            return max(minimum, default)
        try:
            value = int(response)
            return max(minimum, value)
        except ValueError:
            print(status_messages.status("Please enter a whole number.", level="warn"))


def _prompt_float(label: str, default: float, *, minimum: float = 0.0) -> float:
    while True:
        response = prompt_utils.prompt_text(label, default=f"{default}", required=False)
        if not response.strip():
            return max(minimum, default)
        try:
            value = float(response)
            return max(minimum, value)
        except ValueError:
            print(status_messages.status("Please enter a numeric value.", level="warn"))


def _prompt_choice(label: str, options: Mapping[str, str], *, default: str) -> str:
    for key, option_label in options.items():
        print(f" {key}) {option_label}")
    return prompt_utils.get_choice(list(options.keys()), default=default)


def _execute_scan(selection: ScopeSelection, params: RunParameters, base_dir: Path) -> RunOutcome:
    config = _build_analysis_config(params)
    started_at = datetime.now()
    total_groups = len(selection.groups)
    base_apk_ctx: dict[str, dict] = {}
    results: list[AppRunResult] = []
    warnings: list[str] = []
    failures: list[str] = []

    for group_index, group in enumerate(selection.groups, start=1):
        app_result = AppRunResult(package_name=group.package_name, category=group.category)
        results.append(app_result)
        artifact_total = len(group.artifacts)

        for artifact_index, artifact in enumerate(group.artifacts, start=1):
            progress_label = f"[{group_index}/{total_groups}] {group.package_name}"
            if artifact_total > 1:
                progress_label += f" ({artifact_index}/{artifact_total})"
            artifact_label = artifact.artifact_label or artifact.display_path
            # Reduce noise: print progress only once per app (first artifact)
            if artifact_index == 1:
                label = str(artifact_label)
                print(f"{progress_label} … analyzing {label}")

            artifact_started = perf_counter()
            wall_clock_started = datetime.now()
            report, saved_path, message, fatal = _generate_report(
                artifact,
                base_dir=base_dir,
                config=config,
                params=params,
            )
            wall_clock_finished = datetime.now()
            duration = perf_counter() - artifact_started

            if fatal or report is None:
                failure_reason = message or "analysis failed"
                failures.append(f"{artifact.display_path}: {failure_reason}")
                if artifact_index == 1:
                    print(f"{progress_label} … failed ({failure_reason})")
                continue

            if message:
                warnings.append(f"{artifact.display_path}: {message}")

            severity_counter: Counter[str] = Counter()
            for finding in report.findings:
                if isinstance(finding, Finding):
                    severity_counter[_severity_token(finding.severity_gate)] += 1

            summary = (
                "(High {H} | Med {M} | Low {L} | Info {I})".format(
                    H=severity_counter.get("H", 0),
                    M=severity_counter.get("M", 0),
                    L=severity_counter.get("L", 0),
                    I=severity_counter.get("I", 0),
                )
            )

            if artifact_index == 1:
                print(f"{progress_label} … done {summary} ({_format_duration(duration)})")

            app_result.artifacts.append(
                ArtifactOutcome(
                    label=artifact_label,
                    report=report,
                    severity=severity_counter,
                    duration_seconds=duration,
                    saved_path=None if params.dry_run else (saved_path or None),
                    started_at=wall_clock_started,
                    finished_at=wall_clock_finished,
                )
            )

        base_report = app_result.base_report()
        if base_report and base_report.signatures:
            app_result.signer = base_report.signatures[0]

    finished_at = datetime.now()
    return RunOutcome(
        results=results,
        started_at=started_at,
        finished_at=finished_at,
        scope=selection,
        base_dir=base_dir,
        warnings=warnings,
        failures=failures,
    )


def _execute_permission_scan(
    selection: ScopeSelection,
    params: RunParameters,
    *,
    persist_detections: bool = True,
) -> int | None:
    total_groups = len(selection.groups)
    processed_shas: set[str] = set()
    profiles_by_package: dict[str, dict] = {}
    printed_postcard_for: set[str] = set()
    printed_db_status_for: set[str] = set()
    declared_sources: dict[str, dict[str, List[Tuple[str, str]]]] = {}
    sdk_by_package: dict[str, Dict[str, str | None]] = {}
    label_by_package: dict[str, str] = {}
    category_by_package: dict[str, str] = {}

    for group_index, group in enumerate(selection.groups, start=1):
        artifact_total = len(group.artifacts)
        category_by_package[group.package_name] = getattr(group, "category", "Uncategorized")

        for artifact_index, artifact in enumerate(group.artifacts, start=1):
            progress_label = f"[{group_index}/{total_groups}] {group.package_name}"
            if artifact_total > 1:
                progress_label += f" ({artifact_index}/{artifact_total})"

            raw_label = artifact.artifact_label or artifact.display_path
            artifact_label = str(raw_label) if raw_label else "base"
            progress_message = f"{progress_label} … analyzing {artifact_label}"

            try:
                declared, defined, sdk = collect_permissions_and_sdk(
                    str(artifact.path)
                )
            except Exception as exc:  # pragma: no cover - defensive path
                print(f"{progress_message} … failed ({exc})")
                continue

            pkg_declared = declared_sources.setdefault(group.package_name, {})
            pkg_declared[artifact_label] = list(declared)
            sdk_payload = dict(sdk or {})
            if artifact_label == "base":
                sdk_by_package[group.package_name] = sdk_payload
            else:
                sdk_by_package.setdefault(group.package_name, sdk_payload)

            # Stream noise reduction: avoid per-artifact completion spam
            # (postcards and summaries provide the useful context)
            # Skip noisy empty split outputs
            if artifact_label == "base":
                if group.package_name not in printed_postcard_for:
                    app_label = (
                        str(artifact.metadata.get("app_label") or "").strip()
                        or group.package_name
                    )
                    label_by_package[group.package_name] = app_label
                    # Visual spacing between apps
                    print()
                    profile = render_permission_postcard(
                        group.package_name,
                        app_label,
                        declared,
                        defined,
                        index=group_index,
                        total=total_groups,
                    )
                    profiles_by_package[group.package_name] = profile
                    printed_postcard_for.add(group.package_name)
            else:
                # Suppress per-split verbose prints to reduce noise
                pass
            # Persist detected permissions (quick path) — only when enabled
            if persist_detections:
                try:
                    # Persist only for base artifact to reduce noise; avoid duplicate base processing per APK
                    if artifact_label == "base" and declared and group.package_name not in printed_db_status_for:
                        from scytaledroid.StaticAnalysis.persistence.permissions_db import (
                            persist_declared_permissions, _file_sha256,
                        )
                        sha = _file_sha256(artifact.path)
                        if sha and sha in processed_shas:
                            pass
                        else:
                            names = [name for name, _ in (declared or [])]
                            custom_names = [d.get("name") for d in (defined or []) if d.get("name")]
                            result = persist_declared_permissions(
                                package_name=group.package_name,
                                version_name=None,
                                version_code=None,
                                sha256=sha,
                                artifact_label=artifact_label,
                                declared=names,
                                custom_declared=custom_names,
                            )
                            if sha:
                                # Resolve apk context for risk table (apk_id/app_id/sha256)
                                try:
                                    from scytaledroid.Database.db_func.apk_repository import get_apk_by_sha256 as _get_apk
                                    row = _get_apk(sha)
                                    if row:
                                        base_apk_ctx[group.package_name] = {
                                            "apk_id": int(row.get("apk_id", 0) or 0),
                                            "app_id": int(row.get("app_id", 0) or 0) if row.get("app_id") is not None else None,
                                            "sha256": row.get("sha256") or sha,
                                        }
                                except Exception:
                                    pass
                                processed_shas.add(sha)
                            from scytaledroid.Utils.DisplayUtils import status_messages as _sm
                            total = sum(result.values()) if isinstance(result, dict) else 0
                            print(_sm.status(
                                f"DB detect: {total} perms (fw={result.get('framework', 0)}, vendor={result.get('vendor', 0)}, unk={result.get('unknown', 0)})",
                                level="info",
                            ))
                            printed_db_status_for.add(group.package_name)
                except Exception:
                    pass

    # After-run summary
    if profiles_by_package:
        print()
        apps_sorted = sorted(profiles_by_package.values(), key=lambda p: p.get("risk", 0.0), reverse=True)
        # Scope handling: limit to top 10 for All apps; otherwise include all
        if selection.scope == "all":
            subject = apps_sorted[:10]
            subject_label = "All apps"
        else:
            subject = apps_sorted
            subject_label = selection.label

        # Abbreviations block at the top (use app names for labels)
        from ..modules.permissions.simple import (
            _abbr_from_name as _abbr,
            _build_declared_origins as _build_origins,
            _collect_declared_tokens as _collect_tokens,
            render_contribution_summary,
        )
        print("Apps (abbrev):")
        for item in subject:
            abbr = _abbr(item["label"]).strip()
            print(f"  {abbr:<5} {item['label']}")
        print()

        # Risk summary and signal matrix
        render_after_run_summary(subject)
        render_signal_matrix(subject)
        render_contribution_summary(subject)

        # Matrix (compact)
        try:
            from ..modules.permissions.render_matrix import render_permissions as _render_perm_matrix
            _render_perm_matrix(subject, scope_label=subject_label, show=len(subject))
        except Exception:
            pass

        # Persist risk snapshot per-APK to DB (best-effort; single row per apk_id)
        try:
            from scytaledroid.Database.db_func import static_permission_risk as _spr
            from ..modules.permissions.analysis.risk_scoring_engine import permission_risk_grade as _grade
            from datetime import datetime as _dt
            stamp = _dt.utcnow().strftime("%Y%m%d-%H%M%S")
            if _spr.table_exists() or _spr.ensure_table():
                payloads = []
                for item in subject:
                    pkg = str(item.get("package") or item.get("package_name") or item["label"])  # label fallback
                    ctx = base_apk_ctx.get(pkg)
                    if not ctx or not ctx.get("apk_id"):
                        continue
                    score_val = float(item.get("risk", 0.0) or 0.0)
                    grade_val = _grade(score_val)
                    payloads.append(
                        {
                            "apk_id": int(ctx.get("apk_id") or 0),
                            "app_id": ctx.get("app_id"),
                            "package_name": pkg,
                            "sha256": str(ctx.get("sha256") or ""),
                            "session_stamp": stamp,
                            "scope_label": subject_label,
                            "risk_score": score_val,
                            "risk_grade": grade_val,
                            "dangerous": int(item.get("D", 0) or 0),
                            "signature": int(item.get("S", 0) or 0),
                            "vendor": int(item.get("V", 0) or 0),
                        }
                    )
                if payloads:
                    _spr.bulk_upsert(payloads)
        except Exception:
            pass

        # Persist detailed audit artefacts to disk
        from datetime import datetime as _dt

        snapshot_id = f"perm-{_dt.utcnow().strftime('%Y%m%d-%H%M%S')}"
        audit = PermissionAuditAccumulator(
            scope_label=subject_label,
            scope_type=selection.scope,
            total_groups=total_groups,
            snapshot_id=snapshot_id,
        )

        for package, profile in profiles_by_package.items():
            sources = declared_sources.get(package)
            if not sources:
                continue
            origins = _build_origins(
                sources,
                profile.get("fw_ds", set()),
                profile.get("vendor_names", set()),
            )
            tokens = _collect_tokens(sources)
            label = label_by_package.get(package, profile.get("label", package))
            detail = dict(profile.get("score_detail") or {})
            if not detail:
                continue
            audit.add_app(
                package=package,
                label=str(label),
                cohort=category_by_package.get(package, "Uncategorized"),
                sdk=sdk_by_package.get(package, {}),
                counts={
                    "dangerous": int(profile.get("D", 0) or 0),
                    "signature": int(profile.get("S", 0) or 0),
                    "vendor": int(profile.get("V", 0) or 0),
                },
                groups=profile.get("groups", {}),
                declared_in=origins,
                declared_permissions=tokens,
                score_detail=detail,
                vendor_present=bool(profile.get("V", 0)),
            )

        snapshot_payload = audit.finalize()
        snapshot_path = snapshot_payload.get("paths", {}).get("snapshot")
        if snapshot_path:
            print(f"\n[Audit] Snapshot saved to {snapshot_path}")

        # Persist audit snapshot/apps to DB for web app consumption (best-effort)
        try:
            persisted_id = audit.persist_to_db(snapshot_payload)
            if persisted_id:
                print(f"[Audit] Snapshot persisted to DB (id={persisted_id})")
            else:
                print("[Audit] DB persistence skipped or failed (see logs).")
        except Exception:
            pass
        return persisted_id


def _build_analysis_config(params: RunParameters) -> AnalysisConfig:
    profile_map = {
        "metadata": "quick",
        "permissions": "quick",
        "lightweight": "quick",
        "full": "full",
        "split": "quick",
        "strings": "quick",
        "webview": "quick",
        "nsc": "quick",
        "ipc": "quick",
        "crypto": "quick",
        "sdk": "quick",
    }
    profile = profile_map.get(params.profile, "full")
    enabled_detectors = _map_tests_to_detectors(params)
    enable_string_index = params.profile not in {"metadata", "permissions"}
    if params.profile == "custom" and "secrets" in params.selected_tests:
        enable_string_index = True

    return AnalysisConfig(
        profile=profile,
        verbosity=params.log_level,
        enabled_detectors=enabled_detectors or None,
        enable_string_index=enable_string_index,
    )


def _map_tests_to_detectors(params: RunParameters) -> Tuple[str, ...]:
    if params.profile == "metadata":
        return ("integrity_identity",)
    if params.profile == "permissions":
        return ("permissions_profile",)
    if params.profile == "strings":
        # Focused string-related detectors; keep quick profile
        return ("secrets", "webview", "network_surface")
    if params.profile == "webview":
        return ("webview_hygiene",)
    if params.profile == "nsc":
        return ("network_surface",)
    if params.profile == "ipc":
        return ("ipc_components", "provider_acl")
    if params.profile == "crypto":
        return ("crypto_hygiene",)
    if params.profile == "sdk":
        return ("sdk_inventory",)
    if params.profile != "custom":
        return tuple()

    mapping: Mapping[str, Tuple[str, ...]] = {
        "manifest": (
            "integrity_identity",
            "manifest_baseline",
            "ipc_components",
            "provider_acl",
        ),
        "provider_acl": ("provider_acl",),
        "nsc": ("network_surface",),
        "webview": ("webview",),
        "secrets": ("secrets",),
    }
    detectors: list[str] = []
    for test_key in params.selected_tests:
        detectors.extend(mapping.get(test_key, ()))
    return tuple(dict.fromkeys(detectors))


def _generate_report(
    artifact: RepositoryArtifact,
    *,
    base_dir: Path,
    config: AnalysisConfig,
    params: RunParameters,
) -> tuple[Optional[StaticAnalysisReport], Optional[Path], Optional[str], bool]:
    metadata_payload: MutableMapping[str, object] = dict(artifact.metadata)
    metadata_payload.setdefault("run_profile", params.profile)
    metadata_payload.setdefault("run_scope", params.scope)
    metadata_payload.setdefault("run_scope_label", params.scope_label)
    metadata_payload.setdefault("selected_tests", list(params.selected_tests))
    metadata_payload.setdefault(
        "tuning",
        {
            "evidence_lines": params.evidence_lines,
            "finding_limit": params.finding_limit,
            "secrets_entropy": params.secrets_entropy,
            "secrets_hits_per_bucket": params.secrets_hits_per_bucket,
            "secrets_scope": params.secrets_scope,
            "workers": params.workers,
            "reuse_cache": params.reuse_cache,
            "log_level": params.log_level,
            "trace_detectors": list(params.trace_detectors),
            "dry_run": params.dry_run,
        },
    )

    try:
        report = analyze_apk(
            artifact.path,
            metadata=metadata_payload,
            storage_root=base_dir,
            config=config,
        )
    except StaticAnalysisError as exc:
        return None, None, str(exc), True

    if params.dry_run:
        return report, None, "dry-run (not persisted)", False

    try:
        saved_paths = save_report(report)
        # Best-effort DB persistence of observed permissions only for relevant profiles
        if params.profile in {"permissions", "full", "lightweight", "custom"}:
            try:
                from scytaledroid.StaticAnalysis.persistence.permissions_db import (
                    persist_permissions_to_db,
                )

                if report is not None:
                    counts = persist_permissions_to_db(report)
                    try:
                        from scytaledroid.Utils.DisplayUtils import status_messages as _sm
                        total = sum(counts.values()) if isinstance(counts, dict) else 0
                        print(
                            _sm.status(
                                f"Permission Analysis persisted: total={total} (fw={counts.get('framework', 0)}, vendor={counts.get('vendor', 0)}, unk={counts.get('unknown', 0)})",
                                level="info",
                            )
                        )
                    except Exception:
                        pass
            except Exception:
                pass
        return report, saved_paths.json_path, None, False
    except ReportStorageError as exc:
        log.error(str(exc), category="static_analysis")
        # Still attempt DB persistence even if report save failed
        if params.profile in {"permissions", "full", "lightweight", "custom"}:
            try:
                from scytaledroid.StaticAnalysis.persistence.permissions_db import (
                    persist_permissions_to_db,
                )

                if report is not None:
                    counts = persist_permissions_to_db(report)
                    try:
                        from scytaledroid.Utils.DisplayUtils import status_messages as _sm
                        total = sum(counts.values()) if isinstance(counts, dict) else 0
                        print(
                            _sm.status(
                                f"Permission Analysis persisted: total={total} (fw={counts.get('framework', 0)}, vendor={counts.get('vendor', 0)}, unk={counts.get('unknown', 0)})",
                                level="info",
                            )
                        )
                    except Exception:
                        pass
            except Exception:
                pass
        return report, None, str(exc), False


def _render_run_results(outcome: RunOutcome, params: RunParameters) -> None:
    from datetime import datetime as _dt
    stamp = _dt.utcnow().strftime("%Y%m%d-%H%M%S")
    print(f"Duration: {_format_duration(outcome.duration_seconds)}")
    print()

    for index, app_result in enumerate(outcome.results, start=1):
        base_report = app_result.base_report()
        if base_report is None:
            warning = f"No report generated for {app_result.package_name}."
            print(status_messages.status(warning, level="warn"))
            continue

        # For metadata/permissions-only runs, skip string extraction to reduce noise
        if params.profile in {"metadata", "permissions"}:
            string_data = {"counts": {}, "samples": {}}
        else:
            string_data = analyse_strings(base_report.file_path)
            # Persist string summary (best-effort) for web app consumption
            try:
                from scytaledroid.Database.db_func import string_analysis as _sadb
                if _sadb.tables_exist() or _sadb.ensure_tables():
                    summary_id = _sadb.upsert_summary(
                        package_name=app_result.package_name,
                        session_stamp=stamp,
                        scope_label=params.scope_label or ("All apps" if params.scope == "all" else params.scope),
                        counts=string_data.get("counts", {}) if isinstance(string_data, dict) else {},
                    )
                    # Optional: store top samples (small, capped)
                    if summary_id:
                        samples = string_data.get("samples", {}) if isinstance(string_data, dict) else {}
                        _sadb.replace_top_samples(int(summary_id), samples, top_n=3)
            except Exception:
                pass
        total_duration = sum(artifact.duration_seconds for artifact in app_result.artifacts)
        lines, payload, finding_totals = render_app_result(
            base_report,
            signer=app_result.signer,
            split_count=len(app_result.artifacts),
            string_data=string_data,
            duration_seconds=total_duration,
        )

        # Merge detector findings into payload + totals for DB persistence (Full/Lightweight only)
        if params.profile in {"full", "lightweight"}:
            extra_findings: list[dict] = []
            severity_map = {"P0": "High", "P1": "Medium", "P2": "Low", "NOTE": "Info"}
            for result in (base_report.detector_results or ()):  # type: ignore[attr-defined]
                for f in result.findings:
                    sev = severity_map.get(f.severity_gate.value, "Info")
                    extra_findings.append(
                        {
                            "id": f.finding_id or result.detector_id,
                            "severity": sev,
                            "title": f.title,
                            "evidence": {"because": f.because, "tags": list(f.tags or ())},
                            "fix": f.remediate or None,
                        }
                    )
                    # bump totals
                    finding_totals[sev] += 1
            try:
                base = payload.get("baseline", {}) if isinstance(payload, dict) else {}
                cur = list(base.get("findings", []) or [])
                cur.extend(extra_findings)
                base["findings"] = cur
                payload["baseline"] = base
            except Exception:
                pass

        # Persist baseline findings only for full/lightweight/custom runs
        if params.profile in {"full", "lightweight", "custom", "strings"}:
            try:
                from scytaledroid.Database.db_func import static_findings as _sfdb
                if _sfdb.tables_exist() or _sfdb.ensure_tables():
                    details = {}
                    try:
                        b = payload.get("baseline", {}) if isinstance(payload, dict) else {}
                        details = {
                            "manifest_flags": b.get("manifest_flags"),
                            "exports": b.get("exports"),
                            "nsc": b.get("nsc"),
                            "webview": b.get("webview"),
                        }
                    except Exception:
                        details = {}
                    summary_id = _sfdb.upsert_summary(
                        package_name=app_result.package_name,
                        session_stamp=stamp,
                        scope_label=params.scope_label or ("All apps" if params.scope == "all" else params.scope),
                        severity_counts=finding_totals,
                        details=details,
                    )
                    if summary_id:
                        findings = []
                        try:
                            findings = (payload.get("baseline", {}) or {}).get("findings", [])
                        except Exception:
                            findings = []
                        _sfdb.replace_findings(int(summary_id), findings)
            except Exception:
                pass

        for line in lines:
            print(line)

        if not params.dry_run:
            import os as _os
            if _os.environ.get("SCY_BASELINE_WRITE_FILES", "1") != "0":
                saved_path = write_baseline_json(
                    payload,
                    package=app_result.package_name,
                    profile=params.profile,
                    scope=params.scope,
                )
                print(f"  Saved baseline JSON → {saved_path.name}")

        if index < len(outcome.results):
            print()

    if outcome.warnings:
        for message in sorted(set(outcome.warnings)):
            print(status_messages.status(message, level="warn"))
    if outcome.failures:
        for message in sorted(set(outcome.failures)):
            print(status_messages.status(message, level="error"))


def _render_app_table(results: Sequence[AppRunResult]) -> None:
    rows: list[list[str]] = []
    for idx, app_result in enumerate(results, start=1):
        totals = app_result.severity_totals()
        base_report = app_result.base_report()
        version = "—"
        target_sdk = "—"
        if base_report:
            version_name = base_report.manifest.version_name or "—"
            version_code = base_report.manifest.version_code
            version = (
                f"{version_name} ({version_code})"
                if version_code
                else version_name
            )
            target_sdk = base_report.manifest.target_sdk or "—"
        signer = app_result.signer or "—"
        rows.append(
            [
                str(idx),
                app_result.package_name,
                version,
                f"targetSdk={target_sdk}",
                signer,
                f"H {totals.get('H', 0)}",
                f"M {totals.get('M', 0)}",
                f"L {totals.get('L', 0)}",
                f"I {totals.get('I', 0)}",
            ]
        )
    headers = ["#", "Package", "Version", "Target", "Signer", "High", "Med", "Low", "Info"]
    print()
    table_utils.render_table(headers, rows)


def _app_detail_loop(outcome: RunOutcome, params: RunParameters, app_result: AppRunResult) -> None:
    active_levels = set(_SEVERITY_TOKEN_ORDER)
    evidence_lines = params.evidence_lines
    allow_rerun = params.profile != "custom"

    while True:
        _render_app_detail(app_result, evidence_lines, active_levels, params.finding_limit)
        print("[f] Filter severity  [e] Evidence lines  [r] Rerun micro-test  [q] Back")
        command = input("Command: ").strip().lower()
        if command == "q":
            break
        if command == "f":
            active_levels = _prompt_severity_filter(active_levels)
        elif command == "e":
            evidence_lines = _cycle_evidence_lines(evidence_lines)
        elif command == "r" and allow_rerun:
            _run_micro_rerun(outcome, app_result, evidence_lines)
        else:
            print(status_messages.status("Unknown command.", level="warn"))


def _render_app_detail(
    app_result: AppRunResult,
    evidence_lines: int,
    active_levels: Iterable[str],
    finding_limit: int,
) -> None:
    active = set(active_levels)
    base_report = app_result.base_report()
    version = target_sdk = "—"
    if base_report:
        version_name = base_report.manifest.version_name or "—"
        version_code = base_report.manifest.version_code
        version = f"{version_name} ({version_code})" if version_code else version_name
        target_sdk = base_report.manifest.target_sdk or "—"

    totals = app_result.severity_totals()
    print()
    print(f"{app_result.package_name} — Findings")
    print("―" * 40)
    print(
        f"High {totals.get('H',0)}   Med {totals.get('M',0)}   Low {totals.get('L',0)}   Info {totals.get('I',0)}"
    )
    print(f"Version: {version}   targetSdk={target_sdk}   Category: {app_result.category}")

    grouped = _collect_findings(app_result, evidence_lines)
    for section_key in [definition.key for definition in SECTION_DEFINITIONS]:
        entries = grouped.get(section_key, [])
        filtered = [entry for entry in entries if entry["token"] in active]
        if not filtered:
            continue
        title = _SECTION_TITLE_LOOKUP.get(section_key, section_key)
        print()
        print(f"[{title}]")
        for entry in filtered[: finding_limit]:
            print(
                f"  {entry['token']} {entry['id']}  {entry['title']}"
            )
            if entry["evidence"]:
                print(f"      file: {entry['evidence'][0]}")
            if entry["snippet"]:
                print(f"      snippet: {entry['snippet']}")
            print(f"      rationale: {entry['rationale']}")
            if entry["fix"]:
                print(f"      fix: {entry['fix']}")


def _collect_findings(app_result: AppRunResult, evidence_lines: int) -> Dict[str, list[Dict[str, str]]]:
    grouped: Dict[str, list[Dict[str, str]]] = defaultdict(list)
    for artifact in app_result.artifacts:
        for result in artifact.report.detector_results:
            section = result.section_key
            for finding in result.findings:
                token = _severity_token(finding.severity_gate)
                evidence_text = _format_evidence(finding.evidence, evidence_lines)
                snippet = finding.evidence[0].description if finding.evidence else ""
                grouped[section].append(
                    {
                        "token": token,
                        "id": finding.finding_id or finding.title,
                        "title": finding.title,
                        "evidence": evidence_text,
                        "snippet": snippet,
                        "rationale": finding.because,
                        "fix": finding.remediate or "",
                    }
                )
    return grouped


def _format_evidence(evidence: Sequence[EvidencePointer], limit: int) -> list[str]:
    pointers: list[str] = []
    for pointer in evidence[: max(1, limit)]:
        text = pointer.location
        if pointer.description:
            text += f" — {pointer.description}"
        pointers.append(text)
    return pointers


def _prompt_severity_filter(current: Iterable[str]) -> set[str]:
    current_set = set(current)
    options = {token: label for label, token in zip(["High", "Med", "Low", "Info"], _SEVERITY_TOKEN_ORDER)}
    print("Current filter: " + ", ".join(token for token in current_set))
    response = prompt_utils.prompt_text(
        "Filter severities (HM LI)",
        default="".join(current_set),
        required=False,
        hint="Provide combination of H/M/L/I. Empty = all.",
    )
    if not response.strip():
        return set(_SEVERITY_TOKEN_ORDER)
    selected = {char.upper() for char in response if char.upper() in _SEVERITY_TOKEN_ORDER}
    return selected or set(_SEVERITY_TOKEN_ORDER)


def _cycle_evidence_lines(current: int) -> int:
    try:
        index = _EVIDENCE_STEPS.index(current)
    except ValueError:
        index = 0
    index = (index + 1) % len(_EVIDENCE_STEPS)
    return _EVIDENCE_STEPS[index]


def _run_micro_rerun(outcome: RunOutcome, app_result: AppRunResult, evidence_lines: int) -> None:
    rows = [[str(idx), label] for idx, (_, label) in enumerate(_MICRO_TESTS, start=1)]
    table_utils.render_table(["#", "Micro-test"], rows)
    choice = prompt_utils.get_choice([str(idx) for idx in range(1, len(_MICRO_TESTS) + 1)], default="1")
    test_key = _MICRO_TESTS[int(choice) - 1][0]
    params = RunParameters(
        profile="custom",
        scope="app",
        scope_label=app_result.package_name,
        selected_tests=(test_key,),
        evidence_lines=evidence_lines,
        finding_limit=25,
    )
    selection = ScopeSelection("app", app_result.package_name, tuple([group for group in outcome.scope.groups if group.package_name == app_result.package_name]))
    if not selection.groups:
        print(status_messages.status("Micro-run scope could not be resolved.", level="warn"))
        return
    _configure_logging_for_cli(params.log_level)
    micro_outcome = _execute_scan(selection, params, outcome.base_dir)
    if not micro_outcome.results:
        print(status_messages.status("Micro-run produced no results.", level="warn"))
        return
    _render_app_detail(
        micro_outcome.results[0],
        evidence_lines,
        set(_SEVERITY_TOKEN_ORDER),
        params.finding_limit,
    )
    prompt_utils.press_enter_to_continue("Press Enter to return to previous results...")


def _severity_token(level: SeverityLevel) -> str:
    return _SEVERITY_LABELS.get(level, ("Info", "I"))[1]


def _format_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    return f"{seconds:.2f} s"


__all__ = ["static_analysis_menu"]
