"""User prompt helpers for static analysis CLI."""

from __future__ import annotations

from dataclasses import replace
from typing import Dict, Sequence, Tuple

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils

from .models import RunParameters

MICRO_TESTS: Tuple[Tuple[str, str], ...] = (
    ("manifest", "Manifest-only"),
    ("provider_acl", "Provider ACL only"),
    ("nsc", "NSC only"),
    ("webview", "WebView quick"),
    ("secrets", "Secrets sampler"),
)

EVIDENCE_STEPS = (1, 2, 4)


def default_custom_tests() -> Tuple[str, ...]:
    return tuple(key for key, _ in MICRO_TESTS)


def prompt_advanced_options(base_params: RunParameters) -> RunParameters:
    """Collect advanced overrides for a run."""

    params = base_params
    print()
    menu_utils.print_header("Advanced options", "Override defaults for this run")

    table_utils.render_key_value_pairs(_summarise_params(params))
    if not prompt_utils.prompt_yes_no("Modify advanced options?", default=False):
        return params

    selected_tests = params.selected_tests or (
        default_custom_tests() if params.profile == "custom" else tuple()
    )
    if params.profile == "custom":
        selected_tests = prompt_custom_tests(selected_tests)

    evidence = prompt_int("Evidence lines", params.evidence_lines, choices=EVIDENCE_STEPS)
    findings = prompt_int("Max findings/test", params.finding_limit, minimum=1)
    entropy = prompt_float("Secrets sampler entropy ≥", params.secrets_entropy, minimum=0.0)
    hits = prompt_int("Secrets sampler hits/bucket", params.secrets_hits_per_bucket, minimum=1)
    scope_options = {"1": "resources-only", "2": "dex-only", "3": "both"}
    scope_choice = prompt_choice(
        "Secrets sampler scope",
        scope_options,
        default={
            "resources-only": "1",
            "dex-only": "2",
            "both": "3",
        }.get(params.secrets_scope_canonical, "3"),
    )
    secrets_scope = scope_options[scope_choice]

    strings_mode = params.strings_mode
    string_max_samples = params.string_max_samples
    string_min_entropy = params.string_min_entropy
    string_cleartext_only = params.string_cleartext_only
    string_include_https_risk = params.string_include_https_risk
    if params.profile == "strings":
        strings_choice = prompt_choice(
            "Strings mode",
            {"1": "both", "2": "dex", "3": "resources"},
            default={"both": "1", "dex": "2", "resources": "3"}.get(strings_mode, "1"),
        )
        strings_mode = {"1": "both", "2": "dex", "3": "resources"}[strings_choice]
        string_max_samples = prompt_int("Max string samples (UI)", string_max_samples, minimum=1)
        string_min_entropy = prompt_float("Min entropy threshold", string_min_entropy, minimum=0.0)
        string_cleartext_only = prompt_utils.prompt_yes_no(
            "Endpoints panel: show cleartext only",
            default=string_cleartext_only,
        )
        string_include_https_risk = prompt_utils.prompt_yes_no(
            "Count HTTPS endpoints towards network risk",
            default=string_include_https_risk,
        )

    workers = prompt_utils.prompt_text(
        "Workers",
        default=params.workers,
        required=False,
        hint="Use 'auto' to match CPU count.",
    )
    reuse_cache = prompt_utils.prompt_yes_no("Reuse disk cache", default=params.reuse_cache)
    log_level = prompt_choice("Log level", {"1": "INFO", "2": "DEBUG"}, default="1")
    traces_raw = prompt_utils.prompt_text(
        "Trace detectors",
        default=",".join(params.trace_detectors) if params.trace_detectors else "",
        required=False,
        hint="Comma-separated detector IDs (optional).",
    )
    trace_detectors = tuple(token.strip() for token in traces_raw.split(",") if token.strip())
    verbose_output = prompt_utils.prompt_yes_no("Verbose output", default=params.verbose_output)
    dry_run = prompt_utils.prompt_yes_no("Dry-run (no persistence)", default=params.dry_run)

    return replace(
        params,
        selected_tests=selected_tests,
        evidence_lines=evidence,
        finding_limit=findings,
        secrets_entropy=entropy,
        secrets_hits_per_bucket=hits,
        secrets_scope=secrets_scope,
        strings_mode=strings_mode,
        string_max_samples=string_max_samples,
        string_min_entropy=string_min_entropy,
        string_cleartext_only=string_cleartext_only,
        string_include_https_risk=string_include_https_risk,
        workers=workers or "auto",
        reuse_cache=reuse_cache,
        log_level="debug" if log_level == "2" else "info",
        trace_detectors=trace_detectors,
        dry_run=dry_run,
        verbose_output=verbose_output,
    )


def _summarise_params(params: RunParameters) -> Tuple[tuple[str, object], ...]:
    pairs: list[tuple[str, object]] = [
        ("Profile", params.profile_label),
        ("Scope", params.scope_label),
        ("Evidence lines", params.evidence_lines),
        ("Max findings/test", params.finding_limit),
        ("Secrets entropy", params.secrets_entropy),
        ("Secrets hits/bucket", params.secrets_hits_per_bucket),
        ("Secrets scope", params.secrets_scope_label),
    ]

    if params.profile == "custom":
        pairs.append(("Custom tests", _describe_custom_tests(params.selected_tests)))

    if params.profile == "strings":
        pairs.extend(
            (
                ("Strings mode", params.strings_mode),
                ("String max samples", params.string_max_samples),
                ("String min entropy", params.string_min_entropy),
                ("Cleartext only", _format_bool(params.string_cleartext_only)),
                (
                    "HTTPS counts toward risk",
                    _format_bool(params.string_include_https_risk),
                ),
            )
        )

    pairs.extend(
        (
            ("Workers", params.workers),
            ("Reuse cache", _format_bool(params.reuse_cache)),
            ("Log level", params.log_level.upper()),
            ("Verbose output", _format_bool(params.verbose_output)),
            (
                "Trace detectors",
                ", ".join(params.trace_detectors) if params.trace_detectors else "—",
            ),
            ("Dry-run", _format_bool(params.dry_run)),
        )
    )

    return tuple(pairs)


def _format_bool(value: bool) -> str:
    return "Yes" if value else "No"


def _describe_custom_tests(selected: Tuple[str, ...]) -> str:
    if not selected:
        return "All micro-tests"
    labels = {key: label for key, label in MICRO_TESTS}
    ordered = [labels.get(key, key) for key in selected]
    return ", ".join(ordered)


def prompt_custom_tests(selected: Tuple[str, ...]) -> Tuple[str, ...]:
    rows = []
    for idx, (key, label) in enumerate(MICRO_TESTS, start=1):
        marker = "x" if key in selected else " "
        rows.append([str(idx), f"[{marker}] {label}"])
    table_utils.render_table(["#", "Test"], rows)
    default = ",".join(str(idx) for idx, (key, _) in enumerate(MICRO_TESTS, start=1) if key in selected)
    response = prompt_utils.prompt_text(
        "Select tests (comma-separated #)",
        default=default,
        required=False,
    )
    if not response.strip():
        return selected if selected else tuple(key for key, _ in MICRO_TESTS)

    tokens = {token.strip() for token in response.split(",") if token.strip()}
    chosen: list[str] = []
    for token in tokens:
        if not token.isdigit():
            continue
        index = int(token) - 1
        if 0 <= index < len(MICRO_TESTS):
            chosen.append(MICRO_TESTS[index][0])
    return tuple(chosen or (key for key, _ in MICRO_TESTS))


def prompt_int(label: str, default: int, *, choices: Sequence[int] | None = None, minimum: int = 1) -> int:
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
        if response.isdigit():
            return max(minimum, int(response))
        print(status_messages.status("Invalid input. Please enter a number.", level="warn"))


def prompt_float(label: str, default: float, *, minimum: float = 0.0) -> float:
    while True:
        response = prompt_utils.prompt_text(label, default=f"{default}", required=False)
        if not response.strip():
            return max(minimum, default)
        try:
            value = float(response)
            return value if value >= minimum else minimum
        except ValueError:
            print(status_messages.status("Invalid number.", level="warn"))


def prompt_choice(label: str, options: Dict[str, str], *, default: str) -> str:
    print(f"{label}:")
    for key, text in options.items():
        print(f"  {key}) {text}")
    return prompt_utils.get_choice(list(options.keys()), default=default)


__all__ = [
    "MICRO_TESTS",
    "EVIDENCE_STEPS",
    "default_custom_tests",
    "prompt_advanced_options",
    "prompt_custom_tests",
    "prompt_int",
    "prompt_float",
    "prompt_choice",
]
