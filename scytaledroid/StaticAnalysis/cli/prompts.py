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


def prompt_tuning(base_params: RunParameters) -> RunParameters:
    params = base_params
    print()
    menu_utils.print_header("Tuning", "Adjust quick parameters")

    if params.profile == "custom":
        tests = prompt_custom_tests(params.selected_tests)
        params = replace(params, selected_tests=tests)
    else:
        params = replace(params, selected_tests=tuple())

    evidence = prompt_int("Evidence lines", params.evidence_lines, choices=EVIDENCE_STEPS)
    findings = prompt_int("Max findings/test", params.finding_limit, minimum=1)
    entropy = prompt_float("Secrets sampler entropy ≥", params.secrets_entropy, minimum=0.0)
    hits = prompt_int("Secrets sampler hits/bucket", params.secrets_hits_per_bucket, minimum=1)
    scope_choice = prompt_choice(
        "Secrets sampler scope",
        {"1": "resources-only", "2": "dex-strings", "3": "both"},
        default={"resources": "1", "dex": "2", "both": "3"}.get(params.secrets_scope, "1"),
    )
    secrets_scope = {"1": "resources", "2": "dex", "3": "both"}[scope_choice]

    strings_mode = params.strings_mode
    string_max_samples = params.string_max_samples
    string_min_entropy = params.string_min_entropy
    string_cleartext_only = params.string_cleartext_only
    if params.profile == "strings":
        strings_choice = prompt_choice(
            "Strings mode",
            {"1": "both", "2": "dex", "3": "resources"},
            default={"both": "1", "dex": "2", "resources": "3"}.get(params.strings_mode, "1"),
        )
        strings_mode = {"1": "both", "2": "dex", "3": "resources"}[strings_choice]
        string_max_samples = prompt_int("Max string samples (UI)", params.string_max_samples, minimum=1)
        string_min_entropy = prompt_float("Min entropy threshold", params.string_min_entropy, minimum=0.0)
        string_cleartext_only = prompt_utils.prompt_yes_no(
            "Endpoints panel: show cleartext only",
            default=params.string_cleartext_only,
        )

    workers = prompt_utils.prompt_text(
        "Workers",
        default=params.workers,
        required=False,
        hint="Use 'auto' to match CPU count.",
    )
    reuse_cache = prompt_utils.prompt_yes_no("Reuse cache", default=params.reuse_cache)
    log_level = prompt_choice("Log level", {"1": "INFO", "2": "DEBUG"}, default="1")
    traces_raw = prompt_utils.prompt_text(
        "Trace detectors",
        default=",".join(params.trace_detectors) if params.trace_detectors else "",
        required=False,
        hint="Comma-separated detector IDs (optional).",
    )
    trace_detectors = tuple(token.strip() for token in traces_raw.split(",") if token.strip())
    dry_run = prompt_utils.prompt_yes_no("Dry-run (no persistence)", default=params.dry_run)

    return replace(
        params,
        evidence_lines=evidence,
        finding_limit=findings,
        secrets_entropy=entropy,
        secrets_hits_per_bucket=hits,
        secrets_scope=secrets_scope,
        strings_mode=strings_mode,
        string_max_samples=string_max_samples,
        string_min_entropy=string_min_entropy,
        string_cleartext_only=string_cleartext_only,
        workers=workers or "auto",
        reuse_cache=reuse_cache,
        log_level="debug" if log_level == "2" else "info",
        trace_detectors=trace_detectors,
        dry_run=dry_run,
    )


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
    print(f"{label}:" )
    for key, text in options.items():
        print(f"  {key}) {text}")
    return prompt_utils.get_choice(list(options.keys()), default=default)


__all__ = [
    "MICRO_TESTS",
    "EVIDENCE_STEPS",
    "prompt_tuning",
    "prompt_custom_tests",
    "prompt_int",
    "prompt_float",
    "prompt_choice",
]
