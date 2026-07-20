#!/usr/bin/env python3
"""Read-only audit of CLI prompt and menu-choice patterns.

The audit scans Python source with ``ast`` and writes derived JSON/CSV reports.
It does not import application modules, connect to databases, or mutate runtime
state.
"""

from __future__ import annotations

import argparse
import ast
import csv
import json
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCAN_ROOTS = ("scytaledroid", "main.py")
PROMPT_HELPER_FILE = "scytaledroid/Utils/DisplayUtils/prompt_utils.py"

CALL_TYPES = {
    "get_choice",
    "menu_choice",
    "prompt_text",
    "prompt_yes_no",
    "press_enter_to_continue",
    "press_any_key",
    "print_menu",
    "input",
}

MUTATION_PROMPT_TERMS = (
    "apply",
    "backfill",
    "collapse",
    "delete",
    "finalize",
    "migrate",
    "prune",
    "purge",
    "rebuild",
    "repair",
    "write",
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scan-root",
        action="append",
        default=[],
        help="File or directory to scan, relative to repo root unless absolute. Defaults to scytaledroid and main.py.",
    )
    parser.add_argument("--output-dir", default=None, help="Optional explicit output directory.")
    return parser


def _repo_rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT.resolve()))
    except ValueError:
        return str(path)


def _iter_python_files(scan_roots: Iterable[str]) -> list[Path]:
    paths: list[Path] = []
    for raw_root in scan_roots:
        root = Path(raw_root)
        if not root.is_absolute():
            root = REPO_ROOT / root
        if root.is_file() and root.suffix == ".py":
            paths.append(root)
        elif root.is_dir():
            paths.extend(sorted(root.rglob("*.py")))
    return sorted(set(paths))


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _literal(value: ast.AST | None) -> Any:
    if value is None:
        return None
    try:
        return ast.literal_eval(value)
    except Exception:
        return None


def _keyword(node: ast.Call, name: str) -> ast.AST | None:
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _source_segment(source: str, node: ast.AST) -> str:
    try:
        return (ast.get_source_segment(source, node) or "").strip()
    except Exception:
        return ""


def _classify_call(path: Path, node: ast.Call, source: str) -> dict[str, Any]:
    call_type = _call_name(node)
    rel_path = _repo_rel(path)
    prompt_value = _literal(_keyword(node, "prompt"))
    default_value = _literal(_keyword(node, "default"))
    if call_type == "prompt_text" and node.args:
        prompt_value = _literal(node.args[0])
    if call_type == "prompt_yes_no" and node.args:
        prompt_value = _literal(node.args[0])
    if call_type == "input" and node.args:
        prompt_value = _literal(node.args[0])

    finding_class = "standard_helper"
    recommended_action = "none"
    if call_type == "input" and rel_path != PROMPT_HELPER_FILE:
        finding_class = "direct_input_outside_prompt_utils"
        recommended_action = "replace_with_prompt_utils_helper_or_document_exception"
    elif call_type == "get_choice":
        if prompt_value and str(prompt_value) != "> ":
            finding_class = "custom_choice_prompt_text"
            recommended_action = "standardize_if_this_is_a_menu_prompt"
        elif default_value == "0":
            finding_class = "menu_choice_enter_defaults_back"
            recommended_action = "confirm_default_back_is_intentional"
        elif default_value not in (None, ""):
            finding_class = "menu_choice_enter_selects_action"
            recommended_action = "review_if_action_is_destructive_or_expensive"
        else:
            finding_class = "menu_choice_no_default"
            recommended_action = "consider_explicit_default_for_consistent_eof_behavior"
    elif call_type == "menu_choice":
        finding_class = "standard_menu_choice_helper"
        recommended_action = "none"
    elif call_type == "prompt_yes_no":
        prompt_lower = str(prompt_value or "").lower()
        if default_value is True and any(term in prompt_lower for term in MUTATION_PROMPT_TERMS):
            finding_class = "yes_no_mutation_default_yes"
            recommended_action = "prefer_default_false_or_require_explicit_confirmation"
        else:
            finding_class = "yes_no_prompt"
            recommended_action = "confirm_default_matches_mutation_risk"
    elif call_type == "prompt_text":
        finding_class = "text_prompt"
        recommended_action = "ensure_label_is_action_or_value_requested"
    elif call_type.startswith("press_"):
        finding_class = "pause_prompt"
        recommended_action = "none"
    elif call_type == "print_menu":
        finding_class = "menu_render"
        recommended_action = "pair_with_selectable_keys_and_get_choice"

    return {
        "file": rel_path,
        "line": node.lineno,
        "call_type": call_type,
        "finding_class": finding_class,
        "prompt_text": "" if prompt_value is None else str(prompt_value),
        "default": "" if default_value is None else str(default_value),
        "recommended_action": recommended_action,
        "source": _source_segment(source, node),
    }


def collect_prompt_choice_rows(scan_roots: Iterable[str] = DEFAULT_SCAN_ROOTS) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in _iter_python_files(scan_roots):
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_type = _call_name(node)
            if call_type not in CALL_TYPES:
                continue
            rows.append(_classify_call(path, node, source))
    rows.sort(key=lambda row: (str(row["file"]), int(row["line"]), str(row["call_type"])))
    return rows


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def generate_audit(*, scan_roots: Iterable[str] = DEFAULT_SCAN_ROOTS, output_dir: Path | None = None) -> dict[str, Any]:
    rows = collect_prompt_choice_rows(scan_roots)
    call_counts = Counter(str(row["call_type"]) for row in rows)
    finding_counts = Counter(str(row["finding_class"]) for row in rows)
    files_with_direct_input = sorted(
        {str(row["file"]) for row in rows if row["finding_class"] == "direct_input_outside_prompt_utils"}
    )
    if output_dir is None:
        output_dir = REPO_ROOT / "output" / "audit" / "cli_prompt_choice" / datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "scan_roots": list(scan_roots),
        "row_count": len(rows),
        "call_counts": dict(sorted(call_counts.items())),
        "finding_counts": dict(sorted(finding_counts.items())),
        "files_with_direct_input_outside_prompt_utils": files_with_direct_input,
        "output_files": {
            "summary_json": str((output_dir / "summary.json").resolve()),
            "prompt_choice_calls_csv": str((output_dir / "prompt_choice_calls.csv").resolve()),
            "review_candidates_csv": str((output_dir / "review_candidates.csv").resolve()),
        },
        "no_db_writes": True,
        "read_only": True,
    }
    review_rows = [
        row
        for row in rows
        if row["finding_class"]
        in {
            "custom_choice_prompt_text",
            "direct_input_outside_prompt_utils",
            "menu_choice_enter_selects_action",
            "menu_choice_no_default",
            "yes_no_prompt",
            "yes_no_mutation_default_yes",
        }
    ]
    _write_json(output_dir / "summary.json", summary)
    _write_csv(output_dir / "prompt_choice_calls.csv", rows)
    _write_csv(output_dir / "review_candidates.csv", review_rows)
    return summary


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    scan_roots = args.scan_root or list(DEFAULT_SCAN_ROOTS)
    output_dir = Path(args.output_dir) if args.output_dir else None
    summary = generate_audit(scan_roots=scan_roots, output_dir=output_dir)
    print("# cli prompt/choice audit")
    print(f"row_count: {summary['row_count']}")
    print(f"call_counts: {json.dumps(summary['call_counts'], sort_keys=True)}")
    print(f"finding_counts: {json.dumps(summary['finding_counts'], sort_keys=True)}")
    print(f"direct_input_files: {len(summary['files_with_direct_input_outside_prompt_utils'])}")
    print(f"output_dir: {Path(summary['output_files']['summary_json']).parent}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
