"""prompt_utils.py - Centralised interactive prompt helpers for the CLI."""

from __future__ import annotations

import sys
import termios
import tty
from collections.abc import Callable, Iterable

from . import colors, status_messages
from .error_panels import print_error_panel
from .terminal import use_ascii_ui


def _build_prompt(default: str | None) -> str:
    palette = colors.get_palette()
    arrow_symbol = ">" if use_ascii_ui() else "›"
    arrow = colors.apply(arrow_symbol, palette.option_key)
    if default is None:
        return f"{arrow} "
    hint = colors.apply(f"[{default}]", palette.muted)
    return f"{arrow} {hint} "


def get_choice(
    valid: Iterable[str],
    *,
    prompt: str = "> ",
    default: str | None = None,
    casefold: bool = False,
    invalid_message: str = "Invalid choice. Please try again.",
    disabled: Iterable[str] | None = None,
) -> str:
    """Prompt the user to select a value from *valid* and return it."""

    disabled_set = {d.lower() if casefold else d for d in disabled or ()}

    value_map: dict[str, str] = {}
    for entry in valid:
        key = entry.lower() if casefold else entry
        if key in disabled_set:
            continue
        value_map[key] = entry

    if not value_map:
        raise ValueError("No selectable menu entries provided")

    effective_default: str | None = None
    if default is not None:
        default_key = default.lower() if casefold else default
        effective_default = value_map.get(default_key)
        if effective_default is None:
            # Fall back to the first available option so Enter still works.
            effective_default = next(iter(value_map.values()))

    rendered_prompt = prompt if prompt != "> " else _build_prompt(effective_default)

    while True:
        response = input(rendered_prompt).strip()
        if not response:
            if effective_default is not None:
                return effective_default
        else:
            key = response.lower() if casefold else response
            if key in value_map:
                return value_map[key]
        print(status_messages.status(invalid_message, level="warn"))


def prompt_yes_no(prompt: str, *, default: bool = False) -> bool:
    """Ask a yes/no question and return ``True`` for yes."""

    suffix = "[Y/n]" if default else "[y/N]"
    rendered_prompt = f"{prompt} {suffix} "
    valid = {"y": True, "yes": True, "n": False, "no": False}

    while True:
        answer = input(rendered_prompt).strip().lower()
        if not answer:
            return default
        if answer in valid:
            return valid[answer]
        print(status_messages.status("Please respond with yes or no.", level="warn"))


def press_enter_to_continue(
    message: str = "Press Enter to continue...",
    *,
    force: bool = False,
) -> None:
    """Pause execution until the user presses Enter."""

    if not force:
        pass
    palette = colors.get_palette()
    prompt_text = colors.apply(message, palette.muted)
    try:
        input(f"\n{prompt_text}\n")
    except EOFError:
        # Non-interactive execution (e.g., scripts/CI). Treat as "continue".
        return


def press_any_key(
    message: str = "Press any key to continue...",
    *,
    force: bool = False,
) -> None:
    """Pause execution until the user presses a key."""

    if not force:
        pass
    palette = colors.get_palette()
    prompt_text = colors.apply(message, palette.muted)
    if not sys.stdin.isatty():
        input(f"\n{prompt_text}\n")
        return
    print(f"\n{prompt_text}")
    fd = sys.stdin.fileno()
    try:
        old_settings = termios.tcgetattr(fd)
        tty.setraw(fd)
        sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def prompt_text(
    prompt: str,
    *,
    default: str | None = None,
    required: bool = True,
    validator: Callable[[str], bool] | None = None,
    error_message: str = "Please provide a value.",
    error_hint: str | None = None,
    hint: str | None = None,
    show_arrow: bool = True,
) -> str:
    """Prompt for free-form text, optionally validating the response."""

    palette = colors.get_palette()
    arrow_symbol = ">" if use_ascii_ui() else "›"
    arrow = colors.apply(arrow_symbol, palette.option_key) if show_arrow else ""
    label = colors.apply(prompt, palette.prompt)
    default_hint = (
        f" {colors.apply(f'[{default}]', palette.muted)}" if default is not None else ""
    )
    if hint:
        hint_text = colors.apply(hint, palette.hint)
        print(hint_text)
    spacer = " " if arrow else ""
    rendered_prompt = f"{arrow}{spacer}{label}{default_hint} "

    while True:
        response = input(rendered_prompt).strip()
        if not response:
            if default is not None:
                return default
            if not required:
                return ""
        else:
            if validator is None or validator(response):
                return response
        if error_hint:
            print_error_panel("Invalid Input", error_message, hint=error_hint)
        else:
            print(status_messages.status(error_message, level="warn"))


__all__ = [
    "get_choice",
    "press_enter_to_continue",
    "press_any_key",
    "prompt_text",
    "prompt_yes_no",
]
