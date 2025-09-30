"""menu_utils.py - Shared menu framework utilities."""

from __future__ import annotations

from typing import Dict, Iterable, Optional

from . import status_messages, table_utils, text_blocks


def print_banner(app_name: str, app_version: str, app_release: str, app_description: str) -> None:
    """Print the global banner shown at startup."""
    lines = [
        f"Welcome to {app_name}",
        app_description,
        f"Version {app_version} ({app_release})",
    ]
    print(text_blocks.boxed(lines, width=70))
    print()


def print_header(title: str, subtitle: Optional[str] = None) -> None:
    """Print a menu header with optional subtitle."""
    if subtitle:
        print(text_blocks.headline(f"{title} — {subtitle}", width=70))
    else:
        print(text_blocks.headline(title, width=70))


def print_menu(options: Dict[str, str], is_main: bool = False) -> None:
    """Render a numbered menu given a dict of options."""
    for key, label in options.items():
        print(f"{key}) {label}")
    print("0) Exit" if is_main else "0) Back")


def get_choice(valid: Iterable[str], prompt: str = "> ", default: Optional[str] = None) -> str:
    """Prompt user for input and validate against allowed values."""
    valid_set = set(valid)
    while True:
        choice = input(prompt).strip()
        if choice == "" and default is not None:
            return default
        if choice in valid_set:
            return choice
        print(status_messages.status("Invalid choice. Please try again.", level="warn"))


def prompt_yes_no(prompt: str, *, default: bool = False) -> bool:
    """Ask a yes/no question and return True for yes."""
    suffix = "[Y/n]" if default else "[y/N]"
    valid = {"y": True, "yes": True, "n": False, "no": False}

    while True:
        answer = input(f"{prompt} {suffix} ").strip().lower()
        if not answer:
            return default
        if answer in valid:
            return valid[answer]
        print(status_messages.status("Please respond with yes or no.", level="warn"))


def press_enter_to_continue(message: str = "Press Enter to continue...") -> None:
    """Pause execution until user presses Enter."""
    input(f"\n{message}\n")


def print_table(headers: Iterable[str], rows: Iterable[Iterable[object]]) -> None:
    """Convenience wrapper around table rendering helper."""
    table_utils.render_table(list(headers), list(rows))
