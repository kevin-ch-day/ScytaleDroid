"""
menu_utils.py - Shared menu framework utilities
Provides a consistent look-and-feel for ScytaleDroid CLI menus.
"""

from typing import Dict, Optional


def print_banner(app_name: str, app_version: str, app_release: str, app_description: str) -> None:
    """Print the global banner shown at startup."""
    print("=" * 50)
    print(f"   Welcome to {app_name}")
    print(f"   {app_description}")
    print(f"   Version {app_version} ({app_release})")
    print("=" * 50)
    print()


def print_header(title: str, subtitle: Optional[str] = None) -> None:
    """Print a menu header with optional subtitle (e.g., device state)."""
    line = f"=== {title} ==="
    if subtitle:
        line = f"{line}    {subtitle}"
    print(line)


def print_menu(options: Dict[str, str], is_main: bool = False) -> None:
    """
    Render a numbered menu given a dict of options.
    Automatically appends "0) Exit" or "0) Back" depending on context.
    
    Args:
        options: Dictionary where key = choice, value = label
        is_main: True if this is the Main Menu (0 = Exit), False if submenu (0 = Back)
    """
    for key, label in options.items():
        print(f"{key}) {label}")
    if is_main:
        print("0) Exit")
    else:
        print("0) Back")


def get_choice(valid: list[str], prompt: str = "> ") -> str:
    """
    Prompt user for input and validate against allowed values.
    Returns the chosen option as a string.
    """
    while True:
        choice = input(prompt).strip()
        if choice in valid:
            return choice
        print("Invalid choice. Please try again.")


def press_enter_to_continue(message: str = "Press Enter to continue...") -> None:
    """Pause execution until user presses Enter."""
    input(f"\n{message}\n")
