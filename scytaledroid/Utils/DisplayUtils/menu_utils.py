"""menu_utils.py - Shared menu framework utilities.

The menu helpers now take advantage of the richer colour primitives introduced
in :mod:`DisplayUtils.colors`.  In particular, they support optional per-option
descriptions and automatically align multi-line entries so that guidance text is
easier to scan.  This keeps the scope selector and future menus visually
consistent without forcing each caller to juggle alignment logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Optional, Sequence, Tuple

from . import colors, table_utils, text_blocks


@dataclass(frozen=True)
class MenuOption:
    """Structured representation of a menu option."""

    key: str
    label: str
    description: Optional[str] = None
    badge: Optional[str] = None
    disabled: bool = False
    hint: Optional[str] = None


def _coerce_option(
    key: object,
    label: object,
    description: Optional[object],
    *,
    badge: Optional[object] = None,
    disabled: bool = False,
    hint: Optional[object] = None,
) -> MenuOption:
    return MenuOption(
        str(key),
        str(label),
        None if description is None else str(description),
        None if badge is None else str(badge),
        disabled,
        None if hint is None else str(hint),
    )


def _normalise_options(
    options: Mapping[str, str] | Sequence[Tuple[str, str] | Tuple[str, str, str] | MenuOption]
) -> list[MenuOption]:
    if isinstance(options, Mapping):
        return [_coerce_option(key, value, None) for key, value in options.items()]

    normalised: list[MenuOption] = []
    for entry in options:
        if isinstance(entry, MenuOption):
            normalised.append(entry)
        elif isinstance(entry, tuple):
            if len(entry) == 2:
                normalised.append(_coerce_option(entry[0], entry[1], None))
            elif len(entry) == 3:
                normalised.append(_coerce_option(entry[0], entry[1], entry[2]))
            elif len(entry) == 4:
                normalised.append(
                    _coerce_option(entry[0], entry[1], entry[2], badge=entry[3])
                )
            else:  # pragma: no cover - defensive path
                raise ValueError("Menu tuples must contain 2 to 4 items")
        else:  # pragma: no cover - defensive path
            raise TypeError(f"Unsupported menu option type: {type(entry)!r}")
    return normalised


def print_banner(app_name: str, app_version: str, app_release: str, app_description: str) -> None:
    """Print the global banner shown at startup."""

    palette = colors.get_palette()
    title = colors.apply(app_name, palette.header, bold=True)
    description = colors.apply(app_description, palette.muted)
    version = colors.apply(f"Version {app_version} ({app_release})", palette.accent, bold=True)

    divider = colors.apply("".ljust(max(len(app_name), 32), "═"), palette.divider)

    print(title)
    print(divider)
    print(description)
    print(version)
    print()


def print_header(title: str, subtitle: Optional[str] = None) -> None:
    """Print a menu header with optional subtitle."""

    palette = colors.get_palette()
    if subtitle:
        text = text_blocks.headline(f"{title} — {subtitle}", width=70)
    else:
        text = text_blocks.headline(title, width=70)
    lines = text.splitlines()
    if lines:
        lines[0] = colors.apply(lines[0], palette.header)
    if len(lines) > 1:
        lines[1] = colors.apply(lines[1], palette.divider)
    print("\n".join(lines))


def print_hint(message: str, *, icon: str = "💡") -> None:
    """Render a muted hint or tip line."""

    palette = colors.get_palette()
    icon_text = colors.apply(icon, palette.hint)
    body = colors.apply(message, palette.muted)
    print(f"{icon_text} {body}")


def print_metrics(metrics: Sequence[Tuple[str, object]]) -> None:
    """Display key metrics as a short bulleted list with colouring."""

    palette = colors.get_palette()
    for label, value in metrics:
        label_text = colors.apply(str(label), palette.muted)
        value_text = colors.apply(str(value), palette.accent, bold=True)
        print(f"  • {label_text}: {value_text}")


def print_menu(
    options: Mapping[str, str]
    | Sequence[Tuple[str, str]
              | Tuple[str, str, str]
              | MenuOption],
    *,
    is_main: bool = False,
    default: Optional[str] = None,
    exit_label: Optional[str] = None,
    show_descriptions: bool = True,
    boxed: bool = False,
    width: int = 72,
    padding: bool = False,
) -> None:
    """Render a numbered menu with coloured keys and optional default."""

    palette = colors.get_palette()
    items = _normalise_options(options)
    primary_items = [item for item in items if item.key != "0"]

    key_width = max((len(item.key) for item in primary_items), default=1) + 1
    indent = " " * (key_width + 1)

    rendered_blocks: list[list[str]] = []

    for item in primary_items:
        if item.disabled:
            key_style = palette.disabled
            label_style = palette.disabled
        elif item.key == default:
            key_style = palette.option_default
            label_style = palette.accent
        else:
            key_style = palette.option_key
            label_style = palette.option_text

        block: list[str] = []
        key_token = colors.apply(f"{item.key})", key_style)
        label_token = colors.apply(item.label, label_style)
        badge_token = ""
        if item.badge:
            badge_token = f" {colors.apply('[' + item.badge + ']', palette.badge)}"
        disabled_note = (
            f" {colors.apply('(disabled)', palette.muted)}" if item.disabled else ""
        )
        block.append(f"{key_token} {label_token}{badge_token}{disabled_note}")

        if show_descriptions and item.description:
            description = colors.apply(item.description, palette.muted)
            block.append(f"{indent}{description}")
        if item.hint:
            hint_text = colors.apply(item.hint, palette.hint)
            block.append(f"{indent}{hint_text}")

        rendered_blocks.append(block)

    exit_text = exit_label or ("Exit" if is_main else "Back")
    exit_item = MenuOption("0", exit_text)
    exit_is_default = default == "0"
    exit_key_style = palette.option_default if exit_is_default else palette.option_key
    exit_label_style = palette.accent if exit_is_default else palette.option_text
    exit_key = colors.apply("0)", exit_key_style)
    exit_label_coloured = colors.apply(exit_item.label, exit_label_style)
    rendered_blocks.append([f"{exit_key} {exit_label_coloured}"])

    if boxed:
        flat_lines = []
        for block in rendered_blocks:
            flat_lines.extend(block)
        if padding:
            print()
        print(text_blocks.boxed(flat_lines, width=width))
        if padding:
            print()
        return

    if padding:
        print()

    for block in rendered_blocks:
        for line in block:
            print(line)

    if padding:
        print()
def print_table(headers: Iterable[str], rows: Iterable[Iterable[object]]) -> None:
    """Convenience wrapper around table rendering helper."""

    table_utils.render_table(list(headers), list(rows))


def print_section(title: str) -> None:
    """Print a small section divider suitable for nested menus."""

    palette = colors.get_palette()
    heading = text_blocks.headline(title, width=70)
    lines = heading.splitlines()
    if lines:
        lines[0] = colors.apply(lines[0], palette.header)
    if len(lines) > 1:
        lines[1] = colors.apply(lines[1], palette.divider)
    print("\n".join(lines))


__all__ = [
    "MenuOption",
    "print_banner",
    "print_header",
    "print_hint",
    "print_section",
    "print_menu",
    "print_metrics",
    "print_table",
]
