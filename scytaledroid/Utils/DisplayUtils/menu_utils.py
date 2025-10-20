from __future__ import annotations

import textwrap
from dataclasses import dataclass
from typing import Iterable, Mapping, Optional, Sequence, Tuple

from . import colors, summary_cards, table_utils, text_blocks
from .terminal import get_terminal_width, use_ascii_ui


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


def _wrap_text(text: str, width: int) -> list[str]:
    if width <= 0:
        return [text]
    wrapped = textwrap.wrap(
        text,
        width=width,
        break_long_words=False,
        break_on_hyphens=False,
    )
    return wrapped or [text]


def print_banner(app_name: str, app_version: str, app_release: str, app_description: str) -> None:
    """Print the global banner shown at startup."""

    card = summary_cards.format_summary_card(
        app_name,
        [("Version", f"{app_version} ({app_release})")],
        subtitle=app_description,
    )
    print(card)
    print()


def print_main_banner(
    app_name: str,
    app_version: str,
    app_release: str,
    app_description: str,
    *,
    menu_title: str | None = None,
    menu_subtitle: str | None = None,
    metrics: Sequence[Tuple[str, object]] = (),
    hint: str | None = None,
    hero_lines: Sequence[str] = (),
    width: int | None = None,
) -> None:
    """Render the decorated banner used at the top of the main menu."""

    items: list[Tuple[str, object]] = [("Version", f"{app_version} ({app_release})")]
    items.extend(metrics)
    card = summary_cards.format_summary_card(
        app_name,
        items,
        subtitle=app_description,
        footer=hint,
        width=width,
    )
    print(card)
    if hero_lines:
        palette = colors.get_palette()
        icon = "*" if use_ascii_ui() else "✶"
        accent_icon = colors.apply(icon, palette.banner_primary, bold=True)
        for raw_line in hero_lines:
            line = raw_line.strip()
            if not line:
                continue
            text = colors.apply(line, palette.emphasis, bold=True)
            print(f"{accent_icon} {text}")
    if menu_title:
        print()
        print_header(menu_title, subtitle=menu_subtitle)


def print_header(title: str, subtitle: Optional[str] = None) -> None:
    """Print a menu header with optional subtitle."""

    palette = colors.get_palette()
    ascii_ui = use_ascii_ui()
    separator = " - " if ascii_ui else " — "
    # Cap rendering width for readability
    term_width = min(get_terminal_width(), 100)
    if subtitle:
        text = text_blocks.headline(f"{title}{separator}{subtitle}", width=term_width)
    else:
        text = text_blocks.headline(title, width=term_width)
    lines = text.splitlines()
    if lines:
        lines[0] = colors.apply(lines[0], palette.header)
    if len(lines) > 1:
        lines[1] = colors.apply(lines[1], palette.divider)
    print("\n".join(lines))


def print_hint(message: str, *, icon: Optional[str] = None) -> None:
    """Render a muted hint or tip line."""

    palette = colors.get_palette()
    ascii_ui = use_ascii_ui()
    resolved_icon = icon if icon is not None else ("i" if ascii_ui else "💡")
    icon_text = colors.apply(resolved_icon, palette.hint)
    body = colors.apply(message, palette.muted)
    print(f"{icon_text} {body}")


def print_metrics(metrics: Sequence[Tuple[str, object]]) -> None:
    """Display key metrics as a short bulleted list with colouring."""

    palette = colors.get_palette()
    bullet = "-" if use_ascii_ui() else "•"
    for label, value in metrics:
        label_text = colors.apply(str(label), palette.muted)
        value_text = colors.apply(str(value), palette.accent, bold=True)
        print(f"  {bullet} {label_text}: {value_text}")


def print_menu(
    options: Mapping[str, str]
    | Sequence[Tuple[str, str]
              | Tuple[str, str, str]
              | MenuOption],
    *,
    is_main: bool = False,
    default: Optional[str] = None,
    exit_label: Optional[str] = None,
    show_exit: bool = True,
    show_descriptions: bool = True,
    boxed: bool = False,
    width: Optional[int] = None,
    padding: bool = False,
) -> None:
    """Render a numbered menu with coloured keys and optional default."""

    palette = colors.get_palette()
    # Cap rendering width for readability
    term_width = width if width is not None else min(get_terminal_width(), 100)
    items = _normalise_options(options)
    primary_items = [item for item in items if item.key != "0"]

    key_width = max((len(item.key) for item in primary_items), default=1) + 1
    gutter_width = key_width + 1
    indent = " " * gutter_width
    body_width = max(10, term_width - gutter_width - 1)

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
        disabled_note = ""

        reserved = (
            text_blocks.visible_width(key_token)
            + 1
            + text_blocks.visible_width(badge_token)
            + text_blocks.visible_width(disabled_note)
        )
        available_label = max(0, term_width - reserved)
        label_token = text_blocks.truncate_visible(label_token, available_label)
        block.append(f"{key_token} {label_token}{badge_token}{disabled_note}")

        if show_descriptions and item.description:
            wrapped_desc = _wrap_text(item.description, body_width)
            for line in wrapped_desc:
                description = colors.apply(line, palette.muted)
                block.append(f"{indent}{description}")
        if item.hint:
            wrapped_hint = _wrap_text(item.hint, body_width)
            for line in wrapped_hint:
                hint_text = colors.apply(line, palette.hint)
                block.append(f"{indent}{hint_text}")

        rendered_blocks.append(block)

    if show_exit:
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
        print(text_blocks.boxed(flat_lines, width=term_width))
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


def format_menu_panel(
    title: str,
    options: Mapping[str, str]
    | Sequence[Tuple[str, str]
              | Tuple[str, str, str]
              | MenuOption],
    *,
    width: Optional[int] = None,
    default_keys: Sequence[str] = (),
) -> str:
    """Return a boxed summary panel showcasing the provided menu *options*."""

    resolved_width = width or min(get_terminal_width(), 96)
    resolved_width = max(34, min(resolved_width, 96))
    body_width = max(18, resolved_width - 4)
    palette = colors.get_palette()
    default_set = {str(key) for key in default_keys if key is not None}

    lines: list[str] = []
    header_text = colors.apply(title, palette.banner_primary, bold=True)
    lines.append(header_text)

    for option in _normalise_options(options):
        if option.disabled:
            key_style = palette.disabled
            label_style = palette.disabled
        elif option.key in default_set:
            key_style = palette.option_default
            label_style = palette.accent
        else:
            key_style = palette.option_key
            label_style = palette.option_text

        key_token = colors.apply(f"{option.key})", key_style, bold=True)
        label_token = colors.apply(option.label, label_style, bold=True)
        badge_token = ""
        if option.badge:
            badge_token = f" {colors.apply('[' + option.badge + ']', palette.badge)}"
        header_line = text_blocks.truncate_visible(
            f"{key_token} {label_token}{badge_token}",
            body_width,
        )
        lines.append(header_line)

        def _append_wrapped(text: Optional[str], style) -> None:
            if not text:
                return
            for entry in _wrap_text(text, body_width):
                styled = colors.apply(entry, style)
                lines.append(styled)

        _append_wrapped(option.description, palette.muted)
        _append_wrapped(option.hint, palette.hint)
        if option.disabled:
            lines.append(colors.apply("Temporarily unavailable", palette.disabled))
        lines.append("")

    if lines and not lines[-1]:
        lines.pop()

    return text_blocks.boxed(lines, width=resolved_width, padding=1)


def print_menu_panels(
    sections: Sequence[
        Tuple[
            str,
            Mapping[str, str]
            | Sequence[Tuple[str, str] | Tuple[str, str, str] | MenuOption],
        ]
    ],
    *,
    columns: int = 2,
    width: Optional[int] = None,
    default_keys: Sequence[str] = (),
    gap: int = 4,
) -> None:
    """Render menu *sections* as a responsive grid of summary panels."""

    if not sections:
        return

    total_width = width or min(get_terminal_width(), 120)
    column_count = max(1, columns)
    spacer = " " * max(2, gap)
    column_width = max(
        34,
        min((total_width - (column_count - 1) * len(spacer)) // column_count, 96),
    )

    rendered: list[tuple[list[str], int]] = []
    for title, options in sections:
        panel_text = format_menu_panel(
            title,
            options,
            width=column_width,
            default_keys=default_keys,
        )
        panel_lines = panel_text.splitlines()
        visible_width = max((text_blocks.visible_width(line) for line in panel_lines), default=0)
        rendered.append((panel_lines, visible_width))

    for offset in range(0, len(rendered), column_count):
        chunk = rendered[offset : offset + column_count]
        row_height = max(len(lines) for lines, _ in chunk)
        for line_index in range(row_height):
            parts: list[str] = []
            for lines, panel_width in chunk:
                if line_index < len(lines):
                    segment = lines[line_index]
                else:
                    segment = ""
                padding = panel_width - text_blocks.visible_width(segment)
                if padding > 0:
                    segment = f"{segment}{' ' * padding}"
                parts.append(segment)
            print(spacer.join(parts).rstrip())
        print()


def print_table(headers: Iterable[str], rows: Iterable[Iterable[object]]) -> None:
    """Convenience wrapper around table rendering helper."""

    table_utils.render_table(list(headers), list(rows))


def print_section(title: str) -> None:
    """Print a small section divider suitable for nested menus."""

    palette = colors.get_palette()
    heading = text_blocks.headline(title, width=get_terminal_width())
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
    "format_menu_panel",
    "print_menu_panels",
]
