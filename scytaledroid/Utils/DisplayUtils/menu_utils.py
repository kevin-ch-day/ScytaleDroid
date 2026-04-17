from __future__ import annotations

import textwrap
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from . import colors, table_utils, text_blocks
from .terminal import get_terminal_width, use_ascii_ui


@dataclass(frozen=True)
class MenuOption:
    """Structured representation of a menu option."""

    key: str
    label: str
    description: str | None = None
    badge: str | None = None
    disabled: bool = False
    hint: str | None = None


@dataclass(frozen=True)
class MenuItemSpec:
    """Declarative menu item definition used by :func:`render_menu`."""

    key: str
    label: str
    description: str | None = None
    badge: str | None = None
    disabled: bool = False
    hint: str | None = None


@dataclass(frozen=True)
class MenuSpec:
    """Declarative menu definition for data-driven rendering."""

    items: Sequence[MenuItemSpec | MenuOption | tuple[str, str] | tuple[str, str, str]]
    default: str | None = None
    exit_label: str | None = None
    show_exit: bool = True
    show_descriptions: bool = True
    boxed: bool = False
    width: int | None = None
    padding: bool = False
    compact: bool = False
    title: str | None = None
    subtitle: str | None = None
    hint: str | None = None
    footer: str | None = None


def _coerce_option(
    key: object,
    label: object,
    description: object | None,
    *,
    badge: object | None = None,
    disabled: bool = False,
    hint: object | None = None,
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
    options: Mapping[str, str]
    | Sequence[
        tuple[str, str]
        | tuple[str, str, str]
        | MenuOption
        | MenuItemSpec
        | tuple[str, str, str, str]
    ]
) -> list[MenuOption]:
    if isinstance(options, Mapping):
        return [_coerce_option(key, value, None) for key, value in options.items()]

    normalised: list[MenuOption] = []
    for entry in options:
        if isinstance(entry, MenuOption):
            normalised.append(entry)
        elif isinstance(entry, MenuItemSpec):
            normalised.append(
                MenuOption(
                    key=entry.key,
                    label=entry.label,
                    description=entry.description,
                    badge=entry.badge,
                    disabled=entry.disabled,
                    hint=entry.hint,
                )
            )
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


def selectable_keys(
    options: Mapping[str, str]
    | Sequence[
        tuple[str, str]
        | tuple[str, str, str]
        | MenuOption
        | MenuItemSpec
        | tuple[str, str, str, str]
    ],
    *,
    include_exit: bool = True,
    exit_key: str = "0",
) -> list[str]:
    """Return selectable keys, excluding disabled entries."""

    seen: set[str] = set()
    keys: list[str] = []
    for item in _normalise_options(options):
        if item.disabled:
            continue
        if item.key in seen:
            continue
        keys.append(item.key)
        seen.add(item.key)
    if include_exit and exit_key not in seen:
        keys.append(exit_key)
    return keys


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


def _format_kv_lines(
    items: Sequence[tuple[str, object]],
    *,
    label_style: tuple[str, ...],
    value_style: tuple[str, ...],
    max_width: int,
    indent: str = "",
) -> list[str]:
    if not items:
        return []
    label_width = max((text_blocks.visible_width(str(label)) for label, _ in items), default=0)
    lines: list[str] = []
    for label, value in items:
        label_text = colors.apply(str(label).ljust(label_width), label_style)
        value_text = colors.apply(str(value), value_style, bold=True)
        line = f"{indent}{label_text} : {value_text}"
        lines.append(text_blocks.truncate_visible(line, max_width))
    return lines


def print_banner(app_name: str, app_version: str, app_release: str, app_description: str) -> None:
    """Print the global banner shown at startup."""

    palette = colors.get_palette()
    term_width = min(get_terminal_width(), 96)
    header = colors.apply(app_name, palette.header, bold=True)
    version_line = colors.apply(f"Version: {app_version} ({app_release})", palette.accent)
    lines = [header, version_line]
    if app_description:
        for line in _wrap_text(app_description, term_width - 4):
            lines.append(colors.apply(line, palette.muted))
    print(text_blocks.boxed(lines, width=term_width, padding=1))
    print()


def print_main_banner(
    app_name: str,
    app_version: str,
    app_release: str,
    app_description: str,
    *,
    build_id: str | None = None,
    menu_title: str | None = None,
    menu_subtitle: str | None = None,
    metrics: Sequence[tuple[str, object]] = (),
    hint: str | None = None,
    hero_lines: Sequence[str] = (),
    width: int | None = None,
) -> None:
    """Render a simplified banner used at the top of the main menu."""

    palette = colors.get_palette()
    term_width = width or min(get_terminal_width(), 100)
    inner_width = max(0, term_width - 4)
    ascii_ui = use_ascii_ui()

    header = colors.apply(app_name, palette.header, bold=True)
    version_line = colors.apply(
        f"{'Version' if ascii_ui else 'Version'}: {app_version} ({app_release})",
        palette.accent,
    )

    banner_lines = [header, version_line]
    if build_id:
        banner_lines.append(colors.apply(f"Build: {build_id}", palette.muted))
    if app_description:
        for line in _wrap_text(app_description, inner_width):
            banner_lines.append(colors.apply(line, palette.muted))

    if metrics:
        banner_lines.append(colors.apply("Status", palette.banner_primary, bold=True))
        banner_lines.extend(
            _format_kv_lines(
                metrics,
                label_style=palette.muted,
                value_style=palette.accent,
                max_width=inner_width,
                indent="  ",
            )
        )

    if hint:
        banner_lines.append(colors.apply("Tip", palette.banner_primary, bold=True))
        for line in _wrap_text(hint, inner_width):
            banner_lines.append(colors.apply(line, palette.hint))

    hero_messages = [line.strip() for line in hero_lines if line.strip()]
    if hero_messages:
        bullet = "-" if ascii_ui else "•"
        for message in hero_messages:
            banner_lines.append(f"{bullet} {message}")

    print(text_blocks.boxed(banner_lines, width=term_width, padding=1))

    if menu_title:
        print()
        print_header(menu_title, subtitle=menu_subtitle)


def print_header(title: str, subtitle: str | None = None) -> None:
    """Print a simple menu header suitable for plain terminals."""

    heading = title.strip()
    if not heading:
        return
    print(text_blocks.headline(heading))
    if subtitle:
        subheading = subtitle.strip()
        if subheading:
            palette = colors.get_palette()
            print(colors.apply(subheading, palette.muted))


def print_hint(message: str, *, icon: str | None = None) -> None:
    """Render a hint line without relying on complex glyphs."""

    text = message.strip()
    if not text:
        return

    prefix = icon.strip() if icon else ("→" if not use_ascii_ui() else "->")
    palette = colors.get_palette()
    prefix_text = colors.apply(prefix, palette.hint, bold=True)
    body_width = max(20, min(get_terminal_width(), 100) - 4)
    wrapped = _wrap_text(text, body_width)
    for index, line in enumerate(wrapped):
        leader = f"{prefix_text} " if index == 0 else "  "
        print(f"{leader}{colors.apply(line, palette.hint)}")


def print_metrics(metrics: Sequence[tuple[str, object]]) -> None:
    """Display key metrics as a short bulleted list."""

    palette = colors.get_palette()
    valid_metrics = [(str(label), value) for label, value in metrics]
    if not valid_metrics:
        return
    max_label = max((len(label) for label, _ in valid_metrics), default=0)
    for label, value in valid_metrics:
        label_text = colors.apply(label.ljust(max_label), palette.muted, bold=True)
        value_text = colors.apply(str(value), palette.accent, bold=True)
        print(f"{label_text} : {value_text}")


def print_menu(
    options: Mapping[str, str]
    | Sequence[tuple[str, str]
              | tuple[str, str, str]
              | MenuOption
              | MenuItemSpec],
    *,
    is_main: bool = False,
    default: str | None = None,
    exit_label: str | None = None,
    show_exit: bool = True,
    show_descriptions: bool = True,
    boxed: bool = False,
    width: int | None = None,
    padding: bool = False,
    compact: bool = False,
    title: str | None = None,
    subtitle: str | None = None,
    hint: str | None = None,
    footer: str | None = None,
) -> None:
    """Render a numbered menu with coloured keys and optional default."""

    # Cap rendering width for readability
    term_width = width if width is not None else min(get_terminal_width(), 100)
    items = _normalise_options(options)
    primary_items = [item for item in items if item.key != "0"]
    palette = colors.get_palette()
    key_width = max((len(str(item.key)) for item in items), default=1)

    indent = "  " if compact else "    "
    body_width = max(12 if compact else 20, term_width - len(indent) - 4)

    if title:
        print_header(title, subtitle=subtitle)
    elif subtitle:
        print(colors.apply(subtitle, palette.muted))
    if hint:
        print(colors.apply(hint, palette.hint))
        if primary_items:
            print()

    rendered_blocks: list[list[str]] = []

    for item in primary_items:
        block: list[str] = []
        key_display = str(item.key).rjust(key_width)
        key_text = colors.apply(key_display, colors.style("option_key"), bold=True)
        label_text = colors.apply(item.label, colors.style("option_text"))
        label_line = [f"{key_text}) {label_text}"]
        notes: list[str] = []
        if item.badge:
            badge_text = colors.apply(f"[{item.badge}]", colors.style("badge"), bold=True)
            notes.append(badge_text)
        if item.disabled:
            notes.append(colors.apply("(disabled)", colors.style("disabled")))
        elif default and item.key == default:
            notes.append(colors.apply("(default)", colors.style("option_default"), bold=True))
        if item.hint and not show_descriptions:
            notes.append(colors.apply(f"({item.hint})", palette.hint))
        if notes:
            notes_text = " ".join(notes)
            label_line.append(f" {notes_text}")
        block.append("".join(label_line))

        if show_descriptions and item.description:
            wrapped_desc = _wrap_text(item.description, body_width)
            for line in wrapped_desc:
                block.append(colors.apply(f"{indent}{line}", palette.muted))
        if show_descriptions and item.hint:
            wrapped_hint = _wrap_text(item.hint, body_width)
            for line in wrapped_hint:
                hint_text = f"{indent}Hint: {line}"
                block.append(colors.apply(hint_text, palette.hint))

        rendered_blocks.append(block)

    if show_exit:
        exit_text = exit_label or ("Exit" if is_main else "Back")
        exit_item = MenuOption("0", exit_text)
        exit_key = colors.apply(str(exit_item.key).rjust(key_width), colors.style("option_key"), bold=True)
        exit_label = colors.apply(exit_item.label, colors.style("option_text"))
        exit_label_line = f"{exit_key}) {exit_label}"
        if default == "0":
            exit_label_line += " " + colors.apply(
                "(default)", colors.style("option_default"), bold=True
            )
        rendered_blocks.append([exit_label_line])

    if boxed:
        flat_lines: list[str] = []
        for block in rendered_blocks:
            flat_lines.extend(block)
        if padding:
            print()
        print(text_blocks.boxed(flat_lines, width=term_width))
        if padding:
            print()
        return

    if padding and not compact:
        print()

    for block in rendered_blocks:
        for line in block:
            print(line)
        if show_descriptions and len(block) > 1 and not compact:
            print()

    if padding and not compact:
        print()
    if footer:
        print(colors.apply(footer, palette.hint))


def format_menu_panel(
    title: str,
    options: Mapping[str, str]
    | Sequence[tuple[str, str]
              | tuple[str, str, str]
              | MenuOption
              | MenuItemSpec],
    *,
    width: int | None = None,
    default_keys: Sequence[str] = (),
    compact: bool = False,
) -> str:
    """Return a boxed summary panel showcasing the provided menu *options*."""

    resolved_width = width or min(get_terminal_width(), 96)
    resolved_width = max(24 if compact else 34, min(resolved_width, 96))
    body_width = max(12 if compact else 18, resolved_width - 4)
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

        def _append_wrapped(text: str | None, style) -> None:
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
        tuple[
            str,
            Mapping[str, str]
            | Sequence[tuple[str, str] | tuple[str, str, str] | MenuOption],
        ]
    ],
    *,
    columns: int = 2,
    width: int | None = None,
    default_keys: Sequence[str] = (),
    gap: int = 4,
    compact: bool = False,
) -> None:
    """Render menu *sections* as a responsive grid of summary panels."""

    if not sections:
        return

    total_width = width or min(get_terminal_width(), 120)
    column_count = max(1, columns)
    spacer = " " * max(1 if compact else 2, gap)
    column_width = max(
        24 if compact else 34,
        min((total_width - (column_count - 1) * len(spacer)) // column_count, 96),
    )

    rendered: list[tuple[list[str], int]] = []
    for title, options in sections:
        panel_text = format_menu_panel(
            title,
            options,
            width=column_width,
            default_keys=default_keys,
            compact=compact,
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


def render_menu(spec: MenuSpec) -> None:
    """Render a menu using a declarative :class:`MenuSpec`."""

    print_menu(
        spec.items,
        is_main=False,
        default=spec.default,
        exit_label=spec.exit_label,
        show_exit=spec.show_exit,
        show_descriptions=spec.show_descriptions,
        boxed=spec.boxed,
        width=spec.width,
        padding=spec.padding,
        compact=spec.compact,
        title=spec.title,
        subtitle=spec.subtitle,
        hint=spec.hint,
        footer=spec.footer,
    )


def print_section(title: str) -> None:
    """Print a small section divider suitable for nested menus."""

    heading = title.strip()
    if not heading:
        return

    palette = colors.get_palette()
    print(colors.apply(heading, palette.banner_primary, bold=True))
    print(text_blocks.divider(width=max(4, len(heading)), style="divider"))


__all__ = [
    "MenuOption",
    "MenuItemSpec",
    "MenuSpec",
    "print_banner",
    "print_main_banner",
    "print_header",
    "print_hint",
    "print_section",
    "print_menu",
    "render_menu",
    "print_metrics",
    "print_table",
    "selectable_keys",
    "format_menu_panel",
    "print_menu_panels",
]
