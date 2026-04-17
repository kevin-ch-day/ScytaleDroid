"""Terminal theme preview helpers for quick UX validation."""

from __future__ import annotations

from collections.abc import Iterable

from . import colors, summary_cards
from .terminal import use_ascii_ui


def _status_line(label: str, style_name: str, message: str) -> str:
    label_token = colors.apply(f"[{label}]", colors.style(style_name), bold=True)
    message_token = colors.apply(message, colors.style("text"))
    return f"{label_token} {message_token}"


def format_theme_preview(*, title: str = "Theme Preview") -> str:
    """Return a compact, styled preview block for the active palette."""

    palette_name = colors.current_palette_name()
    bullet = "- " if use_ascii_ui() else "• "

    lines: list[str] = []
    lines.append(colors.apply(f"{title}: {palette_name}", colors.style("header"), bold=True))
    lines.append(
        summary_cards.format_summary_card(
            "Core Roles",
            [
                summary_cards.summary_item("Info", "Inventory refreshed", value_style="info"),
                summary_cards.summary_item("Success", "Ready to proceed", value_style="success"),
                summary_cards.summary_item("Warning", "Operator review needed", value_style="warning"),
                summary_cards.summary_item("Error", "Action failed", value_style="error"),
                summary_cards.summary_item("Accent", "Primary selection", value_style="accent"),
            ],
            subtitle="Shared CLI semantics",
            footer="These roles drive banners, menus, dashboards, and run summaries.",
        )
    )
    lines.append(
        summary_cards.format_summary_card(
            "Operator Dashboard",
            [
                summary_cards.summary_item("Inventory", "FRESH", value_style="success"),
                summary_cards.summary_item("Harvest", "117 persisted", value_style="success"),
                summary_cards.summary_item("Blocked", "411 policy / 18 scope", value_style="warning"),
                summary_cards.summary_item("Evidence", "aligned with snapshot 26", value_style="accent"),
            ],
            subtitle="Compact scan-first example",
            footer="Use this look for default operator-facing screens.",
        )
    )
    lines.append(_status_line("INFO", "info", "Inventory refreshed and ready."))
    lines.append(_status_line("WARN", "warning", "Session is stale; re-sync recommended."))
    lines.append(_status_line("ERROR", "error", "Persistence gate failed."))
    lines.append(_status_line("OK", "success", "Canonical handoff validated."))
    lines.append(
        colors.apply("Menu emphasis:", colors.style("muted"))
        + " "
        + colors.apply("1)", colors.style("option_key"), bold=True)
        + " "
        + colors.apply("Refresh inventory", colors.style("option_text"))
        + " "
        + colors.apply("[recommended]", colors.style("badge"), bold=True)
    )

    severity_tokens: Iterable[tuple[str, str]] = (
        ("Critical", "severity_critical"),
        ("High", "severity_high"),
        ("Medium", "severity_medium"),
        ("Low", "severity_low"),
        ("Info", "severity_info"),
    )
    severity_line = "  ".join(
        colors.apply(name, colors.style(style_name), bold=True)
        for name, style_name in severity_tokens
    )
    lines.append(f"{bullet}{colors.apply('Severity scale:', colors.style('muted'))} {severity_line}")
    return "\n".join(lines)


def print_theme_preview(*, title: str = "Theme Preview") -> None:
    print(format_theme_preview(title=title))


__all__ = ["format_theme_preview", "print_theme_preview"]
