"""Discord-specific scripted templates."""

from __future__ import annotations

SCRIPT_STEPS_DISCORD_BASIC_V1: tuple[tuple[str, str, int], ...] = (
    ("open_home", "Open Discord landing/home and wait for initial sync.", 10),
    ("open_fixed_server", "Open the designated server (same server every run).", 15),
    ("open_fixed_text_channel", "Open a designated text channel and wait for messages to load.", 25),
    ("scroll_history_briefly", "Scroll up 2 swipes, pause, then down 2 swipes.", 30),
    ("open_member_or_profile", "Open a user/profile OR member list briefly, then return.", 20),
    ("reaction_or_copy_optional", "Optional: add 1 reaction OR copy text (no typing required).", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 45),
)

V3_BASELINE_REPRO_TIPS_DISCORD: dict[str, tuple[str, ...]] = {
    "com.discord": (
        "Recommended: force-stop the app before starting the baseline idle.",
        "Stay on the Discord home surface; do not type, join voice, or browse channels.",
    ),
}

V3_SCRIPTED_REPRO_TIPS_DISCORD: dict[str, tuple[str, ...]] = {
    "discord_basic_v1": (
        "Use the same fixed server + fixed text channel each run.",
        "Avoid typing/sending; reactions/copy are optional and controlled.",
    ),
}

__all__ = [
    "SCRIPT_STEPS_DISCORD_BASIC_V1",
    "V3_BASELINE_REPRO_TIPS_DISCORD",
    "V3_SCRIPTED_REPRO_TIPS_DISCORD",
]
