"""About App panel with enriched styling."""

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, text_blocks


def about_app() -> None:
    """Show application information with themed styling."""

    print()
    menu_utils.print_header("About ScytaleDroid", "Android Security Research Platform")

    summary_lines = [
        f"{app_config.APP_NAME} v{app_config.APP_VERSION} ({app_config.APP_RELEASE})",
        app_config.APP_DESCRIPTION,
    ]
    print(text_blocks.boxed(summary_lines, width=74))

    menu_utils.print_metrics(
        [
            ("Maintainer", app_config.APP_AUTHOR),
            ("Source", app_config.GITHUB_REPO),
            ("Data directory", app_config.DATA_DIR),
            ("Logs directory", app_config.LOGS_DIR),
        ]
    )

    print()
    print(status_messages.status(
        "Mission: streamline harvesting, static and dynamic triage for Android defenses.",
        level="info",
    ))
    print(status_messages.status(
        "Tip: Run 'Database Tasks' from the main menu before your first static analysis.",
        level="info",
    ))

    prompt_utils.press_enter_to_continue("Press Enter to return to Main Menu…")
