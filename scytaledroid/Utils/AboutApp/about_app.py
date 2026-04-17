"""About App panel with shared operator-facing styling."""

from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def about_app() -> None:
    """Show application information with themed styling."""

    print()
    menu_utils.print_header("About ScytaleDroid", "Android Security Research Platform")
    menu_utils.print_hint(
        "Local-first research tooling for physical-device collection, static exposure analysis, and dynamic evidence measurement."
    )
    menu_utils.print_section("Application")
    menu_utils.print_metrics(
        [
            ("Version", f"{app_config.APP_VERSION} ({app_config.APP_RELEASE})"),
            ("Maintainer", app_config.APP_AUTHOR),
            ("Source", app_config.GITHUB_REPO),
            ("Workspace", str(Path(app_config.DATA_DIR).resolve().parent)),
            ("Data directory", app_config.DATA_DIR),
            ("Logs directory", app_config.LOGS_DIR),
        ]
    )

    print()
    menu_utils.print_section("Mission")
    print(status_messages.status(
        "Mission: build reproducible APK intelligence from real devices.",
        level="info",
    ))
    print(status_messages.status(
        "Focus: longitudinal app changes, permissions, components, and runtime context.",
        level="info",
    ))
    print(status_messages.status(
        "Tip: Run Database tools -> Health checks before your first static run.",
        level="info",
    ))

    prompt_utils.press_enter_to_continue("Press Enter to return to Main Menu…")
