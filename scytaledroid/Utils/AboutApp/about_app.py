"""
about_app.py - About App menu
"""

from scytaledroid.Config import app_config


def about_app() -> None:
    """Show application information."""
    print("\n=== About App ===")
    print(f"{app_config.APP_NAME} v{app_config.APP_VERSION} ({app_config.APP_RELEASE})")
    print(app_config.APP_DESCRIPTION)
    print(f"Author: {app_config.APP_AUTHOR}")
    print(f"GitHub: {app_config.GITHUB_REPO}\n")
    input("Press Enter to return to Main Menu…\n")
