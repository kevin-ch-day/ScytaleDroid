"""Menu helpers for API server control."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

from .runtime import api_status, start_api_server, stop_api_server


def api_menu() -> None:
    """Render the API server menu."""

    while True:
        status = api_status()
        print()
        menu_utils.print_header("API Server")
        menu_utils.print_hint("Start, stop, or restart the local API runtime without leaving the operator console.")
        menu_utils.print_section("Runtime State")
        menu_utils.print_metrics(
            [
                ("State", status.status),
                ("Host", status.host),
                ("Port", status.port),
                ("Detail", status.detail or "-"),
            ]
        )

        options = [
            menu_utils.MenuOption(
                "1",
                "Start server",
                disabled=bool(status.running),
                hint="Already running" if status.running else None,
            ),
            menu_utils.MenuOption(
                "2",
                "Stop server",
                disabled=not bool(status.running),
                hint="Server is not running" if not status.running else None,
            ),
            menu_utils.MenuOption("3", "Restart server"),
        ]
        menu_utils.print_section("Actions")
        menu_utils.render_menu(
            menu_utils.MenuSpec(
                items=options,
                show_exit=True,
                exit_label="Back",
                show_descriptions=False,
            )
        )
        choice = prompt_utils.get_choice(
            menu_utils.selectable_keys(options, include_exit=True),
            default="0",
            disabled=[opt.key for opt in options if opt.disabled],
        )

        if choice == "0":
            return
        if choice == "1":
            try:
                status = start_api_server(force=False)
                level = "success" if status.running else "warn"
                print(status_messages.status(f"API status: {status.status}", level=level))
            except RuntimeError as exc:
                print(status_messages.status(f"API start blocked: {exc}", level="error"))
            continue
        if choice == "2":
            status = stop_api_server()
            level = "success" if not status.running else "warn"
            print(status_messages.status(f"API status: {status.status}", level=level))
            continue
        if choice == "3":
            stop_api_server()
            try:
                status = start_api_server(force=True)
                level = "success" if status.running else "warn"
                print(status_messages.status(f"API status: {status.status}", level=level))
            except RuntimeError as exc:
                print(status_messages.status(f"API start blocked: {exc}", level="error"))
            continue


__all__ = ["api_menu"]
