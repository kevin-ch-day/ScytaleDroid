"""Menu helpers for API server control."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.ui import formatter

from .runtime import api_status, start_api_server, stop_api_server


def api_menu() -> None:
    """Render the API server menu."""

    while True:
        status = api_status()
        print()
        menu_utils.print_header("API Server")
        print(
            formatter.format_kv_block(
                "Status",
                {
                    "State": status.status,
                    "Host": status.host,
                    "Port": str(status.port),
                    "Detail": status.detail or "-",
                },
            )
        )

        print()
        print("1) Start server")
        print("2) Stop server")
        print("3) Restart server")
        print("0) Back")
        choice = prompt_utils.get_choice(["1", "2", "3", "0"], default="0")

        if choice == "0":
            return
        if choice == "1":
            status = start_api_server(force=False)
            level = "success" if status.running else "warn"
            print(status_messages.status(f"API status: {status.status}", level=level))
            continue
        if choice == "2":
            status = stop_api_server()
            level = "success" if not status.running else "warn"
            print(status_messages.status(f"API status: {status.status}", level=level))
            continue
        if choice == "3":
            stop_api_server()
            status = start_api_server(force=True)
            level = "success" if status.running else "warn"
            print(status_messages.status(f"API status: {status.status}", level=level))
            continue


__all__ = ["api_menu"]
