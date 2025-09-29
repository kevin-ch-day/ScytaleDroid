"""
device_analysis_menu.py - Device connection and APK harvesting menu
"""

from scytaledroid.Utils.DisplayUtils import menu_utils


def device_menu() -> None:
    """
    Device menu with dashboard overview.
    For now this is stubbed; later these values will be fetched dynamically.
    """
    # Stubbed values for now — replace with real ADB queries later
    devices_found = 3
    connection_status = "DISCONNECTED"
    current_device = "None"

    # Print dashboard
    print("\n--- Device Dashboard ---")
    print(f"Devices Found: {devices_found}")
    print(f"Connection Status: {connection_status}")
    print(f"Current Device: {current_device}\n")

    # Print menu header + options
    menu_utils.print_header("Device Analysis")
    options = {
        "1": "List devices",
        "3": "Connect to a device",
        "4": "Show device info",
        "5": "Run device scan",
        "6": "Pull APKs",
        "7": "Logcat",
        "8": "Open ADB shell",
        "9": "Disconnect device",
    }
    menu_utils.print_menu(options, is_main=False)
    choice = menu_utils.get_choice(valid=list(options.keys()) + ["0"])

    if choice == "0":
        return  # Back to main menu
    else:
        print(f"[Device option {choice} coming soon...]")
        menu_utils.press_enter_to_continue()
